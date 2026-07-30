//! znx-consensus — reglas de consenso de Prueba de Trabajo: verificación de
//! la prueba de trabajo de un header, reajuste de dificultad, calendario de
//! emisión (subsidio de bloque + halving), y comparación de trabajo
//! acumulado para fork-choice (la cadena con más trabajo acumulado gana,
//! no la más larga en cantidad de bloques — dos bloques fáciles pueden
//! pesar menos que uno solo difícil).
//!
//! Reemplaza el diseño anterior (round-robin PoA + gadget BFT, nunca
//! implementado) — PoW abierta no tiene identidad de validador que rotar
//! ni votos de finalidad que juntar.
//!
//! Este crate no sabe nada de storage ni de red: opera sobre los valores
//! que le pasa el caller (`znx-node`) — headers/targets ya leídos de donde
//! sea que vivan. Tampoco sabe nada de UTXOs (eso es znx-state) — acá solo
//! se decide SI un bloque/cadena es válida para extender/reemplazar la
//! cadena actual, no cómo cambia el estado.

use num_bigint::BigUint;
use thiserror::Error;
use znx_codec::{meets_target, pow_hash};
use znx_types::BlockHeader;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsensusError {
    #[error("el hash del header no cumple el target declarado (falta prueba de trabajo)")]
    InsufficientWork,
}

/// Techo de dificultad: el target más alto (= la dificultad más baja)
/// permitido en la red. Evita que la dificultad caiga a un punto en que
/// una sola máquina doméstica reescriba la cadena entera en minutos, sin
/// impedir que un devnet arranque con muy poca potencia de cómputo (el
/// génesis puede declarar cualquier target por debajo de este techo).
pub const MAX_TARGET: [u8; 32] = {
    let mut t = [0xffu8; 32];
    t[0] = 0x00;
    t
};

/// Cuánto puede moverse la dificultad en un solo reajuste, para arriba o
/// para abajo, aunque el tiempo real observado se haya desviado mucho más
/// que eso del esperado — mismo clamp que usa Bitcoin, evita que una racha
/// corta de bloques anómalos (o un ataque) dispare la dificultad a un
/// extremo de un solo salto.
pub const MAX_ADJUSTMENT_FACTOR: u64 = 4;

/// Verifica que el hash del header cumpla el target que el propio header
/// declara. **No** verifica que ese target sea el correcto para la altura
/// (eso requiere conocer el historial de headers previos — ver
/// `expected_target`); esa segunda verificación la hace el caller antes o
/// después de esta.
pub fn verify_pow(header: &BlockHeader) -> Result<(), ConsensusError> {
    let hash = pow_hash(header);
    if meets_target(&hash, &header.target) {
        Ok(())
    } else {
        Err(ConsensusError::InsufficientWork)
    }
}

/// Subsidio de bloque en la altura dada, según un cronograma por
/// escalones: `subsidy_schedule[0]` rige durante el primer
/// `period_blocks` bloques, `subsidy_schedule[1]` el siguiente período,
/// etc. Una vez agotados los escalones explícitos, el subsidio sigue
/// dividiéndose a la mitad (floor de enteros, igual que el `>>` de
/// Bitcoin real) cada `period_blocks` bloques a partir del último
/// escalón — así que `subsidy_schedule` no tiene que declarar la cola
/// infinita, solo los escalones "irregulares" del principio.
///
/// Caso particular: `subsidy_schedule` de un solo elemento reproduce
/// exactamente el calendario de halving puro de antes de este cronograma
/// por escalones (`initial_subsidy >> (height / period_blocks)`) — es el
/// caso que sigue usando el devnet.
///
/// Después de 128 halvings más allá del último escalón el subsidio es
/// cero por definición — evita un shift de más de 127 bits en un `u128`,
/// que en Rust es un error en vez de simplemente dar cero.
///
/// Panics: `subsidy_schedule` no puede estar vacío — es un error de
/// configuración del génesis, no una condición recuperable en runtime
/// (`Genesis::load` valida esto antes de que este código se llegue a
/// llamar).
pub fn subsidy_for_height(height: u64, subsidy_schedule: &[u128], period_blocks: u64) -> u128 {
    assert!(!subsidy_schedule.is_empty(), "subsidy_schedule no puede estar vacío");
    let period = height / period_blocks;
    let last_index = (subsidy_schedule.len() - 1) as u64;

    if period <= last_index {
        subsidy_schedule[period as usize]
    } else {
        let halvings_past_last = period - last_index;
        if halvings_past_last >= 128 {
            0
        } else {
            subsidy_schedule[last_index as usize] >> halvings_past_last
        }
    }
}

/// Reajusta el target de dificultad al final de un período de
/// `difficulty_adjustment_interval_blocks`, comparando cuánto tardó ese
/// período en la realidad (`actual_timespan_secs`, suma de los intervalos
/// entre bloques observados) contra cuánto debería haber tardado
/// (`expected_timespan_secs = target_block_time_secs *
/// difficulty_adjustment_interval_blocks`). Aritmética con enteros de
/// precisión arbitraria (`BigUint`), no floats: esto es una regla de
/// consenso — todos los nodos tienen que llegar exactamente al mismo
/// resultado, y el punto flotante no garantiza eso de forma determinística
/// entre plataformas/compiladores.
///
/// `new_target = clamp(prev_target * actual/expected, prev_target/4, prev_target*4)`,
/// y el resultado nunca supera `MAX_TARGET` (nunca más fácil que el techo
/// de dificultad de la red).
pub fn retarget(prev_target: &[u8; 32], actual_timespan_secs: u64, expected_timespan_secs: u64) -> [u8; 32] {
    let min_timespan = (expected_timespan_secs / MAX_ADJUSTMENT_FACTOR).max(1);
    let max_timespan = expected_timespan_secs * MAX_ADJUSTMENT_FACTOR;
    let clamped_actual = actual_timespan_secs.clamp(min_timespan, max_timespan);

    let prev = BigUint::from_bytes_be(prev_target);
    let scaled = (prev * BigUint::from(clamped_actual)) / BigUint::from(expected_timespan_secs.max(1));

    let max_target = BigUint::from_bytes_be(&MAX_TARGET);
    let clamped = scaled.min(max_target);

    biguint_to_target(&clamped)
}

fn biguint_to_target(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut target = [0u8; 32];
    // `to_bytes_be` no rellena a 32 bytes y omite ceros a la izquierda —
    // si el valor entra en 32 bytes (siempre debería, ya viene clampeado
    // contra MAX_TARGET antes de llegar acá), se copia alineado a la
    // derecha (los bytes más significativos quedan en cero).
    let start = 32usize.saturating_sub(bytes.len());
    let take = bytes.len().min(32);
    target[start..].copy_from_slice(&bytes[bytes.len() - take..]);
    target
}

/// "Trabajo" que representa un target de dificultad: `2^256 / (target + 1)`
/// — a menor target (más difícil), más trabajo. Se usa para comparar
/// cadenas competidoras por trabajo acumulado, no por cantidad de bloques
/// (dos bloques fáciles pueden pesar menos que uno solo difícil).
pub fn block_work(target: &[u8; 32]) -> BigUint {
    let target_val = BigUint::from_bytes_be(target);
    let numerator = BigUint::from(1u8) << 256u32;
    numerator / (target_val + BigUint::from(1u8))
}

/// Trabajo acumulado de una secuencia de targets (los headers de una
/// cadena candidata) — la cadena con mayor `cumulative_work` es la que
/// gana el fork-choice.
pub fn cumulative_work<'a>(targets: impl IntoIterator<Item = &'a [u8; 32]>) -> BigUint {
    targets.into_iter().fold(BigUint::from(0u8), |acc, target| acc + block_work(target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use znx_types::BlockHeader;

    fn header_with(target: [u8; 32], pow_nonce: u64) -> BlockHeader {
        BlockHeader { height: 1, parent_hash: [0u8; 32], tx_root: [0u8; 32], timestamp: 0, target, pow_nonce }
    }

    #[test]
    fn verify_pow_accepts_a_hash_meeting_an_easy_target() {
        // Target = máximo u256 posible: CUALQUIER hash de 32 bytes cumple
        // (comparación lexicográfica, cada byte es <= 0xff). No es
        // `MAX_TARGET` (el techo real de dificultad de la red, que sí deja
        // afuera algunos hashes) — este test solo quiere un caso trivial.
        let header = header_with([0xffu8; 32], 0);
        assert!(verify_pow(&header).is_ok());
    }

    #[test]
    fn verify_pow_rejects_a_hash_missing_an_impossible_target() {
        let header = header_with([0u8; 32], 0);
        assert_eq!(verify_pow(&header).unwrap_err(), ConsensusError::InsufficientWork);
    }

    #[test]
    fn subsidy_halves_on_schedule_and_floors_to_zero() {
        // Un solo escalón reproduce el halving puro de siempre.
        let schedule = [50u128];
        let interval = 1_000_000u64;

        assert_eq!(subsidy_for_height(0, &schedule, interval), 50);
        assert_eq!(subsidy_for_height(interval - 1, &schedule, interval), 50);
        assert_eq!(subsidy_for_height(interval, &schedule, interval), 25);
        assert_eq!(subsidy_for_height(interval * 2, &schedule, interval), 12);
        assert_eq!(subsidy_for_height(interval * 128, &schedule, interval), 0);
    }

    #[test]
    fn subsidy_follows_explicit_early_steps_then_keeps_halving_past_the_last_one() {
        // Escalones irregulares (no todos halvings limpios) para los
        // primeros períodos, y a partir de ahí sigue a la mitad cada
        // período — el caso real de mainnet (ver docs/CONSENSUS.md).
        let schedule = [50u128, 25, 10, 5];
        let period = 100u64;

        assert_eq!(subsidy_for_height(0, &schedule, period), 50);
        assert_eq!(subsidy_for_height(period - 1, &schedule, period), 50);
        assert_eq!(subsidy_for_height(period, &schedule, period), 25);
        assert_eq!(subsidy_for_height(period * 2, &schedule, period), 10);
        assert_eq!(subsidy_for_height(period * 3, &schedule, period), 5);
        // Pasado el último escalón explícito, sigue a la mitad cada período.
        assert_eq!(subsidy_for_height(period * 4, &schedule, period), 2);
        assert_eq!(subsidy_for_height(period * 5, &schedule, period), 1);
        assert_eq!(subsidy_for_height(period * 6, &schedule, period), 0);
    }

    #[test]
    #[should_panic(expected = "subsidy_schedule no puede estar vacío")]
    fn subsidy_for_height_panics_on_empty_schedule() {
        subsidy_for_height(0, &[], 100);
    }

    #[test]
    fn retarget_keeps_target_unchanged_when_timing_matches_expected() {
        let prev = {
            let mut t = MAX_TARGET;
            t[1] = 0x0f;
            t
        };
        let next = retarget(&prev, 120, 120);
        assert_eq!(next, prev);
    }

    #[test]
    fn retarget_lowers_target_when_blocks_come_in_faster_than_expected() {
        let prev = {
            let mut t = MAX_TARGET;
            t[1] = 0x0f;
            t
        };
        // Los bloques tardaron la mitad de lo esperado -> la red va
        // demasiado rápido -> hay que subir la dificultad (bajar el target).
        let next = retarget(&prev, 60, 120);
        assert!(BigUint::from_bytes_be(&next) < BigUint::from_bytes_be(&prev));
    }

    #[test]
    fn retarget_raises_target_when_blocks_come_in_slower_than_expected() {
        let prev = {
            let mut t = MAX_TARGET;
            t[0] = 0;
            t[1] = 0x0f;
            t
        };
        let next = retarget(&prev, 240, 120);
        assert!(BigUint::from_bytes_be(&next) > BigUint::from_bytes_be(&prev));
    }

    #[test]
    fn retarget_never_exceeds_the_network_difficulty_ceiling() {
        let prev = MAX_TARGET;
        // Timespan real muchísimo más largo que el esperado pediría un
        // target aún más alto que MAX_TARGET -> tiene que quedar clampeado.
        let next = retarget(&prev, 120 * 1000, 120);
        assert_eq!(next, MAX_TARGET);
    }

    #[test]
    fn cumulative_work_is_higher_for_harder_targets() {
        let easy = MAX_TARGET;
        let mut hard = MAX_TARGET;
        hard[0] = 0;
        hard[1] = 0;

        let work_easy = cumulative_work([&easy, &easy]);
        let work_hard = cumulative_work([&hard]);
        assert!(work_hard > work_easy);
    }
}

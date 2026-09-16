use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// None keeps attacks disabled until the controller releases the benchmark.
pub(crate) fn elapsed(fallback: Duration) -> Option<Duration> {
    static START: OnceLock<SystemTime> = OnceLock::new();
    let path = match std::env::var("MANTA_BENCHMARK_START_FILE") {
        Ok(path) => path,
        Err(_) => return Some(fallback),
    };
    let start = match START.get() {
        Some(start) => *start,
        None => {
            let millis = std::fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()?;
            *START.get_or_init(|| UNIX_EPOCH + Duration::from_millis(millis))
        }
    };
    SystemTime::now().duration_since(start).ok()
}

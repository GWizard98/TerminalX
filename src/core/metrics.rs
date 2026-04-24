use once_cell::sync::Lazy;
use prometheus::{Encoder, IntCounter, TextEncoder, Registry, Opts};
use std::collections::HashMap;
use std::sync::Mutex;

static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);
static COUNTERS: Lazy<Mutex<HashMap<&'static str, IntCounter>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn inc_counter(name: &'static str, v: f64) {
    let mut map = COUNTERS.lock().unwrap();
    let ctr = map.entry(name).or_insert_with(|| {
        let opts = Opts::new(name, name);
        let c = IntCounter::with_opts(opts).expect("counter create");
        REGISTRY.register(Box::new(c.clone())).ok();
        c
    });
    ctr.inc_by(v as u64);
}

pub fn gather() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buf = Vec::new();
    encoder.encode(&metric_families, &mut buf).unwrap();
    String::from_utf8(buf).unwrap_or_default()
}

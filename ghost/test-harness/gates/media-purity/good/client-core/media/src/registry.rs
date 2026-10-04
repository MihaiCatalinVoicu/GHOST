use std::sync::Mutex;
static REGISTRY: Mutex<Option<u32>> = Mutex::new(None);
pub fn touch() { let _ = REGISTRY.lock(); }

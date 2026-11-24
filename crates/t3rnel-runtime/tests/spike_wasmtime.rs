// quick wasmtime overhead probe — run as a test in t3rnel-runtime
#[test]
fn spike_wasmtime_overhead() {
    use wasmtime::*;
    let t0 = std::time::Instant::now();
    let engine = Engine::default();
    let t_engine = t0.elapsed();
    let wat = r#"(module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))"#;
    let t1 = std::time::Instant::now();
    let module = Module::new(&engine, wat).unwrap();
    let t_compile = t1.elapsed();
    let t2 = std::time::Instant::now();
    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[]).unwrap();
    let t_instantiate = t2.elapsed();
    let f = instance
        .get_typed_func::<(i32, i32), i32>(&mut store, "add")
        .unwrap();
    let t3 = std::time::Instant::now();
    let mut total = 0i64;
    for i in 0..100_000i64 {
        total += f.call(&mut store, (i as i32, 2)).unwrap() as i64;
    }
    let t_call = t3.elapsed();
    eprintln!(
        "ENGINE={:?} COMPILE={:?} INSTANTIATE={:?} 100k_CALLS={:?} total={}",
        t_engine, t_compile, t_instantiate, t_call, total
    );
    assert!(total > 0);
}

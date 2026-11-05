use std::env;

use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    // IDA keeps names verbatim by default (`GarbleNames = 0` in `ida.cfg`), so
    // the decompiler wraps names that aren't valid C identifiers (e.g., the
    // `#memcpy` of an ARM64EC binary) in backticks. `tests/garble_names` calls
    // three such functions from `main`; another binary can be passed instead.
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "./tests/garble_names".to_owned());
    let mut idb = IDB::open(path)?;

    if !idb.decompiler_available() {
        println!("decompiler not available");
        return Ok(());
    }

    let main_ea = idb
        .functions()
        .find(|(_, f)| matches!(f.name().as_deref(), Some("main" | "_main")))
        .map(|(_, f)| f.start_address())
        .ok_or_else(|| anyhow::anyhow!("main function not found"))?;

    let steps = [
        ("default config", None),
        ("GarbleNames = 2", Some("GarbleNames = 2")),
    ];

    for (label, directive) in steps {
        if let Some(directive) = directive {
            idb.modify_ida_config(directive)?;
        }

        let main = idb.function_at(main_ea).expect("main function");
        let cfunc = idb.decompile(&main)?;
        println!("=== main ({label}) ===\n{}", cfunc.pseudocode());
    }

    Ok(())
}

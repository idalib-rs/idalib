use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    let idb = IDB::open("./tests/ls")?;

    // All types in the database.
    let all = idb.format_decls()?;
    println!("=== all types ===\n{all}");

    // Types for each decompiled function.
    if !idb.decompiler_available() {
        return Ok(());
    }

    for (_, func) in idb.functions() {
        let Ok(cfunc) = idb.decompile(&func) else {
            continue;
        };

        let name = func.name().unwrap_or_default();
        let types = idb.format_cfunc_decls(&cfunc)?;
        println!("=== types for {name} ===\n{types}");
    }

    Ok(())
}

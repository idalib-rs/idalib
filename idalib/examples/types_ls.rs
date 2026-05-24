use idalib::idb::IDB;
use idalib::typeinf::FormatDeclsOptions;

fn main() -> anyhow::Result<()> {
    let idb = IDB::open("./tests/ls")?;

    let opts = FormatDeclsOptions::INCL_DEPS | FormatDeclsOptions::DEF_FWD;

    // All types in the database.
    let all = idb.format_decls(opts)?;
    println!("=== all types ===\n{all}");

    // Types for each decompiled function.
    if idb.decompiler_available() {
        for (_, func) in idb.functions() {
            let name = func.name().unwrap_or_default();

            if let Ok(cfunc) = idb.decompile(&func) {
                let types = idb.format_func_decls(&cfunc, opts)?;
                println!("=== types for {name} ===\n{types}");
            }
        }
    }

    Ok(())
}

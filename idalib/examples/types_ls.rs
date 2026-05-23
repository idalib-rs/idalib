use idalib::idb::IDB;
use idalib::typeinf::FormatDeclsOptions;

fn main() -> anyhow::Result<()> {
    let idb = IDB::open("./tests/ls")?;

    let opts = FormatDeclsOptions::INCL_DEPS | FormatDeclsOptions::DEF_FWD;

    // All types in the database.
    let all = idb.format_decls(opts)?;
    println!("=== all types ===\n{all}");

    // Types used by the first function, enriched with decompiler locals.
    if let Some((_, func)) = idb.functions().next() {
        let name = func.name().unwrap_or_default();

        // Prototype-only (no decompiler needed).
        let proto_types = idb.format_func_decls(&func, opts)?;
        println!("=== types for {name} (prototype) ===\n{proto_types}");

        // With decompiler locals.
        if idb.decompiler_available() {
            if let Ok(cfunc) = idb.decompile(&func) {
                let full_types = idb.format_func_decls_with(&func, &cfunc, opts)?;
                println!("=== types for {name} (with locals) ===\n{full_types}");
            }
        }
    }

    Ok(())
}

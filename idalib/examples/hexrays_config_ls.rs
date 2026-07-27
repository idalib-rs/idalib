use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    let idb = IDB::open("./tests/ls")?;

    if !idb.decompiler_available() {
        println!("decompiler not available");
        return Ok(());
    }

    let Some((_, main)) = idb
        .functions()
        .find(|(_, f)| f.name().as_deref() == Some("main"))
    else {
        println!("main function not found");
        return Ok(());
    };

    // Decompile with the default Hex-Rays configuration.
    let cfunc = idb.decompile(&main)?;
    println!("=== main (default config) ===\n{}", cfunc.pseudocode());

    // Switch argument hints from inlay hints to C-comment style, then
    // decompile again to see the effect on the generated pseudocode.
    idb.change_hexrays_config("#define HAHM_COMMENT 1\nARG_HINTS_MODE = HAHM_COMMENT")?;

    let cfunc = idb.decompile(&main)?;
    println!(
        "=== main (ARG_HINTS_MODE = HAHM_COMMENT) ===\n{}",
        cfunc.pseudocode()
    );

    // Disable argument hints, then decompile again to see the effect.
    idb.change_hexrays_config("#define HAHM_DISABLED 0\nARG_HINTS_MODE = HAHM_DISABLED")?;

    let cfunc = idb.decompile(&main)?;
    println!(
        "=== main (ARG_HINTS_MODE = HAHM_DISABLED) ===\n{}",
        cfunc.pseudocode()
    );

    Ok(())
}

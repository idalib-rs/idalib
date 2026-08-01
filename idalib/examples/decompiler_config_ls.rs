use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    let mut idb = IDB::open("./tests/ls")?;

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
    let main_ea = main.start_address();

    // Each step (re)decompiles `main`, showing how a Hex-Rays config
    // directive changes the generated pseudocode.
    let steps = [
        ("default config", None),
        (
            "ARG_HINTS_MODE = HAHM_COMMENT",
            Some("#define HAHM_COMMENT 1\nARG_HINTS_MODE = HAHM_COMMENT"),
        ),
        (
            "ARG_HINTS_MODE = HAHM_DISABLED",
            Some("#define HAHM_DISABLED 0\nARG_HINTS_MODE = HAHM_DISABLED"),
        ),
    ];

    for (label, directive) in steps {
        if let Some(directive) = directive {
            idb.modify_decompiler_config(directive)?;
        }

        let main = idb.function_at(main_ea).expect("main function");
        let cfunc = idb.decompile(&main)?;
        println!("=== main ({label}) ===\n{}", cfunc.pseudocode());
    }

    Ok(())
}

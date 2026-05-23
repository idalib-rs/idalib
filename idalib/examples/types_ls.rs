use idalib::idb::IDB;
use idalib::typeinf::FormatDeclsOptions;

fn main() -> anyhow::Result<()> {
    let idb = IDB::open("./tests/ls")?;

    let decls = idb.format_decls(FormatDeclsOptions::INCL_DEPS | FormatDeclsOptions::DEF_FWD)?;
    println!("{decls}");

    Ok(())
}

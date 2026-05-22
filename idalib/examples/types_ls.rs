use idalib::idb::IDB;
use idalib::typeinf::PrintDeclsFlags;

fn main() -> anyhow::Result<()> {
    let idb = IDB::open("./tests/ls")?;

    let decls = idb.print_decls(PrintDeclsFlags::INCL_DEPS | PrintDeclsFlags::DEF_FWD)?;
    println!("{decls}");

    Ok(())
}

use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    // Open IDA database
    let idb = IDB::open("./tests/ls")?;

    println!("Testing len(), get_by_index(), and get_address_by_index() (valid indexes)");
    // len()
    for i in 0..idb.names().len() {
        // get_by_index()
        assert!(idb.names().get_by_index(i).is_some());
        // get_address_by_index()
        assert!(idb.names().get_address_by_index(i).is_some());
    }

    println!("Testing len(), get_by_index(), and get_address_by_index() (invalid index)");
    // len()
    let len = idb.names().len();
    // get_by_index()
    assert!(idb.names().get_by_index(len).is_none());
    // get_address_by_index()
    assert!(idb.names().get_address_by_index(len).is_none());

    println!("\nTesting iterator:");
    for name in idb.names().iter() {
        let flags = idb.flags_at(name.address());
        println!(
            "\t{:#x}\t{:?}\tcode: {}\tdata: {}",
            name.address(),
            name.name(),
            flags.is_code(),
            flags.is_data(),
        );
    }

    Ok(())
}

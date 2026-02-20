use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    // Open IDA database
    let mut idb = IDB::open("./tests/ls")?;

    println!("Testing erase_at(), get_at(), and len() (pass 1; clear old bookmarks)");

    // Collect addresses first since we need to mutate
    let func_addrs = idb.functions().map(|f| f.start_address()).collect::<Vec<_>>();
    for addr in &func_addrs {
        // erase_at(), ignore errors (may not exist)
        let _ = idb.bookmarks_mut().erase_at(*addr);

        // get_at() - verify it's gone
        let bookmark = idb.bookmarks().get_at(*addr);
        assert!(bookmark.is_none());
    }

    // len()
    assert_eq!(idb.bookmarks().len(), 0);

    println!("Testing mark() and description()");
    // Collect function info first
    let func_info = idb
        .functions()
        .map(|f| (f.id(), f.start_address(), f.name()))
        .collect::<Vec<_>>();

    for (id, addr, name) in &func_info {
        let desc = format!(
            "Bookmark added by idalib: {id} {} {addr:#x}",
            name.as_ref().map(|s| s.as_str()).unwrap_or("unknown"),
        );

        // mark()
        let _slot = idb.bookmarks_mut().mark(*addr, &desc)?;

        // get_at() and description()
        let bookmark = idb.bookmarks().get_at(*addr);
        let read_desc = bookmark.expect("bookmark should exist").description();
        assert_eq!(read_desc.unwrap(), desc);
    }

    println!("Testing len(), get_by_id(), address(), and description()");
    // Iterate by index using get_by_id
    for i in 0..idb.bookmarks().len() {
        // get_by_id()
        let bookmark = idb.bookmarks().get_by_id(i).expect("bookmark should exist");

        // address()
        let read_addr = bookmark.address().unwrap();
        let addr_str = format!("{read_addr:#x}");

        // description()
        let read_desc = bookmark.description().unwrap();

        assert!(read_desc.ends_with(addr_str.as_str()));
    }

    println!("Testing iter()");
    for bookmark in idb.bookmarks().iter() {
        let addr = bookmark.address().unwrap();
        let desc = bookmark.description().unwrap();
        println!("  Bookmark: {addr:#x} - {desc}");
    }

    println!("Testing erase_at() and get_at() (pass 2)");
    for addr in &func_addrs {
        // erase_at()
        idb.bookmarks_mut().erase_at(*addr)?;

        // get_at() - verify it's gone
        let bookmark = idb.bookmarks().get_at(*addr);
        assert!(bookmark.is_none());
    }

    // len()
    assert_eq!(idb.bookmarks().len(), 0);

    Ok(())
}

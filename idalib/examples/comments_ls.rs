use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    // Open IDA database
    let mut idb = IDB::open("./tests/ls")?;

    // Show everything
    idb.meta_mut().set_show_all_comments();
    idb.meta_mut().set_show_hidden_funcs();
    idb.meta_mut().set_show_hidden_insns();
    idb.meta_mut().set_show_hidden_segms();

    println!("Testing remove_func_cmt() and get_func_cmt() (pass 1; clear old comments)");

    // Collect addresses first since we need to mutate while iterating
    let func_addrs = idb
        .functions()
        .map(|f| f.start_address())
        .collect::<Vec<_>>();

    for addr in &func_addrs {
        // remove_func_cmt()
        idb.remove_func_cmt(*addr)?;

        // get_func_cmt()
        let read_comment = idb.get_func_cmt(*addr);
        assert!(read_comment.is_none());
    }

    println!("Testing set_func_cmt() and get_func_cmt()");

    // Collect function info first
    let func_info = idb
        .functions()
        .map(|f| (f.id(), f.start_address(), f.name()))
        .collect::<Vec<_>>();

    for (id, addr, name) in &func_info {
        let comment = format!(
            "Comment added by idalib: {id} {} {addr:#x}",
            name.as_ref().map(|s| s.as_str()).unwrap_or("unknown")
        );

        // set_func_cmt()
        idb.set_func_cmt(*addr, comment)?;

        // get_func_cmt()
        let read_comment = idb.get_func_cmt(*addr);
        assert!(read_comment.unwrap().starts_with("Comment added by idalib"));
    }

    println!("Testing find_text_iter()");
    let results: Vec<_> = idb.find_text_iter("added by idalib").collect();
    assert!(!results.is_empty());
    assert_eq!(results.len(), func_addrs.len());

    println!("Testing append_cmt() and get_func_cmt()");
    for addr in &func_addrs {
        let comment = "Comment appended by idalib";

        // append_cmt()
        idb.append_cmt(*addr, comment)?;

        // get_func_cmt()
        let read_comment = idb.get_func_cmt(*addr);
        assert!(read_comment.unwrap().ends_with("appended by idalib"));
    }

    println!("Testing remove_func_cmt() and get_func_cmt() (pass 2)");
    for addr in &func_addrs {
        // remove_func_cmt()
        idb.remove_func_cmt(*addr)?;

        // get_func_cmt()
        let read_comment = idb.get_func_cmt(*addr);
        assert!(read_comment.is_none());
    }

    println!("Testing find_text_iter()");
    let results: Vec<_> = idb.find_text_iter("added by idalib").collect();
    assert!(results.is_empty());

    Ok(())
}

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
    for (_id, f) in idb.functions() {
        let addr = f.start_address();

        // remove_func_cmt()
        idb.remove_func_cmt(addr)?;

        // get_func_cmt()
        let read_comment = idb.get_func_cmt(addr);
        assert!(read_comment.is_none());
    }

    println!("Testing set_func_cmt() and get_func_cmt()");
    for (id, f) in idb.functions() {
        let addr = f.start_address();
        let comment = format!(
            "Comment added by idalib: {id} {} {addr:#x}",
            f.name().unwrap()
        );

        // set_func_cmt()
        idb.set_func_cmt(addr, comment)?;

        // get_func_cmt()
        let read_comment = idb.get_func_cmt(addr);
        assert!(read_comment.unwrap().starts_with("Comment added by idalib"));
    }

    println!("Testing find_text_iter()");
    let results: Vec<_> = idb.find_text_iter("added by idalib").collect();
    assert!(!results.is_empty());
    assert_eq!(results.len(), idb.functions().count());

    println!("Testing append_cmt() and get_func_cmt()");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();
        let comment = "Comment appended by idalib";

        // append_cmt()
        idb.append_cmt(addr, comment)?;

        // get_func_cmt()
        let read_comment = idb.get_func_cmt(addr);
        assert!(read_comment.unwrap().ends_with("appended by idalib"));
    }

    println!("Testing remove_func_cmt() and get_func_cmt() (pass 2)");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();

        // remove_func_cmt()
        idb.remove_func_cmt(addr)?;

        // get_func_cmt()
        let read_comment = idb.get_func_cmt(addr);
        assert!(read_comment.is_none());
    }

    println!("Testing find_text_iter()");
    let results: Vec<_> = idb.find_text_iter("added by idalib").collect();
    assert!(results.is_empty());

    Ok(())
}

use idalib::idb::{ExtraCmtKind, IDB};

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

    let addr = idb
        .functions()
        .next()
        .map(|(_id, f)| f.start_address())
        .unwrap();

    for kind in [ExtraCmtKind::Anterior, ExtraCmtKind::Posterior] {
        println!("Testing remove_extra_cmts() and extra_cmts() ({kind:?}; clear old comments)");
        idb.remove_extra_cmts(addr, kind);
        assert_eq!(idb.extra_cmts(addr, kind).count(), 0);

        println!("Testing append_extra_cmt() and extra_cmts() ({kind:?})");
        idb.append_extra_cmt(addr, kind, "Extra comment added by idalib")?;
        idb.append_extra_cmt(addr, kind, "\nLast line")?;
        let lines: Vec<_> = idb.extra_cmts(addr, kind).collect();
        assert_eq!(
            lines,
            ["; Extra comment added by idalib", "; ", "; Last line"]
        );

        println!("Testing set_extra_cmt() and get_extra_cmt() ({kind:?})");
        idb.set_extra_cmt(addr, kind, 1, "Line set by idalib")?;
        assert_eq!(
            idb.get_extra_cmt(addr, kind, 1).as_deref(),
            Some("Line set by idalib")
        );
        assert!(idb.get_extra_cmt(addr, kind, 1000).is_none());
        assert!(idb.set_extra_cmt(addr, kind, 1000, "Out of range").is_err());

        println!("Testing find_text_iter() ({kind:?})");
        assert_eq!(idb.find_text_iter("Line set by idalib").count(), 1);

        println!("Testing remove_extra_cmt() and extra_cmts() ({kind:?})");
        idb.remove_extra_cmt(addr, kind, 1)?;
        assert_eq!(idb.extra_cmts(addr, kind).count(), 1);
        assert!(idb.get_extra_cmt(addr, kind, 2).is_some());
        assert!(idb.remove_extra_cmt(addr, kind, 1).is_err());

        println!("Testing remove_extra_cmts() and get_extra_cmt() ({kind:?})");
        idb.remove_extra_cmts(addr, kind);
        assert_eq!(idb.extra_cmts(addr, kind).count(), 0);
        assert!(idb.get_extra_cmt(addr, kind, 2).is_none());
    }

    Ok(())
}

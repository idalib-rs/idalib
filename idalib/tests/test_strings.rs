use tempdir::TempDir;

use idalib::idb::IDB;
use idalib::tests;

// .data:10026038 ; CHAR Name[]
// .data:10026038 Name            db 'SADFHUHF',0         ; DATA XREF: DllMain(x,x,x)+38↑o
// .data:10026038                                         ; DllMain(x,x,x)+57↑o

fn test_get_strings() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    assert!(idb.is_loaded(0x10026038));
    assert!(idb.is_mapped(0x10026038));

    let string_content = idb.get_string_at(0x10026038);
    assert!(string_content.is_some());
    assert_eq!(string_content.unwrap(), "SADFHUHF");

    let strings: Vec<_> = idb.strings().iter().map(|(_, s)| s).collect();
    assert_eq!(
        strings,
        vec![
            "CloseHandle\0",
            "Sleep\0",
            "CreateProcessA\0",
            "CreateMutexA\0",
            "OpenMutexA\0",
            "KERNEL32.dll\0",
            "WS2_32.dll\0",
            "strncmp\0",
            "MSVCRT.dll\0",
            "_initterm\0",
            "malloc\0",
            "_adjust_fdiv\0",
            "sleep\0",
            "hello\0",
            "127.26.152.13\0",
            "SADFHUHF\0"
        ]
    );
}

fn main() {
    test_get_strings();
}

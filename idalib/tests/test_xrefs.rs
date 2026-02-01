use tempdir::TempDir;

use idalib::idb::IDB;
#[path = "../src/tests.rs"]
mod tests;

fn test_xrefs() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let xrefs_to: Vec<_> = idb.xrefs_to(0x10026038).map(|x| x.from()).collect();
    assert_eq!(xrefs_to, vec![0x10001048, 0x10001067]);
    // 0. instruction at 0x10001048
    // 1. instruction at 0x10001067

    let xrefs_from: Vec<_> = idb.xrefs_from(0x10001048).map(|x| x.to()).collect();
    assert_eq!(xrefs_from, vec![0x1000104d, 0x10026038]);
    // 0. next instruction
    // 1. mutex
}

fn main() {
    test_xrefs();
}

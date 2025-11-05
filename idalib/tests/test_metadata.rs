use tempdir::TempDir;

use idalib::idb::IDB;
use idalib::tests;

fn test_imagebase() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let imagebase = idb.imagebase();
    assert_eq!(
        imagebase, 0x10000000,
        "Expected imagebase 0x10000000, got 0x{:x}",
        imagebase
    );
}

fn test_imagebase_via_metadata() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let metadata = idb.meta();
    let imagebase = metadata.imagebase();
    assert_eq!(
        imagebase, 0x10000000,
        "Expected imagebase 0x10000000 via metadata, got 0x{:x}",
        imagebase
    );
}

fn test_imagebase_consistency() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let imagebase_via_idb = idb.imagebase();
    let imagebase_via_metadata = idb.meta().imagebase();
    assert_eq!(
        imagebase_via_idb, imagebase_via_metadata,
        "Imagebase should be consistent between IDB and metadata access methods"
    );
}

fn test_ostype() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let ostype = idb.meta().ostype();
    assert!(ostype.is_some(), "OSType should be recognized for test binary");
}

fn main() {
    test_imagebase();
    test_imagebase_via_metadata();
    test_imagebase_consistency();
    test_ostype();
}

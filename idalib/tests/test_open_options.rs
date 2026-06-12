use tempdir::TempDir;

use idalib::idb::IDBOpenOptions;
#[path = "../src/tests.rs"]
mod tests;

fn test_arg_disable_auto_analysis() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDBOpenOptions::new()
        .arg("-a")
        .auto_analyse(false)
        .open(&dst)
        .unwrap();

    assert_eq!(
        idb.function_count(),
        0,
        "with -a (disable auto-analysis), no functions should be recognized"
    );
}

fn test_default_options_match_open() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDBOpenOptions::new().open(&dst).unwrap();

    assert!(
        idb.function_count() > 0,
        "default options should produce analyzed functions"
    );
}

fn main() {
    test_arg_disable_auto_analysis();
    test_default_options_match_open();
}

use tempdir::TempDir;

use idalib::idb::IDB;
#[path = "../src/tests.rs"]
mod tests;

fn test_import_enumeration() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    const EXPECTED_IMPORTS: &[(&str, &str, u32, u64)] = &[
        ("KERNEL32", "Sleep", 0, 0x10002000),
        ("KERNEL32", "CreateProcessA", 0, 0x10002004),
        ("KERNEL32", "CreateMutexA", 0, 0x10002008),
        ("KERNEL32", "OpenMutexA", 0, 0x1000200c),
        ("KERNEL32", "CloseHandle", 0, 0x10002010),
        ("WS2_32", "", 3, 0x1000204c),
        ("WS2_32", "", 4, 0x1000203c),
        ("WS2_32", "", 9, 0x10002054),
        ("WS2_32", "", 11, 0x10002038),
        ("WS2_32", "", 16, 0x10002048),
        ("WS2_32", "", 19, 0x10002040),
        ("WS2_32", "", 22, 0x10002044),
        ("WS2_32", "", 23, 0x10002030),
        ("WS2_32", "", 115, 0x10002034),
        ("WS2_32", "", 116, 0x10002050),
        ("MSVCRT", "_adjust_fdiv", 0, 0x10002018),
        ("MSVCRT", "malloc", 0, 0x1000201c),
        ("MSVCRT", "_initterm", 0, 0x10002020),
        ("MSVCRT", "free", 0, 0x10002024),
        ("MSVCRT", "strncmp", 0, 0x10002028),
    ];

    let imports: Vec<_> = idb.imports().collect();

    let expected_set: std::collections::HashSet<(&str, &str, u32, u64)> = EXPECTED_IMPORTS.iter().cloned().collect();
    let actual_set: std::collections::HashSet<(&str, &str, u32, u64)> = imports
        .iter()
        .map(|i| (i.module_name(), i.function_name(), i.ordinal(), i.address()))
        .collect();

    for &expected_import in &expected_set {
        assert!(
            actual_set.contains(&expected_import),
            "Missing expected import: {:?}",
            expected_import
        );
    }

    for &actual_import in &actual_set {
        assert!(
            expected_set.contains(&actual_import),
            "Unexpected import found: {:?}",
            actual_import
        );
    }

    assert_eq!(
        actual_set.len(),
        expected_set.len(),
        "Import count mismatch: expected {}, got {}",
        expected_set.len(),
        actual_set.len()
    );
}

fn main() {
    test_import_enumeration();
}

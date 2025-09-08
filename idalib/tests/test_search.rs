use tempdir::TempDir;

use idalib::idb::IDB;
use idalib::tests;

// .text:10001000                         sub_10001000 proc near
// .text:10001000                         arg_0= dword ptr  4
// .text:10001000
// .text:10001000 8B C1                   mov     eax, ecx
// .text:10001002 8B 4C 24 04             mov     ecx, [esp+arg_0]
// .text:10001006 8A 11                   mov     dl, [ecx]
// .text:10001008 88 10                   mov     [eax], dl
// .text:1000100A C2 04 00                retn    4
//
// 10001000  8B C1 8B 4C 24 04 8A 11  88 10 C2 04 00 90 90 90  ...L$...........
// 10001010  B8 F8 11 00 00 E8 06 02  00 00 8B 84 24 00 12 00  ............$...
// 10001020  00 53 55 56 83 F8 01 57  0F 85 BA 01 00 00 A0 54  .SUV...W.......T

fn test_find_text() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    assert_eq!(idb.find_text(0x10001000, "mov"), Some(0x10001000));
    assert_eq!(idb.find_text(0x10001000, "eax"), Some(0x10001000));
    assert_eq!(idb.find_text(0x10001000, "foo"), None);
}

fn test_find_imm() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    assert_eq!(idb.find_imm(0x10001000, 0x4), Some(0x10001002));
    assert_eq!(idb.find_imm(0x10001000, 0x99999), None);
}

fn test_find_bytes() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    assert_eq!(
        idb.find_bytes_range("8B C1 8B 4C", 0x10001000, 0x10002000),
        Some(0x10001000)
    );

    assert_eq!(
        idb.find_bytes_range("8B ?? 8B ??", 0x10001000, 0x10002000),
        Some(0x10001000)
    );

    assert_eq!(
        idb.find_bytes_range("B8 F8 11", 0x10001000, 0x10002000),
        Some(0x10001010)
    );
}

fn test_parse_binary_pattern() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let (bytes, mask) = idb.parse_binary_pattern("8B C1 8B 4C").unwrap();
    assert_eq!(bytes, vec![0x8B, 0xC1, 0x8B, 0x4C]);
    assert_eq!(mask, vec![0xFF, 0xFF, 0xFF, 0xFF]);

    let (bytes2, mask2) = idb.parse_binary_pattern("8B ?? 8B ??").unwrap();
    assert_eq!(bytes2, vec![0x8B, 0xFF, 0x8B, 0xFF]);
    assert_eq!(mask2, vec![0xFF, 0x00, 0xFF, 0x00]);
}

fn test_find_binary() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let bytes = vec![0x8B, 0xC1, 0x8B, 0x4C];
    let mask = vec![0xFF, 0xFF, 0xFF, 0xFF];
    let result = idb.find_binary_range(&bytes, &mask, 0x10001000, 0x10002000);
    assert_eq!(result, Some(0x10001000));

    let bytes2 = vec![0x8B, 0x00, 0x8B, 0x00];
    let mask2 = vec![0xFF, 0x00, 0xFF, 0x00];
    let result2 = idb.find_binary_range(&bytes2, &mask2, 0x10001000, 0x10002000);
    assert_eq!(result2, Some(0x10001000));

    let bytes3 = vec![0xB8, 0xF8, 0x11];
    let mask3 = vec![0xFF, 0xFF, 0xFF];
    let result3 = idb.find_binary_range(&bytes3, &mask3, 0x10001000, 0x10002000);
    assert_eq!(result3, Some(0x10001010));
}

fn main() {
    test_find_text();
    test_find_imm();
    test_find_bytes();
    test_parse_binary_pattern();
    test_find_binary();
}

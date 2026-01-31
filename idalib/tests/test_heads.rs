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
// .text:1000100A                         sub_10001000 endp
//
// 10001000  8B C1 8B 4C 24 04 8A 11  88 10 C2 04 00 90 90 90  ...L$...........
// 10001010  B8 F8 11 00 00 E8 06 02  00 00 8B 84 24 00 12 00  ............$...
// 10001020  00 53 55 56 83 F8 01 57  0F 85 BA 01 00 00 A0 54  .SUV...W.......T

fn test_heads_iterator() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let start_addr = 0x10001000u64;
    let end_addr = 0x10001020u64;

    let heads: Vec<_> = idb.heads(start_addr..end_addr).collect();

    assert!(!heads.is_empty());
    assert!(heads.len() >= 3);

    assert_eq!(heads[0], start_addr);
    assert_eq!(heads[1], 0x10001002_u64);
    assert_eq!(heads[2], 0x10001006_u64);

    for head in &heads {
        assert!((*head as u64) >= start_addr);
        assert!((*head as u64) < end_addr);
    }
}

fn main() {
    test_heads_iterator();
}

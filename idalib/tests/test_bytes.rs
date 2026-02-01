use tempdir::TempDir;

use idalib::idb::IDB;
#[path = "../src/tests.rs"]
mod tests;

// .text:10001000                         sub_10001000 proc near
// .text:10001000                         arg_0= dword ptr  4
// .text:10001000
// .text:10001000 8B C1                   mov     eax, ecx
// .text:10001002 8B 4C 24 04             mov     ecx, [esp+arg_0]

// 10001000  8B C1 8B 4C 24 04 8A 11  88 10 C2 04 00 90 90 90  ...L$...........
// 10001010  B8 F8 11 00 00 E8 06 02  00 00 8B 84 24 00 12 00  ............$...
// 10001020  00 53 55 56 83 F8 01 57  0F 85 BA 01 00 00 A0 54  .SUV...W.......T

fn test_get_byte() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    assert!(idb.is_loaded(0x10001000));
    assert!(idb.is_mapped(0x10001000));
    assert_eq!(idb.get_byte(0x10001000 + 0), 0x8B);
    assert_eq!(idb.get_byte(0x10001000 + 1), 0xC1);
    assert_eq!(idb.get_word(0x10001000), 0xC18B);
    assert_eq!(idb.get_dword(0x10001000), 0x4C8BC18B);
    assert_eq!(idb.get_qword(0x10001000), 0x118A04244C8BC18B);
    assert_eq!(idb.get_bytes(0x10001000, 2), vec![0x8B, 0xC1]);
}

fn test_is_operand_offset() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // 0x10001000: mov eax, ecx
    let flags = idb.flags_at(0x10001000);
    assert!(!flags.is_operand_offset(0), "operand 0 should not be an offset for reg-to-reg mov");
    assert!(!flags.is_operand_offset(1), "operand 1 should not be an offset for reg-to-reg mov");

    // 0x1000102e: mov al, byte_10026054
    let flags = idb.flags_at(0x1000102E);
    assert!(!flags.is_operand_offset(0), "operand 0 should not be an offset for off-to-reg mov");
    assert!(flags.is_operand_offset(1), "operand 1 should be an offset for off-to-reg mov");
}

fn main() {
    test_get_byte();
    test_is_operand_offset();
}

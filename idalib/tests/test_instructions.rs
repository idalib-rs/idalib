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

// 10001000  8B C1 8B 4C 24 04 8A 11  88 10 C2 04 00 90 90 90  ...L$...........

fn test_instruction_mnemonics() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    const EXPECTED_MNEMONICS: &[(u64, &str); 5] = &[
        (0x10001000, "mov"),
        (0x10001002, "mov"),
        (0x10001006, "mov"),
        (0x10001008, "mov"),
        (0x1000100A, "retn"),
    ];

    for &(addr, expected_mnemonic) in EXPECTED_MNEMONICS {
        assert!(idb.is_code(addr));

        let insn = idb.insn_at(addr).unwrap();
        let mnemonic = insn.mnemonic();

        assert_eq!(expected_mnemonic, mnemonic);
    }
}

fn main() {
    test_instruction_mnemonics();
}

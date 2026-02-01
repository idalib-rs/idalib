use tempdir::TempDir;

use idalib::idb::IDB;
#[path = "../src/tests.rs"]
mod tests;

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

fn test_disasm_line() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    const EXPECTED_DISASM: &[(u64, &str); 5] = &[
        (0x10001000, "mov     eax, ecx"),
        (0x10001002, "mov     ecx, [esp+arg_0]"),
        (0x10001006, "mov     dl, [ecx]"),
        (0x10001008, "mov     [eax], dl"),
        (0x1000100A, "retn    4"),
    ];

    for &(addr, expected_disasm) in EXPECTED_DISASM {
        assert!(idb.is_code(addr));

        let insn = idb.insn_at(addr).unwrap();
        let disasm = insn.disasm_line();

        assert_eq!(expected_disasm, disasm);
    }
}

fn test_print_operand() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    const EXPECTED_OPERANDS: &[(u64, &[&str]); 5] = &[
        (0x10001000, &["eax", "ecx"]),
        (0x10001002, &["ecx", "[esp+arg_0]"]),
        (0x10001006, &["dl", "[ecx]"]),
        (0x10001008, &["[eax]", "dl"]),
        (0x1000100A, &["4"]),
    ];

    for &(addr, expected_operands) in EXPECTED_OPERANDS {
        assert!(idb.is_code(addr));

        let insn = idb.insn_at(addr).unwrap();

        for (i, &expected_operand) in expected_operands.iter().enumerate() {
            let operand = insn.print_operand(i).expect("operand should exist");
            let operand_clean = idalib::tag_remove(&operand);
            assert_eq!(expected_operand, operand_clean);
        }
    }
}

fn test_tag_remove() {
    let input_with_tags = "\x01\x03mov\x02\x03     eax, ecx";
    let expected_clean = "mov     eax, ecx";

    let cleaned = idalib::tag_remove(input_with_tags);
    assert_eq!(expected_clean, cleaned);

    let input_no_tags = "mov eax, ecx";
    let cleaned_no_tags = idalib::tag_remove(input_no_tags);
    assert_eq!(input_no_tags, cleaned_no_tags);

    let empty_input = "";
    let cleaned_empty = idalib::tag_remove(empty_input);
    assert_eq!(empty_input, cleaned_empty);
}

fn test_insn_features() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // Test mov eax, ecx at 0x10001000
    // This instruction should modify operand 0 (eax) and use operand 1 (ecx)
    let mov_insn = idb.insn_at(0x10001000).unwrap();
    assert!(mov_insn.modifies_operand(0), "mov should modify first operand");
    assert!(mov_insn.uses_operand(1), "mov should use second operand");
    assert!(!mov_insn.breaks_flow(), "mov should not break flow");

    // Test retn at 0x1000100A
    // This instruction should break flow (CF_STOP)
    let retn_insn = idb.insn_at(0x1000100A).unwrap();
    assert!(retn_insn.breaks_flow(), "retn should break flow");

    // Verify canon_feature returns non-zero for valid instructions
    assert!(mov_insn.canon_feature() != 0, "mov should have non-zero features");
    assert!(retn_insn.canon_feature() != 0, "retn should have non-zero features");
}

fn main() {
    test_instruction_mnemonics();
    test_disasm_line();
    test_print_operand();
    test_tag_remove();
    test_insn_features();
}

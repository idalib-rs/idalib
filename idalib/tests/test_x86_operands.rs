use tempdir::TempDir;

use idalib::idb::IDB;
use idalib::insn::AddressingMode;
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
//
// 10001000  8B C1 8B 4C 24 04 8A 11  88 10 C2 04 00 90 90 90  ...L$...........

fn test_operand_has_sib() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // mov ecx, [esp+arg_0] - this has SIB byte (0x24)
    let insn_with_sib = idb.insn_at(0x10001002).unwrap();
    let op_with_sib = insn_with_sib.operand(1).unwrap();
    assert!(op_with_sib.has_sib(), "Operand should have SIB byte");
    assert_eq!(op_with_sib.addressing_mode(), AddressingMode::Sib);

    // mov eax, ecx - no SIB
    let insn_no_sib = idb.insn_at(0x10001000).unwrap();
    let op_no_sib = insn_no_sib.operand(1).unwrap();
    assert!(!op_no_sib.has_sib(), "Operand should not have SIB byte");
    assert_eq!(op_no_sib.addressing_mode(), AddressingMode::Base);
}

fn test_operand_sib_byte() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // mov ecx, [esp+arg_0]
    // SIB byte is 0x24: scale=0, index=4, base=4
    let insn = idb.insn_at(0x10001002).unwrap();
    let op = insn.operand(1).unwrap();

    if op.has_sib() {
        let sib_byte = op.sib_byte();
        assert_eq!(sib_byte, 0x24, "SIB byte should be 0x24");
    }
}

fn test_operand_has_displacement() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // mov ecx, [esp+arg_0] - has displacement (0x04)
    let insn_with_displ = idb.insn_at(0x10001002).unwrap();
    let op_with_displ = insn_with_displ.operand(1).unwrap();
    assert!(
        op_with_displ.has_displacement(),
        "Operand should have displacement"
    );

    // mov dl, [ecx] - no displacement
    let insn_no_displ = idb.insn_at(0x10001006).unwrap();
    let op_no_displ = insn_no_displ.operand(1).unwrap();
    assert!(
        !op_no_displ.has_displacement(),
        "Operand should not have displacement"
    );
}

fn test_x86_base_reg() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // mov ecx, [esp+arg_0]
    // Base should be ESP (register 4)
    let insn = idb.insn_at(0x10001002).unwrap();
    let op = insn.operand(1).unwrap();

    match insn.x86_base_reg(&op) {
        Some(base_reg) => {
            // ESP is typically register 4
            assert_eq!(base_reg, 4, "Base register should be ESP (4)");
        }
        None => panic!("Should have found a base register"),
    }
}

fn test_x86_index_reg() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // mov ecx, [esp+arg_0]
    // Index might be none or ESP depending on how IDA interprets the SIB byte
    // ESP cannot be used as an index register in x86, so this is valid to be None
    let insn = idb.insn_at(0x10001002).unwrap();
    let op = insn.operand(1).unwrap();

    // Just verify the function doesn't crash; the result may be None or Some(4)
    let _index_reg = insn.x86_index_reg(&op);
}

fn test_x86_scale() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // mov ecx, [esp+arg_0]
    // Scale should be 1 (scale bits = 00)
    let insn = idb.insn_at(0x10001002).unwrap();
    let op = insn.operand(1).unwrap();

    match insn.x86_scale(&op) {
        Some(scale) => {
            assert_eq!(scale, 1, "Scale should be 1");
        }
        None => panic!("Should have found a scale value"),
    }
}

fn test_sib_base() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // mov ecx, [esp+arg_0]
    // SIB base should be ESP (4)
    let insn = idb.insn_at(0x10001002).unwrap();
    let op = insn.operand(1).unwrap();

    if op.has_sib() {
        match insn.sib_base(&op) {
            Some(base) => {
                assert_eq!(base, 4, "SIB base should be ESP (4)");
            }
            None => panic!("Should have found SIB base register"),
        }
    }
}

fn test_sib_index() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // mov ecx, [esp+arg_0]
    // SIB index might be None or ESP depending on IDA's interpretation
    // ESP cannot be used as an index in x86
    let insn = idb.insn_at(0x10001002).unwrap();
    let op = insn.operand(1).unwrap();

    if op.has_sib() {
        // Just verify the function doesn't crash
        let _index = insn.sib_index(&op);
    }
}

fn test_sib_scale() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // mov ecx, [esp+arg_0]
    // SIB scale should be 1 (scale bits = 00)
    let insn = idb.insn_at(0x10001002).unwrap();
    let op = insn.operand(1).unwrap();

    if op.has_sib() {
        match insn.sib_scale(&op) {
            Some(scale) => {
                assert_eq!(scale, 1, "SIB scale should be 1");
            }
            None => panic!("Should have found SIB scale value"),
        }
    }
}

fn test_operand_displacement() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // mov ecx, [esp+arg_0]
    // Displacement should be 0x04 (arg_0)
    let insn = idb.insn_at(0x10001002).unwrap();
    let op = insn.operand(1).unwrap();

    if op.has_displacement() {
        match op.addr() {
            Some(addr) => {
                assert_eq!(addr, 0x04, "Displacement should be 0x04");
            }
            None => panic!("Should have found displacement address"),
        }
    }
}

fn main() {
    test_operand_has_sib();
    test_operand_sib_byte();
    test_operand_has_displacement();
    test_x86_base_reg();
    test_x86_index_reg();
    test_x86_scale();
    test_sib_base();
    test_sib_index();
    test_sib_scale();
    test_operand_displacement();
}

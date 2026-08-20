use tempdir::TempDir;

use idalib::idb::IDB;
#[path = "../src/tests.rs"]
mod tests;

// The accessors exercised here return `i8` while the SDK declares the fields as
// plain `char`, which is signed on x86-64 and unsigned on AArch64. Without a
// conversion the crate only compiles on one of the two, so these values are
// what must come back on both.
//
// .text:10001002 8B 4C 24 04             mov     ecx, [esp+arg_0]
//
// Operand 1 is a displacement operand whose bytes begin at offset 3 of the
// instruction, with the has-SIB flag in specflag1 and the SIB byte itself,
// 0x24, in specflag2. Nothing in this binary sets the top bit of any of these
// fields, so sign handling itself is pinned by the unit tests beside
// `as_signed_char`.

fn test_operand_byte_offsets() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let insn = idb.insn_at(0x10001002).unwrap();
    let op = insn.operand(1).unwrap();

    assert_eq!(op.offb(), 3, "operand bytes start at offset 3");
    assert_eq!(op.offo(), 0, "outer operand has no separate offset");

    let reg_op = insn.operand(0).unwrap();
    assert_eq!(reg_op.offb(), 0, "register operand has no bytes of its own");
}

fn test_operand_processor_flags() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let insn = idb.insn_at(0x10001002).unwrap();
    let op = insn.operand(1).unwrap();

    assert!(op.has_sib(), "the displacement operand has a SIB byte");
    assert_eq!(op.specflag1(), 1, "specflag1 carries the has-SIB flag");
    assert_eq!(op.specflag2(), 0x24, "specflag2 carries the SIB byte");
    assert_eq!(
        op.sib_byte(),
        0x24,
        "the SIB accessor agrees with the raw flag"
    );
}

fn test_metadata_signed_fields() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();
    let metadata = idb.meta();

    assert_eq!(
        metadata.nametype(),
        6,
        "name representation for this database"
    );
    assert_eq!(
        metadata.strlit_zeroes(),
        0,
        "no trailing zeroes in string literals"
    );
}

fn main() {
    test_operand_byte_offsets();
    test_operand_processor_flags();
    test_metadata_signed_fields();
}

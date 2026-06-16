use tempdir::TempDir;

use idalib::idb::IDB;
use idalib::insn::segpref::{
    Mc68kOperandSize, Mc68xxSuffix, MetapcSegment, MipsFpuFormat, SparcConditionCode,
};

#[path = "../src/tests.rs"]
mod tests;

// .text:10001000 8B C1                   mov     eax, ecx
// .text:10001002 8B 4C 24 04             mov     ecx, [esp+arg_0]
// .text:10001006 8A 11                   mov     dl, [ecx]

fn test_segpref_none_for_regular_instructions() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let insn = idb.insn_at(0x10001000).unwrap();
    assert_eq!(insn.segpref(), 0);
    assert!(idb.segpref(&insn).is_none());

    let insn = idb.insn_at(0x10001002).unwrap();
    assert!(idb.segpref(&insn).is_none());

    let insn = idb.insn_at(0x10001006).unwrap();
    assert!(idb.segpref(&insn).is_none());
}

fn test_metapc_segment_from_raw() {
    assert_eq!(MetapcSegment::from_raw(0), None);
    assert_eq!(MetapcSegment::from_raw(29), Some(MetapcSegment::Es));
    assert_eq!(MetapcSegment::from_raw(30), Some(MetapcSegment::Cs));
    assert_eq!(MetapcSegment::from_raw(31), Some(MetapcSegment::Ss));
    assert_eq!(MetapcSegment::from_raw(32), Some(MetapcSegment::Ds));
    assert_eq!(MetapcSegment::from_raw(33), Some(MetapcSegment::Fs));
    assert_eq!(MetapcSegment::from_raw(34), Some(MetapcSegment::Gs));
    assert_eq!(MetapcSegment::from_raw(35), None);
    assert_eq!(MetapcSegment::from_raw(-1), None);
}

fn test_mc68k_operand_size() {
    assert_eq!(Mc68kOperandSize::from_raw(0), None);
    assert_eq!(Mc68kOperandSize::from_raw(1), Some(Mc68kOperandSize::Byte));
    assert_eq!(Mc68kOperandSize::from_raw(2), Some(Mc68kOperandSize::Word));
    assert_eq!(Mc68kOperandSize::from_raw(3), Some(Mc68kOperandSize::Long));
    assert_eq!(Mc68kOperandSize::from_raw(4), Some(Mc68kOperandSize::Single));
    assert_eq!(Mc68kOperandSize::from_raw(5), Some(Mc68kOperandSize::Double));
    assert_eq!(Mc68kOperandSize::from_raw(6), Some(Mc68kOperandSize::Extended));
    assert_eq!(Mc68kOperandSize::from_raw(7), None);

    // high bit (hide suffix) is masked off
    assert_eq!(Mc68kOperandSize::from_raw(0x01 | -128), Some(Mc68kOperandSize::Byte));
    assert_eq!(Mc68kOperandSize::from_raw(0x03 | -128), Some(Mc68kOperandSize::Long));

    assert_eq!(Mc68kOperandSize::Byte.suffix(), ".b");
    assert_eq!(Mc68kOperandSize::Long.suffix(), ".l");
    assert_eq!(Mc68kOperandSize::Extended.suffix(), ".x");
}

fn test_mips_fpu_format() {
    assert_eq!(MipsFpuFormat::from_raw(0), None);
    assert_eq!(MipsFpuFormat::from_raw(b's' as i8), Some(MipsFpuFormat::Single));
    assert_eq!(MipsFpuFormat::from_raw(b'd' as i8), Some(MipsFpuFormat::Double));
    assert_eq!(MipsFpuFormat::from_raw(b'w' as i8), Some(MipsFpuFormat::Word));
    assert_eq!(MipsFpuFormat::from_raw(b'l' as i8), Some(MipsFpuFormat::Long));
    assert_eq!(MipsFpuFormat::from_raw(b'p' as i8), Some(MipsFpuFormat::PairedSingle));
    assert_eq!(MipsFpuFormat::from_raw(b't' as i8), Some(MipsFpuFormat::Triple));
    assert_eq!(MipsFpuFormat::from_raw(b'q' as i8), Some(MipsFpuFormat::Quad));
    assert_eq!(MipsFpuFormat::from_raw(b'x' as i8), None);

    assert_eq!(MipsFpuFormat::Single.suffix(), ".s");
    assert_eq!(MipsFpuFormat::PairedSingle.suffix(), ".p");
}

fn test_sparc_condition_code() {
    assert_eq!(SparcConditionCode::from_raw(0), Some(SparcConditionCode::Never));
    assert_eq!(SparcConditionCode::from_raw(1), Some(SparcConditionCode::Equal));
    assert_eq!(SparcConditionCode::from_raw(8), Some(SparcConditionCode::Always));
    assert_eq!(SparcConditionCode::from_raw(15), Some(SparcConditionCode::OverflowClear));
    assert_eq!(SparcConditionCode::from_raw(16), None);
    assert_eq!(SparcConditionCode::from_raw(-1), None);
}

fn test_mc68xx_suffix() {
    assert_eq!(Mc68xxSuffix::from_raw(0), None);
    assert_eq!(Mc68xxSuffix::from_raw(-1), Some(Mc68xxSuffix::Long));
    assert_eq!(Mc68xxSuffix::from_raw(1), Some(Mc68xxSuffix::A));
    assert_eq!(Mc68xxSuffix::from_raw(8), Some(Mc68xxSuffix::D));
    assert_eq!(Mc68xxSuffix::from_raw(9), None);

    assert_eq!(Mc68xxSuffix::Long.suffix(), ".l");
    assert_eq!(Mc68xxSuffix::A.suffix(), ".a");
}

fn main() {
    test_segpref_none_for_regular_instructions();
    test_metapc_segment_from_raw();
    test_mc68k_operand_size();
    test_mips_fpu_format();
    test_sparc_condition_code();
    test_mc68xx_suffix();
}

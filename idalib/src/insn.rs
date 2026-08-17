use std::{fmt, mem};

use bitflags::bitflags;

use crate::ffi::insn::insn_t;
use crate::ffi::insn::op::*;
use crate::ffi::insn::op::op_t;
use crate::ffi::util::{is_basic_block_end, is_call_insn, is_indirect_jump_insn, is_ret_insn, idalib_get_disasm_line, idalib_get_insn_mnem, idalib_get_insn_operand};

pub use crate::ffi::insn::{arm, mips, x86};

use crate::Address;
use crate::as_signed_char;

pub type Register = u16;
pub type Phrase = u16;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Insn {
    inner: insn_t,
}

#[derive(Clone, Copy)]
pub struct Operand {
    inner: op_t,
    ea: Address,
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            unsafe { idalib_get_disasm_line(autocxx::c_ulonglong(self.inner.ea)) }
        )
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            unsafe {
                idalib_get_insn_operand(
                    autocxx::c_ulonglong(self.ea),
                    autocxx::c_int(self.inner.n as i32),
                )
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum OperandType {
    // Void -- we exclude it during creation
    Reg = o_reg,
    Mem = o_mem,
    Phrase = o_phrase,
    Displ = o_displ,
    Imm = o_imm,
    Far = o_far,
    Near = o_near,
    IdpSpec0 = o_idpspec0,
    IdpSpec1 = o_idpspec1,
    IdpSpec2 = o_idpspec2,
    IdpSpec3 = o_idpspec3,
    IdpSpec4 = o_idpspec4,
    IdpSpec5 = o_idpspec5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum OperandDataType {
    Byte = dt_byte as _,
    Word = dt_word as _,
    DWord = dt_dword as _,
    Float = dt_float as _,
    Double = dt_double as _,
    TByte = dt_tbyte as _,
    PackReal = dt_packreal as _,
    QWord = dt_qword as _,
    Byte16 = dt_byte16 as _,
    Code = dt_code as _,
    Void = dt_void as _,
    FWord = dt_fword as _,
    Bitfield = dt_bitfild as _,
    String = dt_string as _,
    Unicode = dt_unicode as _,
    LongDouble = dt_ldbl as _,
    Byte32 = dt_byte32 as _,
    Byte64 = dt_byte64 as _,
    Half = dt_half as _,
}

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OperandFlags: u8 {
        const NO_BASE_DISP = OF_NO_BASE_DISP as _;
        const OUTER_DISP = OF_OUTER_DISP as _;
        const NUMBER = OF_NUMBER as _;
        const SHOW = OF_SHOW as _;
    }
}

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct IsReturnFlags: u8 {
        const EXTENDED = IRI_EXTENDED as _;
        const RET_LITERALLY = IRI_RET_LITERALLY as _;
        const SKIP_RETTARGET = IRI_SKIP_RETTARGET as _;
        const STRICT = IRI_STRICT as _;
    }
}

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CanonFeature: u32 {
        const STOP = crate::ffi::insn_features::CF_STOP;
        const CHG1 = crate::ffi::insn_features::CF_CHG1;
        const CHG2 = crate::ffi::insn_features::CF_CHG2;
        const CHG3 = crate::ffi::insn_features::CF_CHG3;
        const CHG4 = crate::ffi::insn_features::CF_CHG4;
        const CHG5 = crate::ffi::insn_features::CF_CHG5;
        const CHG6 = crate::ffi::insn_features::CF_CHG6;
        const USE1 = crate::ffi::insn_features::CF_USE1;
        const USE2 = crate::ffi::insn_features::CF_USE2;
        const USE3 = crate::ffi::insn_features::CF_USE3;
        const USE4 = crate::ffi::insn_features::CF_USE4;
        const USE5 = crate::ffi::insn_features::CF_USE5;
        const USE6 = crate::ffi::insn_features::CF_USE6;
        const JUMP = crate::ffi::insn_features::CF_JUMP;
        const SHFT = crate::ffi::insn_features::CF_SHFT;
        const HLL = crate::ffi::insn_features::CF_HLL;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i8)]
pub enum AddressingMode {
    Base = 0,
    Sib = 1,
}

pub mod segpref {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum SegPref {
        Metapc { segment: MetapcSegment },
        Mc68k { operand_size: Mc68kOperandSize, hide_suffix: bool },
        Mips { fpu_format: MipsFpuFormat },
        Sparc { condition: SparcConditionCode },
        Spc700 { indirect: bool },
        Mc68xx { suffix: Mc68xxSuffix },
        C166 { repeat_count: u8 },
        Trimedia { slot: u8 },
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum MetapcSegment {
        Es,
        Cs,
        Ss,
        Ds,
        Fs,
        Gs,
    }

    impl MetapcSegment {
        pub fn from_raw(val: i8) -> Option<Self> {
            match val {
                29 => Some(Self::Es),
                30 => Some(Self::Cs),
                31 => Some(Self::Ss),
                32 => Some(Self::Ds),
                33 => Some(Self::Fs),
                34 => Some(Self::Gs),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Mc68kOperandSize {
        Byte,
        Word,
        Long,
        Single,
        Double,
        Extended,
    }

    impl Mc68kOperandSize {
        pub fn from_raw(val: i8) -> Option<Self> {
            match val & 0x7F {
                1 => Some(Self::Byte),
                2 => Some(Self::Word),
                3 => Some(Self::Long),
                4 => Some(Self::Single),
                5 => Some(Self::Double),
                6 => Some(Self::Extended),
                _ => None,
            }
        }

        pub fn suffix(&self) -> &'static str {
            match self {
                Self::Byte => ".b",
                Self::Word => ".w",
                Self::Long => ".l",
                Self::Single => ".s",
                Self::Double => ".d",
                Self::Extended => ".x",
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum MipsFpuFormat {
        Single,
        Double,
        Word,
        Long,
        PairedSingle,
        Triple,
        Quad,
    }

    impl MipsFpuFormat {
        pub fn from_raw(val: i8) -> Option<Self> {
            match val as u8 {
                b's' => Some(Self::Single),
                b'd' => Some(Self::Double),
                b'w' => Some(Self::Word),
                b'l' => Some(Self::Long),
                b'p' => Some(Self::PairedSingle),
                b't' => Some(Self::Triple),
                b'q' => Some(Self::Quad),
                _ => None,
            }
        }

        pub fn suffix(&self) -> &'static str {
            match self {
                Self::Single => ".s",
                Self::Double => ".d",
                Self::Word => ".w",
                Self::Long => ".l",
                Self::PairedSingle => ".p",
                Self::Triple => ".t",
                Self::Quad => ".q",
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum SparcConditionCode {
        Never,
        Equal,
        LessOrEqual,
        Less,
        LessOrEqualUnsigned,
        CarrySet,
        Negative,
        OverflowSet,
        Always,
        NotEqual,
        Greater,
        GreaterOrEqual,
        GreaterUnsigned,
        CarryClear,
        Positive,
        OverflowClear,
    }

    impl SparcConditionCode {
        pub fn from_raw(val: i8) -> Option<Self> {
            match val {
                0 => Some(Self::Never),
                1 => Some(Self::Equal),
                2 => Some(Self::LessOrEqual),
                3 => Some(Self::Less),
                4 => Some(Self::LessOrEqualUnsigned),
                5 => Some(Self::CarrySet),
                6 => Some(Self::Negative),
                7 => Some(Self::OverflowSet),
                8 => Some(Self::Always),
                9 => Some(Self::NotEqual),
                10 => Some(Self::Greater),
                11 => Some(Self::GreaterOrEqual),
                12 => Some(Self::GreaterUnsigned),
                13 => Some(Self::CarryClear),
                14 => Some(Self::Positive),
                15 => Some(Self::OverflowClear),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Mc68xxSuffix {
        Long,
        A,
        B,
        H,
        X,
        Y,
        S,
        U,
        D,
    }

    impl Mc68xxSuffix {
        pub fn from_raw(val: i8) -> Option<Self> {
            match val {
                -1 => Some(Self::Long),
                1 => Some(Self::A),
                2 => Some(Self::B),
                3 => Some(Self::H),
                4 => Some(Self::X),
                5 => Some(Self::Y),
                6 => Some(Self::S),
                7 => Some(Self::U),
                8 => Some(Self::D),
                _ => None,
            }
        }

        pub fn suffix(&self) -> &'static str {
            match self {
                Self::Long => ".l",
                Self::A => ".a",
                Self::B => ".b",
                Self::H => ".h",
                Self::X => ".x",
                Self::Y => ".y",
                Self::S => ".s",
                Self::U => ".u",
                Self::D => ".d",
            }
        }
    }
}

pub type InsnType = u16;

impl Insn {
    pub(crate) fn from_repr(inner: insn_t) -> Self {
        Self { inner }
    }

    pub fn address(&self) -> Address {
        self.inner.ea
    }

    pub fn itype(&self) -> InsnType {
        self.inner.itype as _
    }

    /// Raw processor-dependent segment prefix value.
    ///
    /// Use [`IDB::segpref`] to interpret this value as a typed [`segpref::SegPref`]
    /// based on the current processor family.
    pub fn segpref(&self) -> i8 {
        self.inner.segpref as i8
    }

    pub fn operand(&self, n: usize) -> Option<Operand> {
        let op = self.inner.ops.get(n)?;

        if op.type_ != o_void {
            Some(Operand {
                inner: *op,
                ea: self.inner.ea,
            })
        } else {
            None
        }
    }

    pub fn operand_count(&self) -> usize {
        self.inner
            .ops
            .iter()
            .position(|op| op.type_ == o_void)
            .unwrap_or(self.inner.ops.len())
    }

    pub fn len(&self) -> usize {
        self.inner.size as _
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_basic_block_end(&self, call_stops_block: bool) -> bool {
        unsafe { is_basic_block_end(&self.inner, call_stops_block) }
    }

    pub fn is_call(&self) -> bool {
        unsafe { is_call_insn(&self.inner) }
    }

    pub fn is_indirect_jump(&self) -> bool {
        unsafe { is_indirect_jump_insn(&self.inner) }
    }

    pub fn is_ret(&self) -> bool {
        self.is_ret_with(IsReturnFlags::STRICT)
    }

    pub fn is_ret_with(&self, iri: IsReturnFlags) -> bool {
        unsafe { is_ret_insn(&self.inner, iri.bits()) }
    }

    pub fn mnemonic(&self) -> String {
        unsafe { idalib_get_insn_mnem(autocxx::c_ulonglong(self.inner.ea)) }
    }

    pub fn x86_base_reg(&self, operand: &Operand) -> Option<Register> {
        let base = unsafe { crate::ffi::x86::idalib_x86_base_reg(self.inner_ptr(), operand.inner_ptr()).0 };
        if base >= 0 {
            Some(base as u32 as Register)
        } else {
            None
        }
    }

    pub fn x86_index_reg(&self, operand: &Operand) -> Option<Register> {
        let index = unsafe { crate::ffi::x86::idalib_x86_index_reg(self.inner_ptr(), operand.inner_ptr()).0 };
        if index >= 0 {
            Some(index as u32 as Register)
        } else {
            None
        }
    }

    pub fn x86_scale(&self, operand: &Operand) -> Option<u32> {
        let scale_bits = unsafe { crate::ffi::x86::idalib_x86_scale(operand.inner_ptr()).0 };
        if scale_bits >= 0 {
            Some(1u32 << (scale_bits as u32))
        } else {
            None
        }
    }

    pub fn sib_base(&self, operand: &Operand) -> Option<Register> {
        let base = unsafe { crate::ffi::x86::idalib_sib_base(self.inner_ptr(), operand.inner_ptr()).0 };
        if base >= 0 {
            Some(base as u32 as Register)
        } else {
            None
        }
    }

    pub fn sib_index(&self, operand: &Operand) -> Option<Register> {
        let index = unsafe { crate::ffi::x86::idalib_sib_index(self.inner_ptr(), operand.inner_ptr()).0 };
        if index >= 0 {
            Some(index as u32 as Register)
        } else {
            None
        }
    }

    pub fn sib_scale(&self, operand: &Operand) -> Option<u32> {
        let scale_bits = unsafe { crate::ffi::x86::idalib_sib_scale(operand.inner_ptr()).0 };
        if scale_bits >= 0 {
            Some(1u32 << (scale_bits as u32))
        } else {
            None
        }
    }

    /// Get canonical instruction features (CF_STOP, CF_CHG*, CF_USE*, etc.)
    pub fn canon_feature(&self) -> CanonFeature {
        CanonFeature::from_bits_retain(unsafe {
            crate::ffi::insn_features::idalib_get_canon_feature(self.inner.itype as u16)
        })
    }

    /// Check if instruction breaks sequential flow (CF_STOP)
    pub fn breaks_flow(&self) -> bool {
        self.canon_feature().contains(CanonFeature::STOP)
    }

    /// Check if instruction modifies the given operand
    pub fn modifies_operand(&self, operand_index: usize) -> bool {
        unsafe {
            crate::ffi::insn_features::idalib_has_cf_chg(
                self.canon_feature().bits(),
                operand_index as u32,
            )
        }
    }

    /// Check if instruction uses (reads) the given operand
    pub fn uses_operand(&self, operand_index: usize) -> bool {
        unsafe {
            crate::ffi::insn_features::idalib_has_cf_use(
                self.canon_feature().bits(),
                operand_index as u32,
            )
        }
    }

    fn inner_ptr(&self) -> *const insn_t {
        &self.inner as *const insn_t
    }

}

impl Operand {
    pub fn flags(&self) -> OperandFlags {
        OperandFlags::from_bits_retain(self.inner.flags)
    }

    pub fn offb(&self) -> i8 {
        as_signed_char(self.inner.offb)
    }

    pub fn offo(&self) -> i8 {
        as_signed_char(self.inner.offo)
    }

    pub fn n(&self) -> usize {
        self.inner.n as _
    }

    pub fn number(&self) -> usize {
        self.n()
    }

    pub fn type_(&self) -> OperandType {
        unsafe { mem::transmute(self.inner.type_) }
    }

    pub fn dtype(&self) -> OperandDataType {
        unsafe { mem::transmute(self.inner.dtype) }
    }

    pub fn reg(&self) -> Option<Register> {
        if self.is_processor_specific() || self.type_() == OperandType::Reg {
            Some(unsafe { self.inner.__bindgen_anon_1.reg })
        } else {
            None
        }
    }

    pub fn register(&self) -> Option<Register> {
        self.reg()
    }

    pub fn phrase(&self) -> Option<Phrase> {
        if self.is_processor_specific()
            || matches!(self.type_(), OperandType::Phrase | OperandType::Displ)
        {
            Some(unsafe { self.inner.__bindgen_anon_1.phrase })
        } else {
            None
        }
    }

    pub fn value(&self) -> Option<u64> {
        if self.is_processor_specific() || self.type_() == OperandType::Imm {
            Some(unsafe { self.inner.__bindgen_anon_2.value })
        } else {
            None
        }
    }

    pub fn outer_displacement(&self) -> Option<u64> {
        if self.flags().contains(OperandFlags::OUTER_DISP) {
            Some(unsafe { self.inner.__bindgen_anon_2.value })
        } else {
            None
        }
    }

    pub fn address(&self) -> Option<Address> {
        self.addr()
    }

    pub fn addr(&self) -> Option<Address> {
        if self.is_processor_specific()
            || matches!(
                self.type_(),
                OperandType::Phrase | OperandType::Mem | OperandType::Displ | OperandType::Far | OperandType::Near
            )
        {
            Some(unsafe { self.inner.__bindgen_anon_3.addr })
        } else {
            None
        }
    }

    pub fn processor_specific(&self) -> Option<u64> {
        if self.is_processor_specific() {
            Some(unsafe { self.inner.__bindgen_anon_4.specval })
        } else {
            None
        }
    }

    pub fn processor_specific_low(&self) -> Option<u16> {
        if self.is_processor_specific() {
            Some(unsafe { self.inner.__bindgen_anon_4.specval_shorts.low })
        } else {
            None
        }
    }

    pub fn processor_specific_high(&self) -> Option<u16> {
        if self.is_processor_specific() {
            Some(unsafe { self.inner.__bindgen_anon_4.specval_shorts.high })
        } else {
            None
        }
    }

    pub fn processor_specific_flag1(&self) -> Option<i8> {
        if self.is_processor_specific() {
            Some(as_signed_char(self.inner.specflag1))
        } else {
            None
        }
    }

    pub fn processor_specific_flag2(&self) -> Option<i8> {
        if self.is_processor_specific() {
            Some(as_signed_char(self.inner.specflag2))
        } else {
            None
        }
    }

    /// Get addressing mode for phrase/displ operands (used for x86).
    /// Returns:
    /// - Base: standard [base+offset] or [base] addressing
    /// - Sib: SIB byte present, use specflag2 for base
    pub fn addressing_mode(&self) -> AddressingMode {
        match self.inner.specflag1 {
            1 => AddressingMode::Sib,
            _ => AddressingMode::Base,
        }
    }

    /// Get the raw specflag1 for phrase/displ operands.
    ///
    /// Prefer [`Operand::addressing_mode`] on x86, where the only defined values are
    /// 0 (base) and 1 (SIB). Other processor modules assign their own meanings, so
    /// callers that must distinguish those need the raw value.
    pub fn specflag1(&self) -> i8 {
        as_signed_char(self.inner.specflag1)
    }

    /// Get specflag2 for phrase/displ operands (used for x86 SIB byte base extraction).
    pub fn specflag2(&self) -> i8 {
        as_signed_char(self.inner.specflag2)
    }

    pub fn processor_specific_flag3(&self) -> Option<i8> {
        if self.is_processor_specific() {
            Some(as_signed_char(self.inner.specflag3))
        } else {
            None
        }
    }

    pub fn processor_specific_flag4(&self) -> Option<i8> {
        if self.is_processor_specific() {
            Some(as_signed_char(self.inner.specflag4))
        } else {
            None
        }
    }

    pub fn is_processor_specific(&self) -> bool {
        matches!(
            self.type_(),
            OperandType::IdpSpec0
                | OperandType::IdpSpec1
                | OperandType::IdpSpec2
                | OperandType::IdpSpec3
                | OperandType::IdpSpec4
                | OperandType::IdpSpec5
        )
    }

    pub fn has_sib(&self) -> bool {
        unsafe { crate::ffi::x86::idalib_has_sib(self.inner_ptr()) }
    }

    pub fn sib_byte(&self) -> u8 {
        unsafe { crate::ffi::x86::idalib_get_sib_byte(self.inner_ptr()) }
    }

    pub fn has_displacement(&self) -> bool {
        unsafe { crate::ffi::x86::idalib_has_displ(self.inner_ptr()) }
    }

    fn inner_ptr(&self) -> *const op_t {
        &self.inner as *const op_t
    }
}

use std::mem;

use bitflags::bitflags;

use crate::ffi::insn::insn_t;
use crate::ffi::insn::op::*;
use crate::ffi::insn::op::op_t;
use crate::ffi::util::{is_basic_block_end, is_call_insn, is_indirect_jump_insn, is_ret_insn, idalib_get_disasm_line, idalib_get_insn_mnem, idalib_get_insn_operand};

pub use crate::ffi::insn::{arm, mips, x86};

use crate::Address;

pub type Register = u16;
pub type Phrase = u16;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Insn {
    inner: insn_t,
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Operand {
    inner: op_t,
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

    pub fn operand(&self, n: usize) -> Option<Operand> {
        let op = self.inner.ops.get(n)?;

        if op.type_ != o_void {
            Some(Operand { inner: *op })
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

    pub fn disasm_line(&self) -> String {
        unsafe { idalib_get_disasm_line(autocxx::c_ulonglong(self.inner.ea)) }
    }

    pub fn print_operand(&self, n: usize) -> Option<String> {
        self.operand(n).map(|_| unsafe {
            idalib_get_insn_operand(autocxx::c_ulonglong(self.inner.ea), autocxx::c_int(n as i32))
        })
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
    pub fn canon_feature(&self) -> u32 {
        unsafe { crate::ffi::insn_features::idalib_get_canon_feature(self.inner.itype as u16) }
    }

    /// Check if instruction breaks sequential flow (CF_STOP)
    pub fn breaks_flow(&self) -> bool {
        (self.canon_feature() & crate::ffi::insn_features::CF_STOP) != 0
    }

    /// Check if instruction modifies the given operand
    pub fn modifies_operand(&self, operand_index: usize) -> bool {
        unsafe { crate::ffi::insn_features::idalib_has_cf_chg(self.canon_feature(), operand_index as u32) }
    }

    /// Check if instruction uses (reads) the given operand
    pub fn uses_operand(&self, operand_index: usize) -> bool {
        unsafe { crate::ffi::insn_features::idalib_has_cf_use(self.canon_feature(), operand_index as u32) }
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
        self.inner.offb
    }

    pub fn offo(&self) -> i8 {
        self.inner.offo
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
            Some(self.inner.specflag1)
        } else {
            None
        }
    }

    pub fn processor_specific_flag2(&self) -> Option<i8> {
        if self.is_processor_specific() {
            Some(self.inner.specflag2)
        } else {
            None
        }
    }

    /// Get specflag1 for phrase/displ operands (used for x86 addressing mode detection).
    /// Returns the raw specflag1 value which indicates addressing mode:
    /// - 0: standard [base+offset] or [base] addressing
    /// - 1: SIB byte present, use specflag2 for base
    /// - other: unknown/unsupported addressing mode
    pub fn specflag1(&self) -> i8 {
        self.inner.specflag1
    }

    /// Get specflag2 for phrase/displ operands (used for x86 SIB byte base extraction).
    pub fn specflag2(&self) -> i8 {
        self.inner.specflag2
    }

    pub fn processor_specific_flag3(&self) -> Option<i8> {
        if self.is_processor_specific() {
            Some(self.inner.specflag3)
        } else {
            None
        }
    }

    pub fn processor_specific_flag4(&self) -> Option<i8> {
        if self.is_processor_specific() {
            Some(self.inner.specflag4)
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


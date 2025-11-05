use std::marker::PhantomData;
use std::mem;

use bitflags::bitflags;

use crate::Address;
use crate::ffi::BADADDR;
use crate::ffi::inf::*;
use crate::ffi::nalt::*;
use crate::idb::IDB;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct AnalysisFlags: u32 {
        const CODE = AF_CODE as _;
        const MARKCODE = AF_MARKCODE as _;
        const JUMPTBL = AF_JUMPTBL as _;
        const PURDAT = AF_PURDAT as _;
        const USED = AF_USED as _;
        const UNK = AF_UNK as _;

        const PROCPTR = AF_PROCPTR as _;
        const PROC = AF_PROC as _;
        const FTAIL = AF_FTAIL as _;
        const LVAR = AF_LVAR as _;
        const STKARG = AF_STKARG as _;
        const REGARG = AF_REGARG as _;
        const TRACE = AF_TRACE as _;
        const VERSP = AF_VERSP as _;
        const ANORET = AF_ANORET as _;
        const MEMFUNC = AF_MEMFUNC as _;
        const TRFUNC = AF_TRFUNC as _;

        const STRLIT = AF_STRLIT as _;
        const CHKUNI = AF_CHKUNI as _;
        const FIXUP = AF_FIXUP as _;
        const DREFOFF = AF_DREFOFF as _;
        const IMMOFF = AF_IMMOFF as _;
        const DATOFF = AF_DATOFF as _;

        const FLIRT = AF_FLIRT as _;
        const SIGCMT = AF_SIGCMT as _;
        const SIGMLT = AF_SIGMLT as _;
        const HFLIRT = AF_HFLIRT as _;

        const JFUNC = AF_JFUNC as _;
        const NULLSUB = AF_NULLSUB as _;

        const DODATA = AF_DODATA as _;
        const DOCODE = AF_DOCODE as _;
        const FINAL = AF_FINAL as _;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct AnalysisFlags2: u32 {
        const DOEH = AF2_DOEH as _;
        const DORTTI = AF2_DORTTI as _;
        const MACRO = AF2_MACRO as _;
        const MERGESTR = AF2_MERGESTR as _;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ShowXRefFlags: u8 {
        const SEGXRF = SW_SEGXRF as _;
        const XRFMRK = SW_XRFMRK as _;
        const XRFFNC = SW_XRFFNC as _;
        const XRFVAL = SW_XRFVAL as _;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u32)]
pub enum FileType {
    #[doc(hidden)]
    OldEXE = filetype_t::f_EXE_old as _,
    #[doc(hidden)]
    OldCOM = filetype_t::f_COM_old as _,
    BIN = filetype_t::f_BIN as _,
    DRV = filetype_t::f_DRV as _,
    WIN = filetype_t::f_WIN as _,
    HEX = filetype_t::f_HEX as _,
    MEX = filetype_t::f_MEX as _,
    LX = filetype_t::f_LX as _,
    LE = filetype_t::f_LE as _,
    NLM = filetype_t::f_NLM as _,
    COFF = filetype_t::f_COFF as _,
    PE = filetype_t::f_PE as _,
    OMF = filetype_t::f_OMF as _,
    SREC = filetype_t::f_SREC as _,
    ZIP = filetype_t::f_ZIP as _,
    OMFLIB = filetype_t::f_OMFLIB as _,
    AR = filetype_t::f_AR as _,
    LOADER = filetype_t::f_LOADER as _,
    ELF = filetype_t::f_ELF as _,
    W32RUN = filetype_t::f_W32RUN as _,
    AOUT = filetype_t::f_AOUT as _,
    PRC = filetype_t::f_PRC as _,
    EXE = filetype_t::f_EXE as _,
    COM = filetype_t::f_COM as _,
    AIXAR = filetype_t::f_AIXAR as _,
    MACHO = filetype_t::f_MACHO as _,
    PSXOBJ = filetype_t::f_PSXOBJ as _,
    MD1IMG = filetype_t::f_MD1IMG as _,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Compiler {
    UNK = COMP_UNK as _,
    MS = COMP_MS as _,
    BC = COMP_BC as _,
    WATCOM = COMP_WATCOM as _,
    GNU = COMP_GNU as _,
    VISAGE = COMP_VISAGE as _,
    BP = COMP_BP as _,
    UNSURE = COMP_UNSURE as _,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum OSType {
    LINUX = 0,
    WIN32 = 1,
    MAC = 2,
    UNIX = 3,
}

impl OSType {
    /// Attempt to convert a u16 to an OSType enum value.
    ///
    /// Returns Some if the value corresponds to a known OS type, None otherwise.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(OSType::LINUX),
            1 => Some(OSType::WIN32),
            2 => Some(OSType::MAC),
            3 => Some(OSType::UNIX),
            _ => None,
        }
    }
}

pub struct Metadata<'a> {
    _marker: PhantomData<&'a IDB>,
}

impl<'a> Metadata<'a> {
    pub(crate) fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn version(&self) -> u16 {
        unsafe { idalib_inf_get_version() }
    }

    pub fn genflags(&self) -> u16 {
        unsafe { idalib_inf_get_genflags() }
    }

    pub fn is_auto_enabled(&self) -> bool {
        unsafe { idalib_inf_is_auto_enabled() }
    }

    pub fn use_allasm(&self) -> bool {
        unsafe { idalib_inf_use_allasm() }
    }

    pub fn loading_idc(&self) -> bool {
        unsafe { idalib_inf_loading_idc() }
    }

    pub fn no_store_user_info(&self) -> bool {
        unsafe { idalib_inf_no_store_user_info() }
    }

    pub fn readonly_idb(&self) -> bool {
        unsafe { idalib_inf_readonly_idb() }
    }

    pub fn check_manual_ops(&self) -> bool {
        unsafe { idalib_inf_check_manual_ops() }
    }

    pub fn allow_non_matched_ops(&self) -> bool {
        unsafe { idalib_inf_allow_non_matched_ops() }
    }

    pub fn is_graph_view(&self) -> bool {
        unsafe { idalib_inf_is_graph_view() }
    }

    pub fn lflags(&self) -> u32 {
        unsafe { idalib_inf_get_lflags() }
    }

    pub fn decode_fpp(&self) -> bool {
        unsafe { idalib_inf_decode_fpp() }
    }

    pub fn is_32bit_or_higher(&self) -> bool {
        unsafe { idalib_inf_is_32bit_or_higher() }
    }

    pub fn is_32bit_exactly(&self) -> bool {
        unsafe { idalib_inf_is_32bit_exactly() }
    }

    pub fn is_16bit(&self) -> bool {
        unsafe { idalib_inf_is_16bit() }
    }

    pub fn is_64bit(&self) -> bool {
        unsafe { idalib_inf_is_64bit() }
    }

    pub fn is_dll(&self) -> bool {
        unsafe { idalib_inf_is_dll() }
    }

    pub fn is_flat_off32(&self) -> bool {
        unsafe { idalib_inf_is_flat_off32() }
    }

    pub fn is_be(&self) -> bool {
        unsafe { idalib_inf_is_be() }
    }

    pub fn is_wide_high_byte_first(&self) -> bool {
        unsafe { idalib_inf_is_wide_high_byte_first() }
    }

    pub fn dbg_no_store_path(&self) -> bool {
        unsafe { idalib_inf_dbg_no_store_path() }
    }

    pub fn is_snapshot(&self) -> bool {
        unsafe { idalib_inf_is_snapshot() }
    }

    pub fn pack_idb(&self) -> bool {
        unsafe { idalib_inf_pack_idb() }
    }

    pub fn compress_idb(&self) -> bool {
        unsafe { idalib_inf_compress_idb() }
    }

    pub fn is_kernel_mode(&self) -> bool {
        unsafe { idalib_inf_is_kernel_mode() }
    }

    pub fn app_bitness(&self) -> u32 {
        unsafe { idalib_inf_get_app_bitness().into() }
    }

    pub fn database_change_count(&self) -> u32 {
        unsafe { idalib_inf_get_database_change_count() }
    }

    pub fn filetype(&self) -> FileType {
        unsafe { mem::transmute(idalib_inf_get_filetype()) }
    }

    pub fn ostype(&self) -> Option<OSType> {
        let value = unsafe { idalib_inf_get_ostype() };
        OSType::from_u16(value)
    }

    pub fn apptype(&self) -> u16 {
        unsafe { idalib_inf_get_apptype() }
    }

    pub fn asmtype(&self) -> u8 {
        unsafe { idalib_inf_get_asmtype() }
    }

    pub fn specsegs(&self) -> u8 {
        unsafe { idalib_inf_get_specsegs() }
    }

    pub fn af(&self) -> AnalysisFlags {
        AnalysisFlags::from_bits_retain(unsafe { idalib_inf_get_af() })
    }

    pub fn trace_flow(&self) -> bool {
        unsafe { idalib_inf_trace_flow() }
    }

    pub fn mark_code(&self) -> bool {
        unsafe { idalib_inf_mark_code() }
    }

    pub fn create_jump_tables(&self) -> bool {
        unsafe { idalib_inf_create_jump_tables() }
    }

    pub fn noflow_to_data(&self) -> bool {
        unsafe { idalib_inf_noflow_to_data() }
    }

    pub fn create_all_xrefs(&self) -> bool {
        unsafe { idalib_inf_create_all_xrefs() }
    }

    pub fn create_func_from_ptr(&self) -> bool {
        unsafe { idalib_inf_create_func_from_ptr() }
    }

    pub fn create_func_from_call(&self) -> bool {
        unsafe { idalib_inf_create_func_from_call() }
    }

    pub fn create_func_tails(&self) -> bool {
        unsafe { idalib_inf_create_func_tails() }
    }

    pub fn should_create_stkvars(&self) -> bool {
        unsafe { idalib_inf_should_create_stkvars() }
    }

    pub fn propagate_stkargs(&self) -> bool {
        unsafe { idalib_inf_propagate_stkargs() }
    }

    pub fn propagate_regargs(&self) -> bool {
        unsafe { idalib_inf_propagate_regargs() }
    }

    pub fn should_trace_sp(&self) -> bool {
        unsafe { idalib_inf_should_trace_sp() }
    }

    pub fn full_sp_ana(&self) -> bool {
        unsafe { idalib_inf_full_sp_ana() }
    }

    pub fn noret_ana(&self) -> bool {
        unsafe { idalib_inf_noret_ana() }
    }

    pub fn guess_func_type(&self) -> bool {
        unsafe { idalib_inf_guess_func_type() }
    }

    pub fn truncate_on_del(&self) -> bool {
        unsafe { idalib_inf_truncate_on_del() }
    }

    pub fn create_strlit_on_xref(&self) -> bool {
        unsafe { idalib_inf_create_strlit_on_xref() }
    }

    pub fn check_unicode_strlits(&self) -> bool {
        unsafe { idalib_inf_check_unicode_strlits() }
    }

    pub fn create_off_using_fixup(&self) -> bool {
        unsafe { idalib_inf_create_off_using_fixup() }
    }

    pub fn create_off_on_dref(&self) -> bool {
        unsafe { idalib_inf_create_off_on_dref() }
    }

    pub fn op_offset(&self) -> bool {
        unsafe { idalib_inf_op_offset() }
    }

    pub fn data_offset(&self) -> bool {
        unsafe { idalib_inf_data_offset() }
    }

    pub fn use_flirt(&self) -> bool {
        unsafe { idalib_inf_use_flirt() }
    }

    pub fn append_sigcmt(&self) -> bool {
        unsafe { idalib_inf_append_sigcmt() }
    }

    pub fn allow_sigmulti(&self) -> bool {
        unsafe { idalib_inf_allow_sigmulti() }
    }

    pub fn hide_libfuncs(&self) -> bool {
        unsafe { idalib_inf_hide_libfuncs() }
    }

    pub fn rename_jumpfunc(&self) -> bool {
        unsafe { idalib_inf_rename_jumpfunc() }
    }

    pub fn rename_nullsub(&self) -> bool {
        unsafe { idalib_inf_rename_nullsub() }
    }

    pub fn coagulate_data(&self) -> bool {
        unsafe { idalib_inf_coagulate_data() }
    }

    pub fn coagulate_code(&self) -> bool {
        unsafe { idalib_inf_coagulate_code() }
    }

    pub fn final_pass(&self) -> bool {
        unsafe { idalib_inf_final_pass() }
    }

    pub fn af2(&self) -> u32 {
        unsafe { idalib_inf_get_af2() }
    }

    pub fn handle_eh(&self) -> bool {
        unsafe { idalib_inf_handle_eh() }
    }

    pub fn handle_rtti(&self) -> bool {
        unsafe { idalib_inf_handle_rtti() }
    }

    pub fn macros_enabled(&self) -> bool {
        unsafe { idalib_inf_macros_enabled() }
    }

    pub fn merge_strlits(&self) -> bool {
        unsafe { idalib_inf_merge_strlits() }
    }

    pub fn base_address(&self) -> Option<Address> {
        let ea = unsafe { idalib_inf_get_baseaddr() };
        if ea != BADADDR { Some(ea.into()) } else { None }
    }

    pub fn imagebase(&self) -> Address {
        unsafe { idalib_inf_get_imagebase().into() }
    }

    pub fn start_stack_segment(&self) -> Option<Address> {
        let ea = unsafe { idalib_inf_get_start_ss() };
        if ea != BADADDR { Some(ea.into()) } else { None }
    }

    pub fn start_code_segment(&self) -> Option<Address> {
        let ea = unsafe { idalib_inf_get_start_cs() };
        if ea != BADADDR { Some(ea.into()) } else { None }
    }

    pub fn start_instruction_pointer(&self) -> Option<Address> {
        let ea = unsafe { idalib_inf_get_start_ip() };
        if ea != BADADDR { Some(ea.into()) } else { None }
    }

    pub fn start_address(&self) -> Option<Address> {
        let ea = unsafe { idalib_inf_get_start_ea() };
        if ea != BADADDR { Some(ea.into()) } else { None }
    }

    pub fn start_stack_pointer(&self) -> Option<Address> {
        let ea = unsafe { idalib_inf_get_start_sp() };
        if ea != BADADDR { Some(ea.into()) } else { None }
    }

    pub fn main_address(&self) -> Option<Address> {
        let ea = unsafe { idalib_inf_get_main() };
        if ea != BADADDR { Some(ea.into()) } else { None }
    }

    pub fn min_address(&self) -> Address {
        unsafe { idalib_inf_get_min_ea().into() }
    }

    pub fn max_address(&self) -> Address {
        unsafe { idalib_inf_get_max_ea().into() }
    }

    pub fn omin_address(&self) -> Address {
        unsafe { idalib_inf_get_omin_ea().into() }
    }

    pub fn omax_ea(&self) -> Address {
        unsafe { idalib_inf_get_omax_ea().into() }
    }

    pub fn lowoff(&self) -> u64 {
        unsafe { idalib_inf_get_lowoff().into() }
    }

    pub fn highoff(&self) -> u64 {
        unsafe { idalib_inf_get_highoff().into() }
    }

    pub fn maxref(&self) -> u64 {
        unsafe { idalib_inf_get_maxref().into() }
    }

    pub fn netdelta(&self) -> i64 {
        unsafe { idalib_inf_get_netdelta().into() }
    }

    pub fn xrefnum(&self) -> u8 {
        unsafe { idalib_inf_get_xrefnum() }
    }

    pub fn type_xrefnum(&self) -> u8 {
        unsafe { idalib_inf_get_type_xrefnum() }
    }

    pub fn refcmtnum(&self) -> u8 {
        unsafe { idalib_inf_get_refcmtnum() }
    }

    pub fn xrefflag(&self) -> u8 {
        unsafe { idalib_inf_get_xrefflag() }
    }

    pub fn show_xref_seg(&self) -> bool {
        unsafe { idalib_inf_show_xref_seg() }
    }

    pub fn show_xref_tmarks(&self) -> bool {
        unsafe { idalib_inf_show_xref_tmarks() }
    }

    pub fn show_xref_fncoff(&self) -> bool {
        unsafe { idalib_inf_show_xref_fncoff() }
    }

    pub fn show_xref_val(&self) -> bool {
        unsafe { idalib_inf_show_xref_val() }
    }

    pub fn max_autoname_len(&self) -> u16 {
        unsafe { idalib_inf_get_max_autoname_len() }
    }

    pub fn nametype(&self) -> i8 {
        unsafe { idalib_inf_get_nametype() }
    }

    pub fn short_demnames(&self) -> u32 {
        unsafe { idalib_inf_get_short_demnames() }
    }

    pub fn long_demnames(&self) -> u32 {
        unsafe { idalib_inf_get_long_demnames() }
    }

    pub fn demnames(&self) -> u8 {
        unsafe { idalib_inf_get_demnames() }
    }

    pub fn listnames(&self) -> u8 {
        unsafe { idalib_inf_get_listnames() }
    }

    pub fn indent(&self) -> u8 {
        unsafe { idalib_inf_get_indent() }
    }

    pub fn cmt_indent(&self) -> u8 {
        unsafe { idalib_inf_get_cmt_indent() }
    }

    pub fn margin(&self) -> u16 {
        unsafe { idalib_inf_get_margin() }
    }

    pub fn lenxref(&self) -> u16 {
        unsafe { idalib_inf_get_lenxref() }
    }

    pub fn outflags(&self) -> u32 {
        unsafe { idalib_inf_get_outflags() }
    }

    pub fn show_void(&self) -> bool {
        unsafe { idalib_inf_show_void() }
    }

    pub fn show_auto(&self) -> bool {
        unsafe { idalib_inf_show_auto() }
    }

    pub fn gen_null(&self) -> bool {
        unsafe { idalib_inf_gen_null() }
    }

    pub fn show_line_pref(&self) -> bool {
        unsafe { idalib_inf_show_line_pref() }
    }

    pub fn line_pref_with_seg(&self) -> bool {
        unsafe { idalib_inf_line_pref_with_seg() }
    }

    pub fn gen_lzero(&self) -> bool {
        unsafe { idalib_inf_gen_lzero() }
    }

    pub fn gen_org(&self) -> bool {
        unsafe { idalib_inf_gen_org() }
    }

    pub fn gen_assume(&self) -> bool {
        unsafe { idalib_inf_gen_assume() }
    }

    pub fn gen_tryblks(&self) -> bool {
        unsafe { idalib_inf_gen_tryblks() }
    }

    pub fn cmtflg(&self) -> u8 {
        unsafe { idalib_inf_get_cmtflg() }
    }

    pub fn show_repeatables(&self) -> bool {
        unsafe { idalib_inf_show_repeatables() }
    }

    pub fn show_all_comments(&self) -> bool {
        unsafe { idalib_inf_show_all_comments() }
    }

    pub fn hide_comments(&self) -> bool {
        unsafe { idalib_inf_hide_comments() }
    }

    pub fn show_src_linnum(&self) -> bool {
        unsafe { idalib_inf_show_src_linnum() }
    }

    pub fn test_mode(&self) -> bool {
        unsafe { idalib_inf_test_mode() }
    }

    pub fn show_hidden_insns(&self) -> bool {
        unsafe { idalib_inf_show_hidden_insns() }
    }

    pub fn show_hidden_funcs(&self) -> bool {
        unsafe { idalib_inf_show_hidden_funcs() }
    }

    pub fn show_hidden_segms(&self) -> bool {
        unsafe { idalib_inf_show_hidden_segms() }
    }

    pub fn limiter(&self) -> u8 {
        unsafe { idalib_inf_get_limiter() }
    }

    pub fn is_limiter_thin(&self) -> bool {
        unsafe { idalib_inf_is_limiter_thin() }
    }

    pub fn is_limiter_thick(&self) -> bool {
        unsafe { idalib_inf_is_limiter_thick() }
    }

    pub fn is_limiter_empty(&self) -> bool {
        unsafe { idalib_inf_is_limiter_empty() }
    }

    pub fn bin_prefix_size(&self) -> i16 {
        unsafe { idalib_inf_get_bin_prefix_size().into() }
    }

    pub fn prefflag(&self) -> u8 {
        unsafe { idalib_inf_get_prefflag() }
    }

    pub fn prefix_show_segaddr(&self) -> bool {
        unsafe { idalib_inf_prefix_show_segaddr() }
    }

    pub fn prefix_show_funcoff(&self) -> bool {
        unsafe { idalib_inf_prefix_show_funcoff() }
    }

    pub fn prefix_show_stack(&self) -> bool {
        unsafe { idalib_inf_prefix_show_stack() }
    }

    pub fn prefix_truncate_opcode_bytes(&self) -> bool {
        unsafe { idalib_inf_prefix_truncate_opcode_bytes() }
    }

    pub fn strlit_flags(&self) -> u8 {
        unsafe { idalib_inf_get_strlit_flags() }
    }

    pub fn strlit_names(&self) -> bool {
        unsafe { idalib_inf_strlit_names() }
    }

    pub fn strlit_name_bit(&self) -> bool {
        unsafe { idalib_inf_strlit_name_bit() }
    }

    pub fn strlit_serial_names(&self) -> bool {
        unsafe { idalib_inf_strlit_serial_names() }
    }

    pub fn unicode_strlits(&self) -> bool {
        unsafe { idalib_inf_unicode_strlits() }
    }

    pub fn strlit_autocmt(&self) -> bool {
        unsafe { idalib_inf_strlit_autocmt() }
    }

    pub fn strlit_savecase(&self) -> bool {
        unsafe { idalib_inf_strlit_savecase() }
    }

    pub fn strlit_break(&self) -> u8 {
        unsafe { idalib_inf_get_strlit_break() }
    }

    pub fn strlit_zeroes(&self) -> i8 {
        unsafe { idalib_inf_get_strlit_zeroes() }
    }

    pub fn strtype(&self) -> i32 {
        unsafe { idalib_inf_get_strtype() }
    }

    pub fn strlit_sernum(&self) -> u64 {
        unsafe { idalib_inf_get_strlit_sernum().into() }
    }

    pub fn datatypes(&self) -> u64 {
        unsafe { idalib_inf_get_datatypes().into() }
    }

    pub fn abibits(&self) -> u32 {
        unsafe { idalib_inf_get_abibits() }
    }

    pub fn is_mem_aligned4(&self) -> bool {
        unsafe { idalib_inf_is_mem_aligned4() }
    }

    pub fn pack_stkargs(&self) -> bool {
        unsafe { idalib_inf_pack_stkargs() }
    }

    pub fn big_arg_align(&self) -> bool {
        unsafe { idalib_inf_big_arg_align() }
    }

    pub fn stack_ldbl(&self) -> bool {
        unsafe { idalib_inf_stack_ldbl() }
    }

    pub fn stack_varargs(&self) -> bool {
        unsafe { idalib_inf_stack_varargs() }
    }

    pub fn is_hard_float(&self) -> bool {
        unsafe { idalib_inf_is_hard_float() }
    }

    pub fn abi_set_by_user(&self) -> bool {
        unsafe { idalib_inf_abi_set_by_user() }
    }

    pub fn use_gcc_layout(&self) -> bool {
        unsafe { idalib_inf_use_gcc_layout() }
    }

    pub fn map_stkargs(&self) -> bool {
        unsafe { idalib_inf_map_stkargs() }
    }

    pub fn huge_arg_align(&self) -> bool {
        unsafe { idalib_inf_huge_arg_align() }
    }

    pub fn appcall_options(&self) -> u32 {
        unsafe { idalib_inf_get_appcall_options() }
    }

    pub fn privrange_start_address(&self) -> Option<Address> {
        let ea = unsafe { idalib_inf_get_privrange_start_ea() };
        if ea != BADADDR { Some(ea.into()) } else { None }
    }

    pub fn privrange_end_address(&self) -> Option<Address> {
        let ea = unsafe { idalib_inf_get_privrange_end_ea() };
        if ea != BADADDR { Some(ea.into()) } else { None }
    }

    pub fn cc_id(&self) -> Compiler {
        unsafe { mem::transmute(idalib_inf_get_cc_id() & COMP_MASK) }
    }

    pub fn cc_cm(&self) -> u8 {
        unsafe { idalib_inf_get_cc_cm() }
    }

    pub fn cc_size_i(&self) -> u8 {
        unsafe { idalib_inf_get_cc_size_i() }
    }

    pub fn cc_size_b(&self) -> u8 {
        unsafe { idalib_inf_get_cc_size_b() }
    }

    pub fn cc_size_e(&self) -> u8 {
        unsafe { idalib_inf_get_cc_size_e() }
    }

    pub fn cc_defalign(&self) -> u8 {
        unsafe { idalib_inf_get_cc_defalign() }
    }

    pub fn cc_size_s(&self) -> u8 {
        unsafe { idalib_inf_get_cc_size_s() }
    }

    pub fn cc_size_l(&self) -> u8 {
        unsafe { idalib_inf_get_cc_size_l() }
    }

    pub fn cc_size_ll(&self) -> u8 {
        unsafe { idalib_inf_get_cc_size_ll() }
    }

    pub fn cc_size_ldbl(&self) -> u8 {
        unsafe { idalib_inf_get_cc_size_ldbl() }
    }

    pub fn procname(&self) -> String {
        unsafe { idalib_inf_get_procname() }
    }

    pub fn strlit_pref(&self) -> String {
        unsafe { idalib_inf_get_strlit_pref() }
    }

    pub fn input_file_md5(&self) -> [u8; 16] {
        let mut md5 = [0u8; 16];
        unsafe {
            retrieve_input_file_md5(md5.as_mut_ptr());
        }
        md5
    }

    pub fn input_file_sha256(&self) -> [u8; 32] {
        let mut sha256 = [0u8; 32];
        unsafe {
            retrieve_input_file_sha256(sha256.as_mut_ptr());
        }
        sha256
    }

    pub fn input_file_path(&self) -> String {
        unsafe { idalib_get_input_file_path() }
    }

    pub fn input_file_size(&self) -> usize {
        unsafe { retrieve_input_file_size() }
    }
}

pub struct MetadataMut<'a> {
    _marker: PhantomData<&'a mut IDB>,
}

impl<'a> MetadataMut<'a> {
    pub(crate) fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn set_show_all_comments(&mut self) -> bool {
        unsafe { idalib_inf_set_show_all_comments() }
    }

    pub fn set_show_hidden_insns(&mut self) -> bool {
        unsafe { idalib_inf_set_show_hidden_insns() }
    }

    pub fn set_show_hidden_funcs(&mut self) -> bool {
        unsafe { idalib_inf_set_show_hidden_funcs() }
    }

    pub fn set_show_hidden_segms(&mut self) -> bool {
        unsafe { idalib_inf_set_show_hidden_segms() }
    }
}

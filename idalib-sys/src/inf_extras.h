#pragma once

#include <cstdint>

#include "pro.h"
#include "ida.hpp"

#include "cxx.h"

std::uint16_t idalib_inf_get_version() { return inf_get_version(); }

std::uint16_t idalib_inf_get_genflags() { return inf_get_genflags(); }

bool idalib_inf_is_auto_enabled() { return inf_is_auto_enabled(); }

bool idalib_inf_use_allasm() { return inf_use_allasm(); }

bool idalib_inf_loading_idc() { return inf_loading_idc(); }

bool idalib_inf_no_store_user_info() { return inf_no_store_user_info(); }

bool idalib_inf_readonly_idb() { return inf_readonly_idb(); }

bool idalib_inf_check_manual_ops() { return inf_check_manual_ops(); }

bool idalib_inf_allow_non_matched_ops() { return inf_allow_non_matched_ops(); }

bool idalib_inf_is_graph_view() { return inf_is_graph_view(); }

std::uint32_t idalib_inf_get_lflags() { return inf_get_lflags(); }

bool idalib_inf_decode_fpp() { return inf_decode_fpp(); }

bool idalib_inf_is_32bit_or_higher() { return inf_is_32bit_or_higher(); }
bool idalib_inf_is_32bit_exactly()  { return inf_is_32bit_exactly(); }

bool idalib_inf_is_16bit() { return inf_is_16bit(); }
bool idalib_inf_is_64bit() { return inf_is_64bit(); }

bool idalib_inf_is_dll() { return inf_is_dll(); }

bool idalib_inf_is_flat_off32() { return inf_is_flat_off32(); }

bool idalib_inf_is_be() { return inf_is_be(); }

bool idalib_inf_is_wide_high_byte_first() { return inf_is_wide_high_byte_first(); }

bool idalib_inf_dbg_no_store_path() { return inf_dbg_no_store_path(); }

bool idalib_inf_is_snapshot() { return inf_is_snapshot(); }

bool idalib_inf_pack_idb() { return inf_pack_idb(); }

bool idalib_inf_compress_idb() { return inf_compress_idb(); }

bool idalib_inf_is_kernel_mode() { return inf_is_kernel_mode(); }

unsigned int idalib_inf_get_app_bitness() { return inf_get_app_bitness(); }

std::uint32_t idalib_inf_get_database_change_count() { return inf_get_database_change_count(); }

filetype_t idalib_inf_get_filetype() { return inf_get_filetype(); }

std::uint16_t idalib_inf_get_ostype()  { return inf_get_ostype(); }

std::uint16_t idalib_inf_get_apptype()  { return inf_get_apptype(); }

std::uint8_t idalib_inf_get_asmtype()  { return inf_get_asmtype(); }

std::uint8_t idalib_inf_get_specsegs()  { return inf_get_specsegs(); }

std::uint32_t idalib_inf_get_af()  { return inf_get_af(); }

bool idalib_inf_trace_flow()  { return inf_trace_flow(); }

bool idalib_inf_mark_code()  { return inf_mark_code(); }

bool idalib_inf_create_jump_tables()  { return inf_create_jump_tables(); }

bool idalib_inf_noflow_to_data()  { return inf_noflow_to_data(); }

bool idalib_inf_create_all_xrefs()  { return inf_create_all_xrefs(); }

bool idalib_inf_create_func_from_ptr()  { return inf_create_func_from_ptr(); }

bool idalib_inf_create_func_from_call() { return inf_create_func_from_call(); }

bool idalib_inf_create_func_tails() { return inf_create_func_tails(); }

bool idalib_inf_should_create_stkvars() { return inf_should_create_stkvars(); }

bool idalib_inf_propagate_stkargs() { return inf_propagate_stkargs(); }

bool idalib_inf_propagate_regargs() { return inf_propagate_regargs(); }

bool idalib_inf_should_trace_sp() { return inf_should_trace_sp(); }

bool idalib_inf_full_sp_ana() { return inf_full_sp_ana(); }

bool idalib_inf_noret_ana() { return inf_noret_ana(); }

bool idalib_inf_guess_func_type() { return inf_guess_func_type(); }

bool idalib_inf_truncate_on_del() { return inf_truncate_on_del(); }

bool idalib_inf_create_strlit_on_xref() { return inf_create_strlit_on_xref(); }

bool idalib_inf_check_unicode_strlits() { return inf_check_unicode_strlits(); }

bool idalib_inf_create_off_using_fixup() { return inf_create_off_using_fixup(); }

bool idalib_inf_create_off_on_dref() { return inf_create_off_on_dref(); }

bool idalib_inf_op_offset() { return inf_op_offset(); }

bool idalib_inf_data_offset() { return inf_data_offset(); }

bool idalib_inf_use_flirt() { return inf_use_flirt(); }

bool idalib_inf_append_sigcmt() { return inf_append_sigcmt(); }

bool idalib_inf_allow_sigmulti() { return inf_allow_sigmulti(); }

bool idalib_inf_hide_libfuncs() { return inf_hide_libfuncs(); }

bool idalib_inf_rename_jumpfunc() { return inf_rename_jumpfunc(); }

bool idalib_inf_rename_nullsub() { return inf_rename_nullsub(); }

bool idalib_inf_coagulate_data() { return inf_coagulate_data(); }

bool idalib_inf_coagulate_code() { return inf_coagulate_code(); }

bool idalib_inf_final_pass() { return inf_final_pass(); }

std::uint32_t idalib_inf_get_af2()  { return inf_get_af2(); }

bool idalib_inf_handle_eh() { return inf_handle_eh(); }

bool idalib_inf_handle_rtti() { return inf_handle_rtti(); }

bool idalib_inf_macros_enabled() { return inf_macros_enabled(); }

bool idalib_inf_merge_strlits() { return inf_merge_strlits(); }

uval_t idalib_inf_get_baseaddr()  { return inf_get_baseaddr(); }

sel_t idalib_inf_get_start_ss()  { return inf_get_start_ss(); }

sel_t idalib_inf_get_start_cs()  { return inf_get_start_cs(); }

ea_t idalib_inf_get_start_ip()  { return inf_get_start_ip(); }

ea_t idalib_inf_get_start_ea()  { return inf_get_start_ea(); }

ea_t idalib_inf_get_start_sp()  { return inf_get_start_sp(); }


ea_t idalib_inf_get_main()  { return inf_get_main(); }


ea_t idalib_inf_get_min_ea()  { return inf_get_min_ea(); }


ea_t idalib_inf_get_max_ea()  { return inf_get_max_ea(); }


ea_t idalib_inf_get_omin_ea()  { return inf_get_omin_ea(); }


ea_t idalib_inf_get_omax_ea()  { return inf_get_omax_ea(); }


ea_t idalib_inf_get_lowoff()  { return inf_get_lowoff(); }


ea_t idalib_inf_get_highoff()  { return inf_get_highoff(); }


uval_t idalib_inf_get_maxref()  { return inf_get_maxref(); }


sval_t idalib_inf_get_netdelta()  { return inf_get_netdelta(); }


std::uint8_t idalib_inf_get_xrefnum()  { return inf_get_xrefnum(); }


std::uint8_t idalib_inf_get_type_xrefnum()  { return inf_get_type_xrefnum(); }


std::uint8_t idalib_inf_get_refcmtnum()  { return inf_get_refcmtnum(); }


std::uint8_t idalib_inf_get_xrefflag()  { return inf_get_xrefflag(); }

bool idalib_inf_show_xref_seg() { return inf_show_xref_seg(); }

bool idalib_inf_show_xref_tmarks() { return inf_show_xref_tmarks(); }

bool idalib_inf_show_xref_fncoff() { return inf_show_xref_fncoff(); }

bool idalib_inf_show_xref_val() { return inf_show_xref_val(); }


std::uint16_t idalib_inf_get_max_autoname_len()  { return inf_get_max_autoname_len(); }


char idalib_inf_get_nametype()  { return inf_get_nametype(); }


std::uint32_t idalib_inf_get_short_demnames()  { return inf_get_short_demnames(); }


std::uint32_t idalib_inf_get_long_demnames()  { return inf_get_long_demnames(); }


std::uint8_t idalib_inf_get_demnames()  { return inf_get_demnames(); }


std::uint8_t idalib_inf_get_listnames()  { return inf_get_listnames(); }


std::uint8_t idalib_inf_get_indent()  { return inf_get_indent(); }


std::uint8_t idalib_inf_get_cmt_indent()  { return inf_get_cmt_indent(); }


std::uint16_t idalib_inf_get_margin()  { return inf_get_margin(); }


std::uint16_t idalib_inf_get_lenxref()  { return inf_get_lenxref(); }


std::uint32_t idalib_inf_get_outflags()  { return inf_get_outflags(); }

bool idalib_inf_show_void() { return inf_show_void(); }

bool idalib_inf_show_auto() { return inf_show_auto(); }

bool idalib_inf_gen_null() { return inf_gen_null(); }

bool idalib_inf_show_line_pref() { return inf_show_line_pref(); }

bool idalib_inf_line_pref_with_seg() { return inf_line_pref_with_seg(); }

bool idalib_inf_gen_lzero() { return inf_gen_lzero(); }

bool idalib_inf_gen_org() { return inf_gen_org(); }

bool idalib_inf_gen_assume() { return inf_gen_assume(); }

bool idalib_inf_gen_tryblks() { return inf_gen_tryblks(); }


std::uint8_t idalib_inf_get_cmtflg()  { return inf_get_cmtflg(); }

bool idalib_inf_show_repeatables() { return inf_show_repeatables(); }

bool idalib_inf_show_all_comments() { return inf_show_all_comments(); }
bool idalib_inf_set_show_all_comments() { return inf_set_show_all_comments(); }

bool idalib_inf_hide_comments() { return inf_hide_comments(); }

bool idalib_inf_show_src_linnum() { return inf_show_src_linnum(); }

bool idalib_inf_test_mode() { return inf_test_mode(); }
bool idalib_inf_show_hidden_insns() { return inf_show_hidden_insns(); }
bool idalib_inf_set_show_hidden_insns() { return inf_set_show_hidden_insns(); }

bool idalib_inf_show_hidden_funcs() { return inf_show_hidden_funcs(); }
bool idalib_inf_set_show_hidden_funcs() { return inf_set_show_hidden_funcs(); }

bool idalib_inf_show_hidden_segms() { return inf_show_hidden_segms(); }
bool idalib_inf_set_show_hidden_segms() { return inf_set_show_hidden_segms(); }


std::uint8_t idalib_inf_get_limiter()  { return inf_get_limiter(); }

bool idalib_inf_is_limiter_thin() { return inf_is_limiter_thin(); }

bool idalib_inf_is_limiter_thick() { return inf_is_limiter_thick(); }

bool idalib_inf_is_limiter_empty() { return inf_is_limiter_empty(); }


short idalib_inf_get_bin_prefix_size()  { return inf_get_bin_prefix_size(); }


std::uint8_t idalib_inf_get_prefflag()  { return inf_get_prefflag(); }

bool idalib_inf_prefix_show_segaddr() { return inf_prefix_show_segaddr(); }

bool idalib_inf_prefix_show_funcoff() { return inf_prefix_show_funcoff(); }

bool idalib_inf_prefix_show_stack() { return inf_prefix_show_stack(); }

bool idalib_inf_prefix_truncate_opcode_bytes() { return inf_prefix_truncate_opcode_bytes(); }


std::uint8_t idalib_inf_get_strlit_flags()  { return inf_get_strlit_flags(); }

bool idalib_inf_strlit_names() { return inf_strlit_names(); }

bool idalib_inf_strlit_name_bit() { return inf_strlit_name_bit(); }

bool idalib_inf_strlit_serial_names() { return inf_strlit_serial_names(); }

bool idalib_inf_unicode_strlits() { return inf_unicode_strlits(); }

bool idalib_inf_strlit_autocmt() { return inf_strlit_autocmt(); }

bool idalib_inf_strlit_savecase() { return inf_strlit_savecase(); }


std::uint8_t idalib_inf_get_strlit_break()  { return inf_get_strlit_break(); }


char idalib_inf_get_strlit_zeroes()  { return inf_get_strlit_zeroes(); }


int32 idalib_inf_get_strtype()  { return inf_get_strtype(); }

uval_t idalib_inf_get_strlit_sernum()  { return inf_get_strlit_sernum(); }

uval_t idalib_inf_get_datatypes()  { return inf_get_datatypes(); }

std::uint32_t idalib_inf_get_abibits()  { return inf_get_abibits(); }

bool idalib_inf_is_mem_aligned4() { return inf_is_mem_aligned4(); }

bool idalib_inf_pack_stkargs() { return inf_pack_stkargs(); }

bool idalib_inf_big_arg_align() { return inf_big_arg_align(); }

bool idalib_inf_stack_ldbl() { return inf_stack_ldbl(); }

bool idalib_inf_stack_varargs() { return inf_stack_varargs(); }

bool idalib_inf_is_hard_float() { return inf_is_hard_float(); }

bool idalib_inf_abi_set_by_user() { return inf_abi_set_by_user(); }

bool idalib_inf_use_gcc_layout() { return inf_use_gcc_layout(); }

bool idalib_inf_map_stkargs() { return inf_map_stkargs(); }

bool idalib_inf_huge_arg_align() { return inf_huge_arg_align(); }

std::uint32_t idalib_inf_get_appcall_options()  { return inf_get_appcall_options(); }

ea_t idalib_inf_get_privrange_start_ea()  { return inf_get_privrange_start_ea(); }

ea_t idalib_inf_get_privrange_end_ea()  { return inf_get_privrange_end_ea(); }

comp_t idalib_inf_get_cc_id()  { return inf_get_cc_id(); }

cm_t idalib_inf_get_cc_cm()  { return inf_get_cc_cm(); }

std::uint8_t idalib_inf_get_cc_size_i()  { return inf_get_cc_size_i(); }

std::uint8_t idalib_inf_get_cc_size_b()  { return inf_get_cc_size_b(); }

std::uint8_t idalib_inf_get_cc_size_e()  { return inf_get_cc_size_e(); }

std::uint8_t idalib_inf_get_cc_defalign()  { return inf_get_cc_defalign(); }

std::uint8_t idalib_inf_get_cc_size_s()  { return inf_get_cc_size_s(); }

std::uint8_t idalib_inf_get_cc_size_l()  { return inf_get_cc_size_l(); }

std::uint8_t idalib_inf_get_cc_size_ll()  { return inf_get_cc_size_ll(); }

std::uint8_t idalib_inf_get_cc_size_ldbl()  { return inf_get_cc_size_ldbl(); }

rust::String idalib_inf_get_procname() {
  char buf[IDAINFO_PROCNAME_SIZE];
  if (!getinf_buf(INF_PROCNAME, buf, sizeof(buf))) {
    return rust::String();
  }
  return rust::String(buf);
}

rust::String idalib_inf_get_strlit_pref() {
  char buf[IDAINFO_STRLIT_PREF_SIZE];
  if (!getinf_buf(INF_STRLIT_PREF, buf, sizeof(buf))) {
    return rust::String();
  }
  return rust::String(buf);
}

bool idalib_inf_get_cc(compiler_info_t *out)  { return inf_get_cc(out); }

bool idalib_inf_get_privrange(range_t *out)  { return inf_get_privrange(out); }

ea_t idalib_inf_get_imagebase()  { return get_imagebase(); }

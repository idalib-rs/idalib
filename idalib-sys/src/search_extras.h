#pragma once

#include "search.hpp"
#include "bytes.hpp"

#include "cxx.h"

ea_t idalib_find_text(ea_t start_ea, const char *text) {
  return find_text(start_ea, 0, 0, text, SEARCH_DOWN | SEARCH_NEXT);
}

ea_t idalib_find_imm(ea_t start_ea, uint32 imm) {
  return find_imm(start_ea, SEARCH_DOWN | SEARCH_NEXT, imm, nullptr);
}

ea_t idalib_find_defined(ea_t start_ea) {
  return find_defined(start_ea, SEARCH_DOWN | SEARCH_NEXT);
}

ea_t idalib_bin_search(ea_t start_ea, ea_t end_ea, const char *pattern, int flags) {
  compiled_binpat_vec_t bbv;
  if (!parse_binpat_str(&bbv, start_ea, pattern, 16, PBSENC_DEF1BPU, nullptr)) {
    return BADADDR;
  }
  return bin_search(start_ea, end_ea, bbv, flags, nullptr);
}

bool idalib_parse_binpat_str(const char *pattern, rust::Vec<rust::u8> &out_bytes, rust::Vec<rust::u8> &out_mask) {
  compiled_binpat_vec_t bbv;
  if (!parse_binpat_str(&bbv, 0, pattern, 16, PBSENC_DEF1BPU, nullptr)) {
    return false;
  }
  
  if (bbv.empty()) {
    return false;
  }
  
  const compiled_binpat_t &bp = bbv[0];
  
  out_bytes.clear();
  out_bytes.reserve(bp.bytes.size());
  for (size_t i = 0; i < bp.bytes.size(); ++i) {
    out_bytes.push_back(bp.bytes[i]);
  }
  
  out_mask.clear();
  if (!bp.mask.empty()) {
    out_mask.reserve(bp.mask.size());
    for (size_t i = 0; i < bp.mask.size(); ++i) {
      out_mask.push_back(bp.mask[i]);
    }
  } else {
    out_mask.reserve(bp.bytes.size());
    for (size_t i = 0; i < bp.bytes.size(); ++i) {
      out_mask.push_back(0xFF);
    }
  }
  
  return true;
}

ea_t idalib_find_binary(ea_t start_ea, ea_t end_ea, const uint8_t *bytes, const uint8_t *mask, size_t len) {
  return bin_search(start_ea, end_ea, (const uchar *)bytes, (const uchar *)mask, len, BIN_SEARCH_FORWARD);
}

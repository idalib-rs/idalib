#pragma once

#include "strlist.hpp"
#include "bytes.hpp"

#include "cxx.h"

ea_t idalib_get_strlist_item_addr(size_t n) {
  string_info_t si;
  get_strlist_item(&si, n);
  return si.ea;
}

size_t idalib_get_strlist_item_length(size_t n) {
  string_info_t si;
  get_strlist_item(&si, n);
  return (size_t)si.length;
}

rust::String idalib_get_strlit_contents(ea_t ea, size_t len, int32_t strtype) {
  qstring result;
  if (get_strlit_contents(&result, ea, len, strtype)) {
    return rust::String(result.c_str());
  } else {
    return rust::String();
  }
}

size_t idalib_get_max_strlit_length(ea_t ea, int32_t strtype) {
  return get_max_strlit_length(ea, strtype);
}

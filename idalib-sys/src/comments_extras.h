#pragma once

#include "bytes.hpp"
#include "lines.hpp"

#include "cxx.h"

rust::String idalib_get_cmt(ea_t ea, bool rptble) {
  auto cmt = qstring();

  if (get_cmt(&cmt, ea, rptble) != 0) {
    return rust::String(cmt.c_str());
  } else {
    return rust::String();
  }
}

bool idalib_extra_cmt_line(bool anterior, std::size_t idx, int &what) {
  if (idx >= E_NEXT - E_PREV) {
    return false;
  }

  what = (anterior ? E_PREV : E_NEXT) + static_cast<int>(idx);
  return true;
}

bool idalib_get_extra_cmt(ea_t ea, bool anterior, std::size_t idx, rust::String &out) {
  auto what = 0;
  auto cmt = qstring();

  if (!idalib_extra_cmt_line(anterior, idx, what) || get_extra_cmt(&cmt, ea, what) < 0) {
    return false;
  }

  out = rust::String(cmt.c_str());
  return true;
}

bool idalib_set_extra_cmt(ea_t ea, bool anterior, std::size_t idx, const char *cmt) {
  auto what = 0;
  return idalib_extra_cmt_line(anterior, idx, what) && update_extra_cmt(ea, what, cmt);
}

bool idalib_append_extra_cmt(ea_t ea, bool anterior, const char *cmt) {
  return add_extra_cmt(ea, anterior, "%s", cmt);
}

bool idalib_remove_extra_cmt(ea_t ea, bool anterior, std::size_t idx) {
  auto what = 0;
  return idalib_extra_cmt_line(anterior, idx, what) && del_extra_cmt(ea, what);
}

// Unlike delete_extra_cmts(), which stops at the first missing line, this also
// removes hidden lines after a gap, which later appends would otherwise reveal.
void idalib_remove_extra_cmts(ea_t ea, bool anterior) {
  const auto start = anterior ? E_PREV : E_NEXT;

  for (auto what = start; what < start + (E_NEXT - E_PREV); ++what) {
    del_extra_cmt(ea, what);
  }
}

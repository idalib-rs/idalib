#pragma once

#include "hexrays.hpp"
#include "typeinf.hpp"
#include "pro.h"
#include "cxx.h"

#include <set>
#include <sstream>

struct idalib_string_sink_t : text_sink_t {
  std::ostringstream buf;
  int idaapi print(const char *str) override {
    buf << str;
    return 0;
  }
};

// Recursively collect named-type ordinals reachable from `tif` into `seen`.
// Stops at typeref boundaries: print_decls(PDF_INCL_DEPS) handles the
// transitive closure from those seeds, so we only need the direct references.
static void collect_tinfo_ordinals(const tinfo_t &tif, std::set<uint32> &seen) {
  if (!tif.is_correct()) return;

  if (tif.is_typeref()) {
    uint32 ord = tif.get_ordinal();
    if (ord != 0) seen.insert(ord);
    return;
  }

  if (tif.is_ptr()) {
    ptr_type_data_t pi;
    if (tif.get_ptr_details(&pi))
      collect_tinfo_ordinals(pi.obj_type, seen);
    return;
  }

  if (tif.is_array()) {
    array_type_data_t ai;
    if (tif.get_array_details(&ai))
      collect_tinfo_ordinals(ai.elem_type, seen);
    return;
  }

  if (tif.is_func()) {
    func_type_data_t fi;
    if (tif.get_func_details(&fi)) {
      collect_tinfo_ordinals(fi.rettype, seen);
      for (const auto &arg : fi)
        collect_tinfo_ordinals(arg.type, seen);
    }
  }
}

// Calls `print_decls()` with the current IDB's type library (`get_idati()`).
// Returns the declarations as a string. Throws if `print_decls()` signals a
// hard failure (return value == 0).
rust::String idalib_format_decls(uint32 flags) {
  idalib_string_sink_t sink;
  int result = print_decls(sink, get_idati(), nullptr, flags);
  if (result == 0) {
    throw std::runtime_error("print_decls failed");
  }
  return rust::String(sink.buf.str());
}

// Collect named-type ordinals used by a decompiled function's local variables
// (arguments, return value, locals) and emit just those types plus their
// transitive dependencies (via PDF_INCL_DEPS).
rust::String idalib_format_func_type_info(cfunc_t *cfunc, uint32 flags) {
  std::set<uint32> seen;

  lvars_t *lvars = cfunc->get_lvars();
  if (lvars != nullptr) {
    for (const auto &lv : *lvars)
      collect_tinfo_ordinals(lv.tif, seen);
  }

  if (seen.empty())
    return rust::String();

  ordvec_t ordinals;
  for (uint32 ord : seen) ordinals.push_back(ord);

  idalib_string_sink_t sink;
  int result = print_decls(sink, get_idati(), &ordinals, flags);
  if (result == 0) {
    throw std::runtime_error("print_decls failed");
  }
  return rust::String(sink.buf.str());
}

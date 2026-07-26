#pragma once

#include "hexrays.hpp"
#include "typeinf.hpp"
#include "pro.h"
#include "cxx.h"

#include <set>
#include <sstream>
#include <vector>

struct idalib_string_sink_t : text_sink_t {
  std::ostringstream buf;

  int idaapi print(const char *str) override {
    buf << str;
    return 0;
  }
};

// Call `print_decls()` with the current IDB's type library (`get_idati()`).
// Return the declarations as a string.
//
// Throw if `print_decls()` signals a hard failure (return value == 0).
rust::String idalib_format_decls(uint32 flags) {
  idalib_string_sink_t sink;
  int result = print_decls(sink, get_idati(), nullptr, flags);
  if (result == 0) {
    throw std::runtime_error("print_decls failed");
  }
  return rust::String(sink.buf.str());
}

// Collect named-type ordinals reachable from `root` into `seen`.
// Stop at typeref boundaries: `print_decls(PDF_INCL_DEPS)` handles the
// transitive closure from those seeds, so only direct references are needed.
static void collect_tinfo_ordinals(
    const tinfo_t &root,
    std::set<uint32> &seen) {
  std::vector<tinfo_t> worklist = {root};

  while (!worklist.empty()) {
    tinfo_t tif = worklist.back();
    worklist.pop_back();

    if (!tif.is_correct()) {
      continue;
    }

    if (tif.is_typeref()) {
      uint32 ordinal = tif.get_ordinal();
      if (ordinal != 0) {
        seen.insert(ordinal);
      }
      continue;
    }

    if (tif.is_ptr()) {
      ptr_type_data_t pointer;
      if (tif.get_ptr_details(&pointer)) {
        worklist.push_back(pointer.obj_type);
      }
      continue;
    }

    if (tif.is_array()) {
      array_type_data_t array;
      if (tif.get_array_details(&array)) {
        worklist.push_back(array.elem_type);
      }
      continue;
    }

    if (!tif.is_func()) {
      continue;
    }

    func_type_data_t function;
    if (!tif.get_func_details(&function)) {
      continue;
    }

    worklist.push_back(function.rettype);
    for (const auto &argument : function) {
      worklist.push_back(argument.type);
    }
  }
}

// Collect named-type ordinals used by a decompiled function's local variables
// (arguments, return value, locals) and emit just those types plus their
// transitive dependencies (via `PDF_INCL_DEPS`).
//
// Throw if `print_decls()` signals a hard failure (return value == 0).
rust::String idalib_format_cfunc_decls(cfunc_t *cfunc, uint32 flags) {
  if (cfunc == nullptr) {
    return rust::String();
  }

  // `lvars_t` covers arguments (`CVAR_ARG`), the return value
  // (`CVAR_RESULT`), and all locals.
  lvars_t *lvars = cfunc->get_lvars();
  if (lvars == nullptr) {
    return rust::String();
  }

  std::set<uint32> seen;
  for (const auto &local : *lvars) {
    collect_tinfo_ordinals(local.tif, seen);
  }

  if (seen.empty()) {
    return rust::String();
  }

  ordvec_t ordinals;
  for (uint32 ordinal : seen) {
    ordinals.push_back(ordinal);
  }

  idalib_string_sink_t sink;
  int result = print_decls(sink, get_idati(), &ordinals, flags);
  if (result == 0) {
    throw std::runtime_error("print_decls failed");
  }
  return rust::String(sink.buf.str());
}

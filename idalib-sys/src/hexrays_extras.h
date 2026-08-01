#pragma once

#include "hexrays.hpp"
#include "lines.hpp"
#include "pro.h"

#include <cstdint>
#include <memory>
#include <sstream>

#include "cxx.h"

#ifndef CXXBRIDGE1_STRUCT_hexrays_error_t
#define CXXBRIDGE1_STRUCT_hexrays_error_t
struct hexrays_error_t final {
  ::std::int32_t code;
  ::std::uint64_t addr;
  ::rust::String desc;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_hexrays_error_t

struct cblock_iter {
  qlist<cinsn_t>::iterator start;
  qlist<cinsn_t>::iterator end;

  cblock_iter(cblock_t *b) : start(b->begin()), end(b->end()) {}
};

cfunc_t *idalib_hexrays_cfuncptr_inner(const cfuncptr_t *f) { return *f; }

std::unique_ptr<cfuncptr_t>
idalib_hexrays_decompile_function(ea_t func_ea, hexrays_error_t *err, int flags) {
  hexrays_failure_t failure;
  cfuncptr_t cf = decompile_function(func_ea, &failure, flags);

  if (failure.code >= 0 && cf != nullptr) {
    return std::unique_ptr<cfuncptr_t>(new cfuncptr_t(cf));
  }

  err->code = failure.code;
  err->desc = rust::String(failure.desc().c_str());
  err->addr = failure.errea;

  return nullptr;
}

rust::String idalib_hexrays_cfunc_pseudocode(cfunc_t *f) {
  auto sv = f->get_pseudocode();
  auto sb = std::stringstream();

  auto buf = qstring();

  for (int i = 0; i < sv.size(); i++) {
    tag_remove(&buf, sv[i].line);
    sb << buf.c_str() << '\n';
  }

  return rust::String(sb.str());
}

std::unique_ptr<cblock_iter> idalib_hexrays_cblock_iter(cblock_t *b) {
  return std::unique_ptr<cblock_iter>(new cblock_iter(b));
}

cinsn_t *idalib_hexrays_cblock_iter_next(cblock_iter &it) {
  if (it.start != it.end) {
    return &*(it.start++);
  }
  return nullptr;
}

std::size_t idalib_hexrays_cblock_len(cblock_t *b) { return b->size(); }

cblock_t *idalib_hexrays_cfunc_body(cfunc_t *f) { return f->body.cblock; }

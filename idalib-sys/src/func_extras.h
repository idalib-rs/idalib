#pragma once

#include "pro.h"
#include "funcs.hpp"
#include "gdl.hpp"

#include <cstdint>
#include <exception>
#include <memory>

#include "cxx.h"

#ifndef CXXBRIDGE1_STRUCT_func_tail_t
#define CXXBRIDGE1_STRUCT_func_tail_t
struct func_tail_t final {
  ::std::uint64_t start_ea;
  ::std::uint64_t end_ea;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_func_tail_t

void idalib_func_tails(const func_t *f, rust::Vec<func_tail_t> &out) {
  if (f == nullptr) {
    return;
  }

  auto ranges = rangevec_t();

  if (get_func_tails(&ranges, f->start_ea)) {
    for (const auto &r : ranges) {
      out.push_back(func_tail_t{r.start_ea, r.end_ea});
    }
  }
}

uint64_t idalib_func_flags(const func_t *f) {
  return f == nullptr ? 0 : f->flags;
}

rust::String idalib_func_name(const func_t *f) {
  auto name = qstring();

  if (get_func_name(&name, f->start_ea) != 0) {
    return rust::String(name.c_str());
  } else {
    return rust::String();
  }
}

rust::String idalib_get_func_cmt(const func_t *f, bool rptble) {
  auto cmt = qstring();

  if (get_func_cmt(&cmt, f, rptble) != 0) {
    return rust::String(cmt.c_str());
  } else {
    return rust::String();
  }
}

bool idalib_set_func_cmt(const func_t *f, const char *cmt, bool rptble) {
  return set_func_cmt(f, cmt, rptble);
}

std::unique_ptr<qflow_chart_t> idalib_func_flow_chart(func_t *f, int fc_options) {
  if (auto cfg = std::make_unique<qflow_chart_t>(nullptr, f, BADADDR, BADADDR, fc_options); cfg != nullptr) {
    return cfg;
  }
  throw std::runtime_error("cannot build function flow chart");
}

const qbasic_block_t *idalib_qflow_graph_getn_block(const qflow_chart_t *cfg, size_t n) {
  return n < std::size(cfg->blocks) ? &cfg->blocks[n] : nullptr;
}

rust::Slice<const int> idalib_qbasic_block_succs(qbasic_block_t const *blk) {
  return rust::Slice(std::begin(blk->succ), std::size(blk->succ));
}

rust::Slice<const int> idalib_qbasic_block_preds(qbasic_block_t const *blk) {
  return rust::Slice(std::begin(blk->pred), std::size(blk->pred));
}

#pragma once

#include "ua.hpp"

#include "cxx.h"

rust::String idalib_print_insn_mnem(ea_t ea) {
  auto out = qstring();

  if (print_insn_mnem(&out, ea)) {
    return rust::String(out.c_str());
  } else {
    return rust::String();
  }
}

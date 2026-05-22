#pragma once

#include "typeinf.hpp"
#include "pro.h"
#include "cxx.h"

#include <sstream>

struct idalib_string_sink_t : text_sink_t {
  std::ostringstream buf;
  int idaapi print(const char *str) override {
    buf << str;
    return 0;
  }
};

// Calls `print_decls()` with the current IDB's type library (`get_idati()`).
// Returns the declarations as a string. Throws if `print_decls()` signals a
// hard failure (return value == 0).
rust::String idalib_print_decls(uint32 flags) {
  idalib_string_sink_t sink;
  int result = print_decls(sink, get_idati(), nullptr, flags);
  if (result == 0) {
    throw std::runtime_error("print_decls failed");
  }
  return rust::String(sink.buf.str());
}

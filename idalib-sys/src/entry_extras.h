#pragma once

#include "pro.h"
#include "entry.hpp"

#include "cxx.h"

rust::String idalib_entry_name(uval_t ord) {
  auto name = qstring();

  if (get_entry_name(&name, ord) != 0) {
    return rust::String(name.c_str());
  } else {
    return rust::String();
  }
}

rust::String idalib_entry_forwarder(uval_t ord) {
  auto forwarder = qstring();

  ssize_t result = get_entry_forwarder(&forwarder, ord);
  if (result > 0 && !forwarder.empty()) {
    return rust::String(forwarder.c_str());
  } else {
    return rust::String();
  }
}

#pragma once

#include "name.hpp"

#include "cxx.h"

rust::String idalib_get_ea_name(ea_t ea) {
  qstring name;
  if (get_ea_name(&name, ea)) {
    return rust::String(name.c_str());
  } else {
    return rust::String("");
  }
}
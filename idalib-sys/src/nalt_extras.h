#pragma once

#include "nalt.hpp"
#include "pro.h"

#include "cxx.h"

rust::String idalib_get_input_file_path() {
  char path[QMAXPATH] = {0};
  auto size = get_input_file_path(path, sizeof(path));

  if (size > 0) {
    return rust::String(path, size);
  } else {
    return rust::String();
  }
}

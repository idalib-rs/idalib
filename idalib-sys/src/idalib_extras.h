#pragma once

#include "idalib.hpp"

bool idalib_get_library_version(int *major, int *minor, int *build) {
  return get_library_version(*major, *minor, *build);
}

#pragma once

#include "config.hpp"
#include "ida.hpp"
#include "idacfg.hpp"
#include "idalib.hpp"

bool idalib_get_library_version(int *major, int *minor, int *build) {
  return get_library_version(*major, *minor, *build);
}

void idalib_process_config_directive(const char *directive) {
  process_config_directive(directive, IDPOPT_PRI_HIGH);
}

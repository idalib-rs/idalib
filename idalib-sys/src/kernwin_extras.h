#pragma once

#include "auto.hpp"
#include "kernwin.hpp"
#include "license.hpp"
#include "pro.h"

#include <array>
#include <charconv>
#include <cstdint>

struct license_manager_t;

struct license_manager_t_vtbl {
#if defined(__NT__)
  void *_skip_a[3];
#else
  void *_skip_a[4];
#endif
  int (*get_or_borrow_license)(license_manager_t *, void *, void *, uint64_t,
                               qstring *);
};

struct license_manager_t {
  license_manager_t_vtbl *_vtbl;
};

struct config_t {
#if defined(__MACOS__)
  uint8_t _skip_a[0x270];
#elif defined(__LINUX__)
  uint8_t _skip_a[0x2b8];
#elif defined(__NT__)
  uint8_t _skip_a[0x258];
#endif
  void *license_location;
  void *license_info;
};

extern "C" license_manager_t *get_license_manager();
extern "C" config_t *get_current_config();

void idalib_force_batch_mode() { batch = true; }

bool idalib_check_license() {
  auto license = License();
  if (license.valid()) {
    return true;
  }

  // NOTE: this is still needed when calling the API before opening a database.
  auto manager = get_license_manager();
  auto config = get_current_config();
  if (!manager || !manager->_vtbl || !config) {
    return false;
  }

  uint64_t flags = 16;
  qstring error;
  auto result = manager->_vtbl->get_or_borrow_license(
      manager, config->license_location, config->license_info, flags, &error);

  return result == 0 && license.valid();
}

bool idalib_is_decompiler_available() {
  return License().decompiler_available();
}

bool idalib_get_license_id(std::array<uint8_t, 6> &id) {
  if (!idalib_check_license()) {
    return false;
  }

  const auto value = License().id();
  constexpr std::array<size_t, 6> offsets = {0, 3, 5, 8, 10, 13};
  if (value.length() != 15) {
    return false;
  }

  for (size_t i = 0; i < offsets.size(); ++i) {
    unsigned int byte;
    const auto *begin = value.c_str() + offsets[i];
    const auto *end = begin + 2;
    const auto result = std::from_chars(begin, end, byte, 16);
    if (result.ec != std::errc() || result.ptr != end) {
      return false;
    }
    id[i] = static_cast<uint8_t>(byte);
  }

  return true;
}

int idalib_open_database_quiet(int argc, const char *const *argv,
                               bool auto_analysis) {
  auto new_file = 0;
  auto result = init_database(argc, argv, &new_file);

  if (result != 0) {
    return result;
  }

  (*callui)(ui_notification_t::ui_ready_to_run);

  if (auto_analysis) {
    result = !auto_wait();
  }

  return result;
}

rust::String idalib_ea2str(ea_t ea) {
  auto out = qstring();

  if (ea2str(&out, ea)) {
    return rust::String(out.c_str());
  } else {
    return rust::String();
  }
}

void idalib_msg(const char *m) {
  if (m && *m) {
    msg("%s", m);
  }
}

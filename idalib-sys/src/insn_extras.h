#pragma once

#include "intel.hpp"
#include "ua.hpp"
#include "idp.hpp"

#include "cxx.h"

// SIB Decoding Functions (from intel.hpp)
// These extract individual fields from the SIB byte

int idalib_sib_base(const insn_t *insn, const op_t *op) {
  return sib_base(*insn, *op);
}

int idalib_sib_index(const insn_t *insn, const op_t *op) {
  return sib_index(*insn, *op);
}

int idalib_sib_scale(const op_t *op) {
  return sib_scale(*op);
}

// High-level Helper Functions (also from intel.hpp)
// These handle both SIB and non-SIB cases automatically

int idalib_x86_base_reg(const insn_t *insn, const op_t *op) {
  return x86_base_reg(*insn, *op);
}

int idalib_x86_index_reg(const insn_t *insn, const op_t *op) {
  return x86_index_reg(*insn, *op);
}

int idalib_x86_scale(const op_t *op) {
  return x86_scale(*op);
}

bool idalib_has_displ(const op_t *op) {
  return has_displ(*op);
}

// Check for SIB byte presence
bool idalib_has_sib(const op_t *op) {
  return op->hasSIB;
}

// Get the raw SIB byte value
uint8_t idalib_get_sib_byte(const op_t *op) {
  return op->sib;
}

// Get instruction features from processor using itype
uint32_t idalib_get_canon_feature(uint16_t itype) {
  processor_t *ph = (processor_t*)get_ph();
  return ph->get_canon_feature(itype);
}

// Check if instruction modifies operand (wrapper for has_cf_chg)
bool idalib_has_cf_chg(uint32_t feature, uint32_t opnum) {
  return has_cf_chg(feature, opnum);
}

// Check if instruction uses operand (wrapper for has_cf_use)
bool idalib_has_cf_use(uint32_t feature, uint32_t opnum) {
  return has_cf_use(feature, opnum);
}

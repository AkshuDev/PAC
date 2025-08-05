#pragma once

#ifndef INST_HPP
#define INST_HPP
#endif

#include "types.hpp"

#include <unordered_map>
#include <functional>

// Instruction mnemonics
enum class Opcode {
  NOP,
  LOAD,
  STORE,
  MOV,
  ADD,
  SUB,
  JMP,
  HALT,
  SPINST_REGDUMP,
  SPINST_MEMDUMP,
  INVAID
};

// struct
struct Instruction {
  Opcode op;
  byte rd; // dest. reg.
  byte rs1; // src. reg. 1
  byte rs2; // src. reg. 2
  uint32_t imm; // immediate or address (depends on opcode)
};

// Opcode mapping
static std::unordered_map<uint16_t, Instruction> opcode_map = {
  { 0x0021, Opcode::NOP },
  { 0x6021, Opcode::LOAD },
  { 0x6421, Opcode::STORE },
  { 0x3010, Opcode::MOV },
  { 0x0008, Opcode::ADD },
  { 0x0009, Opcode::SUB },
  { 0xB000, Opcode::JMP },
  { 0x6002, Opcode::HALT },
  { 0xFF, Opcode::SPINST_REGDUMP },
  { 0xAA, Opcode::SPINST_MEMDUMP },
};

// Helper func for debug
inline std::string opcode_to_string(Opcode op) {
  switch(op) {
  case Opcode::NOP: return "NOP";
  case Opcode::LOAD: return "LOAD";
  case Opcode::STORE: return "STORE";
  case Opcode::MOV: return "MOV";
  case Opcode::ADD: return "ADD";
  case Opcode::SUB: return "SUB";
  case Opcode::JMP: return "JMP";
  case Opcode::HALT: return "HALT";
  case Opcode::SPINST_MEMDUMP: return "Special [MEMDUMP]";
  case Opcode::SPINST_REGDUMP: return "Special [REGDUMP]";
  default: return "INVALID";
  }
}

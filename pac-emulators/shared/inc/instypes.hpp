#pragma once

#ifndef INSTYPES_HPP
#define INSTYPES_HPP
#endif

#define opcode uint16_t

// Instruction mnemonics
enum class Opcode {
  NOP,
  HALT,
  ADD,
  SUB,
  MUL,
  DIV,
  MOD,
  OR,
  XOR,
  NOR,
  XNOR,
  NOT,
  AND,
  NAND,
  SHL,
  SHR,
  ADDI,
  SUBI,
  MOV,
  MOVN,
  LDI,
  LOAD,
  STORE,
  JMP,
  JZ,
  JNZ,
  JEQ,
  JNE,
  CALL,
  RET,
  PUSH,
  POP,
  CMP,
  TEST,
  IN,
  OUT,
  L32R,
  S32I,
  INVALID,
  SPINST_MEMDUMP,
  SPINST_REGDUMP
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

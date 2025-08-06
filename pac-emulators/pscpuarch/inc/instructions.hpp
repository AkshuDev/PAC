#pragma once

#ifndef INST_HPP
#define INST_HPP
#endif

#include "types.hpp"
#include "instypes.hpp"

#include <unordered_map>
#include <functional>

// struct
#pragma pack(push, 1)
struct Instruction {
  opcode op;
  byte rd; // dest. reg.
  byte rs1; // src. reg. 1
  byte rs2; // src. reg. 2
  uint32_t imm; // immediate or address (depends on opcode)
};
#pragma pack(pop)

// Opcode mapping
static std::unordered_map<opcode, Opcode> opcode_map = {
  { 0x0000, Opcode::NOP },
  { 0x0001, Opcode::HALT },
  { 0x0002, Opcode::ADD },
  { 0x0003, Opcode::SUB },
  { 0x0004, Opcode::MUL },
  { 0x0005, Opcode::DIV },
  { 0x0006, Opcode::MOD },
  { 0x0007, Opcode::AND },
  { 0x0008, Opcode::NAND },
  { 0x0009, Opcode::OR },
  { 0x000A, Opcode::NOR },
  { 0x000B, Opcode::XOR },
  { 0x000C, Opcode::XNOR },
  { 0x000D, Opcode::AND },
  { 0x000E, Opcode::NAND },
  { 0x000F, Opcode::NOT },
  { 0x0010, Opcode::SHL },
  { 0x0011, Opcode::SHR },
  { 0x0012, Opcode::ADDI },
  { 0x0013, Opcode::SUBI },
  { 0x0014, Opcode::MOV },
  { 0x0015, Opcode::MOVN },
  { 0x0016, Opcode::LDI },
  { 0x0017, Opcode::LOAD },
  { 0x0018, Opcode::STORE },
  { 0x0019, Opcode::JMP },
  { 0x001A, Opcode::JZ },
  { 0x001B, Opcode::JNZ },
  { 0x001C, Opcode::JEQ },
  { 0x001D, Opcode::JNE },
  { 0x001E, Opcode::CALL },
  { 0x001F, Opcode::RET },
  { 0x0020, Opcode::PUSH },
  { 0x0021, Opcode::POP },
  { 0x0022, Opcode::CMP },
  { 0x0023, Opcode::TEST },
  { 0x0024, Opcode::IN },
  { 0x0025, Opcode::OUT },
  { 0xFFFF, Opcode::SPINST_MEMDUMP },
  { 0xFFFE, Opcode::SPINST_REGDUMP }
};

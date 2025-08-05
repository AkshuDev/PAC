#pragma once

#ifndef VM_HPP
#define VM_HPP
#endif

#include <types.hpp>
#include <instructions.hpp>
#include <memory.hpp>
#include <register.hpp>

#include <vector>

class XTENSA_VM {
public:
  XTENSA_VM(std::size_t MemorySize, std::size_t RegisterCount);

  void load_program(const std::vector<byte> &program);
  void run();

private:
  std::size_t MEM_SIZE = DEF_MEM_SIZE;
  std::size_t NUM_REGISTERS = DEF_NUM_REGISTERS;
  std::vector<word> registers;
  std::vector<byte> memory;
  word pc;

  void exec_inst(byte opcode);

  // Instruction handlers
  void nop();
  void add();
  void sub();
  void mov();
  void l32r();
  void s32i();
  void spinst_regdump();
  void spinst_memdump();
};

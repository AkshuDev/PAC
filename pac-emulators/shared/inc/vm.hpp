#pragma once

#ifndef VM_HPP
#define VM_HPP
#endif

#include <types.hpp>
#include <instructions.hpp>
#include <memory.hpp>
#include <register.hpp>

#include <vector>

#include <instypes.hpp>

class VM {
public:
  VM(std::size_t MemorySize, std::size_t RegisterCount);

  void load_program(const std::vector<byte> &program);
  void run();

private:
  std::size_t MEM_SIZE = DEF_MEM_SIZE;
  std::size_t NUM_REGISTERS = DEF_NUM_REGISTERS;
  std::vector<word> registers;
  std::vector<byte> memory;
  word pc;

  int exec_inst(Instruction inst);

  // Instruction handlers
  void nop();
  void add(Instruction inst);
  void sub(Instruction inst);
  void mov(Instruction inst);
  void l32r(Instruction inst);
  void s32i(Instruction inst);
  void spinst_regdump(Instruction inst);
  void spinst_memdump(Instruction inst);
};

#include <vm.hpp>
#include <iostream>

XTENSA_VM::XTENSA_VM(std::size_t MemorySize=DEF_MEM_SIZE, std::size_t RegisterCount=DEF_NUM_REGISTERS) : pc(0), MEM_SIZE(MemorySize), NUM_REGISTERS(RegisterCount)
{
  memory.resize(MEM_SIZE, 0); // resize and cleanup
  registers.resize(NUM_REGISTERS, 0);

  std::cout << "Memory Size initalized to: " << memory.size() << " bytes\n";
  std::cout << "Register Count initalized to: " << registers.size() << "\n";
}

// Memory management

void XTENSA_VM::load_program(const std::vector<byte> &program) {
  std::copy(program.begin(), program.end(), memory.begin()); // copy into ram
}

void XTENSA_VM::run() {
  while (pc < MEM_SIZE) {
    byte opcode = readMemory(memory, pc);
    if (opcode_map.find(opcode) == opcode_map.end()) {
      std::cerr << "Invalid Instruction found at memory location [" << std::hex << pc << "] : 0x" << (int)opcode << "\n";
      break;
    }
    exec_inst(opcode);
    pc++;
  }
}

void XTENSA_VM::exec_inst(byte opcode) {
  switch (opcode_map[opcode]) {
  case Instruction::NOP: nop(); break;
  case Instruction::ADD: add(); break;
  case Instruction::SUB: sub(); break;
  case Instruction::MOV: mov(); break;
  case Instruction::L32R: l32r(); break;
  case Instruction::S32I: s32i(); break;
  case Instruction::SPINST_REGDUMP: spinst_regdump(); break;
  case Instruction::SPINST_MEMDUMP: spinst_memdump(); break;
  default:
    std::cerr << "Unkown opcode execution! -> [" << (int)opcode << "\n";
    break;
  }
}

// instruction parsing
void XTENSA_VM::nop() {
  // Do nothing dude!
}

void XTENSA_VM::add() {
  int r1 = readRegister(registers, 1);
  int r2 = readRegister(registers, 2);
  writeRegister(registers, 1, r1 + r2);
}

void XTENSA_VM::sub() {
  int r1 = readRegister(registers, 1);
  int r2 = readRegister(registers, 2);
  writeRegister(registers, 1, r1 - r2);
}

void XTENSA_VM::mov() {
  int r2 = readRegister(registers, 2);
  writeRegister(registers, 1, r2);
}

void XTENSA_VM::l32r() {
  // TODO
}

void XTENSA_VM::s32i() {
  // TODO
}

void XTENSA_VM::spinst_regdump() {
  dumpStateRegisters(registers);
}

void XTENSA_VM::spinst_memdump() {
  dumpStateMemory(memory);
}

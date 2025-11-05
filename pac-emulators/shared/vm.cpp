#include <vm.hpp>
#include <iostream>
#include <cstring>

VM::VM(std::size_t MemorySize=DEF_MEM_SIZE, std::size_t RegisterCount=DEF_NUM_REGISTERS) : pc(0), MEM_SIZE(MemorySize), NUM_REGISTERS(RegisterCount)
{
  memory.resize(MEM_SIZE, 0); // resize and cleanup
  registers.resize(NUM_REGISTERS, 0);

  std::cout << "Memory Size initalized to: " << memory.size() << " bytes\n";
  std::cout << "Register Count initalized to: " << registers.size() << "\n";
}

// Memory management

void VM::load_program(const std::vector<byte> &program) {
  std::copy(program.begin(), program.end(), memory.begin()); // copy into ram
}

void VM::run() {
  while (pc < MEM_SIZE) {
    std::vector<byte> inst_bytes = readMemoryBytes(memory, pc, sizeof(Instruction));
    Instruction inst;
    if (inst_bytes.size() >= sizeof(Instruction)) {
      std::memcpy(&inst, inst_bytes.data(), sizeof(Instruction));
    }
    
    opcode _opcode = inst.op;
    if (opcode_map.find(_opcode) == opcode_map.end()) {
      std::cerr << "Invalid Instruction found at memory location [" << std::hex << pc << "] : 0x" << (int)_opcode << "\n";

      Instruction nb_inst;
      std::vector<byte> nb_mdata = readMemoryBytes(memory, pc - sizeof(Instruction), sizeof(Instruction));

      if (nb_mdata.size() >= sizeof(Instruction)) std::memcpy(&nb_inst, nb_mdata.data(), sizeof(Instruction));
      opcode nb_opcode = nb_inst.op;
      
      std::cerr << "\nNearby Data (2 bytes nearby)\nTop (2 byte):\n\t" << std::hex << "0x" << (int)nb_opcode << "\n";
      break;
    }
    int shutdown = exec_inst(inst);

    if (shutdown == 1) {
      pc += sizeof(Instruction);
      return;
    }
    
    pc += sizeof(Instruction);
  }
}

int VM::exec_inst(Instruction inst) {
  opcode _opcode = inst.op;
  
  switch (opcode_map[_opcode]) {
  case Opcode::NOP: nop(); break;
  case Opcode::ADD: add(inst); break;
  case Opcode::SUB: sub(inst); break;
  case Opcode::MOV: mov(inst); break;
  case Opcode::L32R: l32r(inst); break;
  case Opcode::S32I: s32i(inst); break;
  case Opcode::SPINST_REGDUMP: spinst_regdump(inst); break;
  case Opcode::SPINST_MEMDUMP: spinst_memdump(inst); break;
  case Opcode::HALT: std::cout << "Shutting off...\n"; return 1;
  default:
    std::cerr << "Unkown opcode execution! -> [" << (int)_opcode << "\n";
    break;
  }

  return 0;
}

// instruction parsing
void VM::nop() {
  // Do nothing dude!
}

void VM::add(Instruction inst) {
  int d1 = readRegister(registers, inst.rs1);
  int d2 = readRegister(registers, inst.rs2);
  writeRegister(registers, inst.rd, d1 + d2);
}

void VM::sub(Instruction inst) {
  int d1 = readRegister(registers, inst.rs1);
  int d2 = readRegister(registers, inst.rs2);
  writeRegister(registers, inst.rd, d1 - d2);
}

void VM::mov(Instruction inst) {
  int d1 = readRegister(registers, inst.rs1);
  writeRegister(registers, inst.rd, d1);
}
  
void VM::l32r(Instruction inst) {
  // TODO
}

void VM::s32i(Instruction inst) {
  // TODO
}

void VM::spinst_regdump(Instruction inst) {
  dumpStateRegisters(registers);
}

void VM::spinst_memdump(Instruction inst) {
  dumpStateMemory(memory);
}

#include <vm.hpp>
#include <vector>
#include <string.h>
#include <stdexcept>
#include <iostream>

int safe_strToInt(const std::string &str) {
  try {
    size_t idx;
    int value = std::stoi(str, &idx);

    // Check for non digits after the string
    if (idx != str.length()) {
      throw std::invalid_argument("Non-numeric characters found!");
    }

    return value;
  } catch (const std::invalid_argument &e) {
    std::cerr << "Invalid input: not a valid number -> " << e.what() << "\n";
  } catch (const std::out_of_range &e) {
    std::cerr << "Invalid input: number out of range -> " << e.what() << "\n";
  }

  return -1;
}

int main(int argc, char** argv) {
  std::size_t memsize = DEF_MEM_SIZE;
  std::size_t regcount = DEF_NUM_REGISTERS;

  if (argc > 1) {
    for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "-memory") == 0 && (i + 1) < argc) {
	memsize = safe_strToInt(argv[i + 1]);
	if (memsize == -1) {
	  memsize = DEF_MEM_SIZE;
	}
      }
      else if (strcmp(argv[i], "-registers") == 0 && (i + 1) < argc) {
	regcount = safe_strToInt(argv[i + 1]);
	if (regcount == -1) {
	  regcount = DEF_NUM_REGISTERS;
	}
      }
    }
  }
  
  XTENSA_VM vm(memsize, regcount);

  std::vector<byte> ex_program = {
    0x00,
    0x00, // NOP
    0x00, // rd = NULL
    0x00, // rs1 = NULL
    0x00, // rs2 = NULL
    0x00,
    0x00,
    0x00,
    0x00, // imm = NULL
    0x10,
    0x00, // MOV
    0x02, // rd = 2
    0x01, // rs1 = 1
    0x00, // rs2 = NULL
    0x00,
    0x00,
    0x00,
    0x00, // imm = NULL
    0xFF,
    0xFF, // SP_DUMPMEM
    0x00, // rd = NULL
    0x00, // rs1 = NULL
    0x00, // rs2 = NULL
    0x00,
    0x00,
    0x00,
    0x00, // imm = NULL
    0xFF,
    0xFE, // SP_DUMPREG
    0x00, // rd = NULL
    0x00, // rs1 = NULL
    0x00, // rs2 = NULL
    0x00,
    0x00,
    0x00,
    0x00, // imm = NULL
    //0x6002, // HALT
    //0x0, // rd = NULL
    //0x0, // rs1 = NULL
    //0x0, // rs2 = NULL
    //0x00000000, // imm = NULL
  };

  // print out program
  std::cout << "PROGRAM:\n\nnop\nmov 1, 2\nsp_memdump\nsp_regdump\nhlt ;Halts but acts as shutdown here\n";

  vm.load_program(ex_program);
  vm.run();

  return 0;
}

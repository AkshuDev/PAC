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

  std::vector<byte> program = {
    0x03,
    0x01,
    0x02,
    0x00,
    0xAA,
    0xFF,
  };

  vm.load_program(program);
  vm.run();

  return 0;
}

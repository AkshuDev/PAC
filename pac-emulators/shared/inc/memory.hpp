#pragma once

#ifndef MEMORY_HPP
#define MEMORY_HPP
#endif

#include <vector>
#include <iostream>
#include <stdexcept>

#include <types.hpp>

inline void writeMemory(std::vector<byte> mem, size_t address, byte value) {
  if (address >= mem.size()) {
    std::cerr << "Address for Write is out of bounds of memory - [" << address << "]\n";
    throw std::out_of_range("Attempt to write at address, which is outside the memory limits!");
  }
  mem[address] = value;
}

inline byte readMemory(std::vector<byte> mem, size_t address) {
  if (address >= mem.size()) {
    std::cerr << "Address for Read is out of bounds for memory - [" << address << "]\n";
    throw std::out_of_range("Attempt to read at address, which is outside the memory limits!");
  }
  return mem[address];
}

inline std::vector<byte> readMemoryBytes(std::vector<byte> mem, size_t address, int bytes) {
  if (address >= mem.size() || address + bytes >= mem.size()) {
    std::cerr << "Address for Read is out of bounds for memory - [" << address << "]\n";
    throw std::out_of_range("Attempt to read at address, which is outside the memory limits!");
  }

  std::vector<byte> res;

  for (int i = 0; i < bytes; i++) {
    res.push_back(readMemory(mem, address + i));
  }

  return res;
}

inline void dumpStateMemory(std::vector<byte> mem) {
  std::cout << "[Memory State Dump]\n";
  for (size_t i = 0; i < std::min((size_t)16, mem.size()); i++) {
    std::cout << "[" << i << "]: " << static_cast<int>(mem[i]) << "\n";
  }
}

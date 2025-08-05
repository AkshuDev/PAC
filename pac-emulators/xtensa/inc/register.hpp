#pragma once

#ifndef REGISTER_HPP
#define REGISTER_HPP
#endif

#include <iostream>
#include <vector>
#include <stdexcept>

#include <types.hpp>

inline void writeRegister(std::vector<word> regs, size_t index, word value) {
  if (index >= regs.size()) {
    std::cerr << "Cannot Write to an non existing register - [" << index << "]\n";
    throw std::out_of_range("Attempt to Write to a non existing register");
  }
  regs[index] = value;
}

inline word readRegister(std::vector<word> regs, size_t index) {
  if (index >= regs.size()) {
    std::cerr << "Cannot Read to an non existing register - [" << index << "]\n";
    throw std::out_of_range("Attempt to Read to a non existing register");
  }
  return regs[index];
}

inline void dumpStateRegisters(std::vector<word> regs) {
  std::cout << "[Register State Dump]\n";
  for (size_t i = 0; i < regs.size(); i++) {
    std::cout << "R" << i << ": " << regs[i] << "\n";
  }
}

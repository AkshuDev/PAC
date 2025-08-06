#pragma once

#ifndef TYPES_HPP
#define TYPES_HPP
#endif

#include <cstdint>
#include <string>
#include <array>

constexpr std::size_t DEF_MEM_SIZE = 1024 * 1024; // 1MB
constexpr std::size_t DEF_NUM_REGISTERS = 16;

using byte = uint8_t;
using word = uint32_t;

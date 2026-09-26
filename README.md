# PAC
![Version](https://img.shields.io/badge/Version-v1.0.0-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)
![Build](https://img.shields.io/badge/Build-Stable-red?style=for-the-badge)

Pheonix Assembler Collection - Many architectures, same syntax!

# About this Document
This document only provides brief information of PAC, alongside some tests.

# Features
1. Inbuilt-Linker
2. Multiple Architecture Support
3. Multiple Linking Format Support
4. Easy Debugging errors
5. Full view to generated IR-Nodes, Tokens, and AST Nodes
6. High-Level Assembly
7. Works with Standard Assembling/Linking tools as well such as ***ld***, ***objdump***, etc

# Supported Architectures
PAC Currently supports -
1. x86
2. x86_64
3. x86 native 16-bit
4. PVCpu

# Supported Formats
PAC has an entire pipeline for both encoding and linking, and so to increase performance and reduce file size, PAC supports only ***ELF64*** as output after encoding and input to linker.

The PAC Linker in-fact supports multiple formats, but only takes ***ELF64 Object files*** as an input. Supported formats include -
1. Elf64
2. Elf32
3. PE 32 (Under implementation)
4. PE 32+ (Under implementation)

# Comparison between PAC and Traditional Assemblers

| Feature                                                | NASM    | GAS     | FASM    | PAC |
| ------------------------------------------------------ | ------- | ------- | ------- | --- |
| Structures                                             | Limited | Limited | Yes     | Yes |
| User Types                                             | No      | No      | Yes     | Yes |
| Functions                                              | No      | No      | Yes     | Yes |
| Built-in Linker                                        | No      | No      | No      | Yes |
| IR Dumping                                             | No      | No      | No      | Yes |
| AST Dumping                                            | No      | No      | No      | Yes |
| Token Dumping                                          | No      | No      | No      | Yes |
| Multiple Architectures using same assembler executable | No      | No      | Limited | Yes |
| Open Source                                            | Yes     | Yes     | Yes     | Yes |
| Custom Executable Linking                              | No      | No      | No      | Yes |

# Syntax
See the [Syntax Guide](docs/Syntax.md) for the complete language reference.

# Optimizations and Speed
**NOTE: Tests done on a ~300 line snake game.**

## Speed
After timing the Assembling and Linking on a Release Build of PAC, the results are as follows :-

1. Total Time taken to Assemble and Link the game -> ~0.005 seconds or ~5 milliseconds
2. Total Time taken to only Assemble the game -> ~0.003 seconds or ~3 millisecond
3. Total Time taken to generate IR Nodes for the game -> ~0.003 seconds or ~3 milliseconds
4. Total Time taken to generate AST Nodes for the game -> ~0.003 seconds or ~3 milliseconds
5. Total Time taken to generate tokens for the game -> ~0.002 second or ~2 millisecond

Hardware Used (Basic Information that correlates to speed):
1. CPU - Intel i3
2. Ram - 16GB
3. Drive - SATA 100GB

## Memory Usage
After analyzing the memory usage (***heaptrack***) by Assembling and Linking on a Tuned + Optimized Release Build of PAC, the results are as follows :-

1. Peak Memory Usage: ~144KB (Kilobytes)
2. Total allocations: ~4000
3. Memory leaked by PAC: 0KB (Kilobytes)
4. Memory leaked by ***libc***: 1KB (Kilobyte)
5. Total Memory leaked: 1KB (Kilobyte)

# Working examples
See the [Examples Showcase](docs/Examples.md) to see working examples.

# Thank you for reading this

#pragma once

// This file has all info about PAC
#define __PAC_VERSION__ "0.1.0"
#define __PAC_LEXER_VERSION__ "0.1.0lex"
#define __PAC_PARSER_VERSION__ "0.1.0par"
#define __PAC_ASSEMBLER_VERSION__ "0.1.0asm"
#define __PAC_LINKER_VERSION__ "0.0.1lnk"
#define __PAC_ENCODER_x86_64_VERSION__ "0.1.0enc-x86_64"
#define __PAC_ENCODER_x86_VERSION__ "0.0.1enc-x86"

#define __PAC_INFO__ "PAC-" __PAC_VERSION__ " (Pheonix Assembler Collection - Version " __PAC_VERSION__ ")\n"
#define __PAC_LEXER_INFO__ "PAC-" __PAC_LEXER_VERSION__ " (Pheonix Assembler Collection - Lexer - Version " __PAC_LEXER_VERSION__ ")\n"
#define __PAC_PARSER_INFO__ "PAC-" __PAC_PARSER_VERSION__ " (Pheonix Assembler Collection - Parser - Version " __PAC_PARSER_VERSION__ ")\n"
#define __PAC_ASSEMBLER_INFO__ "PAC-" __PAC_ASSEMBLER_VERSION__ " (Pheonix Assembler Collection - Assembler - Version " __PAC_ASSEMBLER_VERSION__ ")\n"
#define __PAC_LINKER_INFO "PAC-" __PAC_LINKER_VERSION__ " (Pheonix Assembler Collection - Linker - Version " __PAC_LINKER_VERSION__ ")\n"
#define __PAC_ENC_x86_64_INFO__ "PAC-" __PAC_ENCODER_x86_64_VERSION__ " (Pheonix Assembler Collection - Encoder - x86_64 - Version " __PAC_ENCODER_x86_64_VERSION__ ")\n"
#define __PAC_ENC_x86_INFO__ "PAC-" __PAC_ENCODER_x86_VERSION__ " (Pheonix Assembler Collection - Encoder - x86 - Version " __PAC_ENCODER_x86_VERSION__ ")\n"

#define __PAC_FULL_INFO__ __PAC_INFO__ __PAC_LEXER_INFO__ __PAC_PARSER_INFO__ __PAC_ASSEMBLER_INFO__ __PAC_LINKER_VERSION__ __PAC_ENC_x86_64_INFO__ __PAC_ENC_x86_INFO__

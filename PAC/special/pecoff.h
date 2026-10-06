// Author: Pheonix Studios/AkshuDev

#pragma once

#include <stdint.h>

#define PE_MAGIC "PE\0\0"
#define DOS_MAGIC "MZ"

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} DOS_Hdr;

typedef struct {
    uint16_t machine;
    uint16_t no_of_sections;
    uint32_t time_date_stamp;
    uint32_t ptr_to_symtab;
    uint32_t no_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} COFF_Hdr;

typedef struct {
    uint32_t magic;
    uint16_t machine;
    uint16_t no_of_sections;
    uint32_t time_date_stamp;
    uint32_t ptr_to_symtab;
    uint32_t no_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} PE_Hdr;

typedef enum {
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
    IMAGE_FILE_MACHINE_ALPHA = 0x184,
    IMAGE_FILE_MACHINE_ALPHA64 = 0x284,
    IMAGE_FILE_MACHINE_AM33 = 0x1d3,
    IMAGE_FILE_MACHINE_AMD64 = 0x8664,
    IMAGE_FILE_MACHINE_ARM = 0x1c0,
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
    IMAGE_FILE_MACHINE_ARM64EC = 0xA641,
    IMAGE_FILE_MACHINE_ARM64X = 0xA64E,
    IMAGE_FILE_MACHINE_ARMNT = 0x1c4,
    IMAGE_FILE_MACHINE_AXP64 = 0x284,
    IMAGE_FILE_MACHINE_EBC = 0xebc,
    IMAGE_FILE_MACHINE_I386 = 0x14c,
    IMAGE_FILE_MACHINE_IA64 = 0x200,
    IMAGE_FILE_MACHINE_LOONGARCH32 = 0x6232,
    IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264,
    IMAGE_FILE_MACHINE_M32R = 0x9041,
    IMAGE_FILE_MACHINE_MIPS16 = 0x266,
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366,
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,
    IMAGE_FILE_MACHINE_POWERPC = 0x1f0,
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,
    IMAGE_FILE_MACHINE_R3000BE = 0x160,
    IMAGE_FILE_MACHINE_R3000 = 0x162,
    IMAGE_FILE_MACHINE_R4000 = 0x166,
    IMAGE_FILE_MACHINE_R10000 = 0x168,
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032,
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064,
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128,
    IMAGE_FILE_MACHINE_SH3 = 0x1a2,
    IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
    IMAGE_FILE_MACHINE_SH4 = 0x1a6,
    IMAGE_FILE_MACHINE_SH5 = 0x1a8,
    IMAGE_FILE_MACHINE_THUMB = 0x1c2,
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169
} Machine_Types;

typedef enum {
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010,
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
    IMAGE_FILE_32BIT_MACHINE = 0x0100,
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,
    IMAGE_FILE_SYSTEM = 0x1000,
    IMAGE_FILE_DLL = 0x2000,
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000
} Characteristics;

typedef struct {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_init_data;
    uint32_t size_of_uninit_data;
    uint32_t addr_of_entry;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsys_version;
    uint16_t minor_subsys_version;
    uint32_t win32_version_val;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsys;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t no_of_rva_and_sizes;
    uint64_t export_table;
    uint64_t import_table;
    uint64_t resource_table;
    uint64_t exception_table;
    uint64_t certificate_table;
    uint64_t base_reloc_table;
    uint64_t debug;
    uint64_t arch;
    uint64_t global_ptr;
    uint64_t tls_table;
    uint64_t load_config_table;
    uint64_t bound_import;
    uint64_t iat;
    uint64_t delay_import_descriptor;
    uint64_t clr_runtime_header;
    uint64_t reserved;
} Optional_Hdr_32;

typedef struct {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_init_data;
    uint32_t size_of_uninit_data;
    uint32_t addr_of_entry;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsys_version;
    uint16_t minor_subsys_version;
    uint32_t win32_version_val;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsys;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t no_of_rva_and_sizes;
    uint64_t export_table;
    uint64_t import_table;
    uint64_t resource_table;
    uint64_t exception_table;
    uint64_t certificate_table;
    uint64_t base_reloc_table;
    uint64_t debug;
    uint64_t arch;
    uint64_t global_ptr;
    uint64_t tls_table;
    uint64_t load_config_table;
    uint64_t bound_import;
    uint64_t iat;
    uint64_t delay_import_descriptor;
    uint64_t clr_runtime_header;
    uint64_t reserved;
} Optional_Hdr_32p;
typedef Optional_Hdr_32p Optional_Hdr_64;

#define Optional_Hdr_32_Magic 0x10b
#define Optional_Hdr_32p_Magic 0x20b

typedef enum {
    IMAGE_SUBSYSTEM_UNKNOWN = 0,
    IMAGE_SUBSYSTEM_NATIVE = 1,
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
    IMAGE_SUBSYSTEM_OS2_CUI = 5,
    IMAGE_SUBSYSTEM_POSIX_CUI = 7,
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
    IMAGE_SUBSYSTEM_EFI_ROM = 13,
    IMAGE_SUBSYSTEM_XBOX = 14,
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
} Subsystems;

typedef enum {
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040,
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100,
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
} DLL_Characteristics;

typedef struct {
    uint32_t virtual_addr;
    uint32_t size;
} Image_Data_Directory;

typedef struct {
    uint64_t name;
    uint32_t virtual_size;
    uint32_t virtual_addr;
    uint32_t size_of_raw_data;
    uint32_t ptr_to_raw_data;
    uint32_t ptr_to_relocs;
    uint32_t ptr_to_line_no;
    uint16_t no_of_relocs;
    uint16_t no_of_line_no;
    uint32_t characteristics;
} Section_Hdr;

typedef enum {
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008,
    IMAGE_SCN_CNT_CODE = 0x00000020,
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
    IMAGE_SCN_LNK_OTHER = 0x00000100,
    IMAGE_SCN_LNK_INFO = 0x00000200,
    IMAGE_SCN_LNK_REMOVE = 0x00000800,
    IMAGE_SCN_LNK_COMDAT = 0x00001000,
    IMAGE_SCN_GPREL = 0x00008000,
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000,
    IMAGE_SCN_MEM_16BIT = 0x00020000,
    IMAGE_SCN_MEM_LOCKED = 0x00040000,
    IMAGE_SCN_MEM_PRELOAD = 0x00080000,
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000,
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000,
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000,
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000,
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000,
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000,
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000,
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000,
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000,
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000,
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000,
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000,
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000,
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000,
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
    IMAGE_SCN_MEM_SHARED = 0x10000000,
    IMAGE_SCN_MEM_EXECUTE = 0x20000000,
    IMAGE_SCN_MEM_READ = 0x40000000,
    IMAGE_SCN_MEM_WRITE = 0x80000000
} Section_Flags;

typedef struct {
    uint32_t virtual_addr;
    uint32_t symtab_idx;
    uint16_t type;
} COFF_Reloc;

// too many relocs so i used macros, i also used the same order as used in the winnt header file
#define IMAGE_REL_I386_ABSOLUTE 0x0000
#define IMAGE_REL_I386_DIR16 0x0001
#define IMAGE_REL_I386_REL16 0x0002
#define IMAGE_REL_I386_DIR32 0x0006
#define IMAGE_REL_I386_DIR32NB 0x0007
#define IMAGE_REL_I386_SEG12 0x0009
#define IMAGE_REL_I386_SECTION 0x000A
#define IMAGE_REL_I386_SECREL 0x000B
#define IMAGE_REL_I386_TOKEN 0x000C
#define IMAGE_REL_I386_SECREL7 0x000D
#define IMAGE_REL_I386_REL32 0x0014
#define IMAGE_REL_MIPS_ABSOLUTE 0x0000
#define IMAGE_REL_MIPS_REFHALF 0x0001
#define IMAGE_REL_MIPS_REFWORD 0x0002
#define IMAGE_REL_MIPS_JMPADDR 0x0003
#define IMAGE_REL_MIPS_REFHI 0x0004
#define IMAGE_REL_MIPS_REFLO 0x0005
#define IMAGE_REL_MIPS_GPREL 0x0006
#define IMAGE_REL_MIPS_LITERAL 0x0007
#define IMAGE_REL_MIPS_SECTION 0x000A
#define IMAGE_REL_MIPS_SECREL 0x000B
#define IMAGE_REL_MIPS_SECRELLO 0x000C
#define IMAGE_REL_MIPS_SECRELHI 0x000D
#define IMAGE_REL_MIPS_TOKEN 0x000E
#define IMAGE_REL_MIPS_JMPADDR16 0x0010
#define IMAGE_REL_MIPS_REFWORDNB 0x0022
#define IMAGE_REL_MIPS_PAIR 0x0025
#define IMAGE_REL_ALPHA_ABSOLUTE 0x0000
#define IMAGE_REL_ALPHA_REFLONG 0x0001
#define IMAGE_REL_ALPHA_REFQUAD 0x0002
#define IMAGE_REL_ALPHA_GPREL32 0x0003
#define IMAGE_REL_ALPHA_LITERAL 0x0004
#define IMAGE_REL_ALPHA_LITUSE 0x0005
#define IMAGE_REL_ALPHA_GPDISP 0x0006
#define IMAGE_REL_ALPHA_BRADDR 0x0007
#define IMAGE_REL_ALPHA_HINT 0x0008
#define IMAGE_REL_ALPHA_INLINE_REFLONG 0x0009
#define IMAGE_REL_ALPHA_REFHI 0x000A
#define IMAGE_REL_ALPHA_REFLO 0x000B
#define IMAGE_REL_ALPHA_PAIR 0x000C
#define IMAGE_REL_ALPHA_MATCH 0x000D
#define IMAGE_REL_ALPHA_SECTION 0x000E
#define IMAGE_REL_ALPHA_SECREL 0x000F
#define IMAGE_REL_ALPHA_REFLONGNB 0x0010
#define IMAGE_REL_ALPHA_SECRELLO 0x0011
#define IMAGE_REL_ALPHA_SECRELHI 0x0012
#define IMAGE_REL_ALPHA_REFQ3 0x0013
#define IMAGE_REL_ALPHA_REFQ2 0x0014
#define IMAGE_REL_ALPHA_REFQ1 0x0015
#define IMAGE_REL_ALPHA_GPRELLO 0x0016
#define IMAGE_REL_ALPHA_GPRELHI 0x0017
#define IMAGE_REL_PPC_ABSOLUTE 0x0000
#define IMAGE_REL_PPC_ADDR64 0x0001
#define IMAGE_REL_PPC_ADDR32 0x0002
#define IMAGE_REL_PPC_ADDR24 0x0003
#define IMAGE_REL_PPC_ADDR16 0x0004
#define IMAGE_REL_PPC_ADDR14 0x0005
#define IMAGE_REL_PPC_REL24 0x0006
#define IMAGE_REL_PPC_REL14 0x0007
#define IMAGE_REL_PPC_TOCREL16 0x0008
#define IMAGE_REL_PPC_TOCREL14 0x0009
#define IMAGE_REL_PPC_ADDR32NB 0x000A
#define IMAGE_REL_PPC_SECREL 0x000B
#define IMAGE_REL_PPC_SECTION 0x000C
#define IMAGE_REL_PPC_IFGLUE 0x000D
#define IMAGE_REL_PPC_IMGLUE 0x000E
#define IMAGE_REL_PPC_SECREL16 0x000F
#define IMAGE_REL_PPC_REFHI 0x0010
#define IMAGE_REL_PPC_REFLO 0x0011
#define IMAGE_REL_PPC_PAIR 0x0012
#define IMAGE_REL_PPC_SECRELLO 0x0013
#define IMAGE_REL_PPC_SECRELHI 0x0014
#define IMAGE_REL_PPC_GPREL 0x0015
#define IMAGE_REL_PPC_TOKEN 0x0016
#define IMAGE_REL_PPC_TYPEMASK 0x00FF
#define IMAGE_REL_PPC_NEG 0x0100
#define IMAGE_REL_PPC_BRTAKEN 0x0200
#define IMAGE_REL_PPC_BRNTAKEN 0x0400
#define IMAGE_REL_PPC_TOCDEFN 0x0800
#define IMAGE_REL_SH3_ABSOLUTE 0x0000
#define IMAGE_REL_SH3_DIRECT16 0x0001
#define IMAGE_REL_SH3_DIRECT32 0x0002
#define IMAGE_REL_SH3_DIRECT8 0x0003
#define IMAGE_REL_SH3_DIRECT8_WORD 0x0004
#define IMAGE_REL_SH3_DIRECT8_LONG 0x0005
#define IMAGE_REL_SH3_DIRECT4 0x0006
#define IMAGE_REL_SH3_DIRECT4_WORD 0x0007
#define IMAGE_REL_SH3_DIRECT4_LONG 0x0008
#define IMAGE_REL_SH3_PCREL8_WORD 0x0009
#define IMAGE_REL_SH3_PCREL8_LONG 0x000A
#define IMAGE_REL_SH3_PCREL12_WORD 0x000B
#define IMAGE_REL_SH3_STARTOF_SECTION 0x000C
#define IMAGE_REL_SH3_SIZEOF_SECTION 0x000D
#define IMAGE_REL_SH3_SECTION 0x000E
#define IMAGE_REL_SH3_SECREL 0x000F
#define IMAGE_REL_SH3_DIRECT32_NB 0x0010
#define IMAGE_REL_SH3_GPREL4_LONG 0x0011
#define IMAGE_REL_SH3_TOKEN 0x0012
#define IMAGE_REL_SHM_PCRELPT 0x0013
#define IMAGE_REL_SHM_REFLO 0x0014
#define IMAGE_REL_SHM_REFHALF 0x0015
#define IMAGE_REL_SHM_RELLO 0x0016
#define IMAGE_REL_SHM_RELHALF 0x0017
#define IMAGE_REL_SHM_PAIR 0x0018
#define IMAGE_REL_SH_NOMODE 0x8000
#define IMAGE_REL_ARM_ABSOLUTE 0x0000
#define IMAGE_REL_ARM_ADDR32 0x0001
#define IMAGE_REL_ARM_ADDR32NB 0x0002
#define IMAGE_REL_ARM_BRANCH24 0x0003
#define IMAGE_REL_ARM_BRANCH11 0x0004
#define IMAGE_REL_ARM_TOKEN 0x0005
#define IMAGE_REL_ARM_GPREL12 0x0006
#define IMAGE_REL_ARM_GPREL7 0x0007
#define IMAGE_REL_ARM_BLX24 0x0008
#define IMAGE_REL_ARM_BLX11 0x0009
#define IMAGE_REL_ARM_SECTION 0x000E
#define IMAGE_REL_ARM_SECREL 0x000F
#define IMAGE_REL_ARM_MOV32A 0x0010
#define IMAGE_REL_ARM_MOV32 0x0010
#define IMAGE_REL_ARM_MOV32T 0x0011
#define IMAGE_REL_THUMB_MOV32 0x0011
#define IMAGE_REL_ARM_BRANCH20T 0x0012
#define IMAGE_REL_THUMB_BRANCH20 0x0012
#define IMAGE_REL_ARM_BRANCH24T 0x0014
#define IMAGE_REL_THUMB_BRANCH24 0x0014
#define IMAGE_REL_ARM_BLX23T 0x0015
#define IMAGE_REL_THUMB_BLX23 0x0015
#define IMAGE_REL_AM_ABSOLUTE 0x0000
#define IMAGE_REL_AM_ADDR32 0x0001
#define IMAGE_REL_AM_ADDR32NB 0x0002
#define IMAGE_REL_AM_CALL32 0x0003
#define IMAGE_REL_AM_FUNCINFO 0x0004
#define IMAGE_REL_AM_REL32_1 0x0005
#define IMAGE_REL_AM_REL32_2 0x0006
#define IMAGE_REL_AM_SECREL 0x0007
#define IMAGE_REL_AM_SECTION 0x0008
#define IMAGE_REL_AM_TOKEN 0x0009
#define IMAGE_REL_AMD64_ABSOLUTE 0x0000
#define IMAGE_REL_AMD64_ADDR64 0x0001
#define IMAGE_REL_AMD64_ADDR32 0x0002
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32 0x0004
#define IMAGE_REL_AMD64_REL32_1 0x0005
#define IMAGE_REL_AMD64_REL32_2 0x0006
#define IMAGE_REL_AMD64_REL32_3 0x0007
#define IMAGE_REL_AMD64_REL32_4 0x0008
#define IMAGE_REL_AMD64_REL32_5 0x0009
#define IMAGE_REL_AMD64_SECTION 0x000A
#define IMAGE_REL_AMD64_SECREL 0x000B
#define IMAGE_REL_AMD64_SECREL7 0x000C
#define IMAGE_REL_AMD64_TOKEN 0x000D
#define IMAGE_REL_AMD64_SREL32 0x000E
#define IMAGE_REL_AMD64_PAIR 0x000F
#define IMAGE_REL_AMD64_SSPAN32 0x0010
#define IMAGE_REL_IA64_ABSOLUTE 0x0000
#define IMAGE_REL_IA64_IMM14 0x0001
#define IMAGE_REL_IA64_IMM22 0x0002
#define IMAGE_REL_IA64_IMM64 0x0003
#define IMAGE_REL_IA64_DIR32 0x0004
#define IMAGE_REL_IA64_DIR64 0x0005
#define IMAGE_REL_IA64_PCREL21B 0x0006
#define IMAGE_REL_IA64_PCREL21M 0x0007
#define IMAGE_REL_IA64_PCREL21F 0x0008
#define IMAGE_REL_IA64_GPREL22 0x0009
#define IMAGE_REL_IA64_LTOFF22 0x000A
#define IMAGE_REL_IA64_SECTION 0x000B
#define IMAGE_REL_IA64_SECREL22 0x000C
#define IMAGE_REL_IA64_SECREL64I 0x000D
#define IMAGE_REL_IA64_SECREL32 0x000E
#define IMAGE_REL_IA64_DIR32NB 0x0010
#define IMAGE_REL_IA64_SREL14 0x0011
#define IMAGE_REL_IA64_SREL22 0x0012
#define IMAGE_REL_IA64_SREL32 0x0013
#define IMAGE_REL_IA64_UREL32 0x0014
#define IMAGE_REL_IA64_PCREL60X 0x0015
#define IMAGE_REL_IA64_PCREL60B 0x0016
#define IMAGE_REL_IA64_PCREL60F 0x0017
#define IMAGE_REL_IA64_PCREL60I 0x0018
#define IMAGE_REL_IA64_PCREL60M 0x0019
#define IMAGE_REL_IA64_IMMGPREL64 0x001C
#define IMAGE_REL_IA64_ADDEND 0x001F
#define IMAGE_REL_CEF_ABSOLUTE 0x0000
#define IMAGE_REL_CEF_ADDR32 0x0001
#define IMAGE_REL_CEF_ADDR64 0x0002
#define IMAGE_REL_CEF_ADDR32NB 0x0003
#define IMAGE_REL_CEF_SECTION 0x0004
#define IMAGE_REL_CEF_SECREL 0x0005
#define IMAGE_REL_CEF_TOKEN 0x0006
#define IMAGE_REL_CEE_ABSOLUTE 0x0000
#define IMAGE_REL_CEE_ADDR32 0x0001
#define IMAGE_REL_CEE_ADDR64 0x0002
#define IMAGE_REL_CEE_ADDR32NB 0x0003
#define IMAGE_REL_CEE_SECTION 0x0004
#define IMAGE_REL_CEE_SECREL 0x0005
#define IMAGE_REL_CEE_TOKEN 0x0006
#define IMAGE_REL_M32R_ABSOLUTE 0x0000
#define IMAGE_REL_M32R_ADDR32 0x0001
#define IMAGE_REL_M32R_ADDR32NB 0x0002
#define IMAGE_REL_M32R_ADDR24 0x0003
#define IMAGE_REL_M32R_GPREL16 0x0004
#define IMAGE_REL_M32R_PCREL24 0x0005
#define IMAGE_REL_M32R_PCREL16 0x0006
#define IMAGE_REL_M32R_PCREL8 0x0007
#define IMAGE_REL_M32R_REFHALF 0x0008
#define IMAGE_REL_M32R_REFHI 0x0009
#define IMAGE_REL_M32R_REFLO 0x000A
#define IMAGE_REL_M32R_PAIR 0x000B
#define IMAGE_REL_M32R_SECTION 0x000C
#define IMAGE_REL_M32R_SECREL32 0x000D
#define IMAGE_REL_M32R_TOKEN 0x000E
#define IMAGE_REL_EBC_ABSOLUTE 0x0000
#define IMAGE_REL_EBC_ADDR32NB 0x0001
#define IMAGE_REL_EBC_REL32 0x0002
#define IMAGE_REL_EBC_SECTION 0x0003
#define IMAGE_REL_EBC_SECREL 0x0004

typedef struct {
    uint32_t type;
    uint16_t line_no;
} LineNo_Entry;

typedef struct {
    union {
        uint64_t short_name;
        struct {
            uint32_t zeros;
            uint32_t offset;
        };
    };
} ShortName;

typedef struct {
    ShortName name;
    uint32_t value;
    int16_t section_no;
    uint16_t type;
    uint8_t storage_class;
    uint8_t no_aux_symbols;
} Symbol_Entry;

typedef enum {
    IMAGE_SYM_UNDEFINED = 0x0,
    IMAGE_SYM_ABSOLUTE = -1,
    IMAGE_SYM_DEBUG = -2
} SymbolNoSpecialValues;

typedef enum {
    IMAGE_SYM_TYPE_NULL = 0,
    IMAGE_SYM_TYPE_VOID = 1,
    IMAGE_SYM_TYPE_CHAR = 2,
    IMAGE_SYM_TYPE_SHORT = 3,
    IMAGE_SYM_TYPE_INT = 4,
    IMAGE_SYM_TYPE_LONG = 5,
    IMAGE_SYM_TYPE_FLOAT = 6,
    IMAGE_SYM_TYPE_DOUBLE = 7,
    IMAGE_SYM_TYPE_STRUCT = 8,
    IMAGE_SYM_TYPE_UNION = 9,
    IMAGE_SYM_TYPE_ENUM = 10,
    IMAGE_SYM_TYPE_MOE = 11,
    IMAGE_SYM_TYPE_BYTE = 12,
    IMAGE_SYM_TYPE_WORD = 13,
    IMAGE_SYM_TYPE_UINT = 14,
    IMAGE_SYM_TYPE_DWORD = 15
} Symbol_Type;
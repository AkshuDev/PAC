# PAC
![Version](https://img.shields.io/badge/Version-v1.0.0-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)
![Build](https://img.shields.io/badge/Build-Stable-red?style=for-the-badge)

Pheonix Assembler Collection - Many architectures, same syntax!

## Features
1. Inbuilt-Linker
2. Multiple Architecture Support
3. Multiple Linking Format Support
4. Easy Debugging errors
5. Full view to generated IR-Nodes, Tokens, and AST Nodes
6. High-Level Assembly
7. Works with Standard Assembling/Linking tools as well such as ***ld***, ***objdump***, etc

## Supported Architectures
PAC Currently supports -
1. x86
2. x86_64
3. x86 native 16-bit
4. PVCpu

## Supported Formats
PAC has an entire pipeline for both encoding and linking, and so to increase performance and reduce file size, PAC supports only ***ELF64*** as output after encoding and input to linker.

The PAC Linker infact supports multiple formats, but only takes ***ELF64 Object files*** as an input. Supported formats include -
1. Elf64
2. Elf32
3. PE 32 (Under implementation)
4. PE 32+ (Under implementation)

## Comparison between PAC and Traditional Assemblers

| Feature | NASM | GAS | LLVM | PAC |
|----------|------|------|------| ------ |
| Structures | Limited | No | Yes | Yes |
| User Types | No | No | Yes | Yes |
| Functions | No | No | Yes | Yes |
| Built-in Linker | No | No | No | Yes |
| IR Dumping | No | No | Yes | Yes |
| AST Dumping | No | No | No | Yes |
| Token Dumping | No | No | No | Yes |
| Multiple Architectures using same assembler executable | No | No | Limited | Yes |

## Syntax
PAC Syntax isn't just some Assembly, it is high-level Assembly!

PAC Includes Structures/Preprocessing/Functions/Types and more!

### New Keywords
All new keywords begin with '.' example:
```pac-asm
    .struct MyStruct :res
        a!int
        b!int
    .endstruct
```

#### Types
PAC's default types include: **byte**, **short**, **int**, **long**, **ubyte**, **ushort**, **uint**, **ulong**, **ptr**, **float**, **double**

PAC also offers users a way to create their own types using '**.type**' keyword, example:
```pac-asm
    .type new_type = ubyte // .type <new type> = <type>
    .type another_type=new_type
    .struct MyStruct :res
        a!new_type // Same as ubyte
        b!another_type // Same as ubyte
    .endstruct
```

#### Structures
PAC offers structures, here is how to use them -

##### Making Structures

To Define Structures, you must use the '**.struct**' keyword to open a Structure Block, Then type the structure name, after this you can use '**:res**' keyword to define the Structure as '*Reserved*' or in simple terms, allocated in sections like '**.bss**'
Then you follow this format to define a new field: '**Name!Type**', for example

```pac-asm
    .struct MyStruct :res
        myField!ubyte
        anotherField!ushort
    .endstruct
```

Finally **DO NOT** Forget to close the structure block using the keyword '**.endstruct**'

For Structures with data in them, dont use '**:res**' keyword. For every field '=' is mandatory in data structures, but for whichever field you like, assign it a value after '='. All other fields are auto assigned to '0'.

Example -

```pac-asm
	.struct MyStruct
		myField!ubyte[] = "Some String", 0xA
		anotherField!ushort = // No Value = Auto Zeroed
		yetAnotherField!ulong = 0x123456789ABCDEF
	.endstruct
```

##### Accessing Structures
To Access your created Structures you need to use this format: '**Structure-Name.Field**', For example -
```pac-asm
    mov %qg0, MyStruct.myField
```

If the structure name is used, it symbolises the first field in the structure, example -
```pac-asm
    :section .bss
    .struct MyStruct :res
        myField!ubyte
        anotherField!ulong
    .endstruct

    :section .text
    lea %rax, [MyStruct] // This is same as MyStruct.myField
    lea %rbx, [MyStruct.anotherField] // Absolute field access
```

### Global/External
To Export/Import a function/label from another file, you must use the following methods -

#### To Import
To import a function/label from another file, you must use the '**:external**' keyword with the name of the function (**NOTE: Use '$' Prefix**) or label, **NOTE: Use this keyword only inside the .text section**.

Example -
```pac-asm
    :section .text
        :external $myfunc // Function
        :external mylabel // Label
```

#### To Export
To export a function/label to another file, you must use the '**:global**' keyword with the name of the label or function (**NOTE: Use the '$' Prefix**)

Example -
```pac-asm
    :section .text
        :global $myfunc // Function
        :global mylabel // Label
```

### Sections and their keywords
#### Defining a Section
To Define a section use the '**:section**' keyword followed by the section name

Example -
```pac-asm
    :section .text // Defining .text section
```

#### Align
You can change any section's alignment value via the '**:align**' keyword. Example -
```pac-asm
    :section .symbols // Symbol Section
        :align 8 // Align to 8-bytes
```

#### Start
You can also define any section's starting address using the '**:start**' keyword. Example -
```pac-asm
    :section .stack // Stack Section
        :start 0xFFFF // Start at 0xFFFF
```

#### Size
You can also define any section's **MAX** size, only for that specific file, using the '**:size**' keyword. Example -
```pac-asm
    :section .data // Data Section
        :size 0xFF // Size = 256/0xFF bytes
```

### Functions and Labels
#### Functions
Functions allow you to hide and prevent collisions for labels which are inside the function block

##### Defining Functions
To Define Functions, use the '**.func**' keyword followed by the name of the functions, This starts the function block, add as many labels as needed, but always close the block using the '**.endfunc**' keyword.

Example -
```pac-asm
    .func myfunc
        mov %qg0, 1 // Random Instruction
        call $myfunc.print
        print:
            ret // Placeholder
        ret
    .endfunc
```

##### Accessing Function
To Access a function, just add a '$' prefix to the function name. Example - 
```pac-asm
    call $myfunc
```

##### Accessing Labels inside Functions
To Access a label inside a function, you have to use this format '**$Function Name.Label Name**'. Example -
```pac-asm
    call $myfunc.print // Calls the print label inside the function 'myfunc'
```

**NOTE: Such an access only works within the parent function of that label**

#### Labels
Labels are an easy way to access memory locations, so instead of calculating memory offsets, using a label makes the process a lot easier. Or they can be called "Traditional Assembly Functions". 

Example -
```pac-asm
mylabel:
	// Assembly goes here
```

### Preprocessing
All preprocessor statements start with a '@'
#### Define
Defines a macro. Example -
```pac-asm
    @def myMacro
```

#### Undefine
Undefines a Defined macro. Example -
```pac-asm
    @undef myMacro
```

#### Include
Includes another file. Example -
```pac-asm
    @inc "myfile.pasm"
```

**NOTE: A String literal or macro is mandatory**

#### Important Notice
PAC has many reserved keywords which may be an exact match of the instruction your trying to run and so, in those cases prefixing 'inst.' before it, will fix the issue.

Examples (includes all instructions which need this prefix) -
```pac-asm
	// x86/x64
	inst.int 0x0
```

### Linking, information
When using PAC's inbuilt linker, unlike normal linkers, the format of sections defined by the user in their first passed file is followed!

# Optimisations and Speed
**NOTE: Tests done on a ~300 line snake game.**

## Speed
After timing the Assembling and Linking on a Tuned + Optimised Release Build of PAC, the results are as follows :-

1. Total Time taken to Assemble and Link the game -> ~0.005 seconds or ~5 milliseconds
2. Total Time taken to only Assemble the game -> ~0.003 seconds or ~3 millisecond
3. Total Time taken to generate IR Nodes for the game -> ~0.003 seconds or ~3 milliseconds
4. Total Time taken to generate AST Nodes for the game -> ~0.003 seconds or ~3 milliseconds
5. Total Time taken to generate tokens for the game -> ~0.002 second or ~2 millisecond

## Memory Usage
After analyzing the memory usage (***heaptrack***) by Assembling and Linking on a Tuned + Optimised Release Build of PAC, the results are as follows :-

1. Peak Memory Usage: ~144KB (Kilobytes)
2. Total allocations: ~4000
3. Memory leaked by PAC: 0KB (Kilobytes)
4. Memory leaked by ***libc***: 1KB (Kilobyte)
5. Total Memory leaked: 1KB (Kilobyte)

# Working examples

**NOTE: The shell preview might have incorrect carret, this is due to markdown preview, within a real terminal its always correct due to monospace font**

**NOTE: PAC auto defaults architecture and bits to HOST, and output format to ELF64, for the following tests, parameters were passed just to FORCE the parameter**

**NOTE: PAC outputs everything with color using ANSI Escape Codes, however this file might not have those colors**

For the following examples, these contents are used ->
**NOTE: PAC outputs everything with color using ANSI Escape Codes, however this file might not have those colors**

For the following examples, these contents are used ->
```pac-asm
	:section .rodata
		msg!ubyte[] = "Pretty Neat huh?", 0xa

	:section .text
		:global _start

	_start:
		mov %eax, 4
		mov %ebx, 1
		lea %ecx, [msg]
		mov %edx, 17
		inst.int 0x80

		mov %eax, 1
		mov %ebx, 0
		inst.int 0x80
```

## Example on x86 32-bit and x86_64 64-bit
## Example on x86 32-bit and x86_64 64-bit
Assembling + Linking with an Optimised Release Build of PAC

**This test used Elf64 Output with x86, and so OS will deny this executable, doesn't mean its wrong, just be aware as PAC doesn't enforce ABI, but OS does** ->
**This test used Elf64 Output with x86, and so OS will deny this executable, doesn't mean its wrong, just be aware as PAC doesn't enforce ABI, but OS does** ->
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/simpleTest_x86.pasm -o tests/bin/simpleTest -a x86 -b 32
	tests/simpleTest_x86.pasm: warning: No entry point specified, defaulting to the first label/func!
	Linker Warning: No Entry Label Specified, Defaulting to '_start'
	
	[user@host PAC]$ tests/bin/simpleTest
	bash: tests/bin/simpleTest: cannot execute binary file: Exec format error
```

**To prove this, if you rebuilt using x86_64 architecture instead, it will work**
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/simpleTest_x86.pasm -o tests/bin/simpleTest -a x86_64 -b 64
	tests/simpleTest_x86.pasm: warning: No entry point specified, defaulting to the first label/func!
	Linker Warning: No Entry Label Specified, Defaulting to '_start'
	
	[user@host PAC]$ tests/bin/simpleTest
	Pretty Neat huh?
```

---

---

**This test utilizes x86 and Elf32 output format**
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/simpleTest_x86.pasm -o tests/bin/simpleTest -a x86 -b 32 -f elf32
	tests/simpleTest_x86.pasm: warning: No entry point specified, defaulting to the first label/func!
	Linker Warning: No Entry Label Specified, Defaulting to '_start'
	
	[user@host PAC]$ tests/bin/simpleTest
	Pretty Neat huh?
```

**As you can see tools like PDASM and ***readelf*** also show the binary is correct**
```text
	[user@host PAC]$ pdasm info tests/bin/simpleTest --all
	===== ELF Header =====
	Class:            ELF32
	Endianness:       Little Endian
	Type:             0x2
	Machine:          Intel 80386 (32-Bit)
	Version:          0x1
	Entry Point:      0x402000
	Program Hdr Off:  0x34
	Section Hdr Off:  0x94
	PH Count:         3
	SH Count:         6
	SH String Index:  3

	===== Program Headers =====
	Idx   Type       Flags    Offset     VirtAddr   PhysAddr   FileSz     MemSz
	---------------------------------------------------------------------------------------------------------------------------
	0     LOAD       R--      0x00000000 0x00400000 0x00000000 0x00000094 0x000000a0
	1     LOAD       R--      0x00001000 0x00401000 0x00000000 0x00000018 0x00000018
	2     LOAD       R-X      0x00002000 0x00402000 0x00000000 0x00000030 0x00000030

	===== Section Headers =====
	Idx  Name                 Type         Addr     Offset   Size     ES     Flg    Lk     Inf
	--------------------------------------------------------------------------------------------------------------------------------
	0                         NULL         0x00000000 0x00000000 0x00000000 0      0      0      0
	1    .rodata              PROGBITS     0x00401000 0x00001000 0x00000018 0      2      0      0
	2    .text                PROGBITS     0x00402000 0x00002000 0x00000030 0      6      0      0
	3    .shstrtab            STRTAB       0x00000000 0x00002030 0x00000029 0      0      0      0
	4    .symtab              SYMTAB       0x00000000 0x00002060 0x00000040 16     0      5      4
	5    .strtab              STRTAB       0x00000000 0x000020a0 0x00000027 0      0      0      0

	===== Symbols =====
	Idx  Name                     Type     Bind     Value      Size   Section
	--------------------------------------------------------------------------------------------------
	0                             NOTYPE   LOCAL    0x00000000 0      UND
	1    tests/simpleTest_x86.pasm FILE     LOCAL    0x00000000 0      UND
	2    msg                      OBJECT   LOCAL    0x00401000 17     .rodata
	3    _start                   FUNC     GLOBAL   0x00402000 0      .text

	===== Relocations =====

	[user@host PAC]$ readelf -a tests/bin/simpleTest
	ELF Header:
	Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
	Class:                             ELF32
	Data:                              2's complement, little endian
	Version:                           1 (current)
	OS/ABI:                            UNIX - System V
	ABI Version:                       0
	Type:                              EXEC (Executable file)
	Machine:                           Intel 80386
	Version:                           0x1
	Entry point address:               0x402000
	Start of program headers:          52 (bytes into file)
	Start of section headers:          148 (bytes into file)
	Flags:                             0x0
	Size of this header:               52 (bytes)
	Size of program headers:           32 (bytes)
	Number of program headers:         3
	Size of section headers:           40 (bytes)
	Number of section headers:         6
	Section header string table index: 3

	Section Headers:
	[Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
	[ 0]                   NULL            00000000 000000 000000 00      0   0  0
	[ 1] .rodata           PROGBITS        00401000 001000 000018 00   A  0   0  8
	[ 2] .text             PROGBITS        00402000 002000 000030 00  AX  0   0 16
	[ 3] .shstrtab         STRTAB          00000000 002030 000029 00      0   0  1
	[ 4] .symtab           SYMTAB          00000000 002060 000040 10      5   4  8
	[ 5] .strtab           STRTAB          00000000 0020a0 000027 00      0   0  1
	Key to Flags:
	W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
	L (link order), O (extra OS processing required), G (group), T (TLS),
	C (compressed), x (unknown), o (OS specific), E (exclude),
	D (mbind), p (processor specific)

	There are no section groups in this file.

	Program Headers:
	Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
	LOAD           0x000000 0x00400000 0x00000000 0x00094 0x000a0 R   0x1000
	LOAD           0x001000 0x00401000 0x00000000 0x00018 0x00018 R   0x1000
	LOAD           0x002000 0x00402000 0x00000000 0x00030 0x00030 R E 0x1000

	Section to Segment mapping:
	Segment Sections...
	00
	01     .rodata
	02     .text

	There is no dynamic section in this file.

	There are no relocations in this file.
	No processor specific unwind information to decode

	Symbol table '.symtab' contains 4 entries:
	Num:    Value  Size Type    Bind   Vis      Ndx Name
		0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND
		1: 00000000     0 FILE    LOCAL  DEFAULT  UND tests/simpleTest[...]
		2: 00401000    17 OBJECT  LOCAL  DEFAULT    1 msg
		3: 00402000     0 FUNC    GLOBAL DEFAULT    2 _start

	No version information found in this file.

	There is no GOT section in this file.
```

**This test uses x86_64 and Elf64 Output format**
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/simpleTest_x86.pasm -o tests/bin/simpleTest -a x86_64 -f elf64
	tests/simpleTest_x86.pasm: warning: No entry point specified, defaulting to the first label/func!
	Linker Warning: No Entry Label Specified, Defaulting to '_start'

	[user@host PAC]$ tests/bin/simpleTest
	Pretty Neat huh?
```

## Examples of various flags
**This test utilizes the lexout flag**
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/simpleTest_x86.pasm -o tests/bin/simpleTest --lexout
	Lexing file: tests/simpleTest_x86.pasm
	[  1:1  ] SECTION              ':section'
	[  1:10 ] IDENTIFIER           '.rodata'
	[  2:1  ] SP_EOL               ''
	[  2:2  ] IDENTIFIER           'msg'
	[  2:5  ] OP_NOT               '!'
	[  2:6  ] T_UBYTE              'ubyte'
	[  2:11 ] LBRACKET             '['
	[  2:12 ] RBRACKET             ']'
	[  2:14 ] OP_ASSIGN            '='
	[  2:18 ] LIT_STRING           'Pretty Neat huh?'
	[  2:34 ] COMMA                ','
	[  2:36 ] LIT_HEX              '0xa'
	[  3:1  ] SP_EOL               ''
	[  4:1  ] SP_EOL               ''
	[  4:1  ] SECTION              ':section'
	[  4:10 ] IDENTIFIER           '.text'
	[  5:1  ] SP_EOL               ''
	[  5:2  ] GLOBAL               ':global'
	[  5:10 ] IDENTIFIER           '_start'
	[  6:1  ] SP_EOL               ''
	[  7:1  ] SP_EOL               ''
	[  7:1  ] LABEL_DEF            '_start'
	[  8:1  ] SP_EOL               ''
	[  8:2  ] ASM_MOV              'mov'
	[  8:7  ] REGISTER             'ax'
	[  8:9  ] COMMA                ','
	[  8:11 ] LIT_INT              '0'
	[  8:13 ] COMMENT_LINE         '// Uselss but fun'
	[  9:1  ] SP_EOL               ''
	[  9:2  ] ASM_MOV              'mov'
	[  9:7  ] REGISTER             'eax'
	[  9:10 ] COMMA                ','
	[  9:12 ] LIT_INT              '4'
	[ 10:1  ] SP_EOL               ''
	[ 10:2  ] ASM_MOV              'mov'
	[ 10:7  ] REGISTER             'ebx'
	[ 10:10 ] COMMA                ','
	[ 10:12 ] LIT_INT              '1'
	[ 11:1  ] SP_EOL               ''
	[ 11:2  ] ASM_LEA              'lea'
	[ 11:7  ] REGISTER             'ecx'
	[ 11:10 ] COMMA                ','
	[ 11:12 ] LBRACKET             '['
	[ 11:13 ] IDENTIFIER           'msg'
	[ 11:16 ] RBRACKET             ']'
	[ 12:1  ] SP_EOL               ''
	[ 12:2  ] ASM_MOV              'mov'
	[ 12:7  ] REGISTER             'edx'
	[ 12:10 ] COMMA                ','
	[ 12:12 ] LIT_INT              '17'
	[ 13:1  ] SP_EOL               ''
	[ 13:2  ] ASM_INT              'inst.int'
	[ 13:11 ] LIT_HEX              '0x80'
	[ 14:1  ] SP_EOL               ''
	[ 15:1  ] SP_EOL               ''
	[ 15:2  ] ASM_MOV              'mov'
	[ 15:7  ] REGISTER             'eax'
	[ 15:10 ] COMMA                ','
	[ 15:12 ] LIT_INT              '1'
	[ 16:1  ] SP_EOL               ''
	[ 16:2  ] ASM_MOV              'mov'
	[ 16:7  ] REGISTER             'ebx'
	[ 16:10 ] COMMA                ','
	[ 16:12 ] LIT_INT              '0'
	[ 17:1  ] SP_EOL               ''
	[ 17:2  ] ASM_INT              'inst.int'
	[ 17:11 ] LIT_HEX              '0x80'
```

---

**This test utilizes the --parseout flag**
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/simpleTest_x86.pasm -o tests/bin/simpleTest --parseout
	Parsing file: tests/simpleTest_x86.pasm
	[AST] [Directive] .rodata
	[AST] Sadly DeclIdentifier Array is not yet supported.
	[AST] [Directive] .text
	[AST] [Directive] _start
	[AST] [Label] _start
	[AST] [Instruction] mov ax, 0
	[AST] [Instruction] mov eax, 4
	[AST] [Instruction] mov ebx, 1
	[AST] [Instruction] lea ecx, [[Identifier] msg]
	[AST] [Instruction] mov edx, 17
	[AST] [Instruction] int 128
	[AST] [Instruction] mov eax, 1
	[AST] [Instruction] mov ebx, 0
	[AST] [Instruction] int 128
```

---

**This test utilizes the --asmout flag**
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/simpleTest_x86.pasm -o tests/bin/simpleTest --asmout
	Assembling file: tests/simpleTest_x86.pasm
	tests/simpleTest_x86.pasm: warning: No entry point specified, defaulting to the first label/func!
	NOTE: Addresses/Sizes provided in IR dump might not be correct as they are fixed in the 2-phase system during encoding
	=== IR Dump (9 instructions) ===
	[IR] [0x20] mov ax, 0
	[IR] [0x2F] mov eax, 4
	[IR] [0x3E] mov ebx, 1
	[IR] [0x4D] lea ecx, [0x0]
	[IR] [0x5C] mov edx, 17
	[IR] [0x6B] int 128
	[IR] [0x7A] mov eax, 1
	[IR] [0x89] mov ebx, 0
	[IR] [0x98] int 128
	=== End IR ===
	=== Symbol Dump (3 symbols) ===
	[FILE] tests/simpleTest_x86.pasm
	[IDENTIFIER] msg at 0x0 => Pretty Neat huh?\x0A in section: .rodata of size 0x11
	[LABEL] _start at 0x20 => \x00 in section: .text of size 0x0
	=== End Symbol ===
	=== Section Dump (2 sections) ===
	[0x0] .rodata => 24 bytes
	[0x20] .text => 279 bytes
	=== End Section ===
```

---


**This test utilizes the --only-asm flag**
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/simpleTest_x86.pasm -o tests/build/simpleTest.o --only-asm
	tests/simpleTest_x86.pasm: warning: No entry point specified, defaulting to the first label/func!
	[user@host PAC]$ objdump -d tests/build/simpleTest.o

	tests/build/simpleTest.o:     file format elf64-x86-64


	Disassembly of section .text:

	0000000000000000 <_start>:
	0:	66 b8 00 00          	mov    $0x0,%ax
	4:	b8 04 00 00 00       	mov    $0x4,%eax
	9:	bb 01 00 00 00       	mov    $0x1,%ebx
	e:	8d 0d 00 00 00 00    	lea    0x0(%rip),%ecx        # 14 <_start+0x14>
	14:	ba 11 00 00 00       	mov    $0x11,%edx
	19:	cd 80                	int    $0x80
	1b:	b8 01 00 00 00       	mov    $0x1,%eax
	20:	bb 00 00 00 00       	mov    $0x0,%ebx
	25:	cd 80                	int    $0x80
	27:	0f 1f 00             	nopl   (%rax)
	2a:	0f 1f 00             	nopl   (%rax)
	2d:	0f 1f 00             	nopl   (%rax)
	# NOTE: objdump uses AT&T Syntax (src, dst), while PAC has its own syntax (dst, src)
```

---

**This test utilizes the --only-link flag**
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/build/simpleTest.o -o tests/bin/simpleTest --only-link
	Linker Warning: No Entry Label Specified, Defaulting to '_start'
	[user@host PAC]$ tests/bin/simpleTest
	Pretty Neat huh?
```

## Example of diagnostics system
For this specific test, these contents are used ->
```pac-asm
	:section .rodata
		msg!ubyte[] = "Pretty Neat huh?", 0xa

	:section .text
		:global _start

	@def _start // Predefine macro with label name

	_start:
		mov %eax, 4
		mov %ebx, 1
		lea %ecx, [msg]
		mov %edx, 17
		inst.int 0x80

		mov %eax, 1
		mov %ebx, 0
		inst.int 0x80

	@def myFunc_0 // Predefine macro with auto-generated func name

	.func myFunc:
		// Also nothing
	mylabel: // $myFunc.mylabel
		// Nothing
	.endfunc
```

**Test utilizes manually added errors to present the diagnostics system of PAC**
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/simpleTest_x86.pasm -o tests/bin/simpleTest
	tests/simpleTest_x86.pasm:10:1: warning: Label/Function conflicts with previous definition
	- ("_start")
	8 | @def _start
	9 |
	> 10 | _start:
		   ^^^^^^
	11 | 	mov %eax, 4
	tests/simpleTest_x86.pasm:8:6: tip: Macro created here, try renaming your Macros? - ("_start")
	6 |
	7 | // Predefine macro with label name
	> 8 | @def _start
			   ^^^^^^
	9 |
	tests/simpleTest_x86.pasm:26:1: warning: Auto-Generated Label/Function conflicts with previous definition
	- ("myFunc_0")
	24 | .func myFunc:
	25 | 	// Also nothing
	> 26 | mylabel: // $myFunc.mylabel
		   ^^^^^^^
	27 | 	// Nothing
	tests/simpleTest_x86.pasm:22:6: tip: Macro created here, try renaming your Macros? - ("myFunc_0")
	20 |
	21 | // Predefine macro with auto-generated func name
	> 22 | @def myFunc_0
				^^^^^^^^
	23 |
	tests/simpleTest_x86.pasm: warning: No entry point specified, defaulting to the first label/func!
	Linker Warning: No Entry Label Specified, Defaulting to '_start'
```

---

For this specific test, these contents are used ->
```pac-asm
	:section .rodata
		msg!ubyte[] = "Pretty Neat huh?", 0xa
		_start!ulong = 10 // Predefine identifier with label name

	:section .text
		:global _start

	_start:
		mov %eax, 4
		mov %ebx, 1
		lea %ecx, [msg]
		mov %edx, 17
		inst.int 0x80

		mov %eax, 1
		mov %ebx, 0
		inst.int 0x80
```

**Test utilizes manually added errors to present the diagnostics system of PAC**
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/simpleTest_x86.pasm -o tests/bin/simpleTest
	tests/simpleTest_x86.pasm:8:1: warning: Label/Function conflicts with previous definition
	- ("_start")
	6 | 	:global _start
	7 |
	> 8 | _start:
		  ^^^^^^
	9 | 	mov %eax, 4
	tests/simpleTest_x86.pasm:3:2: tip: Identifier created here, try renaming your identifiers? - ("_start")
	1 | :section .rodata
	2 | 	msg!ubyte[] = "Pretty Neat huh?", 0xa
	> 3 | 	_start!ulong = 10 // Predefine identifier with label name
		    ^^^^^^
	4 |
	tests/simpleTest_x86.pasm: warning: No entry point specified, defaulting to the first label/func!
	Linker Warning: No Entry Label Specified, Defaulting to '_start'
```

---

For this specific test, these contents are used ->
```pac-asm
	:section .rodata
		msg!ubyte[] = "Pretty Neat huh?", 0xa

	:section .text
		:global _start

	_start:
		mov %eax, 4
		mov %ebx, 1
		lea %ecx, [msg]
		mov %edx, 17
		inst.int 0x80

		jmp 5

		mov %eax, 1
		mov %ebx, 0
		inst.int 0x80
```

**Test utilizes manually added errors to present the diagnostics system of PAC**
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/simpleTest_x86.pasm -o tests/bin/simpleTest
	tests/simpleTest_x86.pasm: warning: No entry point specified, defaulting to the first label/func!
	tests/simpleTest_x86.pasm:14:2: error: Invalid Instruction
	12 | 	inst.int 0x80
	13 |
	> 14 | 	jmp 5
			^
	15 |
	Generated IR of this Instruction:
		[IR] [0x6B] jmp 5
```

---

For this specific test, these contents are used ->
```pac-asm
	:section .rodata
		msg!ubyte[] = "Pretty Neat huh?", 0xa

	:section .text
		:global _start

	@def exit 0x99
	_start:
		mov %eax, 4
		mov %ebx, 1
		lea %ecx, [msg]
		mov %edx, 17
		inst.int 0x80

		jmp exit
	
	exit:
		mov %eax, 1
		mov %ebx, 0
		inst.int 0x80
```

**Test utilizes manually added errors to present the diagnostics system of PAC**
```shell
	[user@host PAC]$ bin/linux/x86_64/pac tests/simpleTest_x86.pasm -o tests/bin/simpleTest
		tests/simpleTest_x86.pasm:17:1: warning: Label/Function conflicts with previous definition
	- ("exit")
	15 | 	jmp exit
	16 |
	> 17 | exit:
		   ^^^^
	18 | 	mov %eax, 1
	tests/simpleTest_x86.pasm:7:6: tip: Macro created here, try renaming your Macros? - ("exit")
	5 | 	:global _start
	6 |
	> 7 | @def exit 0x99
			   ^^^^
	8 | _start:
	tests/simpleTest_x86.pasm: warning: No entry point specified, defaulting to the first label/func!
	tests/simpleTest_x86.pasm:15:2: error: Invalid Instruction
	13 | 	inst.int 0x80
	14 |
	> 15 | 	jmp exit
			^
	16 |
	Generated IR of this Instruction:
		[IR] [0x6B] jmp 153
```

# Thank you for reading this

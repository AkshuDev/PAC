# PAC
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

**NOTE: PAC auto defaults architecture and bits to HOST, and output format to ELF64, for the following tests, parameters were passed just to FORCE the parameter**

## Example on x86 32-bit and x86_64 64-bit
For this example, these contents are used ->
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

Assembling + Linking with an Optimised Release Build of PAC

**Test used ELF64 Output with x86, and so OS will deny this executable, doesn't mean its wrong, just be aware as PAC doesn't enforce ABI, but OS does** ->
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
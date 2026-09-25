# Syntax
PAC Syntax isn't just some Assembly, it is high-level Assembly!

PAC Includes Structures/Preprocessing/Functions/Types and more!

## New Keywords
All new keywords begin with '.' example:
```pac-asm
    .struct MyStruct :res
        a!int
        b!int
    .endstruct
```

### Types
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

### Defining Data
To define data you must use this format '**Name!Type = Value**', for example

```pac-asm
	mydata!ubyte = 0x75
```

For arrays, you can use '**\[Size\]**', however specifying size is completely optional since PAC can figure size out itself, for example

```pac-asm
	mystring!ubyte[6] = "Hello"
	mystring2!ubyte[] = "Hello World!"
```

### Reserving Data
To reserve data you must use this format '**:res Name!Type**', for example

```pac-asm
	:res mydata!ubyte
```

For arrays, you can use '**\[Size\]**', however in the case of reserving data, specifying size is mandatory since PAC can't figure reserve size itself, for example

```pac-asm
	:res myreserve!ubyte[6]
	:res myreserve2!ubyte[] // ERROR, size is required!
```

### Structures
PAC offers structures, here is how to use them -

#### Making Structures

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

#### Accessing Structures
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

## Global/External
To Export/Import a function/label from another file, you must use the following methods -

### To Import
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

## Sections and their keywords
### Defining a Section
To Define a section use the '**:section**' keyword followed by the section name

Example -
```pac-asm
    :section .text // Defining .text section
```

### Align
You can change any section's alignment value via the '**:align**' keyword (Comes before definition). Example -
```pac-asm
	:align 8 // Align to 8-bytes
    :section .symbols // Symbol Section
```

### Start
You can also define any section's starting address using the '**:start**' keyword (Comes before definition). Example -
```pac-asm
	:start 0xFFFF // Start at 0xFFFF
    :section .stack // Stack Section
```

### Size
You can also define any section's **MAX** size, only for that specific file, using the '**:size**' keyword (Comes before definition). Example -
```pac-asm
	:size 0xFF // Size = 256/0xFF bytes
    :section .data // Data Section
```

## Functions and Labels
### Functions
Functions allow you to hide and prevent collisions for labels which are inside the function block

#### Defining Functions
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

#### Accessing Function
To Access a function, just add a '$' prefix to the function name. Example - 
```pac-asm
    call $myfunc
```

### Labels
Labels are an easy way to access memory locations, so instead of calculating memory offsets, using a label makes the process a lot easier. Or they can be called "Traditional Assembly Functions". However PAC treats labels as "Traditional Assembly Functions".

Example -
```pac-asm
	mylabel:
		// Assembly goes here
```

### Labels in functions
Labels in functions are just well, normal labels.

Example -
```pac-asm
	.func myfunc:
		mylabel:
			// Assembly goes here
	.endfunc
```

#### Accessing Labels inside Functions
To Access a label inside a function, you have to use this format '**$Function Name.Label Name**'. Example -
```pac-asm
    call $myfunc.print // Calls the print label inside the function 'myfunc'
```

**NOTE: Such an access only works within the parent function of that label**

## Preprocessing
All preprocessor statements start with a '@'
### Define
Defines a macro. Example -
```pac-asm
    @def myMacro
```

### Undefine
Undefines a Defined macro. Example -
```pac-asm
    @undef myMacro
```

### Include
Includes another file. Example -
```pac-asm
    @inc "myfile.pasm"
```

**NOTE: A String literal or macro is mandatory**

## Important Notice
PAC has many reserved keywords which may be an exact match of the instruction your trying to run and so, in those cases prefixing 'inst.' before it, will fix the issue.

Examples (includes all instructions which need this prefix) -
```pac-asm
	// x86/x64
	inst.int 0x0
```

## Linking, information
When using PAC's inbuilt linker, unlike normal linkers, the format of sections defined by the user in their first passed file is followed!

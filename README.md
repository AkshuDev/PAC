# PAC
Pheonix Assembler Collection - Many architectures, same syntax!

## Syntax
PAC Syntax isn't just some Assembly, it is high-level Assembly!

PAC Includes Structures/Preprocessing/Functions/Types/more

### New Keywords
All new keywords begin with '.' example:
```pac-asm
    .struct
        a: int
        b: int
    .endstruct
```

#### Types
PAC's default types include: **byte**, **short**, **int**, **long**, **ubyte**, **ushort**, **uint**, **ulong**, **ptr**, **float**, **double**

PAC also offers users a way to create their own types using '**.type**' keyword, example:
```pac-asm
    .type new_type:ubyte // .type <new type>:<type>
    .type another_type:new_type
    .struct
        a: new_type // Same as ubyte
        b: another_type // Same as ubyte
    .endstruct
```

#### Structures
PAC offers structures, here is how to use them -

##### Making Structures

To Define Structures, you must use the '**.struct**' keyword to open a Structure Block, Then type the structure name.
Then you follow this format to define a new field: '**Name: Type**', for example

```pac-asm
    .struct MyStruct
        myField: ubyte
        anotherField: ushort
    .endstruct
```

Finally **DO NOT** Forget to close the structure block using the keyword '**.endstruct**'

##### Accessing Structures
To Access your created Structures you need to use this format: '**Structure Name.Field**', For example -
```pac-asm
    mov %qg0, MyStruct.myField
```


##### Change Structure's Field's Value
To change the value of a field inside a structure, you need to first access it then use the '=' sign to assign it a new value, either constant or variable. Example -

```pac-asm
    MyStruct.anotherField = 123 // Constant
    MyStruct.myField = %bg1 // Variable (Register)
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
To export a function/label to another file, you must use the '**:global**' keyword with the name of the label or function (**NOTE: Use the '$' Prefix**), **NOTE: Use this keyword only inside the .text section.**

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

#### Labels
Labels are your average Assembly functions, nothing special here!

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

### Linking, information
When using PAC's inbuilt linker, unlike normal linkers, the format of sections defined by the user in their first passed file is followed!
```
```
```
```
```
```
```
```
```
```
```
```

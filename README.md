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

PAC also offers users a way to create their own types using **.type** keyword, example:
```pac-asm
    .type new_type:ubyte // .type <new type>:<type>
    .type another_type:new_type
    .struct
        a: new_type
        b: another_type
    .endstruct
```


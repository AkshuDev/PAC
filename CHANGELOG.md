# PAC Changelog

## Version 1.0.3
### Upgrades
- Integer capacity increased from **0x7FFFFFFFFFFFFFFF** to **0xFFFFFFFFFFFFFFFF**
- Bug fixes
- Symbol resolution fixes

### Additions
- None

### Known Flaws
- Failed to change versioning data
- Bug which caused CLI to not support other number notations such as binary
- Extremely less security against malformed programs (Caused SEGFAULTS)
- Linker failure ignored in exit status

## Version 1.0.4
### Upgrades
- Fixed versioning data
- Fixed bug which caused CLI to not support other number notations such as binary
- Added higher security against malformed programs
- Added linker fail check in exit status
- Added better memory management
- Added better symbol resolution
- Fixed PVCpu IMM Bug

### Additions
- Added Changelog to package
- Added Octal Support
- Added Binary Linking
- Added 'external' Support
- Added 'sizeof' Support

### Known Flaws
- NOBITS Sections could be included in the file on disk via the linker
- One of the Linker Error paths did not quit
- Linker Bugs
- Extremely big linker bug which merged non-contiguous sections with bss on paermission match causing all kinds of issues

## Version 1.1.0
### Upgrades
- NOBITS Sections are no longer included in the file on disk via the linker
- All Linker Error paths now quit
- Fixed Linker Bugs
- Removed the support for creating PACI (PAC IR) files which were broken in many cases
- Fixed the `--savetemp` command
- Better parsing, higher enforcing
- Better linker enforcement
- Fixed parser bugs
- Fixed the extremely big linker bug which merged non-contiguous sections with bss on permission match, which was also causing all kinds of issues

### Additions
- Added PE Linking output support
- Added Assemble-Time Expression Evaluation

### Known Flaws
- Potential double free incase of reallocation fail, at symbol list sorting block in encoder

## Version 1.1.1
### Upgrades
- Fixed typos in documents
- Fixed potential double free, at symbol list sorting block in encoder

### Additions
- None

### Known Flaws
- None

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

## Version 1.1.0
### Upgrades
- NOBITS Sections are no longer included in the file on disk via the linker
- All Linker Error paths now quit
- Fixed Linker Bugs

### Additions
- Added PE Linking output support
- Added Assemble-Time Expression Evaluation

### Known Flaws
- None
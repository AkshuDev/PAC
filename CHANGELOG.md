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

### Additions
- Added Changelog to package
- Added Octal Support

### Known Flaws
- None


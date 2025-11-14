# Pheonix Assembler Collection, Makefile

# Compiler
CC = gcc

# Directories
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
INC_DIR := inc

# Colors
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
CYAN := \033[0;36m
RESET := \033[0m

# Default target OS/ARCH detection
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m | tr '[:upper:]' '[:lower:]')

# Flags
COBITS := 
CFLAGS_RELEASE := -O3 -march=native -flto -Wall -Wextra -fstack-protector-strong -std=c2x -I $(INC_DIR) $(COBITS)
CFLAGS_DEBUG := -O0 -g3 -Wall -Wextra -fsanitize=address,undefined -fstack-protector-strong -std=c2x -I $(INC_DIR) $(COBITS)

# Build type
BUILD ?= debug
ifeq ($(BUILD),debug)
    CFLAGS := $(CFLAGS_DEBUG)
else
    CFLAGS := $(CFLAGS_RELEASE)
endif

# Find all C source files recursively
SRC_FILES := $(shell find $(SRC_DIR) -type f -name '*.c')
HEADER_FILES := $(shell find $(SRC_DIR) -type f -name '*.h')

# Map source files to object files in BUILD_DIR
OBJ_FILES := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC_FILES))

# Output executable
OUTPUT := $(BIN_DIR)/$(OS)/$(ARCH)/pac

# === Rules ===

.PHONY: all clean dirs

all: dirs
	@echo "$(CYAN)==> Starting $(BUILD_NAME) build for PAC ($(OS)/$(ARCH))$(RESET)"
	@$(MAKE) $(OUTPUT)
	@echo "$(GREEN)==> Build completed: $(OUTPUT)$(RESET)"

# Create necessary directories
dirs:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BIN_DIR)/$(OS)/$(ARCH)

# Link final executable
$(OUTPUT): $(OBJ_FILES)
	@echo "$(YELLOW)==> Linking final executable$(RESET)"
	@$(CC) $(CFLAGS) $^ -o $@
	@echo "$(GREEN)==> Linked $(OUTPUT)$(RESET)"

# Compile source files to object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADER_FILES)
	@mkdir -p $(dir $@)
	@echo "$(CYAN)Compiling $<...$(RESET)"
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "$(GREEN)done$(RESET)"

# Clean build
clean:
	@echo "$(RED)==> Cleaning all build artifacts$(RESET)"
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "$(RED)==> Clean complete$(RESET)"

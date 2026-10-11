ASM ?= pac

# Colors
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
CYAN := \033[0;36m
RESET := \033[0m

BIN_DIR := bin
HELPERS_DIR := ../helpers
INC_DIR := $(HELPERS_DIR)/inc

ASMFLAGS := -I $(INC_DIR) -e core -b 64 -a x86_64 -f elf64

PASM := $(wildcard *.pasm)
HELPERS_PASM := $(wildcard $(HELPERS_DIR)/*.pasm)

OUTPUT := $(BIN_DIR)/game_time

.PHONY: all clean

$(OUTPUT): $(HELPERS_PASM) $(PASM)
	@mkdir -p $(BIN_DIR)

	@printf "$(YELLOW)==> Assembling and Linking final executable$(RESET)\n"
	@$(ASM) $(ASMFLAGS) $(HELPERS_PASM) $(PASM) -o $@
	@printf "$(GREEN)==> Linked %s$(RESET)\n" $(OUTPUT)

all: $(OUTPUT)

clean:
	@printf "$(RED)==> Cleaning all build artifacts$(RESET)\n"
	@rm -rf $(BIN_DIR)
	@printf "$(RED)==> Clean complete$(RESET)\n"
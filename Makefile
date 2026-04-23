NFX := nfx/nfx.json
LICENSE := LICENSE
README := README.md

PAC_LINUX := PAC/bin/linux/x86_64/pac
PAC_WINDOWS := PAC/bin/windows/x86_64/pac.exe

BUILD_DIR := nfx_zip
KEY_DIR := keys
NFX_DIR := nfx

WORK_JSON := $(NFX_DIR)/build.json
BUILD_DATE := $(shell date +%Y-%m-%d)

ZIP := $(BUILD_DIR)/PAC.zip
CANON_NFX := $(NFX_DIR)/nfx.canonical.json
SIG := $(BUILD_DIR)/PAC.zip.sig

# Colors
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
CYAN := \033[0;36m
RESET := \033[0m

.PHONY: all clean

dirs:
	@mkdir -p $(BUILD_DIR) $(KEY_DIR) $(NFX_DIR)

build-linux:
	@printf "$(YELLOW)==> Building %s \n$(RESET)" $(PAC_LINUX)
	@make -C PAC BUILD=release
	@printf "$(GREEN)==> Done building %s \n$(RESET)" $(PAC_LINUX)

build-windows:
	@printf "$(YELLOW)==> Building %s \n$(RESET)" $(PAC_WINDOWS)
	@make -C PAC BUILD=release build_win
	@printf "$(GREEN)==> Done building %s \n$(RESET)" $(PAC_WINDOWS)

prepare-json:
	@cp $(NFX) $(WORK_JSON)

canonical: sizes date
	@printf "$(YELLOW)==> Creating canonical JSON...\n$(RESET)"
	@jq -S . $(WORK_JSON) > $(CANON_NFX)
	@printf "$(GREEN)==> Created canonical JSON! (%s) \n$(RESET)" $(CANON_NFX)

sizes: hashes
	@printf "$(YELLOW)==> Getting Sizes... \n$(RESET)"
	@LINUX_SIZE=$$(stat -c %s $(PAC_LINUX)); \
		printf "$(GREEN)==> Linux size: %s\n$(RESET)" $$LINUX_SIZE; \
		jq '.Binaries[0].Size = '$$LINUX_SIZE'' $(WORK_JSON) > $(WORK_JSON).tmp && mv $(WORK_JSON).tmp $(WORK_JSON)

	@WIN_SIZE=$$(stat -c %s $(PAC_WINDOWS)); \
		printf "$(GREEN)==> Windows size: %s\n$(RESET)" $$WIN_SIZE; \
		jq '.Binaries[1].Size = '$$WIN_SIZE'' $(WORK_JSON) > $(WORK_JSON).tmp && mv $(WORK_JSON).tmp $(WORK_JSON)

hashes: prepare-json
	@printf "$(YELLOW)==> Getting Hashes... \n$(RESET)"
	@LINUX_HASH=$$(sha256sum $(PAC_LINUX) | awk '{print $$1}'); \
		printf "$(GREEN)==> Linux hash: %s\n$(RESET)" $$LINUX_HASH; \
		jq '.Binaries[0].Sha256 = "'$$LINUX_HASH'"' $(WORK_JSON) > $(WORK_JSON).tmp && mv $(WORK_JSON).tmp $(WORK_JSON)

	@WIN_HASH=$$(sha256sum $(PAC_WINDOWS) | awk '{print $$1}'); \
		printf "$(GREEN)==> Windows hash: %s\n$(RESET)" $$WIN_HASH; \
		jq '.Binaries[1].Sha256 = "'$$WIN_HASH'"' $(WORK_JSON) > $(WORK_JSON).tmp && mv $(WORK_JSON).tmp $(WORK_JSON)

date:
	@printf "$(YELLOW)==> Injecting build date...\n$(RESET)"
	@jq '.Build.Date = "$(BUILD_DATE)"' $(WORK_JSON) > $(WORK_JSON).tmp && mv $(WORK_JSON).tmp $(WORK_JSON)
	@printf "$(GREEN)==> Build date set to $(BUILD_DATE)\n$(RESET)"

zip: dirs build-linux build-windows canonical
	@printf "$(YELLOW)==> Creating Zip... (%s) \n$(RESET)" $(ZIP)
	@cp $(CANON_NFX) nfx.json
	@zip -r $(ZIP) \
		nfx.json \
		$(PAC_LINUX) \
		$(PAC_WINDOWS) \
		$(LICENSE) \
		$(README) \
		$(KEY_DIR)/allowed_signers
	@rm nfx.json
	@printf "$(GREEN)==> Created Zip! (%s) \n$(RESET)" $(ZIP)
sign: zip
	@printf "$(YELLOW)==> Signing... \n$(RESET)"

	@if [ -z "$(PRIV_KEY)" ]; then \
		printf "$(RED)==> PRIV_KEY is not set. Usage: make sign PRIV_KEY=<key> \n$(RESET)"; \
		exit 1; \
	fi

	@ssh-keygen -Y sign \
		-f $(PRIV_KEY) \
		-n file \
		$(ZIP)

	@printf "$(GREEN)==> Signed! \n$(RESET)"

verify:
	@printf "$(YELLOW)==> Verifying... \n$(RESET)" $(CANON_NFX)

	@ssh-keygen -Y verify \
		-f $(KEY_DIR)/allowed_signers \
		-I pheonix-pac \
		-n file \
		-s $(SIG) \
		< $(ZIP)
	@printf "$(GREEN)==> Verification complete! \n$(RESET)"

all: dirs build-linux build-windows hashes sizes canonical zip sign verify
	@printf "$(GREEN)==> Packaged at %s (unsigned) and %s (signed) \n$(RESET)" $(ZIP) $(SIG)

clean:
	@printf "$(YELLOW)==> Cleaning... \n$(RESET)"
	@rm -rf $(BUILD_DIR) $(CANON_NFX)
	@printf "$(GREEN)==> Cleaned! \n$(RESET)"
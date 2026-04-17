NFX := nfx/nfx.json
LICENSE := LICENSE
README := README.md

PAC_LINUX := PAC/bin/linux/x86_64/pac
PAC_WINDOWS := PAC/bin/windows/x86_64/pac.exe

BUILD_DIR := nfx_zip
KEY_DIR := keys
NFX_DIR := nfx

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

canonical: $(NFX_DIR)/tmp4.json
	@printf "$(YELLOW)==> Creating canonical JSON... (%s) \n$(RESET)" $(CANON_NFX)
	@jq -S . $(NFX_DIR)/tmp4.json > $(CANON_NFX) && rm $(NFX_DIR)/tmp4.json
	@printf "$(GREEN)==> Created canonical JSON! (%s) \n$(RESET)" $(CANON_NFX)

sizes:
	@printf "$(YELLOW)==> Getting Sizes... \n$(RESET)"
	@SIZE=$$(stat -c %s $(PAC_LINUX) | awk '{print $$1}'); \
		printf "$(GREEN)==> Got size for %s -> %s \n$(RESET)" $(PAC_LINUX) $$SIZE; \
		jq '.Binaries[0].Size = '$$SIZE'' $(NFX_DIR)/tmp2.json > $(NFX_DIR)/tmp3.json && rm $(NFX_DIR)/tmp2.json
	@SIZE=$$(stat -c %s $(PAC_WINDOWS) | awk '{print $$1}'); \
		printf "$(GREEN)==> Got size for %s -> %s \n$(RESET)" $(PAC_WINDOWS) $$SIZE; \
		jq '.Binaries[1].Size = '$$SIZE'' $(NFX_DIR)/tmp3.json > $(NFX_DIR)/tmp4.json && rm $(NFX_DIR)/tmp3.json

hashes:
	@printf "$(YELLOW)==> Getting Hashes... \n$(RESET)"
	@HASH=$$(sha256sum $(PAC_LINUX) | awk '{print $$1}'); \
		printf "$(GREEN)==> Got hash for %s -> %s \n$(RESET)" $(PAC_LINUX) $$HASH; \
		jq '.Binaries[0].Sha256 = "'$$HASH'"' $(NFX) > $(NFX_DIR)/tmp.json
	@HASH=$$(sha256sum $(PAC_WINDOWS) | awk '{print $$1}'); \
		printf "$(GREEN)==> Got hash for %s -> %s \n$(RESET)" $(PAC_WINDOWS) $$HASH; \
		jq '.Binaries[1].Sha256 = "'$$HASH'"' $(NFX_DIR)/tmp.json > $(NFX_DIR)/tmp2.json && rm $(NFX_DIR)/tmp.json

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
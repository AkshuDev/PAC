# === Vars ===
# Settings
ARCH := $(shell uname -m)
OS := $(shell uname)

srcdir := src
incdir := inc
builddir := build
bindir := bin

# Compiler Settings
CXX := g++
CXXFLAGS := -Wall -Wextra -std=c++20 -I$(incdir)

# Files
SRCS := $(wildcard $(srcdir)/*.cpp)
OBJS := $(patsubst $(srcdir)/%.cpp,$(builddir)/%.o,$(SRCS))

# Target
TARGET := pac-xtensa-emulator-$(ARCH)-$(OS)

# Default target
all: $(bindir)/$(TARGET)

# Just do it
$(bindir)/$(TARGET): $(SRCS)
	@mkdir -p $(builddir)
	@mkdir -p $(bindir)
	@echo "Compiling and assembling and linking ..."
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS)

clean:
	@echo "Cleaning..."
	@rm -rf $(builddir) $(bindir)

dist-clean:
	rm -rf bin

print:
	@echo "SRCS: $(SRCS)"
	@echo "OBJS: $(OBJS)"

# Finished

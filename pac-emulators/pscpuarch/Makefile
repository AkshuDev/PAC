# === Vars ===
# Settings
ARCH := $(shell uname -m)
OS := $(shell uname)

srcdir := src
sharedsrcdir := ../shared
sharedincdir := ../shared/inc
incdir := inc
builddir := build
bindir := bin

# Compiler Settings
CXX := g++
CXXFLAGS := -w -Wall -Wextra -std=c++20 -I$(incdir) -I$(sharedincdir)

# Files
SRCS := $(wildcard $(sharedsrcdir)/*.cpp)
OBJS := $(patsubst $(sharedsrcdir)/%.cpp,$(builddir)/%.o,$(SRCS))

# Target
TARGET := pac-pscpusrch-emulator-$(ARCH)-$(OS)

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

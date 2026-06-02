TOOLS_DIR ?= .tools
WIBO_VERSION ?= 1.1.0
MSVC420_URL ?= https://github.com/itsmattkc/MSVC420/archive/refs/heads/master.zip
MSVCRT40_URL ?= https://raw.githubusercontent.com/neuromancer/my-teacher-is-an-alien-re/main/3rdparty/msvcrt40.dll
BINARY_COMP ?= binary-comp

DEFAULT_WIBO := $(TOOLS_DIR)/wibo/wibo
DEFAULT_MSVC42_DIR := $(TOOLS_DIR)/MSVC420

WIBO ?= $(DEFAULT_WIBO)
MSVC42_DIR ?= $(DEFAULT_MSVC42_DIR)

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
WIBO_ASSET ?= wibo-macos
else ifeq ($(UNAME_M),x86_64)
WIBO_ASSET ?= wibo-x86_64
else
WIBO_ASSET ?= wibo-i686
endif

WIBO_URL ?= https://github.com/decompals/wibo/releases/download/$(WIBO_VERSION)/$(WIBO_ASSET)
MSVC420_ZIP := $(TOOLS_DIR)/downloads/msvc420.zip
MSVCRT40_DLL := $(TOOLS_DIR)/downloads/msvcrt40.dll

.PHONY: all setup download-wibo download-msvc install-msvcrt build demo clean distclean

all: build

setup:
	@if [ ! -x "$(WIBO)" ]; then \
		if [ "$(abspath $(WIBO))" != "$(abspath $(DEFAULT_WIBO))" ]; then \
			echo "wibo override not found or not executable: $(WIBO)" >&2; \
			exit 1; \
		fi; \
		$(MAKE) download-wibo; \
	fi
	@if [ ! -f "$(MSVC42_DIR)/bin/CL.EXE" ]; then \
		if [ "$(abspath $(MSVC42_DIR))" != "$(abspath $(DEFAULT_MSVC42_DIR))" ]; then \
			echo "MSVC42_DIR override does not contain bin/CL.EXE: $(MSVC42_DIR)" >&2; \
			exit 1; \
		fi; \
		$(MAKE) download-msvc; \
	fi
	@$(MAKE) install-msvcrt

download-wibo:
	mkdir -p "$(dir $(DEFAULT_WIBO))"
	curl -L --fail -o "$(DEFAULT_WIBO)" "$(WIBO_URL)"
	chmod +x "$(DEFAULT_WIBO)"

$(MSVC420_ZIP):
	mkdir -p "$(dir $@)"
	curl -L --fail -o "$@" "$(MSVC420_URL)"

$(MSVCRT40_DLL):
	mkdir -p "$(dir $@)"
	curl -L --fail -o "$@" "$(MSVCRT40_URL)"

download-msvc: $(MSVC420_ZIP)
	rm -rf "$(DEFAULT_MSVC42_DIR)" "$(TOOLS_DIR)/msvc420-extract"
	mkdir -p "$(TOOLS_DIR)/msvc420-extract"
	python3 -c "import pathlib, shutil, zipfile; zip_path=pathlib.Path('$(MSVC420_ZIP)'); extract=pathlib.Path('$(TOOLS_DIR)/msvc420-extract'); target=pathlib.Path('$(DEFAULT_MSVC42_DIR)'); zipfile.ZipFile(zip_path).extractall(extract); roots=[p for p in extract.iterdir() if p.is_dir()]; shutil.move(str(roots[0]), str(target))"
	rm -rf "$(TOOLS_DIR)/msvc420-extract"

install-msvcrt: $(MSVCRT40_DLL)
	cp -f "$(MSVCRT40_DLL)" "$(MSVC42_DIR)/bin/msvcrt40.dll"

build: setup
	WIBO="$(abspath $(WIBO))" MSVC42_DIR="$(abspath $(MSVC42_DIR))" sh build.sh
	$(BINARY_COMP) export-asm --config binary-comp.json --target demo --clean --no-source

demo: build
	$(BINARY_COMP) exe --config binary-comp.json --target demo --functions
	$(BINARY_COMP) report --config binary-comp.json --target demo --no-build
	$(BINARY_COMP) compare --config binary-comp.json --target demo --no-build Door::canOpen code/FUN_0040109E.disassembled.txt
	$(BINARY_COMP) values --config binary-comp.json --target demo --no-build --include-stack-locals
	$(BINARY_COMP) data --config binary-comp.json --target demo || true
	$(BINARY_COMP) seh --config binary-comp.json --target demo --report --no-build || true

clean:
	rm -rf artifacts code

distclean: clean
	rm -rf "$(TOOLS_DIR)"

prefix ?= /usr/local
destdir ?= ${prefix}
config ?= release
arch ?=
static ?= false
linker ?=

BUNDLE := tarida

BUILD_DIR ?= build/$(config)
SRC_DIR ?= tarida
binary := $(BUILD_DIR)/tarida
# tests_binary := $(BUILD_DIR)/test
docs_dir := build/$(BUNDLE)-docs

ifdef config
	ifeq (,$(filter $(config),debug release))
		$(error Unknown configuration "$(config)")
	endif
endif

PONYC_FLAGS ?= --path=/opt/homebrew/opt/libressl/lib --path=/opt/homebrew/opt/pcre2/lib/
COMPILE_WITH := corral run -- ponyc $(PONYC_FLAGS)

ifeq ($(config),release)
	PONYC = $(COMPILE_WITH)
else
	PONYC = $(COMPILE_WITH) --debug
endif

ifneq ($(arch),)
	arch_arg := --cpu $(arch)
endif

ifdef static
	ifeq (,$(filter $(static),true false))
		$(error "static must be true or false)
	endif
endif

ifeq ($(static),true)
	LINKER += --static
endif

ifneq ($(linker),)
	LINKER += --link-ldcmd=$(linker)
endif

SOURCE_FILES := $(shell find $(SRC_DIR) -name *.pony)
TEST_FILES := $(shell find $(SRC_DIR)/test -name \*.pony -o -name helper.sh)
VERSION := "$(tag) [$(config)]"

$(binary): $(SOURCE_FILES) | $(BUILD_DIR)
	${PONYC} $(arch_arg) $(LINKER) $(SRC_DIR) -o ${BUILD_DIR}

install: $(binary)
	@echo "install"
	mkdir -p $(DESTDIR)$(prefix)/bin
	cp $^ $(DESTDIR)$(prefix)/bin

# $(tests_binary): $(SOURCE_FILES) $(TEST_FILES) | $(BUILD_DIR)
# 	${PONYC} $(arch_arg) $(LINKER) --debug -o ${BUILD_DIR} $(SRC_DIR)/test

# unit-tests: $(tests_binary)
# 	$^ --exclude=integration

test: unit-tests

clean:
	rm -rf $(docs_dir)
	rm -rf $(BUILD_DIR)

$(docs_dir): $(SOURCE_FILES)
	rm -rf $(docs_dir)
	$(PONYC) --docs-public --pass=docs --output build $(SRC_DIR)

docs: $(docs_dir)

all: test $(binary)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

.PHONY: all clean install test unittest integration


# FLAGS ?= --path=/opt/homebrew/opt/libressl/lib --path=/opt/homebrew/opt/pcre2/lib/

# all: compile

# compile:
# 	corral run -- ponyc $(FLAGS) tarida -o _build

# debug:
# 	corral run -- ponyc $(FLAGS) -d tarida -o _build -b debug_tarida

# integration:
# 	corral run -- ponyc $(FLAGS) -d tarida_shs_integration -o _build -b shs_tarida

# test:
# 	corral run -- ponyc $(FLAGS) -d tarida_test -o _build -b test_tarida
# 	./_build/test_tarida

# clean:
# 	rm -rf _build

FLAGS ?= --path=/opt/homebrew/opt/libressl/lib --path=/opt/homebrew/opt/pcre2/lib/

all: compile

compile:
	corral run -- ponyc $(FLAGS) tarida -o _build

debug:
	corral run -- ponyc $(FLAGS) -d tarida -o _build -b debug_tarida

integration:
	corral run -- ponyc $(FLAGS) -d tarida_shs_integration -o _build -b shs_tarida

test:
	corral run -- ponyc $(FLAGS) -d tarida_test -o _build -b test_tarida
	./_build/test_tarida

clean:
	rm -rf _build

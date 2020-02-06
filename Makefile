all: compile

compile:
	stable env ponyc tarida -o _build

debug:
	stable env ponyc -d tarida -o _build -b debug_tarida

integration:
	stable env ponyc -d tarida_shs_integration -o _build -b shs_tarida

test: debug
	stable env ponyc -d tarida_test -o _build -b test_tarida
	./_build/test_tarida

clean:
	rm -rf _build

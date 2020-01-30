all: compile

compile:
	stable env ponyc tarida -o _build

debug:
	stable env ponyc -d tarida -o _build -b debug_tarida

test:
	stable env ponyc -d tarida_test -o _build -b test_tarida
	./_build/test_tarida

clean:
	rm -rf _build

all: compile

compile:
	stable env ponyc tarida -o _build

debug:
	stable env ponyc -d tarida -o _build -b tarida_debug

clean:
	rm -rf _build

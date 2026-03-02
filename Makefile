LDLIBS := -lyara

.PHONY: build clean

build: main

clean:
	rm -rf main

LDLIBS := -lyara

.PHONY: build clean

build: main

main: main.o scan.o

clean:
	rm -rf main *.o

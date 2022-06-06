.PHONY: build test

build:
	protostar build --disable-hint-validation

test:
	protostar test src
	
date:
	date

format:
	black scripts
	cairo-format -i src/**/*.cairo

clean:
	rm -Rf build
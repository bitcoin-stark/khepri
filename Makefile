.PHONY: build test

build:
	protostar build

test:
	protostar test src
	
date:
	date

format:
	black scripts
	cairo-format -i src/**/*.cairo

build-block-header-verifier:
	starknet-compile --cairo_path "./src:./lib/cairo_contracts/src" src/header/block_header_verifier.cairo --disable_hint_validation --output build/block_header_verifier.json --abi build/block_header_verifier_abi.json 
.PHONY: build run check fmt clippy test

build:
	cargo build --release

run:
	cargo run --

check: test clippy
	cargo fmt --check

test:
	cargo test

clippy:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

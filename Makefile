# Makefile - convenience targets for autofs-rs
#
# 20261126 - Created by Claude (claude.ai, Anthropic) - scottfk

REFERENCE ?= ../autofs

.PHONY: all reference check clippy fmt clean

all:
	cargo build --release

reference:
	tools/build-reference.sh $(REFERENCE)

check:
	@test -x $(REFERENCE)/daemon/automount || tools/build-reference.sh $(REFERENCE)
	AUTOFS_REFERENCE=$(abspath $(REFERENCE)) cargo test --release

clippy:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

clean:
	cargo clean

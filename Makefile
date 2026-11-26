# Makefile - convenience targets for autofs-rs
#
# 20261126 - Created by Claude (claude.ai, Anthropic) - scottfk
# 20261126 - Add the tables target (tools/gen-tables.py) - Claude - scottfk

REFERENCE ?= ../autofs

.PHONY: all reference tables check clippy fmt clean

all:
	cargo build --release

reference:
	tools/build-reference.sh $(REFERENCE)

tables:
	@test -f $(REFERENCE)/daemon/master_tok.c || tools/build-reference.sh $(REFERENCE)
	python3 -I tools/gen-tables.py $(REFERENCE)

check:
	@test -x $(REFERENCE)/daemon/automount || tools/build-reference.sh $(REFERENCE)
	AUTOFS_REFERENCE=$(abspath $(REFERENCE)) cargo test --release

clippy:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

clean:
	cargo clean

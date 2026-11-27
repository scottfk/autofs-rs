# Makefile - convenience targets for autofs-rs
#
# 20261126 - Created by Claude (claude.ai, Anthropic) - scottfk
# 20261126 - Add the tables target (tools/gen-tables.py) - Claude - scottfk
# 20261127 - Add the vmcheck target (daemon tests on the root test VM) - Claude - scottfk

REFERENCE ?= ../autofs

.PHONY: all reference tables check vmcheck clippy fmt clean

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

# The daemon tests: as root on the test VM (see crates/automount/tests/common/vm.rs).
vmcheck:
	@test -x $(REFERENCE)/daemon/automount || tools/build-reference.sh $(REFERENCE)
	AUTOFS_REFERENCE=$(abspath $(REFERENCE)) cargo test --release --test diff_daemon -- --ignored --test-threads=1

clippy:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

clean:
	cargo clean

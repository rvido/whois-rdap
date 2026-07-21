# whois-rdap Makefile
# Targets: release, debug, test, test-verbose, lint, fmt, fmt-check,
#          install, uninstall, clean, clean-cache, bench, doc, help

.PHONY: all release debug test test-verbose lint fmt fmt-check \
        install uninstall clean clean-cache doc bench help

# ── Configurable variables ────────────────────────────────────────────────────

# Installation prefix (override with: make install PREFIX=/usr/local)
PREFIX       ?= $(HOME)/.local
INSTALL_DIR  := $(PREFIX)/bin
BINARY       := whois-rdap
CARGO        := cargo
SQLITE_FLAGS := "-DSQLITE_OMIT_DEPRECATED -DSQLITE_OMIT_PROGRESS_CALLBACK -DSQLITE_OMIT_SHARED_CACHE -DSQLITE_OMIT_AUTOVACUUM -DSQLITE_OMIT_TRACE -DSQLITE_OMIT_GET_TABLE -DSQLITE_OMIT_TCL_VARIABLE"

# Parallelism for tests (defaults to number of logical CPUs)
TEST_THREADS ?= $(shell nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)

# ── Default target ────────────────────────────────────────────────────────────

all: release

# ── Build targets ─────────────────────────────────────────────────────────────

## Build an optimised release binary (LTO, stripped, size-optimised)
release:
	LIBSQLITE3_FLAGS=$(SQLITE_FLAGS) $(CARGO) build --release $(CARGO_FLAGS)
	@echo ""
	@echo "  Binary:  target/release/$(BINARY)"
	@echo "  Size:    $$(du -sh target/release/$(BINARY) | cut -f1)"

## Build a debug binary (fast compile, debug info included)
debug:
	LIBSQLITE3_FLAGS=$(SQLITE_FLAGS) $(CARGO) build $(CARGO_FLAGS)
	@echo ""
	@echo "  Binary:  target/debug/$(BINARY)"

# ── Test targets ──────────────────────────────────────────────────────────────

## Run the full test suite
test:
	$(CARGO) test $(CARGO_FLAGS) -- --test-threads=$(TEST_THREADS)

## Run the full test suite with live output (no output capture)
test-verbose:
	$(CARGO) test $(CARGO_FLAGS) -- --nocapture --test-threads=$(TEST_THREADS)

## Run only unit tests (skip integration tests if any)
test-unit:
	$(CARGO) test --lib $(CARGO_FLAGS)

## Run only a specific test by name (usage: make test-one NAME=test_parse_ip_response_arin_format)
test-one:
	$(CARGO) test $(NAME) -- --nocapture

# ── Lint & format ─────────────────────────────────────────────────────────────

## Run clippy (deny warnings, as in CI)
lint: fmt-check
	$(CARGO) clippy --all-targets -- -D warnings

## Format all source files with rustfmt
fmt:
	$(CARGO) fmt

## Check formatting without modifying files (useful in CI)
fmt-check: fmt
	$(CARGO) fmt -- --check

# ── Documentation ─────────────────────────────────────────────────────────────

## Build and open rustdoc
doc:
	$(CARGO) doc --no-deps --open

## Build rustdoc without opening
doc-build:
	$(CARGO) doc --no-deps

# ── Install / uninstall ───────────────────────────────────────────────────────

## Install the release binary to $(INSTALL_DIR) (default: ~/.local/bin)
install: release
	@mkdir -p $(INSTALL_DIR)
	install -m 755 target/release/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo "  Installed → $(INSTALL_DIR)/$(BINARY)"

## Remove the installed binary
uninstall:
	rm -f $(INSTALL_DIR)/$(BINARY)
	@echo "  Removed  $(INSTALL_DIR)/$(BINARY)"

# ── Clean ─────────────────────────────────────────────────────────────────────

## Remove the Cargo build artefacts (target/)
clean:
	$(CARGO) clean

## Remove the on-disk RDAP SQLite cache (~/.cache/whois-rdap/)
clean-cache:
	rm -rf "$${XDG_CACHE_HOME:-$$HOME/.cache}/whois-rdap"
	@echo "  RDAP cache cleared."

## Full reset: build artefacts + on-disk cache
clean-all: clean clean-cache

# ── Benchmarks ────────────────────────────────────────────────────────────────

## Run benchmarks (requires nightly or criterion benches)
bench:
	$(CARGO) bench $(CARGO_FLAGS)

# ── Convenience ───────────────────────────────────────────────────────────────

## Run lint + fmt-check + test in sequence (suitable for pre-commit / CI)
ci: fmt-check lint test

## Quick-run the debug binary (pass args via: make run ARGS="8.8.8.8 --json")
run: debug
	./target/debug/$(BINARY) $(ARGS)

## Quick-run the release binary
run-release: release
	./target/release/$(BINARY) $(ARGS)

# ── Help ──────────────────────────────────────────────────────────────────────

## Show this help message
help:
	@echo ""
	@echo "Usage: make [target] [VARIABLE=value]"
	@echo ""
	@echo "Build targets:"
	@echo "  release        Optimised release binary (LTO, stripped)"
	@echo "  debug          Debug binary (fast compile)"
	@echo ""
	@echo "Test targets:"
	@echo "  test           Run full test suite"
	@echo "  test-verbose   Run tests with live stdout output"
	@echo "  test-unit      Run only library unit tests"
	@echo "  test-one       Run a single test  (NAME=<test_name>)"
	@echo ""
	@echo "Quality targets:"
	@echo "  lint           clippy -D warnings"
	@echo "  fmt            Format source with rustfmt"
	@echo "  fmt-check      Check formatting (no changes)"
	@echo "  ci             fmt-check + lint + test  (CI gate)"
	@echo ""
	@echo "Documentation:"
	@echo "  doc            Build and open rustdoc"
	@echo "  doc-build      Build rustdoc only"
	@echo ""
	@echo "Install targets:"
	@echo "  install        Install binary to PREFIX/bin  (default: ~/.local/bin)"
	@echo "  uninstall      Remove installed binary"
	@echo ""
	@echo "Clean targets:"
	@echo "  clean          Remove Cargo build artefacts (target/)"
	@echo "  clean-cache    Remove RDAP SQLite cache (~/.cache/whois-rdap/)"
	@echo "  clean-all      clean + clean-cache"
	@echo ""
	@echo "Other:"
	@echo "  bench          Run benchmarks"
	@echo "  run            Run debug binary  (ARGS='8.8.8.8 --json')"
	@echo "  run-release    Run release binary"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX         Installation prefix        (default: \$$HOME/.local)"
	@echo "  CARGO_FLAGS    Extra flags passed to cargo"
	@echo "  TEST_THREADS   Parallelism for cargo test (default: nproc)"
	@echo ""

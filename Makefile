# Lantern - build and measure on the target device.
#
# `make` builds the release binary and prints both on-disk and runtime
# footprint, because on this host the budget is the design.

CARGO  ?= cargo
BIN     = target/release/lantern
DIST    = dist/lantern

.PHONY: all build test clean size footprint doctor check

all: build footprint

build:
	$(CARGO) build --release
	@echo
	@echo "== binary =="
	@ls -la $(BIN)
	@echo "== stripped size =="
	@du -h $(BIN) | cut -f1

# Unit + integration tests (no API spend: every test uses the scripted provider).
test:
	$(CARGO) test --workspace

# On-disk footprint of everything the build produced.
size: build
	@echo
	@echo "== build footprint =="
	@du -sh target target/release 2>/dev/null
	@du -sh dist 2>/dev/null || true
	@df -h / | tail -1

# Runtime footprint: resident memory and wall time of a full doctor run.
footprint: build
	@echo
	@echo "== runtime footprint (lantern doctor) =="
	@sh scripts/footprint.sh $(BIN) doctor

doctor: build
	$(BIN) doctor

# Fast feedback loop.
check:
	$(CARGO) check --workspace --all-targets

clean:
	$(CARGO) clean
	rm -rf dist

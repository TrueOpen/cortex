GO ?= go
BIN_DIR ?= bin
GOFLAGS ?=
# VERSION is linked into both binaries (cortexd --version, and the startup
# log). It defaults to the nearest tag, so a build from a release tag reports
# that release and anything after it reports how far past it is.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/TrueOpen/cortex/internal/buildinfo.Version=$(VERSION)
RELEASE_DIR ?= dist
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

# Bindings from the pinned wire release descriptor; see proto/CHAIN_BINDINGS.md.
CHAIN_GEN_OUT ?= $(BIN_DIR)/.chain-bindings

.PHONY: all build cortexd cortexctl release install uninstall test test-fast test-integration-readiness proto-gen-chain proto-drift-chain replay-order clean help

all: build

build: cortexd cortexctl ## Build all command binaries.

cortexd: $(BIN_DIR) ## Build the cortexd daemon.
	$(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/cortexd ./cmd/cortexd

cortexctl: $(BIN_DIR) ## Build the cortexctl CLI.
	$(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/cortexctl ./cmd/cortexctl

release: ## Build the linux/amd64 release archive and SHA256SUMS: make release VERSION=v0.1.0
	@case "$(VERSION)" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "VERSION must be a release tag like v0.1.0, got $(VERSION)"; exit 1;; esac
	@case "$(VERSION)" in *-dirty|*-g*) echo "refusing to release $(VERSION): build from a clean checkout of the tag"; exit 1;; esac
	mkdir -p $(RELEASE_DIR)/cortex-$(VERSION)-linux-amd64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(RELEASE_DIR)/cortex-$(VERSION)-linux-amd64/cortexd ./cmd/cortexd
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(RELEASE_DIR)/cortex-$(VERSION)-linux-amd64/cortexctl ./cmd/cortexctl
	tar -C $(RELEASE_DIR) -czf $(RELEASE_DIR)/cortex-$(VERSION)-linux-amd64.tar.gz cortex-$(VERSION)-linux-amd64
	cd $(RELEASE_DIR) && shasum -a 256 cortex-$(VERSION)-linux-amd64.tar.gz > SHA256SUMS

install: build ## Install command binaries to $(DESTDIR)$(BINDIR).
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN_DIR)/cortexd $(DESTDIR)$(BINDIR)/cortexd
	install -m 0755 $(BIN_DIR)/cortexctl $(DESTDIR)$(BINDIR)/cortexctl

uninstall: ## Remove installed command binaries from $(DESTDIR)$(BINDIR).
	rm -f $(DESTDIR)$(BINDIR)/cortexd
	rm -f $(DESTDIR)$(BINDIR)/cortexctl

test: ## Run the full test suite.
	$(GO) test $(GOFLAGS) ./... -count=1

test-fast: ## Run focused package checks.
	$(GO) test $(GOFLAGS) ./internal/evidence ./test/fakes

test-integration-readiness: ## Run integration readiness smoke checks.
	$(GO) test $(GOFLAGS) ./test/integration_readiness -count=1

proto-gen-chain: ## Generate the pinned wire release into an empty scratch directory.
	@case "$(abspath $(CHAIN_GEN_OUT))" in \
	  "$(abspath proto)"|"$(abspath proto)"/*|"$(abspath .)") \
	    echo "CHAIN_GEN_OUT must be an empty scratch directory outside proto/."; \
	    exit 1;; \
	esac
	$(GO) run ./scripts/wiregen -out "$(CHAIN_GEN_OUT)"

proto-drift-chain: ## Compare complete compiled descriptors with the pinned wire release.
	$(GO) test $(GOFLAGS) ./internal/devex -count=1 -v \
	  -run 'TestChainBindingsMatchReleasedDescriptor|TestVendoredChainBindingsKeepImportsLocalised'

replay-order: ## Replay captured OPEN_TASK frames through the real admission path: make replay-order FRAMES=/path/to/frames.json
	@if [ -z "$(FRAMES)" ]; then \
	  echo "FRAMES is unset."; \
	  echo "This target replays captured OPEN_TASK frames through the real inbound"; \
	  echo "path and reports, per frame, admission or the exact gate that refused it."; \
	  echo "Only the envelope signature layer is skipped, so canonical order verification"; \
	  echo "still runs. It needs a capture file, which is developer-supplied:"; \
	  echo; \
	  echo "  make replay-order FRAMES=internal/daemon/testdata/real_order_broadcast_frames.json"; \
	  echo; \
	  echo "The file is a JSON array of {task_id, subject, envelope} rows, in the shape of"; \
	  echo "internal/daemon/testdata/real_order_broadcast_frames.json. Both the 20-field"; \
	  echo "TRUEOPEN_BUS_ENVELOPE_V1 shape and the pre-V1 capture shape are accepted."; \
	  exit 1; \
	fi
	CORTEX_REPLAY_FRAMES="$(abspath $(FRAMES))" $(GO) test $(GOFLAGS) ./internal/daemon -count=1 -v \
	  -run TestReplayCapturedOrderFrames

clean: ## Remove build outputs.
	rm -rf $(BIN_DIR)

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %-28s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

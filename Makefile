.PHONY: build test run clean fmt update-rules install

BINARY := veilgate
RULES_DIR ?= $(HOME)/.veilgate/rules

build:
	go build -o $(BINARY) ./cmd/veilgate

test:
	go test -race -v ./...

run: build
	./$(BINARY) -config configs/veilgate.yaml

fmt:
	gofmt -w -s .
	go vet ./...

clean:
	rm -f $(BINARY)

# Fetch the latest community rule files into RULES_DIR.
# Run on first install and on every upgrade to pick up new community files.
# Override the target directory: make update-rules RULES_DIR=/path/to/rules
update-rules: build
	./$(BINARY) update-rules --dir "$(RULES_DIR)"

# Build the binary and pull the latest community rules.
install: build update-rules
	@echo "veilgate installed. Set rules_dir: $(RULES_DIR) in your veilgate.yaml."

.PHONY: build test run clean fmt

BINARY := veilgate

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

GO ?= go

.PHONY: fmt vet test build

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

build:
	mkdir -p bin
	$(GO) build -o bin/kernloom-adapter-klshield ./cmd/kernloom-adapter-klshield


ifneq ("$(wildcard .env)","")
	include .env
	export
endif

BINARY  := deploy-witness
VERSION := $(shell sed -n 's/^## \[\([0-9][^]]*\)\].*/\1/p' CHANGELOG.md | head -1)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: development build run clean lint test vet fmt \
        build-linux-amd64 build-linux-arm64 build-all install

# Run the audit straight from source. Pass flags with ARGS, e.g.
#   make development ARGS="--sections ports,services --stdout"
development:
	go run . $(ARGS)

# Build a static binary for this machine.
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

# Build and run against the current host.
run: build
	./$(BINARY) $(ARGS)

# Cross-compiled binaries to drop onto the servers being audited.
build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" \
		-o bin/$(BINARY)-linux-amd64 .

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" \
		-o bin/$(BINARY)-linux-arm64 .

build-all: build-linux-amd64 build-linux-arm64

install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)

clean:
	rm -rf $(BINARY) bin

fmt:
	gofmt -w .

vet:
	go vet ./...

lint:
	golangci-lint run

test:
	go clean -testcache && go test ./...

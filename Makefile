ifneq ("$(wildcard .env)","")
	include .env
	export
endif

BINARY  := deploy-witness
VERSION := $(shell sed -n 's/^## \[\([0-9][^]]*\)\].*/\1/p' CHANGELOG.md | head -1)
LDFLAGS := -s -w -X main.version=$(VERSION)

# The two packages copied in from the organisation's shared repositories, and the
# releases they were copied from. Building needs neither — that is the point; only
# refreshing the copies does. See app/csv/doc.go and app/contract/auditv1/doc.go.
UTILS_VERSION     := v0.9.0
CONTRACTS_VERSION := v0.9.0
UTILS             ?= ../utils
CONTRACTS         ?= ../contracts

.PHONY: development build run clean lint test vet fmt sync-shared \
        build-linux-amd64 build-linux-arm64 build-all install dist

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

# The committed downloads in dist/: every supported OS and architecture, plus the
# sha256 manifest install.sh verifies against. Rebuilt from a released tree (the
# version is stamped from CHANGELOG.md) and committed with that release, so the
# links on GitHub always serve the binaries of the source next to them.
DIST_TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

dist:
	rm -rf dist && mkdir -p dist
	@for target in $(DIST_TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; ext=; \
		[ "$$os" = windows ] && ext=.exe; \
		echo "dist/$(BINARY)-$$os-$$arch$$ext"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/$(BINARY)-$$os-$$arch$$ext . || exit 1; \
	done
	cd dist && sha256sum $(BINARY)-* > checksums.txt

install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)

# Refresh the copied packages from local checkouts of `utils` and `contracts`.
# Maintainers only: check the repositories out at the tags above, run this, and
# read the diff — it is the whole record of what the shared code did.
#   make sync-shared UTILS=../utils CONTRACTS=../contracts
sync-shared:
	@test -d "$(UTILS)" || { echo "no checkout at $(UTILS) — pass UTILS=<path to utils $(UTILS_VERSION)>"; exit 2; }
	@test -d "$(CONTRACTS)" || { echo "no checkout at $(CONTRACTS) — pass CONTRACTS=<path to contracts $(CONTRACTS_VERSION)>"; exit 2; }
	install -m 0644 $(UTILS)/csv/csv.go app/csv/csv.go
	install -m 0644 $(UTILS)/csv/csv_test.go app/csv/csv_test.go
	install -m 0644 $(CONTRACTS)/gen/go/bloodheaven/audit/v1/report.pb.go \
		app/contract/auditv1/report.pb.go
	go build ./... && go test ./app/csv/ ./app/report/

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

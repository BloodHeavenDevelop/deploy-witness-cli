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
        build-linux-amd64 build-linux-arm64 build-all install dist bench \
        bench-score release-gate bench-baseline regression

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

# The reproducible test bench (DW-83): every scenario under bench/scenarios, staged in
# one disposable Docker-in-Docker container (pinned image, images loaded from this
# machine, nothing pulled), audited, then deployed — prediction against Docker's
# actual behaviour. Needs Docker that can run a privileged container. Results land in
# bench/out/<UTC timestamp>/. Narrow it with BENCH_ARGS="-only port_conflict".
bench: build
	go run ./bench/dwbench -bin ./$(BINARY) -commit "$$(git rev-parse --short HEAD 2>/dev/null)" $(BENCH_ARGS)

# Quality of the latest bench run, per rule, against the committed baseline
# (DW-84). RESULTS=<results.json> scores another run.
bench-score:
	go run ./bench/dwscore $(if $(RESULTS),-results $(RESULTS))

# The release criteria: a fresh bench run must pass the gate — no bench error, no
# audit side effect, no broken ground truth, no failing critical or regression
# scenario, nothing that passed in the baseline failing now, no baseline scenario
# missing. Run it before cutting a release.
release-gate: bench
	go run ./bench/dwscore -gate

# Make the latest run the new baseline. Only after release-gate passes, and with a
# CHANGELOG line saying why the baseline moved.
bench-baseline:
	@latest=$$(ls -1d bench/out/*/ 2>/dev/null | sort | tail -1); \
	test -n "$$latest" || { echo "no run under bench/out — make bench first"; exit 2; }; \
	go run ./bench/dwscore -gate -results "$${latest}results.json" && \
	install -m 0644 "$${latest}results.json" bench/baseline/results.json && \
	echo "bench/baseline/results.json <- $${latest}results.json"

# Start a regression case for a confirmed defect (DW-90): make regression NAME=DW-123-short-slug
# copies the template; fill case.yaml and input.json with artificial data, watch
# `make test` fail, then fix the CLI. The cases run in every `make test`.
regression:
	@test -n "$(NAME)" || { echo "usage: make regression NAME=<TASK>-<short-slug>"; exit 2; }
	@test ! -e app/witness/testdata/regressions/$(NAME) || { echo "$(NAME) exists"; exit 2; }
	cp -r app/witness/testdata/regressions/_template app/witness/testdata/regressions/$(NAME)
	sed -i 's/^id: TASK-short-slug/id: $(NAME)/; s/^task: TASK/task: $(firstword $(subst -, ,$(NAME)))-$(word 2,$(subst -, ,$(NAME)))/' \
		app/witness/testdata/regressions/$(NAME)/case.yaml
	@echo "app/witness/testdata/regressions/$(NAME)/: fill case.yaml and input.json"

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

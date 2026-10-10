#!/usr/bin/env bash
# Reproduces every output under docs/site-materials/outputs/ (DW-73).
#
#   make build                                  # in the repository root
#   docs/site-materials/run.sh                  # writes docs/site-materials/outputs/
#
# What it does to the host, and undoes on exit (also on Ctrl-C or failure):
#   - a python3 listener on 0.0.0.0:8080            (the "foreign process")
#   - a created, never started container "orders-api" from an image that is
#     already local (DW_BLOCKER_IMAGE, default alpine:3.21; nothing is pulled)
#   - a docker volume "dwkit-data"
#   - a docker network "dwkit-net" (10.250.73.0/24)
# It refuses to start if any of those already exists, so it never touches
# something it did not create. deploy-witness itself runs unprivileged and
# offline: no --online, --egress or --upload anywhere in this script.
#
# Environment:
#   DW_BIN            binary to run          (default: <repo>/deploy-witness)
#   DW_WORK           scratch directory      (default: mktemp -d; raw, unsanitised reports land here)
#   DW_OUT            sanitised outputs      (default: docs/site-materials/outputs)
#   DW_BLOCKER_IMAGE  image for the foreign container (must already be local)
set -euo pipefail

KIT=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$KIT/../.." && pwd)
BIN=${DW_BIN:-$REPO/deploy-witness}
WORK=${DW_WORK:-$(mktemp -d)}
OUT=${DW_OUT:-$KIT/outputs}
BLOCKER_IMAGE=${DW_BLOCKER_IMAGE:-alpine:3.21}
PORT=8080
CONTAINER=orders-api
VOLUME=dwkit-data
NETWORK=dwkit-net
SUBNET=10.250.73.0/24

die() { echo "run.sh: $*" >&2; exit 1; }

[ -x "$BIN" ] || die "no binary at $BIN — run 'make build' in $REPO first"
command -v docker >/dev/null || die "docker is required"
command -v python3 >/dev/null || die "python3 is required"
docker info >/dev/null 2>&1 || die "docker does not answer for this user"
[ -z "${DOCKER_HOST:-}" ] || die "unset DOCKER_HOST first; the scenarios set it themselves where needed"

# Refuse to run over anything that is not ours.
if ss -lntH "sport = :$PORT" | grep -q .; then die "port $PORT is already in use"; fi
if docker container inspect "$CONTAINER" >/dev/null 2>&1; then die "a container named $CONTAINER exists"; fi
if docker volume inspect "$VOLUME" >/dev/null 2>&1; then die "a volume named $VOLUME exists"; fi
if docker network inspect "$NETWORK" >/dev/null 2>&1; then die "a network named $NETWORK exists"; fi
if docker network ls -q | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' | grep -qw "$SUBNET"; then
	die "a docker network already uses $SUBNET"
fi
docker image inspect "$BLOCKER_IMAGE" >/dev/null 2>&1 \
	|| die "$BLOCKER_IMAGE is not local; set DW_BLOCKER_IMAGE to an image this host has (nothing is pulled)"

mkdir -p "$WORK/raw"
command cp -rf "$KIT/scenarios/orders" "$KIT/scenarios/shop" "$KIT/scenarios/rules" "$WORK/"

# What the sanitiser must replace — collected BEFORE the throwaway objects
# exist, so their names stay readable in the outputs.
python3 - "$WORK/context.json" "$WORK" "$BLOCKER_IMAGE" <<'PY'
import json, os, socket, subprocess, sys
out, work, blocker = sys.argv[1:4]
def lines(*cmd):
    return [l for l in subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines() if l and "<none>" not in l]
addrs = [a.split()[3].split("/")[0] for a in lines("ip", "-o", "addr", "show")]
ctx = {
    "workdir": os.path.realpath(work),
    "home": os.path.expanduser("~"),
    "user": os.environ.get("USER") or os.getlogin(),
    "hostname": socket.gethostname(),
    "addresses": [a for a in addrs if a not in ("127.0.0.1", "::1")],
    "images": lines("docker", "image", "ls", "--all", "--format", "{{.Repository}}:{{.Tag}}"),
    "image_ids": lines("docker", "image", "ls", "--all", "--format", "{{.ID}}"),
    "networks": lines("docker", "network", "ls", "--format", "{{.Name}}"),
    "volumes": lines("docker", "volume", "ls", "--format", "{{.Name}}"),
    "containers": lines("docker", "ps", "-a", "--format", "{{.Names}}"),
    "keep_images": ["nginx:1.27-alpine", blocker],
    "keep_image_ids": lines("docker", "image", "inspect", "--format", "{{slice .Id 7 19}}", blocker),
    "keep_networks": ["bridge", "host", "none"],
    "keep_ports": [8080],
}
json.dump(ctx, open(out, "w"), indent=2)
PY

LISTENER=""
CREATED_CONTAINER=""
CREATED_VOLUME=""
CREATED_NETWORK=""
cleanup() {
	[ -n "$LISTENER" ] && kill "$LISTENER" 2>/dev/null && wait "$LISTENER" 2>/dev/null || true
	[ -n "$CREATED_CONTAINER" ] && docker rm "$CONTAINER" >/dev/null 2>&1 || true
	[ -n "$CREATED_VOLUME" ] && docker volume rm "$VOLUME" >/dev/null 2>&1 || true
	[ -n "$CREATED_NETWORK" ] && docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

start_conflicts() {
	python3 -m http.server "$PORT" --bind 0.0.0.0 >/dev/null 2>&1 &
	LISTENER=$!
	docker create --pull never --name "$CONTAINER" "$BLOCKER_IMAGE" true >/dev/null
	CREATED_CONTAINER=1
	for _ in $(seq 50); do ss -lntH "sport = :$PORT" | grep -q . && return; sleep 0.1; done
	die "listener on $PORT did not come up"
}
stop_conflicts() {
	kill "$LISTENER"; wait "$LISTENER" 2>/dev/null || true; LISTENER=""
	docker rm "$CONTAINER" >/dev/null; CREATED_CONTAINER=""
}

# run <name> <project dir> <env assignments, or -> <deploy-witness args...>
# The command is run twice in the same host state: once as CSV, once with
# --format json (the tool writes one format per run).
run() {
	local name=$1 dir=$2 envs=$3; shift 3
	local raw="$WORK/raw/$name" env=()
	[ "$envs" = - ] || env=($envs)
	mkdir -p "$raw"
	{
		printf '$ cd %s\n' "$dir"
		printf '$ %sdeploy-witness %s --out ./report\n' "${env:+${env[*]} }" "$*"
	} >"$raw/terminal.txt"
	local rc=0
	(cd "$WORK/$dir" && env "${env[@]}" "$BIN" "$@" --out "$raw/csv") 2>>"$raw/terminal.txt" || rc=$?
	echo "exit $rc" >>"$raw/terminal.txt"
	rc=0
	(cd "$WORK/$dir" && env "${env[@]}" "$BIN" "$@" --format json --out "$raw/json") 2>"$raw/terminal-json.txt" || rc=$?
	echo "exit $rc" >>"$raw/terminal-json.txt"
}

PREFLIGHT=(--sections ports,witness --compose ./docker-compose.yml)

# a — conflict: a foreign process holds 8080, a foreign container holds the name.
start_conflicts
run a-conflict orders - "${PREFLIGHT[@]}"

# c1 — insufficient data: the same conflicts, but the engine does not answer.
run c1-docker-unreachable orders "DOCKER_HOST=unix:///nonexistent/docker.sock" "${PREFLIGHT[@]}"

# c2 — insufficient data: the same conflicts, but the ports section is not selected.
run c2-ports-not-selected orders - --sections witness --compose ./docker-compose.yml

# b — no conflict: the same file after both conflicts are gone.
stop_conflicts
run b-no-conflict orders - "${PREFLIGHT[@]}"

# d — external volume (known defects DW-42, DW-43): reachable engine, then none.
docker volume create "$VOLUME" >/dev/null
CREATED_VOLUME=1
run d1-external-volume shop - "${PREFLIGHT[@]}"
run d2-external-volume-docker-unreachable shop "DOCKER_HOST=unix:///nonexistent/docker.sock" "${PREFLIGHT[@]}"

docker volume rm "$VOLUME" >/dev/null; CREATED_VOLUME=""

# e — the rules the Compose file decides on its own, plus a subnet overlap
# with a network another project (here: this script) owns.
docker network create --subnet "$SUBNET" "$NETWORK" >/dev/null
CREATED_NETWORK=1
run e-manifest-rules rules - "${PREFLIGHT[@]}"

cleanup
trap - EXIT

# Sanitise into the kit.
for raw in "$WORK"/raw/*/; do
	name=$(basename "$raw")
	python3 "$KIT/sanitize.py" "$WORK/context.json" "$raw" "$OUT/$name"
done
echo "raw (unsanitised) reports: $WORK/raw — delete them when done: rm -r $WORK"
echo "sanitised outputs:         $OUT"

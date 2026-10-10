#!/usr/bin/env bash
#
# deploy-witness installer for Linux and macOS.
#
# Downloads the prebuilt binary for this machine from dist/ in this repository,
# verifies it against dist/checksums.txt, installs it to /usr/local/bin and runs it
# with every flag it was given:
#
#   read -rs AUDIT_UPLOAD_TOKEN && export AUDIT_UPLOAD_TOKEN
#   curl -fsSL https://raw.githubusercontent.com/BloodHeavenDevelop/deploy-witness-cli/main/install.sh \
#     | sudo --preserve-env=AUDIT_UPLOAD_TOKEN bash -s -- --upload https://<deployment>
#
# The token travels in the environment rather than as --upload-token, so it stays
# out of the shell history and the process list; the binary inherits it from here.
#
# With no flags it installs and stops. --no-run does the same with flags present.
# DEPLOY_WITNESS_REF picks the branch, tag or commit to download from (default main).
#
# Windows has no installer: download dist/deploy-witness-windows-amd64.exe and run it.

set -euo pipefail

BINARY_NAME="deploy-witness"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
REF="${DEPLOY_WITNESS_REF:-main}"
BASE_URL="https://raw.githubusercontent.com/BloodHeavenDevelop/deploy-witness-cli/${REF}/dist"

NO_RUN=0
CLI_ARGS=()

die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
info() { printf '  %s\n' "$*" >&2; }
step() { printf '\n==> %s\n' "$*" >&2; }

for arg in "$@"; do
    case "$arg" in
        --no-run) NO_RUN=1 ;;
        *) CLI_ARGS+=("$arg") ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root to install into ${INSTALL_PATH} — pipe into: sudo bash -s -- …"

command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 \
    || die "curl or wget is required"
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 \
    || die "sha256sum or shasum is required to verify the download"

download() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    else
        wget -qO "$2" "$1"
    fi
}

case "$(uname -s)" in
    Linux) OS="linux" ;;
    Darwin) OS="darwin" ;;
    *) die "unsupported system: $(uname -s) — on Windows, download ${BINARY_NAME}-windows-amd64.exe from ${BASE_URL}/" ;;
esac
case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "unsupported architecture: $(uname -m) (amd64 and arm64 are available)" ;;
esac
ASSET="${BINARY_NAME}-${OS}-${ARCH}"

step "Downloading ${ASSET} (${REF})"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
download "${BASE_URL}/${ASSET}" "${WORK_DIR}/${BINARY_NAME}" || die "download failed: ${BASE_URL}/${ASSET}"
download "${BASE_URL}/checksums.txt" "${WORK_DIR}/checksums.txt" || die "could not fetch checksums.txt"

step "Verifying the download"
EXPECTED="$(awk -v f="$ASSET" '$2 == f || $2 == "*"f {print $1}' "${WORK_DIR}/checksums.txt" | head -1)"
[ -n "$EXPECTED" ] || die "checksums.txt has no entry for ${ASSET}"
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "${WORK_DIR}/${BINARY_NAME}" | awk '{print $1}')"
else
    ACTUAL="$(shasum -a 256 "${WORK_DIR}/${BINARY_NAME}" | awk '{print $1}')"
fi
[ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch — refusing to install"
info "sha256 verified"

step "Installing"
mkdir -p "$(dirname "$INSTALL_PATH")"
install -m 0755 "${WORK_DIR}/${BINARY_NAME}" "$INSTALL_PATH"
info "${INSTALL_PATH} ($("$INSTALL_PATH" --version 2>/dev/null || echo 'version unknown'))"

if [ "$NO_RUN" = "1" ] || [ "${#CLI_ARGS[@]}" -eq 0 ]; then
    info "Installed, not run. See what it can execute:  ${BINARY_NAME} --commands"
    exit 0
fi

step "Running ${BINARY_NAME}"
rm -rf "$WORK_DIR"
trap - EXIT
# stdin is this script under `curl … | bash`; the CLI gets /dev/null instead.
exec "$INSTALL_PATH" "${CLI_ARGS[@]}" < /dev/null

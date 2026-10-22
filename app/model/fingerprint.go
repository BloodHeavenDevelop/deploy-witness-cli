package model

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

// fingerprintSalt keeps the fingerprint from being reversible into the machine-id it
// derives from. A bare hash of a 32-hex-character machine-id is a rainbow-table
// lookup away from the original for anybody who has a list of the ids they care
// about; a constant salt makes the digest specific to this purpose.
const fingerprintSalt = "deploy-witness/witness/level-2"

// MachineFingerprint identifies this machine, stably and without telling anyone
// anything they should not know.
//
// It is a hash of /etc/machine-id, never the id itself. A receiver needs to
// recognise the same host across two reports; it does not need an identifier that
// works as a key into anything else about the machine, and /etc/machine-id is not
// ours to publish. When the id is unreadable the answer is empty rather than
// substituted with something weaker.
func MachineFingerprint() string {
	raw, err := os.ReadFile("/etc/machine-id")
	if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
		return ""
	}
	return saltedDigest(string(raw))
}

// EngineFingerprint identifies a container engine the same way MachineFingerprint
// identifies the machine: a salted hash of the engine's own ID (`docker info`
// .ID), never the ID itself. The local report keeps the raw ID beside it so the
// person who ran the audit can match it against `docker info`; the upload carries
// this value alone. An empty ID gives an empty fingerprint.
func EngineFingerprint(engineID string) string {
	if strings.TrimSpace(engineID) == "" {
		return ""
	}
	return saltedDigest(engineID)
}

// saltedDigest is the one hashing scheme both fingerprints use.
func saltedDigest(value string) string {
	sum := sha256.Sum256([]byte(fingerprintSalt + ":" + strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

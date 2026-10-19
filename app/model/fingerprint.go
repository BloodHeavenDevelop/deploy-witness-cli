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
	sum := sha256.Sum256([]byte(fingerprintSalt + ":" + strings.TrimSpace(string(raw))))
	return hex.EncodeToString(sum[:])
}

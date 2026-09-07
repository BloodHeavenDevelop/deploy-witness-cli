package manifest

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// parseImage splits an image reference into its parts. Raw always keeps what the
// file said, because that is what a finding quotes back at the reader.
//
// The tag is left empty when the reference does not carry one. That is not the
// same statement as `:latest`, even though the two resolve identically: a rule
// that wants to say "this manifest pins nothing" can say so from either, and a
// rule that wants to quote the file must not be handed a tag the file never wrote.
func parseImage(raw string) model.ImageRef {
	ref := model.ImageRef{Raw: raw}
	rest := strings.TrimSpace(raw)

	// The digest is last and unambiguous, so it comes off first.
	if at := strings.Index(rest, "@"); at >= 0 {
		ref.Digest = rest[at+1:]
		rest = rest[:at]
	}

	// The first path segment is a registry only when it looks like a host: it has a
	// dot, it has a port, or it is exactly localhost. `team/app` has none of those,
	// and `team` is an organisation on Docker Hub rather than a registry.
	if slash := strings.Index(rest, "/"); slash >= 0 {
		head := rest[:slash]
		if head == "localhost" || strings.ContainsAny(head, ".:") {
			ref.Registry = head
			rest = rest[slash+1:]
		}
	}

	// With the registry removed, any remaining colon introduces the tag — a port
	// number cannot be confused for one any more.
	if colon := strings.LastIndex(rest, ":"); colon >= 0 {
		ref.Tag = rest[colon+1:]
		rest = rest[:colon]
	}

	ref.Repository = rest
	return ref
}

// memorySuffixes are the units compose accepts, all binary. The empty suffix is
// plain bytes.
var memorySuffixes = map[string]int64{
	"":    1,
	"b":   1,
	"k":   1 << 10,
	"kb":  1 << 10,
	"kib": 1 << 10,
	"m":   1 << 20,
	"mb":  1 << 20,
	"mib": 1 << 20,
	"g":   1 << 30,
	"gb":  1 << 30,
	"gib": 1 << 30,
	"t":   1 << 40,
	"tb":  1 << 40,
	"tib": 1 << 40,
}

// parseMemory converts a compose memory string to bytes: 512m, 1.5g, 1024k, 2G,
// or a plain byte count. Compose allows a float with a suffix, so 1.5g is legal
// and means 1610612736 rather than an error.
func parseMemory(text string) (int64, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0, fmt.Errorf("empty memory size")
	}

	split := len(trimmed)
	for split > 0 {
		c := trimmed[split-1]
		if (c >= '0' && c <= '9') || c == '.' {
			break
		}
		split--
	}

	number := strings.TrimSpace(trimmed[:split])
	suffix := strings.ToLower(strings.TrimSpace(trimmed[split:]))

	multiplier, ok := memorySuffixes[suffix]
	if !ok {
		return 0, fmt.Errorf("%q: unknown memory unit %q", text, suffix)
	}

	amount, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a memory size", text)
	}
	if amount < 0 {
		return 0, fmt.Errorf("%q is a negative memory size", text)
	}
	return int64(amount*float64(multiplier) + 0.5), nil
}

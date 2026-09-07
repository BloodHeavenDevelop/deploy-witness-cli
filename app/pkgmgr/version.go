package pkgmgr

import (
	"strings"
)

// Compare returns -1, 0 or 1 for a<b, a==b, a>b.
type Compare func(a, b string) int

// ComparatorFor picks the version ordering a distribution family actually uses.
//
// This matters for correctness, not tidiness: "1.0-10" is newer than "1.0-9"
// everywhere, but "1.0~rc1" is *older* than "1.0" only under dpkg and rpm rules,
// and a lexicographic comparison would mark a release candidate as the fix for
// the release it precedes.
func ComparatorFor(family string) Compare {
	switch family {
	case "debian":
		return CompareDebian
	case "rhel", "suse":
		return CompareRPM
	default:
		return CompareGeneric
	}
}

// ---------------------------------------------------------------- Debian

// CompareDebian implements the dpkg version ordering: epoch, then upstream
// version, then Debian revision, each with dpkg's own character ordering in
// which '~' sorts before the empty string.
func CompareDebian(a, b string) int {
	ae, au, ar := splitDebian(a)
	be, bu, br := splitDebian(b)

	if c := compareInt(ae, be); c != 0 {
		return c
	}
	if c := verrevcmp(au, bu); c != 0 {
		return sign(c)
	}
	return sign(verrevcmp(ar, br))
}

func splitDebian(v string) (epoch, upstream, revision string) {
	v = strings.TrimSpace(v)
	epoch = "0"
	if i := strings.Index(v, ":"); i >= 0 {
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndex(v, "-"); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// dpkgOrder is dpkg's character weight. Letters sort before every other
// character, and '~' sorts before everything including end-of-string.
func dpkgOrder(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	default:
		return int(c) + 256
	}
}

func verrevcmp(a, b string) int {
	at := func(s string, i int) byte {
		if i < len(s) {
			return s[i]
		}
		return 0 // stands in for C's NUL terminator
	}
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }

	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0

		for (at(a, i) != 0 && !isDigit(at(a, i))) || (at(b, j) != 0 && !isDigit(at(b, j))) {
			ac, bc := dpkgOrder(at(a, i)), dpkgOrder(at(b, j))
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		for at(a, i) == '0' {
			i++
		}
		for at(b, j) == '0' {
			j++
		}
		for isDigit(at(a, i)) && isDigit(at(b, j)) {
			if firstDiff == 0 {
				firstDiff = int(at(a, i)) - int(at(b, j))
			}
			i++
			j++
		}
		if isDigit(at(a, i)) {
			return 1
		}
		if isDigit(at(b, j)) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}

// ---------------------------------------------------------------- RPM

// CompareRPM implements rpmvercmp over epoch:version-release.
func CompareRPM(a, b string) int {
	ae, av, ar := splitRPM(a)
	be, bv, br := splitRPM(b)

	if c := compareInt(ae, be); c != 0 {
		return c
	}
	if c := rpmvercmp(av, bv); c != 0 {
		return c
	}
	// An absent release must not lose to a present one: rpm treats a query with
	// no release as "any release", and OSV ranges are routinely written that way.
	if ar == "" || br == "" {
		return 0
	}
	return rpmvercmp(ar, br)
}

func splitRPM(v string) (epoch, version, release string) {
	v = strings.TrimSpace(v)
	epoch = "0"
	if i := strings.Index(v, ":"); i >= 0 {
		e := v[:i]
		// rpm renders a missing epoch as "(none)" or an empty field.
		if e == "" || e == "(none)" {
			e = "0"
		}
		epoch, v = e, v[i+1:]
	}
	if i := strings.LastIndex(v, "-"); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}

	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	isAlpha := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}

	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Separators are not significant; skip anything that is not alphanumeric
		// and not one of rpm's two ordering markers.
		for i < len(a) && !isDigit(a[i]) && !isAlpha(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isDigit(b[j]) && !isAlpha(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		// '~' sorts before everything, so 1.0~rc1 < 1.0.
		aTilde := i < len(a) && a[i] == '~'
		bTilde := j < len(b) && b[j] == '~'
		if aTilde || bTilde {
			if !aTilde {
				return 1
			}
			if !bTilde {
				return -1
			}
			i++
			j++
			continue
		}

		// '^' sorts after the version it follows but before the next release.
		aCaret := i < len(a) && a[i] == '^'
		bCaret := j < len(b) && b[j] == '^'
		if aCaret || bCaret {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if !aCaret {
				return 1
			}
			if !bCaret {
				return -1
			}
			i++
			j++
			continue
		}

		if i >= len(a) || j >= len(b) {
			break
		}

		startI, startJ := i, j
		numeric := isDigit(a[i])
		if numeric {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}

		segA, segB := a[startI:i], b[startJ:j]
		if len(segB) == 0 {
			// One side had digits where the other had letters: digits win.
			if numeric {
				return 1
			}
			return -1
		}

		if numeric {
			segA = strings.TrimLeft(segA, "0")
			segB = strings.TrimLeft(segB, "0")
			if len(segA) != len(segB) {
				if len(segA) > len(segB) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(segA, segB); c != 0 {
			return c
		}
	}

	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

// ---------------------------------------------------------------- Generic

// CompareGeneric is a numeric-aware fallback for ecosystems with no dedicated
// rule (Alpine, Arch, anything unrecognised). It compares alternating digit and
// non-digit runs, and treats '~' as lower than the empty string, which covers the
// pre-release convention every one of them happens to share.
func CompareGeneric(a, b string) int {
	as, bs := versionSegments(a), versionSegments(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}

	for k := 0; k < n; k++ {
		var x, y string
		if k < len(as) {
			x = as[k]
		}
		if k < len(bs) {
			y = bs[k]
		}
		if x == y {
			continue
		}
		if x == "~" || y == "~" {
			if x == "~" {
				return -1
			}
			return 1
		}
		xNum, yNum := isNumeric(x), isNumeric(y)
		switch {
		case xNum && yNum:
			if c := compareInt(x, y); c != 0 {
				return c
			}
		case x == "":
			return -1
		case y == "":
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return sign(c)
			}
		}
	}
	return 0
}

func versionSegments(v string) []string {
	var out []string
	var cur strings.Builder
	var curDigit bool

	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}

	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '~':
			flush()
			out = append(out, "~")
		case c >= '0' && c <= '9':
			if cur.Len() > 0 && !curDigit {
				flush()
			}
			curDigit = true
			cur.WriteByte(c)
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			if cur.Len() > 0 && curDigit {
				flush()
			}
			curDigit = false
			cur.WriteByte(c)
		default:
			flush()
		}
	}
	flush()
	return out
}

// ---------------------------------------------------------------- helpers

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// compareInt compares two decimal strings of arbitrary length without parsing
// them — version components routinely overflow int64 (a date-stamped release such
// as 20240115123045 is fine, but some vendors go further).
func compareInt(a, b string) int {
	a = strings.TrimLeft(strings.TrimSpace(a), "0")
	b = strings.TrimLeft(strings.TrimSpace(b), "0")
	if !isNumeric(a) && a != "" {
		return sign(strings.Compare(a, b))
	}
	if len(a) != len(b) {
		if len(a) > len(b) {
			return 1
		}
		return -1
	}
	return sign(strings.Compare(a, b))
}

func sign(v int) int {
	switch {
	case v > 0:
		return 1
	case v < 0:
		return -1
	default:
		return 0
	}
}

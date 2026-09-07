package pkgmgr

import "testing"

func TestCompareDebian(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.0-0", 0},
		{"1.0", "1.1", -1},
		{"1.1", "1.0", 1},
		{"1.0-1", "1.0-2", -1},
		{"1.0.0", "1.0", 1},
		// '~' sorts before the empty string, so a release candidate precedes the
		// release it is a candidate for.
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		// The epoch dominates everything to its right.
		{"1:1.0", "2.0", 1},
		{"0:1.0", "1.0", 0},
		// Real Debian versions.
		{"3.0.11-1~deb12u2", "3.0.13-1~deb12u1", -1},
		{"2.36-9+deb12u7", "2.36-9+deb12u10", -1},
	}

	for _, c := range cases {
		if got := CompareDebian(c.a, c.b); got != c.want {
			t.Errorf("CompareDebian(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareRPM(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0", "2.0.1", -1},
		{"5.5p1", "5.5p2", -1},
		{"10xyz", "10.1xyz", -1},
		{"xyz10", "xyz10.1", -1},
		{"1b.1", "1a.1", 1},
		// '~' before, '^' after.
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0", "1.0^", -1},
		{"1.0^", "1.0", 1},
		// Epoch beats version.
		{"1:1.0", "0:2.0", 1},
		{"(none):1.0", "1.0", 0},
		// Release ordering.
		{"3.0.7-27.el9", "3.0.7-26.el9", 1},
		// A query with no release matches any release rather than losing to one.
		{"3.0.7", "3.0.7-26.el9", 0},
	}

	for _, c := range cases {
		if got := CompareRPM(c.a, c.b); got != c.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareGeneric(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0-1", "1.0-1", 0},
		{"1.0-1", "1.0-2", -1},
		// Numeric, not lexicographic: "9" must lose to "10".
		{"1.9-1", "1.10-1", -1},
		// Leading zeros are not significant.
		{"26.01-1", "26.02-1", -1},
		{"1.0", "1.0.1", -1},
		{"1.0~rc1", "1.0", -1},
		// Alpine build revisions.
		{"1.36.1-r5", "1.36.1-r7", -1},
	}

	for _, c := range cases {
		if got := CompareGeneric(c.a, c.b); got != c.want {
			t.Errorf("CompareGeneric(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestComparatorForIsAntisymmetric(t *testing.T) {
	pairs := [][2]string{
		{"1.0", "2.0"},
		{"1.0~rc1", "1.0"},
		{"1:1.0", "2.0"},
		{"1.0-1", "1.0-2"},
	}

	for _, family := range []string{"debian", "rhel", "arch", ""} {
		cmp := ComparatorFor(family)
		for _, p := range pairs {
			forward, backward := cmp(p[0], p[1]), cmp(p[1], p[0])
			if forward != -backward {
				t.Errorf("%s: cmp(%q,%q)=%d but cmp(%q,%q)=%d",
					family, p[0], p[1], forward, p[1], p[0], backward)
			}
		}
	}
}

func TestSplitNameArch(t *testing.T) {
	cases := []struct{ in, name, arch string }{
		{"openssl.x86_64", "openssl", "x86_64"},
		{"kernel.noarch", "kernel", "noarch"},
		// A dot that is part of the name must not be mistaken for an arch suffix.
		{"java-1.8.0-openjdk", "java-1.8.0-openjdk", ""},
		{"openssl", "openssl", ""},
	}

	for _, c := range cases {
		name, arch := splitNameArch(c.in)
		if name != c.name || arch != c.arch {
			t.Errorf("splitNameArch(%q) = (%q, %q), want (%q, %q)", c.in, name, arch, c.name, c.arch)
		}
	}
}

func TestStripNEVR(t *testing.T) {
	cases := []struct{ in, want string }{
		{"openssl-1:3.0.7-27.el9.x86_64", "openssl.x86_64"},
		{"kernel-5.14.0-427.el9.x86_64", "kernel.x86_64"},
	}

	for _, c := range cases {
		if got := stripNEVR(c.in); got != c.want {
			t.Errorf("stripNEVR(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

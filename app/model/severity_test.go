package model

import "testing"

func TestScoreFromVectorCVSS3(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		// Log4Shell — the canonical scope-changed 10.0.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		// v3.0 uses the same formula.
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	}

	for _, c := range cases {
		got, ok := ScoreFromVector(c.vector)
		if !ok {
			t.Errorf("ScoreFromVector(%q) reported failure", c.vector)
			continue
		}
		if got != c.want {
			t.Errorf("ScoreFromVector(%q) = %.1f, want %.1f", c.vector, got, c.want)
		}
	}
}

func TestScoreFromVectorCVSS2(t *testing.T) {
	got, ok := ScoreFromVector("AV:N/AC:L/Au:N/C:P/I:P/A:P")
	if !ok {
		t.Fatal("v2 vector was not recognised")
	}
	if got != 7.5 {
		t.Errorf("v2 base score = %.1f, want 7.5", got)
	}
}

func TestScoreFromVectorRejectsUnscorable(t *testing.T) {
	// v4.0 uses a lookup-table model, not a formula; claiming a score would be
	// worse than admitting we cannot compute one.
	if _, ok := ScoreFromVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"); ok {
		t.Error("CVSS v4.0 should not be scored")
	}
	if _, ok := ScoreFromVector(""); ok {
		t.Error("an empty vector should not be scored")
	}
	if _, ok := ScoreFromVector("CVSS:3.1/AV:N"); ok {
		t.Error("an incomplete v3 vector should not be scored")
	}
}

func TestScoreFromVectorAcceptsBareNumber(t *testing.T) {
	got, ok := ScoreFromVector("9.1")
	if !ok || got != 9.1 {
		t.Errorf("ScoreFromVector(\"9.1\") = (%v, %v), want (9.1, true)", got, ok)
	}
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{"Critical", SeverityCritical},
		{"Important/Sec.", SeverityHigh}, // dnf's spelling
		{"HIGH", SeverityHigh},
		{"Moderate", SeverityMedium},
		{"low", SeverityLow},
		{"unimportant", SeverityLow},
		{"", SeverityUnknown},
		{"whatever", SeverityUnknown},
	}

	for _, c := range cases {
		if got := ParseSeverity(c.in); got != c.want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSeverityFromScore(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{10.0, SeverityCritical},
		{9.0, SeverityCritical},
		{8.9, SeverityHigh},
		{7.0, SeverityHigh},
		{6.9, SeverityMedium},
		{4.0, SeverityMedium},
		{3.9, SeverityLow},
		{0.1, SeverityLow},
		{0, SeverityNone},
	}

	for _, c := range cases {
		if got := SeverityFromScore(c.score); got != c.want {
			t.Errorf("SeverityFromScore(%.1f) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestUnknownOutranksGraded(t *testing.T) {
	// An ungraded finding must survive a --min-severity=medium filter, so its
	// rank has to sit above medium.
	if SeverityUnknown.Rank() <= SeverityMedium.Rank() {
		t.Error("unknown must rank above medium so it is never filtered out silently")
	}
	if SeverityUnknown.Rank() >= SeverityHigh.Rank() {
		t.Error("unknown must rank below high so real high findings sort first")
	}
}

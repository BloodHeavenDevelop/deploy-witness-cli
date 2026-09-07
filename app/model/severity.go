package model

import (
	"math"
	"strconv"
	"strings"
)

// Severity is the normalised severity vocabulary the whole report speaks. Every
// distribution and every advisory feed spells its levels differently; they are
// mapped onto these five values plus `unknown` exactly once, at ingest, so the
// CSV never mixes "Important", "high" and "HIGH" in one column.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityNone     Severity = "none"
	SeverityUnknown  Severity = "unknown"
)

// Rank orders severities for filtering and sorting. `unknown` deliberately ranks
// above `none` and `low`: a finding we could not grade is not evidence that it is
// harmless, and dropping it under `--min-severity=medium` would hide it.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityUnknown:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ParseSeverity normalises a vendor severity label. dnf emits "Important/Sec.",
// Ubuntu "high", SUSE "important", OSV "MODERATE" — all land here.
func ParseSeverity(raw string) Severity {
	v := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.Index(v, "/"); i > 0 { // dnf: "Important/Sec."
		v = strings.TrimSpace(v[:i])
	}
	v = strings.TrimSuffix(v, ".")

	switch v {
	case "critical", "crit", "urgent", "severe":
		return SeverityCritical
	case "important", "high":
		return SeverityHigh
	case "moderate", "medium", "mod":
		return SeverityMedium
	case "low", "minor", "negligible", "unimportant":
		return SeverityLow
	case "none", "no severity", "not yet assigned":
		return SeverityNone
	default:
		return SeverityUnknown
	}
}

// SeverityFromScore applies the CVSS v3 qualitative rating scale.
func SeverityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// ScoreFromVector computes a CVSS base score from a vector string. OSV records
// carry vectors, not scores, so without this every OSV-sourced finding would be
// severity `unknown` — which is precisely the column an operator sorts by.
//
// CVSS v3.0/v3.1 and v2 are computed. v4.0 uses a lookup-table scoring model that
// is not reproducible from a formula, so it returns false and the caller falls
// back to whatever qualitative label the record carries.
func ScoreFromVector(vector string) (float64, bool) {
	v := strings.TrimSpace(vector)
	if v == "" {
		return 0, false
	}
	// A bare number is also accepted — some feeds put the score in this field.
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return f, true
	}

	metrics := map[string]string{}
	var prefix string
	for i, part := range strings.Split(v, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		if i == 0 && strings.EqualFold(kv[0], "CVSS") {
			prefix = kv[1]
			continue
		}
		metrics[strings.ToUpper(kv[0])] = strings.ToUpper(kv[1])
	}

	switch {
	case strings.HasPrefix(prefix, "3."):
		return cvss3Base(metrics)
	case strings.HasPrefix(prefix, "4."):
		return 0, false
	case prefix == "":
		// v2 vectors carry no "CVSS:x.y" prefix.
		return cvss2Base(metrics)
	default:
		return 0, false
	}
}

func cvss3Base(m map[string]string) (float64, bool) {
	scopeChanged := m["S"] == "C"

	av, ok := pick(m, "AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if !ok {
		return 0, false
	}
	ac, ok := pick(m, "AC", map[string]float64{"L": 0.77, "H": 0.44})
	if !ok {
		return 0, false
	}
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	}
	pr, ok := pick(m, "PR", prTable)
	if !ok {
		return 0, false
	}
	ui, ok := pick(m, "UI", map[string]float64{"N": 0.85, "R": 0.62})
	if !ok {
		return 0, false
	}

	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, okC := pick(m, "C", cia)
	i, okI := pick(m, "I", cia)
	a, okA := pick(m, "A", cia)
	if !okC || !okI || !okA {
		return 0, false
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	score := impact + exploitability
	if scopeChanged {
		score *= 1.08
	}
	return roundUp(math.Min(score, 10)), true
}

func cvss2Base(m map[string]string) (float64, bool) {
	av, ok := pick(m, "AV", map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0})
	if !ok {
		return 0, false
	}
	ac, ok := pick(m, "AC", map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71})
	if !ok {
		return 0, false
	}
	au, ok := pick(m, "AU", map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704})
	if !ok {
		return 0, false
	}

	cia := map[string]float64{"N": 0, "P": 0.275, "C": 0.660}
	c, okC := pick(m, "C", cia)
	i, okI := pick(m, "I", cia)
	a, okA := pick(m, "A", cia)
	if !okC || !okI || !okA {
		return 0, false
	}

	impact := 10.41 * (1 - (1-c)*(1-i)*(1-a))
	exploitability := 20 * av * ac * au
	f := 1.176
	if impact == 0 {
		f = 0
	}
	score := ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f
	return math.Round(score*10) / 10, true
}

func pick(m map[string]string, key string, table map[string]float64) (float64, bool) {
	v, ok := table[m[key]]
	return v, ok
}

// roundUp is the CVSS v3.1 "Roundup" function. Plain math.Ceil on a float is not
// equivalent — 8.6 - 0.0 is representable as 8.599999999999999 and would round to
// 8.7, producing scores no calculator agrees with.
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000.0
	}
	return (math.Floor(float64(i)/10000) + 1) / 10.0
}

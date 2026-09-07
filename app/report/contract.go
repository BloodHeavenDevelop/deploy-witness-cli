package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	auditv1 "github.com/BloodHeavenDevelop/contracts/gen/go/bloodheaven/audit/v1"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// This file is the one place deploy-witness speaks the platform's audit contract.
//
// The contract lives in the `contracts` repository and is shared with witness,
// which produces levels 0 and 1 of the same product. Duplicating the shape here
// instead would mean the divergence is discovered in production, on the first
// upload — so the generated types are imported, and the conversion is confined to
// this file. Nothing else in the tool knows protobuf exists.

// SchemaVersion is what this build produces and what a receiver checks first. An
// agent built months ago and run today must be told its report is not understood,
// rather than having it half-read.
const SchemaVersion = "1.0"

// levelServer is the level of every report this tool makes: 2, the on-server
// witness. Levels 0 and 1 are the domain-side checks, and they are not this
// binary's business.
const levelServer = 2

// Contract converts a finished report into the shared audit contract.
//
// Only the witness section maps: the contract is a *findings* document, and
// deploy-witness's package inventory, pending updates and CVE list have no place in
// it. They stay in the CSV, which is where a person reads them. Sending them would
// be volunteering a full software inventory of somebody's production host to a
// remote service that did not ask for one.
func Contract(r *model.Report) *auditv1.Report {
	out := &auditv1.Report{
		SchemaVersion:     SchemaVersion,
		Level:             levelServer,
		ServerFingerprint: fingerprint(),
		ServerHostname:    r.Hostname,
		GeneratedAt:       r.GeneratedAt.UTC().Format(time.RFC3339),
		StaleAfter:        r.GeneratedAt.UTC().Add(staleAfter).Format(time.RFC3339),
		Producer:          fmt.Sprintf("%s/%s", r.Tool, r.Version),
	}

	for _, finding := range r.Findings {
		out.Findings = append(out.Findings, contractFinding(finding))
	}
	for _, section := range r.Sections {
		out.Collectors = append(out.Collectors, contractCollector(section))
	}
	for _, change := range r.Changes {
		out.Changes = append(out.Changes, &auditv1.ChangeItem{
			Kind: change.Kind, Target: change.Target, Detail: change.Detail,
		})
	}
	for _, item := range r.Rollback {
		out.Rollback = append(out.Rollback, &auditv1.RollbackItem{
			Kind: item.Kind, Available: item.Available, Detail: item.Detail,
		})
	}
	// The whole journal, including any refusal. A client who ran an unfamiliar
	// binary on their production host is owed the full list of what it did.
	for _, command := range r.Commands {
		out.CommandJournal = append(out.CommandJournal,
			fmt.Sprintf("%s — %s (%s)", command.Command, command.Outcome, command.Duration))
	}

	return out
}

// staleAfter is how long a level 2 report is presented as current. Server state
// drifts; a week later the picture may not hold, and the reader is told so rather
// than left to guess.
const staleAfter = 7 * 24 * time.Hour

func contractFinding(f model.Finding) *auditv1.Finding {
	out := &auditv1.Finding{
		Code:         f.Code,
		Collector:    f.Collector,
		Category:     contractCategory(f.Category),
		Severity:     contractSeverity(f.Severity),
		Subject:      f.Subject,
		Title:        f.Title,
		Description:  f.Description,
		WhyItMatters: f.WhyItMatters,
		WhatToDo:     f.WhatToDo,
		Confidence:   contractConfidence(f.Confidence),
		SortOrder:    int32(f.SortOrder),
	}
	for _, e := range f.Evidence {
		out.Evidence = append(out.Evidence, &auditv1.Evidence{
			Command:    e.Command,
			Output:     e.Output,
			Truncated:  e.Truncated,
			CapturedAt: e.CapturedAt,
		})
	}
	return out
}

func contractCollector(section model.SectionResult) *auditv1.CollectorResult {
	duration, _ := time.ParseDuration(section.Duration)
	return &auditv1.CollectorResult{
		Collector:  string(section.Section),
		Status:     contractStatus(section.Status),
		Note:       strings.Join(section.Notes, "; "),
		DurationMs: int32(duration.Milliseconds()),
	}
}

func contractSeverity(s model.FindingSeverity) auditv1.Severity {
	switch s {
	case model.FindingBlocker:
		return auditv1.Severity_SEVERITY_BLOCKER
	case model.FindingWarning:
		return auditv1.Severity_SEVERITY_WARNING
	case model.FindingInfo:
		return auditv1.Severity_SEVERITY_INFO
	default:
		return auditv1.Severity_SEVERITY_UNSPECIFIED
	}
}

func contractCategory(category string) auditv1.Category {
	switch category {
	case model.CategoryConflict:
		return auditv1.Category_CATEGORY_CONFLICT
	case model.CategoryResource:
		return auditv1.Category_CATEGORY_RESOURCE
	case model.CategorySecurity:
		return auditv1.Category_CATEGORY_SECURITY
	case model.CategoryExpiry:
		return auditv1.Category_CATEGORY_EXPIRY
	case model.CategoryMissing:
		return auditv1.Category_CATEGORY_MISSING
	default:
		return auditv1.Category_CATEGORY_UNSPECIFIED
	}
}

func contractConfidence(c model.Confidence) auditv1.Confidence {
	switch c {
	case model.ConfidenceHigh:
		return auditv1.Confidence_CONFIDENCE_HIGH
	case model.ConfidenceMedium:
		return auditv1.Confidence_CONFIDENCE_MEDIUM
	case model.ConfidenceLow:
		return auditv1.Confidence_CONFIDENCE_LOW
	default:
		return auditv1.Confidence_CONFIDENCE_UNSPECIFIED
	}
}

// contractStatus maps a section outcome onto the contract's collector status.
//
// `partial` maps to PARTIAL and not to OK. It first went out as OK, and the receiving
// service duly stored a run that had degraded on an unprivileged host as a complete
// audit of that machine — the note survived on the collector row while the report as
// a whole claimed to be finished. That is precisely the failure this repository's
// second promise exists to prevent, so the contract gained the state rather than the
// mapping gaining a compromise.
func contractStatus(status model.Status) auditv1.CollectorStatus {
	switch status {
	case model.StatusOk:
		return auditv1.CollectorStatus_COLLECTOR_STATUS_OK
	case model.StatusPartial:
		return auditv1.CollectorStatus_COLLECTOR_STATUS_PARTIAL
	case model.StatusFailed:
		return auditv1.CollectorStatus_COLLECTOR_STATUS_FAILED
	case model.StatusSkipped:
		return auditv1.CollectorStatus_COLLECTOR_STATUS_SKIPPED
	default:
		return auditv1.CollectorStatus_COLLECTOR_STATUS_UNSPECIFIED
	}
}

// fingerprintSalt keeps the fingerprint from being reversible into the machine-id it
// derives from. A bare hash of a 32-hex-character machine-id is a rainbow-table
// lookup away from the original for anybody who has a list of the ids they care
// about; a constant salt makes the digest specific to this purpose.
const fingerprintSalt = "deploy-witness/witness/level-2"

// fingerprint identifies this machine to the receiving service, stably and without
// telling it anything it should not know.
//
// It is a hash of /etc/machine-id, never the id itself. The receiver needs to
// recognise the same host across two uploads; it does not need an identifier that
// works as a key into anything else about the machine, and /etc/machine-id is not
// ours to publish. When the id is unreadable the answer is empty rather than
// substituted with something weaker, and the receiver stores the report without a
// host identity.
func fingerprint() string {
	raw, err := os.ReadFile("/etc/machine-id")
	if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(fingerprintSalt + ":" + strings.TrimSpace(string(raw))))
	return hex.EncodeToString(sum[:])
}

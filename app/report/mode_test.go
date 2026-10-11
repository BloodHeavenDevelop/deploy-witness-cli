package report

import (
	"strings"
	"testing"
	"time"

	auditv1 "github.com/BloodHeavenDevelop/deploy-witness-cli/app/contract/auditv1"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

func reportWith(mode model.Mode, witness *model.SectionResult) *model.Report {
	r := &model.Report{GeneratedAt: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC), Tool: "deploy-witness",
		Version: "test", Hostname: "h", Mode: mode}
	r.Sections = []model.SectionResult{{Section: model.SectionPorts, Status: model.StatusOk}}
	if witness != nil {
		r.Sections = append(r.Sections, *witness)
	}
	if mode == model.ModeComposePreflight {
		r.Manifest = &model.Manifest{Path: "/srv/app/docker-compose.yml"}
	}
	return r
}

func summaryRow(rows []model.SummaryRow, section string) (model.SummaryRow, bool) {
	for _, row := range rows {
		if row.Section == section {
			return row, true
		}
	}
	return model.SummaryRow{}, false
}

// DW-70: summary.csv says which kind of run this was, and a host audit's preflight
// row is skipped — never ok.
func TestSummaryLabelsTheMode(t *testing.T) {
	host := reportWith(model.ModeHostAudit, &model.SectionResult{
		Section: model.SectionWitness, Status: model.StatusSkipped, Notes: []string{"host-audit: …"}})
	rows := summaryRows(host)

	if !strings.HasPrefix(rows[0].Notes, "host audit:") {
		t.Errorf("report row = %q, want it labelled host audit", rows[0].Notes)
	}
	pre, ok := summaryRow(rows, "preflight")
	if !ok || pre.Status != string(model.StatusSkipped) || !strings.HasPrefix(pre.Notes, "host-audit:") {
		t.Errorf("preflight row = %+v, want skipped host-audit", pre)
	}

	cases := []struct {
		witness *model.SectionResult
		status  model.Status
		phrase  string
	}{
		{&model.SectionResult{Section: model.SectionWitness, Status: model.StatusOk}, model.StatusOk, "was compared"},
		{&model.SectionResult{Section: model.SectionWitness, Status: model.StatusPartial}, model.StatusPartial, "could not be made"},
		{&model.SectionResult{Section: model.SectionWitness, Status: model.StatusFailed}, model.StatusFailed, "not a preflight result"},
		{nil, model.StatusFailed, "not a preflight result"},
	}
	for _, tc := range cases {
		rows := summaryRows(reportWith(model.ModeComposePreflight, tc.witness))
		if !strings.HasPrefix(rows[0].Notes, "Compose preflight:") {
			t.Errorf("report row = %q, want it labelled Compose preflight", rows[0].Notes)
		}
		pre, _ := summaryRow(rows, "preflight")
		if pre.Status != string(tc.status) || !strings.HasPrefix(pre.Notes, "compose-preflight:") ||
			!strings.Contains(pre.Notes, tc.phrase) {
			t.Errorf("witness %+v: preflight row = %+v, want %s / %q", tc.witness, pre, tc.status, tc.phrase)
		}
	}
}

// The upload carries the host audit's witness row as a SKIPPED collector with the
// mode in its note: without it, a host audit would arrive as a run with every
// collector complete and no findings.
func TestContractCarriesTheHostAuditWitnessRow(t *testing.T) {
	r := reportWith(model.ModeHostAudit, &model.SectionResult{
		Section: model.SectionWitness, Status: model.StatusSkipped, Duration: "0s",
		Notes: []string{"host-audit: no --compose was given"}})
	var witness *auditv1.CollectorResult
	for _, c := range Contract(r).Collectors {
		if c.Collector == string(model.SectionWitness) {
			witness = c
		}
	}
	if witness == nil || witness.Status != auditv1.CollectorStatus_COLLECTOR_STATUS_SKIPPED ||
		!strings.HasPrefix(witness.Note, "host-audit:") {
		t.Fatalf("witness collector = %+v, want SKIPPED with a host-audit note", witness)
	}
}

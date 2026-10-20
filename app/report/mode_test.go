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

// DW-70: summary.csv says which kind of run this was. In a host audit the preflight
// and witness rows are not applicable — outside the run's scope — and no row of the
// summary is skipped, partial or failed on account of the missing Compose file.
func TestSummaryLabelsTheMode(t *testing.T) {
	host := reportWith(model.ModeHostAudit, &model.SectionResult{
		Section: model.SectionWitness, Status: model.StatusNotApplicable, Notes: []string{"host-audit: …"}})
	rows := summaryRows(host)

	if !strings.HasPrefix(rows[0].Notes, "host audit:") {
		t.Errorf("report row = %q, want it labelled host audit", rows[0].Notes)
	}
	pre, ok := summaryRow(rows, "preflight")
	if !ok || pre.Status != string(model.StatusNotApplicable) || !strings.HasPrefix(pre.Notes, "host-audit: not applicable") {
		t.Errorf("preflight row = %+v, want not-applicable host-audit", pre)
	}
	for _, row := range rows {
		switch model.Status(row.Status) {
		case model.StatusSkipped, model.StatusPartial, model.StatusFailed:
			t.Errorf("host audit row %q is %s; nothing in it is incomplete", row.Section, row.Status)
		}
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

// The upload leaves a host audit's not-applicable witness row out: every contract
// status but OK counts against completeness on the receiving side, and the receiver
// reads "no witness collector" as a host audit. A preflight always sends one.
func TestContractLeavesTheHostAuditWitnessOut(t *testing.T) {
	r := reportWith(model.ModeHostAudit, &model.SectionResult{
		Section: model.SectionWitness, Status: model.StatusNotApplicable, Duration: "0s",
		Notes: []string{"host-audit: not applicable"}})
	collectors := Contract(r).Collectors
	if len(collectors) != 1 || collectors[0].Collector != string(model.SectionPorts) {
		t.Fatalf("collectors = %v, want only ports", collectors)
	}
	for _, c := range collectors {
		if c.Status != auditv1.CollectorStatus_COLLECTOR_STATUS_OK {
			t.Errorf("collector %s = %s, want OK", c.Collector, c.Status)
		}
	}

	for _, status := range []model.Status{model.StatusOk, model.StatusPartial, model.StatusFailed} {
		r := reportWith(model.ModeComposePreflight, &model.SectionResult{Section: model.SectionWitness, Status: status})
		found := false
		for _, c := range Contract(r).Collectors {
			found = found || c.Collector == string(model.SectionWitness)
		}
		if !found {
			t.Errorf("preflight with witness %s: no witness collector in the upload", status)
		}
	}
}

// DW-79: rollback.csv renders an item that could not be verified as `unknown`, not
// `false`.
func TestRollbackCSVRendersUnknown(t *testing.T) {
	r := reportWith(model.ModeComposePreflight, &model.SectionResult{Section: model.SectionWitness, Status: model.StatusOk})
	r.Rollback = []model.RollbackItem{
		model.NewRollbackItem("image-tag", model.RollbackAvailable, "a"),
		model.NewRollbackItem("volume-backup", model.RollbackUnavailable, "b"),
		model.NewRollbackItem("snapshot", model.RollbackUnverified, "unable to verify: c"),
	}
	rows := rollbackRows(r)
	got := []string{rows[0].Available, rows[1].Available, rows[2].Available}
	if strings.Join(got, ",") != "true,false,unknown" {
		t.Errorf("Available = %v", got)
	}
	for _, item := range Contract(r).Rollback {
		if item.Kind == "snapshot" && (item.Available || !strings.HasPrefix(item.Detail, "unable to verify:")) {
			t.Errorf("contract snapshot = %+v", item)
		}
	}
}

// DW-80: the outcome of every rule is a table of its own, every finding states its
// outcome in an appended column, and the preflight row keeps the result (what was
// concluded) apart from the status (whether the comparison ran).
func TestOutcomesAreReportedApartFromStatus(t *testing.T) {
	r := reportWith(model.ModeComposePreflight, &model.SectionResult{Section: model.SectionWitness, Status: model.StatusOk})
	r.Rules = []model.RuleResult{
		{Code: "witness.port_conflict", Rule: "port-conflict", Outcome: model.OutcomeUnknown, Reason: "r", Requires: "q"},
		{Code: "witness.no_healthcheck", Rule: "healthcheck", Outcome: model.OutcomeNoProblem, Reason: "r", Requires: "q"},
	}
	r.Findings = []model.Finding{{Code: "witness.port_conflict", Severity: model.FindingWarning,
		Outcome: model.OutcomeUnknown, Evidence: []model.Evidence{{Command: "ss"}}}}

	var witness, rules *table
	for _, tb := range tables(r) {
		tb := tb
		switch tb.name {
		case "witness":
			witness = &tb
		case "rules":
			rules = &tb
		}
	}
	if rules == nil || len(rules.rows) != 2 {
		t.Fatalf("rules.csv = %+v", rules)
	}
	if witness == nil || witness.headers[len(witness.headers)-1] != "Outcome" {
		t.Fatalf("witness.csv must append Outcome as its last column: %+v", witness)
	}
	data, err := render(*witness)
	if err != nil || !strings.Contains(string(data), "unknown") {
		t.Errorf("witness.csv = %s (%v)", data, err)
	}

	pre, _ := summaryRow(summaryRows(r), "preflight")
	if pre.Status != string(model.StatusOk) || !strings.Contains(pre.Notes, "0 rule(s) found a problem, 1 could not decide") {
		t.Errorf("preflight row = %+v", pre)
	}
}

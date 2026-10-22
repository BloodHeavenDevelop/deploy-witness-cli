package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/witness"
)

// A preflight report describes one plan on one engine at one moment, and nothing
// else. Recheck answers, just before deploying, whether a report the engineer holds
// still confirms the run they are about to make: the plan is resolved again exactly
// as the audit resolved it, the engine is asked who it is, and the report's age and
// rule set are compared. Nothing is collected and nothing is written; the report
// stays the only record, held by whoever ran the audit — DeployWitness keeps none.

// RecheckResult is the verdict.
type RecheckResult struct {
	// Confirmed is true only when every comparison held.
	Confirmed bool
	// Lines is what was compared and how it came out, one line each.
	Lines []string
}

// Recheck compares the report at path with the plan this configuration describes
// and with the engine on this host now. An unreadable report, or one that is not a
// Compose preflight, is an error (exit 2); anything that does not match is a
// verdict (exit 4).
func (a *Auditor) Recheck(path string, maxAge time.Duration, now time.Time) (RecheckResult, error) {
	var res RecheckResult
	raw, err := os.ReadFile(path)
	if err != nil {
		return res, fmt.Errorf("--recheck %q: %w", path, err)
	}
	var doc struct {
		Audit *model.Report `json:"audit"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Audit == nil {
		return res, fmt.Errorf("--recheck %q: not a report.json written by deploy-witness (--format json)", path)
	}
	old := doc.Audit
	if old.Mode != model.ModeComposePreflight || old.Plan == nil || old.Provenance == nil {
		return res, fmt.Errorf("--recheck %q: the report is not a Compose preflight with a recorded plan "+
			"(a host audit, or a report from before plans were recorded) — run the preflight again", path)
	}

	if err := a.Prepare(); err != nil {
		return res, err
	}

	ok := true
	check := func(held bool, pass, fail string) {
		if held {
			res.Lines = append(res.Lines, "ok: "+pass)
			return
		}
		ok = false
		res.Lines = append(res.Lines, "re-run: "+fail)
	}

	check(a.plan.Digest == old.Plan.Digest,
		"the plan is the one the report checked ("+a.plan.Digest+")",
		fmt.Sprintf("the plan changed since the report: it checked %s, the plan now resolves to %s — the report "+
			"says nothing about this run", old.Plan.Digest, a.plan.Digest))

	engineID := a.currentEngineID()
	switch {
	case old.Plan.Engine.ID == "":
		check(false, "", "the report recorded no engine identity, so it cannot be tied to this engine")
	case engineID == "":
		check(false, "", "the container engine did not identify itself now, so whether it is the engine the "+
			"report inspected ("+old.Plan.Engine.ID+") is unknown")
	default:
		check(engineID == old.Plan.Engine.ID, "the engine is the one the report inspected ("+engineID+")",
			fmt.Sprintf("the report inspected engine %s, this host's engine is %s — another server, or a "+
				"reinstalled engine", old.Plan.Engine.ID, engineID))
	}

	finished, err := time.Parse(time.RFC3339, old.Provenance.FinishedAt)
	switch {
	case err != nil:
		check(false, "", "the report records no finishing time")
	case now.Before(finished):
		check(false, "", fmt.Sprintf("the report finished at %s, which is in the future of this host's clock "+
			"(%s) — one of the two clocks is wrong", old.Provenance.FinishedAt, stamp(now)))
	default:
		// The report's times have a resolution of one second, so its age is at
		// least that much: a report is never younger than the second it finished in.
		age := now.Sub(finished)
		if age < time.Second {
			age = time.Second
		}
		shown := age.Round(time.Second)
		check(age <= maxAge, fmt.Sprintf("the report is %s old (limit %s)", shown, maxAge),
			fmt.Sprintf("the report is %s old, past the %s limit (--max-age): the host may have changed since",
				shown, maxAge))
	}

	check(old.Provenance.RulesVersion == witness.RulesVersion,
		"the rules are the ones the report was made with (rules "+witness.RulesVersion+")",
		fmt.Sprintf("the report was made with rules %s, this build has rules %s", old.Provenance.RulesVersion,
			witness.RulesVersion))
	if len(old.Provenance.TimeChecks) > 0 {
		check(false, "", fmt.Sprintf("the report's own timeline was inconsistent (%d time check(s) failed)",
			len(old.Provenance.TimeChecks)))
	}

	res.Confirmed = ok
	return res, nil
}

// currentEngineID asks the local engine who it is, with the same allowlisted query
// the audit uses.
func (a *Auditor) currentEngineID() string {
	kind := ""
	switch {
	case run.Available("docker"):
		kind = "docker"
	case run.Available("podman"):
		kind = "podman"
	default:
		return ""
	}
	out, err := a.runner.Output(kind, "info", "--format", "{{json .}}")
	if err != nil {
		return ""
	}
	var info struct {
		ID string `json:"ID"`
	}
	if json.Unmarshal([]byte(out), &info) != nil {
		return ""
	}
	return info.ID
}

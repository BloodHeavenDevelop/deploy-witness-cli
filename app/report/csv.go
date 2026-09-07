// Package report renders an audit to CSV.
package report

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/utils/csv"
)

// table is one CSV file: a name, the column headers, the field paths behind them
// and the rows.
type table struct {
	name    string
	headers []string
	paths   []string
	rows    []any
}

// Tables lays out the report. Column order is part of the contract: anything
// consuming these files reads by position as often as by header, so new columns
// are appended, never inserted.
func tables(r *model.Report) []table {
	return []table{
		{
			name:    "summary",
			headers: []string{"Section", "Status", "Records", "Critical", "High", "Duration", "Notes"},
			paths:   []string{"section", "status", "records", "critical", "high", "duration", "notes"},
			rows:    anySlice(summaryRows(r)),
		},
		{
			name:    string(model.SectionSystem),
			headers: []string{"Category", "Key", "Value", "Source"},
			paths:   []string{"category", "key", "value", "source"},
			rows:    anySlice(r.System),
		},
		{
			name:    string(model.SectionUpdates),
			headers: []string{"Package", "Installed", "Available", "Arch", "Repository", "Security", "Severity", "Advisory", "Source"},
			paths:   []string{"package", "installed", "available", "arch", "repository", "security", "severity", "advisory", "source"},
			rows:    anySlice(r.Updates),
		},
		{
			name:    string(model.SectionVulnerabilities),
			headers: []string{"Package", "Installed", "Fixed in", "Severity", "Score", "Id", "Aliases", "Summary", "Ecosystem", "Source", "Reference"},
			paths:   []string{"package", "installed", "fixedIn", "severity", "score", "id", "aliases", "summary", "ecosystem", "source", "reference"},
			rows:    anySlice(r.Vulnerabilities),
		},
		{
			name:    string(model.SectionPorts),
			headers: []string{"Protocol", "Address", "Port", "Exposure", "State", "PID", "Process", "User", "Command"},
			paths:   []string{"protocol", "address", "port", "exposure", "state", "pid", "process", "user", "command"},
			rows:    anySlice(r.Ports),
		},
		{
			name:    string(model.SectionServices),
			headers: []string{"Name", "Description", "Load", "Active", "Sub", "Enabled", "Main PID", "User", "Active since", "Manager"},
			paths:   []string{"name", "description", "load", "active", "sub", "enabled", "mainPid", "user", "since", "manager"},
			rows:    anySlice(r.Services),
		},
		{
			name: string(model.SectionWitness),
			headers: []string{"Code", "Collector", "Category", "Severity", "Subject", "Title", "Description",
				"Why it matters", "What to do", "Confidence", "Evidence"},
			paths: []string{"code", "collector", "category", "severity", "subject", "title", "description",
				"whyItMatters", "whatToDo", "confidence", "evidenceSummary"},
			rows: anySlice(findingRows(r)),
		},
		{
			// The evidence gets a file of its own rather than being crushed into one
			// cell: a finding may have several pieces, each with a multi-line capture,
			// and the whole promise is that the reader can check them.
			name:    "evidence",
			headers: []string{"Code", "Subject", "Command", "Output", "Truncated", "Captured at"},
			paths:   []string{"code", "subject", "command", "output", "truncated", "capturedAt"},
			rows:    anySlice(evidenceRows(r)),
		},
		{
			name:    "changes",
			headers: []string{"Kind", "Target", "Detail"},
			paths:   []string{"kind", "target", "detail"},
			rows:    anySlice(r.Changes),
		},
		{
			name:    "rollback",
			headers: []string{"Kind", "Available", "Detail"},
			paths:   []string{"kind", "available", "detail"},
			rows:    anySlice(r.Rollback),
		},
		{
			// Not a section: the journal is what the run did, not something it
			// found. It is written unconditionally so that "the audit ran no
			// commands at all" is a visible claim rather than a missing file.
			name:    "commands",
			headers: []string{"Command", "Started at", "Duration", "Exit code", "Outcome"},
			paths:   []string{"command", "startedAt", "duration", "exitCode", "outcome"},
			rows:    anySlice(r.Commands),
		},
	}
}

// findingRow is one witness finding as a CSV row. It exists because a finding
// carries structured evidence, and a CSV cell cannot; the count and the first
// command go here, and evidence.csv holds the rest.
type findingRow struct {
	Code            string `json:"code"`
	Collector       string `json:"collector"`
	Category        string `json:"category"`
	Severity        string `json:"severity"`
	Subject         string `json:"subject"`
	Title           string `json:"title"`
	Description     string `json:"description"`
	WhyItMatters    string `json:"whyItMatters"`
	WhatToDo        string `json:"whatToDo"`
	Confidence      string `json:"confidence"`
	EvidenceSummary string `json:"evidenceSummary"`
}

func findingRows(r *model.Report) []findingRow {
	out := make([]findingRow, 0, len(r.Findings))
	for _, f := range r.Findings {
		summary := "none"
		if len(f.Evidence) > 0 {
			summary = fmt.Sprintf("%d in evidence.csv, first: %s", len(f.Evidence), f.Evidence[0].Command)
		}
		out = append(out, findingRow{
			Code: f.Code, Collector: f.Collector, Category: f.Category,
			Severity: string(f.Severity), Subject: f.Subject, Title: f.Title,
			Description: f.Description, WhyItMatters: f.WhyItMatters, WhatToDo: f.WhatToDo,
			Confidence: string(f.Confidence), EvidenceSummary: summary,
		})
	}
	return out
}

// evidenceRow ties one capture back to the finding it supports.
type evidenceRow struct {
	Code       string `json:"code"`
	Subject    string `json:"subject"`
	Command    string `json:"command"`
	Output     string `json:"output"`
	Truncated  bool   `json:"truncated"`
	CapturedAt string `json:"capturedAt"`
}

func evidenceRows(r *model.Report) []evidenceRow {
	var out []evidenceRow
	for _, f := range r.Findings {
		for _, e := range f.Evidence {
			out = append(out, evidenceRow{
				Code: f.Code, Subject: f.Subject, Command: e.Command,
				Output: e.Output, Truncated: e.Truncated, CapturedAt: e.CapturedAt,
			})
		}
	}
	return out
}

func summaryRows(r *model.Report) []model.SummaryRow {
	rows := []model.SummaryRow{{
		Section: "report",
		Status:  string(model.StatusOk),
		Notes: fmt.Sprintf("%s %s on %s at %s UTC",
			r.Tool, r.Version, r.Hostname, r.GeneratedAt.UTC().Format("2006-01-02 15:04:05")),
	}}

	for _, s := range r.Sections {
		rows = append(rows, model.SummaryRow{
			Section:  string(s.Section),
			Status:   string(s.Status),
			Records:  s.Records,
			Critical: s.Critical,
			High:     s.High,
			Duration: s.Duration,
			Notes:    strings.Join(s.Notes, "; "),
		})
	}
	return rows
}

// WriteDir renders one CSV file per section and returns the paths written.
//
// A section that produced no rows still gets a file containing its header row:
// an absent file is indistinguishable from a section that was never run, and the
// difference between "nothing listening" and "we did not look" is the whole
// value of an audit.
func WriteDir(dir string, r *model.Report) ([]string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}

	var written []string
	for _, t := range tables(r) {
		data, err := render(t)
		if err != nil {
			return written, fmt.Errorf("%s.csv: %w", t.name, err)
		}

		path := filepath.Join(dir, t.name+".csv")
		// 0600: the report names accounts, open ports and unpatched packages —
		// a reconnaissance summary that should not be world-readable by default.
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

// WriteCombined renders every section into a single stream, each table preceded
// by a `# name` line and followed by a blank line. Spreadsheets and `csvkit`
// both read this; a single flat table cannot hold six different column sets.
func WriteCombined(w io.Writer, r *model.Report) error {
	for i, t := range tables(r) {
		data, err := render(t)
		if err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		}
		if i > 0 {
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "# %s\n", t.name); err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func render(t table) ([]byte, error) {
	if len(t.rows) == 0 {
		// csv.Generate needs at least the header contract; emit it directly so an
		// empty section is still a valid, self-describing file.
		var buf bytes.Buffer
		buf.WriteString(strings.Join(quoteAll(t.headers), ",") + "\n")
		return buf.Bytes(), nil
	}
	return csv.Generate(t.rows, t.paths, t.headers)
}

// quoteAll applies minimal CSV quoting to the header row.
func quoteAll(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		if strings.ContainsAny(v, `,"`+"\n") {
			out[i] = `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
		} else {
			out[i] = v
		}
	}
	return out
}

func anySlice[T any](items []T) []any {
	out := make([]any, len(items))
	for i, item := range items {
		out[i] = item
	}
	return out
}

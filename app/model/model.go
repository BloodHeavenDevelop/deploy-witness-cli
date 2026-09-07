package model

import "time"

// Section names one audited area. They double as the CSV file base names and as
// the values accepted by --sections.
type Section string

const (
	SectionSystem          Section = "system"
	SectionUpdates         Section = "updates"
	SectionVulnerabilities Section = "vulnerabilities"
	SectionPorts           Section = "ports"
	SectionServices        Section = "services"
	// SectionWitness compares a deployment manifest against the host. It is the
	// only section that needs an input: without --compose there is nothing to
	// compare the host to, and it reports that rather than running empty.
	SectionWitness Section = "witness"
)

// AllSections is the default run order. System goes first because every later
// collector reads the OS release and package manager it detects.
var AllSections = []Section{
	SectionSystem,
	SectionUpdates,
	SectionVulnerabilities,
	SectionPorts,
	SectionServices,
	// Witness goes last: it reads the ports and services the sections above
	// collected instead of gathering them a second time.
	SectionWitness,
}

// Status is how a section ended. `partial` is load-bearing: a section that
// collected some rows but hit an error must never be reported as `ok`, or the
// reader takes a truncated table for a complete one.
type Status string

const (
	StatusOk      Status = "ok"
	StatusPartial Status = "partial"
	StatusSkipped Status = "skipped"
	StatusFailed  Status = "failed"
)

// Fact is one observation about the host. The section is a flat key/value table
// rather than a struct-per-topic so that a machine with an unusual layout simply
// contributes fewer rows instead of forcing empty columns on everyone else.
type Fact struct {
	Category string `json:"category"`
	Key      string `json:"key"`
	Value    string `json:"value"`
	Source   string `json:"source"`
}

// Update is one upgradable package as the local package manager sees it.
type Update struct {
	Package    string   `json:"package"`
	Installed  string   `json:"installed"`
	Available  string   `json:"available"`
	Arch       string   `json:"arch"`
	Repository string   `json:"repository"`
	Security   bool     `json:"security"`
	Severity   Severity `json:"severity"`
	Advisory   string   `json:"advisory"`
	Source     string   `json:"source"`
}

// Vulnerability is one CVE/advisory affecting one installed package.
//
// Source records which of the three feeds produced the row, because they are not
// equally trustworthy: distribution metadata knows about backported fixes, the
// OSV feeds do not and will flag a patched package whose version string never
// changed upstream.
type Vulnerability struct {
	Package   string   `json:"package"`
	Installed string   `json:"installed"`
	FixedIn   string   `json:"fixedIn"`
	Severity  Severity `json:"severity"`
	Score     string   `json:"score"`
	Id        string   `json:"id"`
	Aliases   string   `json:"aliases"`
	Summary   string   `json:"summary"`
	Ecosystem string   `json:"ecosystem"`
	Source    string   `json:"source"`
	Reference string   `json:"reference"`
}

// Vulnerability source labels.
const (
	VulnSourceDistro  = "distro-metadata"
	VulnSourceOffline = "offline-db"
	VulnSourceOSVAPI  = "osv-api"
)

// Port is one listening socket.
type Port struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Exposure string `json:"exposure"`
	State    string `json:"state"`
	Pid      int    `json:"pid"`
	Process  string `json:"process"`
	User     string `json:"user"`
	Command  string `json:"command"`
}

// Socket exposure classes, in ascending order of reach.
const (
	ExposureLoopback  = "loopback"
	ExposureInterface = "interface"
	ExposureAll       = "all-interfaces"
)

// Service is one service unit as the init system reports it.
type Service struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Enabled     string `json:"enabled"`
	MainPid     int    `json:"mainPid"`
	User        string `json:"user"`
	Since       string `json:"since"`
	Manager     string `json:"manager"`
}

// CommandRun is one command the audit executed, or tried to.
//
// The whole journal ships with the report. A client who ran an unfamiliar binary
// on their production host can compare this list against the published allowlist
// and see that the two agree — which is the only way "it only reads" stops being
// a claim and becomes something they can check themselves.
type CommandRun struct {
	Command   string `json:"command"`
	StartedAt string `json:"startedAt"`
	Duration  string `json:"duration"`
	ExitCode  int    `json:"exitCode"`
	// Outcome is ok, failed, timeout, missing or refused. A `refused` row is a
	// defect in this tool, never a property of the host, and it is printed rather
	// than hidden precisely because it would be the most important line here.
	Outcome string `json:"outcome"`
}

// SectionResult is the audit trail for one section: what ran, whether it
// finished, and what went wrong if it did not.
type SectionResult struct {
	Section  Section  `json:"section"`
	Status   Status   `json:"status"`
	Records  int      `json:"records"`
	Critical int      `json:"critical"`
	High     int      `json:"high"`
	Duration string   `json:"duration"`
	Notes    []string `json:"notes"`
}

// Note appends a human-readable remark and downgrades the section status. A
// collector that partially failed says so here rather than logging into the void.
func (r *SectionResult) Note(note string) {
	r.Notes = append(r.Notes, note)
}

// Fail marks the section as unusable.
func (r *SectionResult) Fail(note string) {
	r.Status = StatusFailed
	r.Note(note)
}

// Degrade marks the section as incomplete but still worth reading.
func (r *SectionResult) Degrade(note string) {
	if r.Status == StatusOk {
		r.Status = StatusPartial
	}
	r.Note(note)
}

// Report is the whole audit, in memory, before it is rendered to CSV.
type Report struct {
	GeneratedAt     time.Time       `json:"generatedAt"`
	Hostname        string          `json:"hostname"`
	Tool            string          `json:"tool"`
	Version         string          `json:"version"`
	System          []Fact          `json:"system"`
	Updates         []Update        `json:"updates"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Ports           []Port          `json:"ports"`
	Services        []Service       `json:"services"`
	Sections        []SectionResult `json:"sections"`
	Commands        []CommandRun    `json:"commands"`

	// The witness section's output. Manifest and Capabilities are the two sides
	// it compared; keeping them in the report is what lets a reader check a finding
	// rather than take it on faith.
	Manifest     *Manifest      `json:"manifest,omitempty"`
	Capabilities *Capabilities  `json:"capabilities,omitempty"`
	Findings     []Finding      `json:"findings"`
	Changes      []ChangeItem   `json:"changes"`
	Rollback     []RollbackItem `json:"rollback"`
}

// SummaryRow is one line of summary.csv — the index an operator reads first.
type SummaryRow struct {
	Section  string `json:"section"`
	Status   string `json:"status"`
	Records  int    `json:"records"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Duration string `json:"duration"`
	Notes    string `json:"notes"`
}

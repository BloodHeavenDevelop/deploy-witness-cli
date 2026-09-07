package model

// This file holds the three vocabularies the witness section is built from, and
// they are deliberately separate:
//
//   - Manifest — what a deployment *asks for*, read from docker-compose.yml.
//   - Capabilities — what the host *offers*, observed on the machine.
//   - Finding — what happens when the two disagree.
//
// Nothing in the first two carries a judgement, and nothing in the third performs
// an observation. A collector that decides something is wrong, or a rule that goes
// and looks at the host, is the mistake this split exists to prevent: it is what
// makes a finding impossible to explain to the person who has to act on it.
//
// Two rules apply to everything here:
//
//   - Environment variable *values* are never read. Names and the presence of a
//     file, yes; contents, never. The manifest types carry EnvNames, not env.
//   - A Finding without Evidence is not shown. The types allow it to be built;
//     the engine rejects it before it reaches any output.

// ─────────────────────────────────────────────────────────── the manifest

// Manifest is one parsed docker-compose file: the requirements side of witness.
type Manifest struct {
	// Path is where the file was read from, as given on the command line.
	Path string `json:"path"`
	// Version is the `version:` key when the file still declares one. Absent is
	// normal for Compose V2 and is not a problem.
	Version  string            `json:"version"`
	Services []ManifestService `json:"services"`
	Networks []ManifestNetwork `json:"networks"`
	Volumes  []ManifestVolume  `json:"volumes"`
	// Warnings records what the parser could not make sense of: an unresolved
	// ${VARIABLE}, a field in a shape it did not expect, a value it declined to
	// guess at. They surface in the report, because a requirement that was not
	// understood is not a requirement that was met.
	Warnings []string `json:"warnings"`
}

// ManifestService is one service block.
type ManifestService struct {
	Name  string   `json:"name"`
	Image ImageRef `json:"image"`
	// Build is the build context when the service is built rather than pulled.
	// Its presence changes several rules: a floating tag on a locally built image
	// is not the same risk as one on a pulled image.
	Build         string `json:"build"`
	ContainerName string `json:"containerName"`
	// Platform is an explicit `platform:`, e.g. linux/amd64. Empty means the
	// service takes whatever the host is, which is the case that needs checking
	// against the image's own architecture.
	Platform       string        `json:"platform"`
	Ports          []PortMapping `json:"ports"`
	Expose         []int         `json:"expose"`
	Volumes        []VolumeMount `json:"volumes"`
	Networks       []string      `json:"networks"`
	NetworkMode    string        `json:"networkMode"`
	DependsOn      []string      `json:"dependsOn"`
	Restart        string        `json:"restart"`
	HasHealthcheck bool          `json:"hasHealthcheck"`
	// EnvNames are the *names* of the variables the service declares. Values are
	// not read, not stored and not reported.
	EnvNames []string     `json:"envNames"`
	EnvFiles []EnvFileRef `json:"envFiles"`
	// MemReservationBytes and MemLimitBytes come from deploy.resources. Zero means
	// the manifest asked for nothing, which is itself worth knowing: a service with
	// no reservation cannot be checked against available memory.
	MemReservationBytes int64  `json:"memReservationBytes"`
	MemLimitBytes       int64  `json:"memLimitBytes"`
	CPUReservation      string `json:"cpuReservation"`
	CPULimit            string `json:"cpuLimit"`
	// Privileged, CapAdd and Devices are the flags that hand a container authority
	// over the host. They are reported whenever present, without exception.
	Privileged bool     `json:"privileged"`
	CapAdd     []string `json:"capAdd"`
	Devices    []string `json:"devices"`
	// MountsContainerSocket is true when the service bind-mounts the Docker or
	// Podman socket, which is equivalent to giving it root on the host.
	MountsContainerSocket bool     `json:"mountsContainerSocket"`
	ExtraHosts            []string `json:"extraHosts"`
	DNS                   []string `json:"dns"`
	// Labels are the service's `labels:`. They are configuration rather than
	// secrets, and they are the only place a compose file states which domain a
	// service expects to be reached at — a Traefik router rule or a proxy label. A
	// domain-collision check has no requirement side without them.
	Labels map[string]string `json:"labels"`
}

// ImageRef is an image reference, split so rules can ask about one part.
type ImageRef struct {
	// Raw is exactly what the manifest said, and it is what evidence quotes.
	Raw        string `json:"raw"`
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
}

// Pinned reports whether the reference identifies one specific image. A digest
// pins; a tag never does, not even a version-looking one, because a tag can be
// moved and `latest` usually is.
func (r ImageRef) Pinned() bool { return r.Digest != "" }

// PortMapping is one published port. A range publishes HostPort..HostPortEnd.
type PortMapping struct {
	HostIP        string `json:"hostIp"`
	HostPort      int    `json:"hostPort"`
	HostPortEnd   int    `json:"hostPortEnd"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
}

// HostPorts expands the mapping into the individual host ports it claims.
func (p PortMapping) HostPorts() []int {
	if p.HostPort == 0 {
		return nil
	}
	end := p.HostPortEnd
	if end < p.HostPort {
		end = p.HostPort
	}
	out := make([]int, 0, end-p.HostPort+1)
	for port := p.HostPort; port <= end; port++ {
		out = append(out, port)
	}
	return out
}

// Volume mount kinds.
const (
	MountBind   = "bind"
	MountVolume = "volume"
	MountTmpfs  = "tmpfs"
)

// VolumeMount is one entry from a service's `volumes:`.
type VolumeMount struct {
	Kind string `json:"kind"`
	// Source is a host path for a bind mount and a volume name for a volume.
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readOnly"`
}

// EnvFileRef is a referenced env_file and whether it is actually there. The
// contents are never read — only that the path resolves.
type EnvFileRef struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
}

// ManifestNetwork is one declared network.
type ManifestNetwork struct {
	Name     string `json:"name"`
	Driver   string `json:"driver"`
	External bool   `json:"external"`
	// Subnets are the explicit IPAM subnets, in CIDR form. They are what a
	// subnet-overlap check needs.
	Subnets []string `json:"subnets"`
}

// ManifestVolume is one declared named volume.
type ManifestVolume struct {
	Name     string `json:"name"`
	Driver   string `json:"driver"`
	External bool   `json:"external"`
}

// ─────────────────────────────────────────────────────── the host's capabilities

// Capabilities is everything observed about the host that a requirement could
// collide with. Every field is either populated or explicitly absent — a nil
// pointer means "not observed", which the rules must distinguish from "empty".
type Capabilities struct {
	Arch              string       `json:"arch"`
	MemTotalBytes     int64        `json:"memTotalBytes"`
	MemAvailableBytes int64        `json:"memAvailableBytes"`
	SwapTotalBytes    int64        `json:"swapTotalBytes"`
	Filesystems       []Filesystem `json:"filesystems"`
	// Ports and Services are the existing collectors' output, reused rather than
	// gathered a second time.
	Ports    []Port    `json:"ports"`
	Services []Service `json:"services"`
	// Runtime is nil when no container runtime was found, which is a finding in
	// its own right rather than an empty container list.
	Runtime           *ContainerRuntime  `json:"runtime"`
	Containers        []Container        `json:"containers"`
	ContainerNetworks []ContainerNetwork `json:"containerNetworks"`
	ContainerVolumes  []ContainerVolume  `json:"containerVolumes"`
	Images            []ContainerImage   `json:"images"`
	// Proxy is nil when neither nginx nor apache is installed.
	Proxy        *Proxy         `json:"proxy"`
	Panels       []Panel        `json:"panels"`
	Certificates []Certificate  `json:"certificates"`
	Jobs         []ScheduledJob `json:"jobs"`
	Backup       BackupPosture  `json:"backup"`
	Databases    []Database     `json:"databases"`
	// RebootRequired is "yes", "no" or "unknown". The third value is a real answer
	// and must not be collapsed into "no".
	RebootRequired string `json:"rebootRequired"`
	// Notes is what could not be observed and why. A rule that depends on an
	// unobserved capability must say so instead of concluding from the absence.
	Notes []string `json:"notes"`
}

// Filesystem is one mounted filesystem, with inodes: a deployment that writes
// many small files can exhaust those long before it fills the bytes, and a report
// that only shows capacity will call that host healthy right up to the failure.
type Filesystem struct {
	Mount          string `json:"mount"`
	Device         string `json:"device"`
	FSType         string `json:"fsType"`
	TotalBytes     uint64 `json:"totalBytes"`
	UsedBytes      uint64 `json:"usedBytes"`
	AvailableBytes uint64 `json:"availableBytes"`
	InodesTotal    uint64 `json:"inodesTotal"`
	InodesFree     uint64 `json:"inodesFree"`
	ReadOnly       bool   `json:"readOnly"`
}

// ContainerRuntime is the installed container engine.
type ContainerRuntime struct {
	// Kind is "docker" or "podman".
	Kind    string `json:"kind"`
	Version string `json:"version"`
	// ComposeKind is "plugin" (docker compose), "standalone" (docker-compose v1),
	// "podman-compose" or "" when no compose implementation was found.
	ComposeKind    string `json:"composeKind"`
	ComposeVersion string `json:"composeVersion"`
	StorageDriver  string `json:"storageDriver"`
	// Reachable is false when the engine is installed but its socket could not be
	// queried — usually a permission problem, and the reason every container list
	// below would otherwise look empty.
	Reachable bool   `json:"reachable"`
	Note      string `json:"note"`
}

// Container is one existing container, running or not.
type Container struct {
	Name   string `json:"name"`
	Image  string `json:"image"`
	State  string `json:"state"`
	Status string `json:"status"`
	// Ports is the published port list as the runtime reports it.
	Ports    []PortMapping `json:"ports"`
	Networks []string      `json:"networks"`
	// Project is the compose project label, when the container belongs to one.
	// It is how the engine tells "this port is taken by something else" from
	// "this port is taken by the previous version of this very deployment".
	Project string `json:"project"`
	Service string `json:"service"`
}

// ContainerNetwork is one existing runtime network.
type ContainerNetwork struct {
	Name    string   `json:"name"`
	Driver  string   `json:"driver"`
	Subnets []string `json:"subnets"`
	Project string   `json:"project"`
}

// ContainerVolume is one existing runtime volume.
type ContainerVolume struct {
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Mountpoint string `json:"mountpoint"`
	Project    string `json:"project"`
}

// ContainerImage is one image already on the host.
type ContainerImage struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
	// Architecture is the image's own, which is what an arm64/amd64 mismatch is
	// detected from.
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	SizeBytes    int64  `json:"sizeBytes"`
}

// Proxy is the host's web front end, if it has one.
type Proxy struct {
	// Kind is "nginx" or "apache".
	Kind    string `json:"kind"`
	Version string `json:"version"`
	// ServerNames are every name the proxy already answers for, with the file and
	// line they came from — a domain collision is only actionable if the reader can
	// find the vhost.
	ServerNames []ProxyServerName `json:"serverNames"`
	// ListenPorts are the ports its configuration binds.
	ListenPorts []int `json:"listenPorts"`
	// CertificatePaths are the certificate files the configuration references.
	CertificatePaths []string `json:"certificatePaths"`
	ConfigRoot       string   `json:"configRoot"`
	Note             string   `json:"note"`
}

// ProxyServerName is one name the proxy serves and where it is configured.
type ProxyServerName struct {
	Name string `json:"name"`
	File string `json:"file"`
	Line int    `json:"line"`
}

// Panel is a hosting control panel. They matter out of proportion to their size:
// a panel owns ports 80 and 443, rewrites nginx configuration on its own schedule,
// and will undo a hand-made change without warning.
type Panel struct {
	Name string `json:"name"`
	// Version is best-effort; a panel that hides it still counts as present.
	Version string `json:"version"`
	// Evidence is the path or unit that established its presence.
	Evidence string `json:"evidence"`
	Running  bool   `json:"running"`
	// OwnsPorts are the ports it is known to hold.
	OwnsPorts []int `json:"ownsPorts"`
}

// Certificate is one TLS certificate found on disk.
type Certificate struct {
	Path string `json:"path"`
	// Subject and SANs answer "does this cover the domain we are about to serve".
	Subject string   `json:"subject"`
	SANs    []string `json:"sans"`
	Issuer  string   `json:"issuer"`
	// NotAfter is RFC3339 UTC. Empty means the file could not be parsed, which is
	// reported rather than treated as "no expiry".
	NotAfter   string `json:"notAfter"`
	DaysLeft   int    `json:"daysLeft"`
	SelfSigned bool   `json:"selfSigned"`
	// Manager is "certbot", "acme.sh", "lego", "panel" or "" when nothing on the
	// host claims to renew it. An unmanaged certificate is a dated liability.
	Manager string `json:"manager"`
	// AutoRenew is whether a renewal job for it was actually found — not whether a
	// renewal tool is installed.
	AutoRenew bool `json:"autoRenew"`
}

// ScheduledJob is one cron entry or systemd timer.
type ScheduledJob struct {
	// Kind is "crontab", "cron.d", "cron.daily", "at" or "timer".
	Kind string `json:"kind"`
	// Owner is the account the job runs as.
	Owner    string `json:"owner"`
	Schedule string `json:"schedule"`
	// Command is the job's command line. It is swept for secrets before it is
	// reported, because people put passwords in cron lines.
	Command string `json:"command"`
	Source  string `json:"source"`
}

// BackupPosture is what the host does about backups. It is a struct rather than a
// list because the interesting answer is usually a negative one, and a negative
// needs somewhere to live.
type BackupPosture struct {
	// Tools are the backup tools installed: restic, borg, duplicity, rsnapshot…
	Tools []string `json:"tools"`
	// Jobs are the scheduled entries that appear to run one.
	Jobs []string `json:"jobs"`
	// Locations are the backup directories found, with the modification time of
	// the newest file in each. The file contents are never read — the date is the
	// whole point, and it is what tells a live backup from an abandoned one.
	Locations []BackupLocation `json:"locations"`
	// Note is what could not be established.
	Note string `json:"note"`
}

// BackupLocation is one backup directory and how fresh it is.
type BackupLocation struct {
	Path string `json:"path"`
	// NewestFileAt is RFC3339 UTC, empty when the directory is empty or unreadable.
	NewestFileAt string `json:"newestFileAt"`
	AgeDays      int    `json:"ageDays"`
	FileCount    int    `json:"fileCount"`
	SizeBytes    int64  `json:"sizeBytes"`
}

// Database is a database server present on the host.
//
// Nothing here connects to it and nothing reads its contents: the type, the
// version, the port, whether it is bound beyond loopback and how much disk its
// data directory occupies are all observable from outside, and they are all a
// witness check needs.
type Database struct {
	// Kind is "postgres", "mysql", "mariadb", "mongodb", "redis" or "unknown".
	Kind    string `json:"kind"`
	Version string `json:"version"`
	Port    int    `json:"port"`
	// Exposure reuses the socket exposure vocabulary: loopback, interface or
	// all-interfaces.
	Exposure  string `json:"exposure"`
	DataDir   string `json:"dataDir"`
	SizeBytes int64  `json:"sizeBytes"`
	Source    string `json:"source"`
}

// ─────────────────────────────────────────────────────────────── findings

// Finding is one statement about the deployment about to happen.
//
// The four prose fields are not decoration. Title says what, Description says on
// what basis, WhyItMatters says what breaks, WhatToDo says the next action. A
// finding missing any of them is a notification, not a finding.
type Finding struct {
	Code         string          `json:"code"`
	Collector    string          `json:"collector"`
	Category     string          `json:"category"`
	Severity     FindingSeverity `json:"severity"`
	Subject      string          `json:"subject"`
	Title        string          `json:"title"`
	Description  string          `json:"description"`
	WhyItMatters string          `json:"whyItMatters"`
	WhatToDo     string          `json:"whatToDo"`
	Confidence   Confidence      `json:"confidence"`
	SortOrder    int             `json:"sortOrder"`
	Evidence     []Evidence      `json:"evidence"`
}

// FindingSeverity is how much attention a finding deserves.
//
// Three values, not the six of the CVE scale this repository uses elsewhere. A
// vulnerability feed grades how bad a flaw is in the abstract; a witness finding
// answers a different question — whether the person reading it has to stop. Mapping
// that onto "medium" and "low" would invite exactly the hedging the product is
// meant to avoid.
type FindingSeverity string

const (
	// SeverityInfo — worth knowing, nothing is wrong.
	FindingInfo FindingSeverity = "info"
	// FindingWarning — a real problem that is not breaking anything yet.
	FindingWarning FindingSeverity = "warning"
	// FindingBlocker — already broken, or already exploitable. Deliberately rare:
	// a false blocker stops a deployment that would have been fine, and the next
	// one goes out with the checks switched off.
	FindingBlocker FindingSeverity = "blocker"
)

// Rank orders finding severities, worst first.
func (s FindingSeverity) Rank() int {
	switch s {
	case FindingBlocker:
		return 0
	case FindingWarning:
		return 1
	case FindingInfo:
		return 2
	default:
		return 3
	}
}

// Finding categories: what kind of trouble, not how bad.
const (
	CategoryConflict = "conflict"
	CategoryResource = "resource"
	CategorySecurity = "security"
	CategoryExpiry   = "expiry"
	CategoryMissing  = "missing"
)

// Confidence states where a false positive is possible.
type Confidence string

// Anything inferred from a fingerprint, an index or a parse of free-form text is
// at most ConfidenceMedium. Only a direct observation earns High.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Evidence is how a finding can be reproduced.
type Evidence struct {
	// Command is what a reader would run to see the same thing. For an observation
	// read from a file rather than a command, it is the path.
	Command string `json:"command"`
	Output  string `json:"output"`
	// Truncated says the fragment was cut. A shortened capture that does not admit
	// it invites the reader to conclude too much from it.
	Truncated  bool   `json:"truncated"`
	CapturedAt string `json:"capturedAt"`
}

// ChangeItem is one line of "what the deployment will actually do" — the section
// somebody shows their own client when asked what they changed.
type ChangeItem struct {
	// Kind is "file", "command", "firewall-port", "dns-record", "container" or
	// "disk-space".
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}

// RollbackItem is one line of the answer to "and how do we undo it".
type RollbackItem struct {
	// Kind is "snapshot", "image-tag", "proxy-config" or "volume-backup".
	Kind string `json:"kind"`
	// Available says whether the thing exists right now. False is the interesting
	// case, and the reason this section is not merely a set of instructions.
	Available bool   `json:"available"`
	Detail    string `json:"detail"`
}

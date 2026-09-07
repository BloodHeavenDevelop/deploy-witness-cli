// Package panels detects hosting control panels installed on the host.
//
// A panel matters out of all proportion to the few directories that give it away.
// It owns ports 80 and 443, it rewrites the web server's configuration on its own
// schedule, and it will silently undo a hand-made change: a vhost added by hand to
// a Plesk or cPanel host survives exactly until the panel next regenerates its
// templates. A deployment planned without knowing a panel is there is a deployment
// that will be reverted by software nobody remembered was running.
//
// That is why detection is deliberately cheap and deliberately conservative. It
// stats a fixed list of paths — no walking, no subprocesses beyond one
// `systemctl is-active` per unit of an already-detected panel — and when presence
// rests on a single marker that other software could also have left behind, the
// evidence string says so rather than asserting the panel is installed.
package panels

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// marker is one filesystem path whose existence points at a panel.
type marker struct {
	// Path is relative to the scan root and never starts with a slash, so the
	// whole detector can be pointed at a fixture directory.
	Path string
	// Dir requires the path to be a directory. A panel's installation root is a
	// directory; a stray file of the same name is not the panel.
	Dir bool
	// Weak marks a marker that is not by itself proof: a data directory that
	// outlives an uninstall, or a unit file that says a package was once
	// installed. Presence established only from weak markers is reported as
	// inferred, with the marker named, instead of as a plain fact.
	Weak bool
}

// signature is everything known about one panel.
type signature struct {
	Name string
	// Markers are checked in order; the first strong one that exists becomes the
	// evidence.
	Markers []marker
	// Versions are candidate version files, relative to the root. The first one
	// that yields a version-looking string wins. A panel that hides its version
	// still counts as present, so an empty Version is never a reason to drop it.
	Versions []string
	// Units are the service units the panel runs under. They are used for two
	// things: as (weak) filesystem markers, and as the argument to
	// `systemctl is-active`, which is how Running is established.
	Units []string
	// Ports are the ports this panel is known to hold — its own admin port, plus
	// 80 and 443 wherever it fronts the web server itself. This is the field a
	// port-collision rule reads, so a panel that terminates TLS lists 443 even
	// though nothing named after the panel is bound to it.
	Ports []int
	// PortFile is a file whose content is the panel's admin port as a bare
	// number (aaPanel writes one). When it parses, the port it names is added.
	PortFile string
}

// signatures is the detection table. Ports are the documented defaults for each
// panel; where a panel lets the admin port be moved, the moved port is picked up
// from PortFile when the panel writes one, and the default is kept otherwise —
// a wrong-but-documented port is still the port a reader should check.
var signatures = []signature{
	{
		Name: "Plesk",
		Markers: []marker{
			{Path: "usr/local/psa", Dir: true},
			{Path: "opt/psa", Dir: true},
			{Path: "etc/psa", Dir: true},
		},
		Versions: []string{"usr/local/psa/version", "opt/psa/version"},
		Units:    []string{"sw-cp-server.service", "sw-engine.service", "psa.service"},
		// 8443/8880 are the panel itself; 80/443 because Plesk owns the nginx and
		// Apache configuration on the hosts it is installed on.
		Ports: []int{80, 443, 8443, 8880},
	},
	{
		Name: "cPanel/WHM",
		Markers: []marker{
			{Path: "usr/local/cpanel", Dir: true},
			{Path: "var/cpanel", Dir: true, Weak: true},
		},
		Versions: []string{"usr/local/cpanel/version"},
		Units:    []string{"cpanel.service", "cpsrvd.service"},
		// 2082/2083 cPanel, 2086/2087 WHM, 2095/2096 webmail, and the web server
		// cPanel generates the configuration for.
		Ports: []int{80, 443, 2082, 2083, 2086, 2087, 2095, 2096},
	},
	{
		Name: "DirectAdmin",
		Markers: []marker{
			{Path: "usr/local/directadmin", Dir: true},
			{Path: "usr/local/directadmin/conf/directadmin.conf"},
		},
		Units: []string{"directadmin.service"},
		Ports: []int{80, 443, 2222},
	},
	{
		Name: "ISPmanager",
		Markers: []marker{
			{Path: "usr/local/mgr5", Dir: true},
			{Path: "usr/local/mgr5/etc/ispmgr.conf"},
		},
		Units: []string{"ihttpd.service", "ispmgr.service"},
		Ports: []int{80, 443, 1500},
	},
	{
		Name: "Coolify",
		Markers: []marker{
			{Path: "data/coolify/source/docker-compose.yml"},
			{Path: "data/coolify", Dir: true, Weak: true},
		},
		// Coolify runs as containers, so 80/443 are held by its own proxy. 8000 is
		// the dashboard, 6001/6002 its realtime channel.
		Ports: []int{80, 443, 6001, 6002, 8000},
	},
	{
		Name: "CapRover",
		Markers: []marker{
			{Path: "captain/data/config-captain.json"},
			{Path: "captain", Dir: true, Weak: true},
		},
		// 3000 is the dashboard before the wildcard domain is set up, 996 its HTTPS
		// form; 80/443 belong to the captain-nginx container.
		Ports: []int{80, 443, 996, 3000},
	},
	{
		Name: "Portainer",
		Markers: []marker{
			{Path: "var/lib/docker/volumes/portainer_data", Dir: true, Weak: true},
			{Path: "opt/portainer", Dir: true, Weak: true},
			{Path: "var/lib/portainer", Dir: true, Weak: true},
		},
		Units: []string{"portainer.service"},
		// Portainer does not front the web server, so it claims only its own
		// ports: 9000 HTTP, 9443 HTTPS, 8000 the edge-agent tunnel.
		Ports: []int{8000, 9000, 9443},
	},
	{
		Name: "aaPanel",
		Markers: []marker{
			{Path: "www/server/panel/class", Dir: true},
			{Path: "www/server/panel", Dir: true},
		},
		Units:    []string{"bt.service"},
		PortFile: "www/server/panel/data/port.pl",
		// 888 is the phpMyAdmin vhost aaPanel installs; 7800 and 8888 are the
		// panel's own defaults (aaPanel and its Chinese sibling respectively), kept
		// as candidates when port.pl cannot be read.
		Ports: []int{80, 443, 888, 7800, 8888},
	},
	{
		Name: "HestiaCP",
		Markers: []marker{
			{Path: "usr/local/hestia", Dir: true},
		},
		Versions: []string{"usr/local/hestia/conf/hestia.conf"},
		Units:    []string{"hestia.service"},
		Ports:    []int{80, 443, 8083},
	},
	{
		Name: "VestaCP",
		Markers: []marker{
			{Path: "usr/local/vesta", Dir: true},
		},
		Versions: []string{"usr/local/vesta/conf/vesta.conf"},
		Units:    []string{"vesta.service"},
		Ports:    []int{80, 443, 8083},
	},
	{
		Name: "Virtualmin",
		Markers: []marker{
			{Path: "etc/webmin/virtual-server/config"},
			{Path: "etc/webmin/virtual-server", Dir: true},
		},
		Versions: []string{"etc/webmin/virtual-server/version", "etc/webmin/version"},
		Units:    []string{"webmin.service"},
		// Virtualmin, unlike plain Webmin, generates the Apache/nginx vhosts.
		Ports: []int{80, 443, 10000},
	},
	{
		Name: "Webmin",
		Markers: []marker{
			{Path: "usr/libexec/webmin", Dir: true},
			{Path: "usr/share/webmin", Dir: true},
			{Path: "etc/webmin/miniserv.conf"},
			{Path: "etc/webmin", Dir: true, Weak: true},
		},
		Versions: []string{"etc/webmin/version"},
		Units:    []string{"webmin.service"},
		// 10000 Webmin, 20000 Usermin. Plain Webmin does not own the web server.
		Ports: []int{10000, 20000},
	},
	{
		Name: "CyberPanel",
		Markers: []marker{
			{Path: "usr/local/CyberCP", Dir: true},
			{Path: "usr/local/lscp", Dir: true, Weak: true},
		},
		Versions: []string{"usr/local/CyberCP/version.txt"},
		Units:    []string{"lscpd.service"},
		// 8090 is CyberPanel, 7080 the OpenLiteSpeed admin console it ships with.
		Ports: []int{80, 443, 7080, 8090},
	},
	{
		Name: "ISPConfig",
		Markers: []marker{
			{Path: "usr/local/ispconfig", Dir: true},
		},
		Ports: []int{80, 443, 8080},
	},
}

// containerSignature detects a panel that ships as containers rather than as
// packages. The container name is the marker, and the image tag is the version.
type containerSignature struct {
	Name string
	// Prefixes are matched against the container name, lowercased.
	Prefixes []string
	// VersionFrom is the container name whose image tag carries the panel version;
	// a Coolify install has several containers and only one of them is the app.
	VersionFrom string
}

var containerSignatures = []containerSignature{
	{Name: "Coolify", Prefixes: []string{"coolify"}, VersionFrom: "coolify"},
	{Name: "CapRover", Prefixes: []string{"captain-", "captain."}, VersionFrom: "captain-captain"},
	{Name: "Portainer", Prefixes: []string{"portainer"}, VersionFrom: "portainer"},
}

// Collect populates caps.Panels.
//
// It never returns an error, and it never reports an empty list as a clean
// answer: a host with no panel and a host whose marker paths could not be read
// are different findings, and the second one lands in result as a note.
func Collect(runner *run.Runner, caps *model.Capabilities, result *model.SectionResult) {
	found, concerns := detect("/")

	// Container-hosted panels (Coolify, CapRover, Portainer) leave a data
	// directory that may well outlive them, so the running containers are the
	// better evidence when the container collector managed to read them.
	found = merge(found, detectContainers(caps.Containers))

	for _, concern := range concerns {
		if concern.critical {
			result.Degrade("panels: " + concern.message)
			continue
		}
		result.Note("panels: " + concern.message)
	}

	if len(found) == 0 {
		return
	}

	systemd := run.Available("systemctl")
	for i := range found {
		if found[i].Running {
			// Already established from a running container.
			continue
		}
		unit, ok := runningUnit(runner, caps, systemd, found[i].Name)
		if ok {
			found[i].Running = true
			found[i].Evidence = appendEvidence(found[i].Evidence, "unit "+unit+" active")
		}
	}

	if !systemd {
		result.Note("panels: systemctl is not available, so the Running column is " +
			"left false for every panel — it means \"not established\", not \"stopped\"")
	}

	sort.SliceStable(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	caps.Panels = found
}

// concern is something detect could not check.
type concern struct {
	message string
	// critical separates "I could not check a marker that would have proved a
	// panel" from "I could not check one that would only have hinted at it". The
	// first degrades the section, because a whole panel may be hiding behind it;
	// the second is a note, because the inference it feeds is reported as an
	// inference anyway. Without the distinction the section goes partial on every
	// unprivileged run of a host that merely has Docker installed, and a status
	// that is always partial stops carrying information.
	critical bool
}

// detect walks nothing: it stats the marker paths of every signature under root.
// It returns the panels it established and what it could not check — a marker path
// that could not be stat'ed for a reason other than "it is not there" is a gap in
// coverage, and reporting it as an absence is the one thing this tool must not do.
func detect(root string) (panels []model.Panel, concerns []concern) {
	for _, sig := range signatures {
		var strong, weak []string

		for _, m := range append(markersOf(sig), unitFileMarkers(sig)...) {
			path := filepath.Join(root, m.Path)
			info, err := os.Stat(path)
			if err != nil {
				if !os.IsNotExist(err) {
					concerns = append(concerns, concern{
						message: path + " could not be examined (" + err.Error() +
							"), so " + sig.Name + " could neither be confirmed nor ruled out",
						critical: !m.Weak,
					})
				}
				continue
			}
			if m.Dir && !info.IsDir() {
				continue
			}
			if m.Weak {
				weak = append(weak, path)
			} else {
				strong = append(strong, path)
			}
		}

		if len(strong) == 0 && len(weak) == 0 {
			continue
		}

		panel := model.Panel{
			Name:      sig.Name,
			OwnsPorts: ports(root, sig, &concerns),
		}

		switch {
		case len(strong) > 0:
			panel.Evidence = strong[0]
			if extra := len(strong) + len(weak) - 1; extra > 0 {
				panel.Evidence += " (+" + strconv.Itoa(extra) + " further marker(s))"
			}
		default:
			// Nothing but a data directory or a leftover unit file. Say exactly
			// that: the panel may have been removed and left its state behind.
			panel.Evidence = weak[0] + " (presence inferred from this marker alone — " +
				"a data directory or unit file can outlive the panel that made it)"
		}

		panel.Version = version(root, sig, &concerns)
		panels = append(panels, panel)
	}

	sort.SliceStable(panels, func(i, j int) bool { return panels[i].Name < panels[j].Name })
	return panels, concerns
}

// markersOf copies a signature's markers so append cannot scribble on the table.
func markersOf(sig signature) []marker {
	out := make([]marker, len(sig.Markers))
	copy(out, sig.Markers)
	return out
}

// unitFileMarkers turns a signature's unit names into weak filesystem markers.
// An installed `psa.service` is a strong hint and a poor proof: the package may
// have been removed with its unit file left behind, and on a host without systemd
// the file means nothing at all.
func unitFileMarkers(sig signature) []marker {
	dirs := []string{"etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system"}
	out := make([]marker, 0, len(sig.Units)*len(dirs))
	for _, unit := range sig.Units {
		for _, dir := range dirs {
			out = append(out, marker{Path: dir + "/" + unit, Weak: true})
		}
	}
	return out
}

// versionPattern is what a version looks like in any of the formats these panels
// write: a bare `2.111`, a `18.0.62 Ubuntu 20.04` first field, a shell
// `VERSION='1.8.11'` and a JSON `{"version": "2.3"}` all reduce to this.
var versionPattern = regexp.MustCompile(`[0-9]+(?:\.[0-9]+)+`)

// maxVersionFileBytes bounds a version probe. Every file in Versions is a few
// bytes to a few kilobytes; anything larger is not the file we think it is.
const maxVersionFileBytes = 64 << 10

// version reads the first version-looking string out of a signature's version
// files. It is best-effort by design: a panel that hides its version is still
// present, and reporting no version is better than reporting a guessed one.
func version(root string, sig signature, concerns *[]concern) string {
	for _, rel := range sig.Versions {
		path := filepath.Join(root, rel)
		raw, err := readBounded(path, maxVersionFileBytes)
		if err != nil {
			if !os.IsNotExist(err) {
				// Most panel trees are root-only. Not being able to read the
				// version file is normal unprivileged and worth saying once.
				// The panel is reported regardless: a version nobody could
				// read is not a panel nobody should know about.
				*concerns = append(*concerns, concern{message: sig.Name +
					" version file " + path + " is unreadable (" + err.Error() +
					"), so its version is blank while the panel itself is confirmed"})
			}
			continue
		}
		// A line that names the version wins over an incidental number earlier in
		// the file.
		for _, line := range strings.Split(raw, "\n") {
			if strings.Contains(strings.ToLower(line), "version") {
				if v := versionPattern.FindString(line); v != "" {
					return v
				}
			}
		}
		if v := versionPattern.FindString(raw); v != "" {
			return v
		}
	}
	return ""
}

// ports is the signature's port list plus whatever its PortFile names.
func ports(root string, sig signature, concerns *[]concern) []int {
	out := make([]int, len(sig.Ports))
	copy(out, sig.Ports)

	if sig.PortFile != "" {
		path := filepath.Join(root, sig.PortFile)
		raw, err := readBounded(path, 64)
		switch {
		case err == nil:
			if port, convErr := strconv.Atoi(strings.TrimSpace(raw)); convErr == nil &&
				port > 0 && port < 65536 {
				out = appendPort(out, port)
			}
		case !os.IsNotExist(err):
			*concerns = append(*concerns, concern{message: sig.Name +
				" admin port file " + path + " is unreadable (" + err.Error() +
				"), so the documented default ports are reported instead of the configured one"})
		}
	}

	sort.Ints(out)
	return out
}

func appendPort(ports []int, port int) []int {
	for _, existing := range ports {
		if existing == port {
			return ports
		}
	}
	return append(ports, port)
}

// readBounded reads at most limit bytes, and refuses anything that is not a
// regular file — a marker path that turned into a device or a fifo is not
// something this tool opens.
func readBounded(path string, limit int64) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", os.ErrInvalid
	}

	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	buf := make([]byte, limit)
	n, err := file.Read(buf)
	if n == 0 && err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// detectContainers finds the container-hosted panels from the container list the
// runtime collector already read. A running container is far better evidence than
// a data directory, and its image tag is the only version these panels expose
// without asking them.
func detectContainers(containers []model.Container) []model.Panel {
	var out []model.Panel

	for _, sig := range containerSignatures {
		var names []string
		var running bool
		var version string

		for _, c := range containers {
			name := strings.ToLower(strings.TrimPrefix(c.Name, "/"))
			if !hasAnyPrefix(name, sig.Prefixes) {
				continue
			}
			names = append(names, c.Name)
			if strings.EqualFold(c.State, "running") {
				running = true
			}
			if name == sig.VersionFrom {
				version = imageTag(c.Image)
			}
		}
		if len(names) == 0 {
			continue
		}

		sort.Strings(names)
		evidence := "container " + names[0]
		if len(names) > 1 {
			evidence += " (+" + strconv.Itoa(len(names)-1) + " further container(s))"
		}

		out = append(out, model.Panel{
			Name:      sig.Name,
			Version:   version,
			Evidence:  evidence,
			Running:   running,
			OwnsPorts: portsFor(sig.Name),
		})
	}

	return out
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// imageTag pulls the tag out of an image reference. A digest is not a version, so
// a digest-pinned image reports none.
func imageTag(image string) string {
	if image == "" || strings.Contains(image, "@") {
		return ""
	}
	slash := strings.LastIndex(image, "/")
	colon := strings.LastIndex(image, ":")
	if colon < 0 || colon < slash {
		return ""
	}
	tag := image[colon+1:]
	if tag == "latest" {
		// `latest` names no version, and recording it as one invites a reader to
		// believe the panel's version was established.
		return ""
	}
	return tag
}

// portsFor is the port list of a named signature, for the container detector.
func portsFor(name string) []int {
	for _, sig := range signatures {
		if sig.Name == name {
			out := make([]int, len(sig.Ports))
			copy(out, sig.Ports)
			sort.Ints(out)
			return out
		}
	}
	return nil
}

// unitsFor is the unit list of a named signature.
func unitsFor(name string) []string {
	for _, sig := range signatures {
		if sig.Name == name {
			return sig.Units
		}
	}
	return nil
}

// merge folds the container-derived panels into the filesystem-derived ones. The
// same panel found twice keeps both pieces of evidence: "the data directory is
// there and a container is running" is a stronger statement than either half.
func merge(base, extra []model.Panel) []model.Panel {
	for _, add := range extra {
		index := -1
		for i := range base {
			if base[i].Name == add.Name {
				index = i
				break
			}
		}
		if index < 0 {
			base = append(base, add)
			continue
		}
		base[index].Evidence = appendEvidence(base[index].Evidence, add.Evidence)
		base[index].Running = base[index].Running || add.Running
		if base[index].Version == "" {
			base[index].Version = add.Version
		}
		for _, port := range add.OwnsPorts {
			base[index].OwnsPorts = appendPort(base[index].OwnsPorts, port)
		}
		sort.Ints(base[index].OwnsPorts)
	}
	return base
}

func appendEvidence(existing, add string) string {
	switch {
	case add == "":
		return existing
	case existing == "":
		return add
	default:
		return existing + "; " + add
	}
}

// runningUnit establishes whether a panel is running, and from which unit.
//
// The service inventory is consulted first, because it was already collected and
// asking systemd again costs a subprocess per unit. Its absence proves nothing,
// though: by default that inventory holds only the running units, so a unit that
// is not in it is asked about directly.
func runningUnit(runner *run.Runner, caps *model.Capabilities, systemd bool, name string) (string, bool) {
	units := unitsFor(name)
	if len(units) == 0 {
		return "", false
	}

	for _, unit := range units {
		for _, svc := range caps.Services {
			if svc.Name == unit && svc.Active == "active" {
				return unit, true
			}
		}
	}
	if !systemd {
		return "", false
	}

	for _, unit := range units {
		// is-active exits 3 for an inactive unit and 4 for one systemd does not
		// know; both are answers, not failures.
		out, _, err := runner.OutputAllowExit([]int{1, 3, 4}, "systemctl", "is-active", unit)
		if err != nil {
			continue
		}
		if strings.TrimSpace(out) == "active" {
			return unit, true
		}
	}
	return "", false
}

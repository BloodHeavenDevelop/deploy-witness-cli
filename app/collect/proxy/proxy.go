// Package proxy observes the host's web front end — nginx or Apache — for the
// witness section.
//
// Three things about it are worth knowing before reading the rest:
//
//   - The effective configuration is asked for, not reconstructed. `nginx -T` and
//     `apachectl -S` resolve every include, every sites-enabled symlink and whatever
//     a control panel regenerated last night; a hand-rolled walk of /etc/nginx sees
//     none of that. The walk exists only as the fallback for when the dump cannot
//     run — which is what happens unprivileged — and when it is used, the report
//     says so instead of presenting a partial list as the whole truth.
//   - Every server name carries the file and the line it is configured at. "This
//     domain is already served on this host" is only actionable if the reader can
//     open the vhost, so a name without a location is worth much less than one with.
//   - Certificate *paths* are collected, never certificate contents — and never a
//     private key, a .htpasswd, or anything else this package has no business
//     opening. Parsing the certificates is another collector's job.
package proxy

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// The two values model.Proxy.Kind may take.
const (
	kindNginx  = "nginx"
	kindApache = "apache"
)

// Collect observes the installed web front end and fills caps.Proxy.
//
// caps.Proxy is left nil when the host has neither nginx nor Apache: a nil pointer
// is the model's way of saying "no web front end", and it is a different statement
// from a Proxy with an empty name list, which says "there is one and it serves
// nothing".
func Collect(runner *run.Runner, caps *model.Capabilities, result *model.SectionResult) {
	nginxRoot, haveNginx := nginxPresent()
	apacheBinary, apacheRoot, haveApache := apachePresent()

	switch {
	case haveNginx:
		proxy := collectNginx(runner, nginxRoot, result)
		if haveApache {
			// Both installed is a real configuration — Apache behind nginx, or a
			// leftover package still holding a port. Only one of them fits in
			// model.Proxy, so the other one is named rather than dropped.
			where := apacheBinary
			if where == "" {
				where = apacheRoot
			}
			proxy.Note = appendNote(proxy.Note,
				"apache is installed on this host as well ("+where+
					") and was not inspected, so an Apache vhost or port is not represented here")
			result.Degrade("both nginx and apache are installed; only nginx was inspected")
		}
		caps.Proxy = proxy
	case haveApache:
		caps.Proxy = collectApache(runner, apacheBinary, apacheRoot, result)
	}
}

// ─────────────────────────────────────────────────────────────────────── nginx

// nginxBinary resolves nginx on PATH, or "" when it is not there.
func nginxBinary() string { return run.Path("nginx") }

// collectNginx fills a model.Proxy from `nginx -T`, or from a walk of the
// configuration tree when that command cannot run.
func collectNginx(runner *run.Runner, configRoot string, result *model.SectionResult) *model.Proxy {
	proxy := &model.Proxy{Kind: kindNginx, Version: nginxVersion(runner)}
	acc := newAccumulator()

	dump, err := runner.Output("nginx", "-T")
	if err == nil && strings.Contains(dump, "# configuration file") {
		root, _ := parseNginxDump(dump, acc)
		if root != "" {
			proxy.ConfigRoot = filepath.Dir(root)
		}
	} else {
		reason := "`nginx -T` returned no configuration dump"
		switch {
		case errors.Is(err, run.ErrNotFound):
			// An nginx tree with no nginx on PATH: /usr/sbin is missing from many
			// unprivileged PATHs, and this is what that looks like from here.
			reason = "nginx is installed but not on this PATH, so `nginx -T` could not be run"
		case err != nil:
			reason = "`nginx -T` failed (" + firstLine(err.Error()) + ")"
		}

		if configRoot == "" {
			configRoot = firstExisting(nginxConfigCandidates...)
		}
		crawl := walkNginxTree(configRoot, acc)
		proxy.ConfigRoot = crawl.base

		degraded := reason + ": the names, ports and certificate paths below come from" +
			" walking " + crawl.base + " directly, which cannot see an include it could not" +
			" resolve or a vhost kept outside the standard directories — read the list as" +
			" incomplete, not as everything this server answers for"
		if crawl.files == 0 {
			degraded = reason + " and no configuration file under " + crawl.base +
				" could be read, so nothing at all is known about which names, ports and" +
				" certificates this nginx already uses"
		}
		proxy.Note = appendNote(proxy.Note, degraded)
		result.Degrade("proxy (nginx): " + degraded)

		for _, note := range crawl.notes() {
			proxy.Note = appendNote(proxy.Note, note)
			result.Note("proxy (nginx): " + note)
		}
	}

	finish(proxy, acc, result)
	return proxy
}

// nginxVersion reads the nginx version, in two steps and for one irritating reason.
//
// nginx prints `nginx -v` to *stderr*, which run.Runner does not capture, so on the
// overwhelming majority of hosts the allowlisted command yields an empty stdout. The
// command is still run — a build that prints to stdout is answered from stdout — and
// when it comes back empty the version string compiled into the binary is read
// instead. That read is bounded, read-only, and of a file already on disk, which is
// the same class of observation as everything else here; it is not a network call
// and it does not execute anything.
func nginxVersion(runner *run.Runner) string {
	if out, err := runner.Output("nginx", "-v"); err == nil {
		if version := parseNginxVersion(out); version != "" {
			return version
		}
	}

	binary := nginxBinary()
	if binary == "" {
		return ""
	}
	blob, _, err := readLimited(binary, maxVersionScanBytes)
	if err != nil {
		return ""
	}
	return parseNginxVersion(blob)
}

// ────────────────────────────────────────────────────────────────────── Apache

// apachePresent reports whether the host has Apache, which control binary answers
// for it, and where its configuration root is. As with nginx, a configuration tree
// counts: /usr/sbin is missing from many unprivileged PATHs.
func apachePresent() (binary, configRoot string, present bool) {
	for _, candidate := range apacheControlBinaries {
		if run.Available(candidate) {
			binary = candidate
			break
		}
	}
	configRoot = firstExisting(apacheConfigCandidates...)
	return binary, configRoot, binary != "" || configRoot != ""
}

// collectApache fills a model.Proxy from `apachectl -S`, falling back to a walk of
// the configuration tree.
func collectApache(runner *run.Runner, binary, configRoot string, result *model.SectionResult) *model.Proxy {
	proxy := &model.Proxy{Kind: kindApache}
	acc := newAccumulator()

	if binary != "" {
		if out, err := runner.Output(binary, "-v"); err == nil {
			proxy.Version = parseApacheVersion(out)
		}
	}

	var (
		vhostFiles []string
		mapped     bool
		reason     string
	)
	switch {
	case binary == "":
		reason = "no Apache control binary (" + strings.Join(apacheControlBinaries, ", ") +
			") is on PATH, so the virtual host map could not be asked for"
	default:
		out, err := runner.Output(binary, "-S")
		if err == nil && strings.Contains(out, "VirtualHost configuration") {
			serverRoot, files := parseApacheVhostMap(out, acc)
			proxy.ConfigRoot = serverRoot
			vhostFiles = files
			mapped = true
		} else if err != nil {
			reason = "`" + binary + " -S` failed (" + firstLine(err.Error()) + ")"
		} else {
			reason = "`" + binary + " -S` printed no virtual host map"
		}
	}

	// The tree is walked either way, because the map answers two of the three
	// questions and not the third: it never names a certificate, and it only lists
	// the addresses that carry a vhost. What the walk contributes on top of a
	// successful map is the certificate paths and the `Listen` ports; the names stay
	// the map's, which is the only source that knows where each vhost opens.
	scan := scanApachePortsAndCertificates
	if !mapped {
		scan = scanApacheFile
	}
	crawl := walkApacheTree(proxy.ConfigRoot, configRoot, scan, vhostFiles, acc)
	if proxy.ConfigRoot == "" {
		proxy.ConfigRoot = crawl.base
	}

	if !mapped {
		degraded := reason + ": the names, ports and certificate paths below come from" +
			" walking " + crawl.base + " directly, which cannot see an Include it could not" +
			" resolve or a vhost kept outside the standard directories — read the list as" +
			" incomplete"
		if crawl.files == 0 {
			degraded = reason + " and no configuration file under " + crawl.base +
				" could be read, so nothing at all is known about which names, ports and" +
				" certificates this Apache already uses"
		}
		proxy.Note = appendNote(proxy.Note, degraded)
		result.Degrade("proxy (apache): " + degraded)
	}
	for _, note := range crawl.notes() {
		proxy.Note = appendNote(proxy.Note, note)
		result.Note("proxy (apache): " + note)
	}

	finish(proxy, acc, result)
	return proxy
}

// ─────────────────────────────────────────────────────────────────────── shared

// finish moves the accumulated observations onto the proxy, and reports the one
// bound that can trim them.
func finish(proxy *model.Proxy, acc *accumulator, result *model.SectionResult) {
	proxy.ServerNames = acc.names
	proxy.ListenPorts = acc.sortedPorts()
	proxy.CertificatePaths = acc.sortedCerts()

	if acc.namesTruncated {
		note := "more than " + strconv.Itoa(maxServerNames) + " server names are configured;" +
			" the list stops there and is not the full set"
		proxy.Note = appendNote(proxy.Note, note)
		result.Note("proxy (" + proxy.Kind + "): " + note)
	}
}

// firstLine keeps a command's error message to one line: stderr from a web server
// is a paragraph, and the report has one cell for it.
func firstLine(text string) string {
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	return strings.TrimSpace(text)
}

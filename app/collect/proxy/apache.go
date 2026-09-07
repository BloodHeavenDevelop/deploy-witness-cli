package proxy

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ────────────────────────────────────────────────────── where Apache keeps things

// apacheControlBinaries are the wrappers that answer `-v` and `-S`, in the order
// they are tried. Debian ships apache2ctl, RHEL ships apachectl and httpd, SUSE
// ships apachectl; a host may well have two of them, and they answer identically.
var apacheControlBinaries = []string{"apachectl", "apache2ctl", "httpd"}

// apacheConfigCandidates are the root configuration files per family.
var apacheConfigCandidates = []string{
	"/etc/apache2/apache2.conf",  // Debian/Ubuntu
	"/etc/httpd/conf/httpd.conf", // RHEL family
	"/etc/apache2/httpd.conf",    // SUSE
	"/usr/local/apache2/conf/httpd.conf",
}

// apacheDropInGlobs are walked relative to the ServerRoot, for the same reason the
// nginx ones are: they are where the vhosts live, and they must be reachable even
// when the root configuration was not readable.
var apacheDropInGlobs = []string{
	"conf.d/*.conf",
	"conf-enabled/*.conf",
	"sites-enabled/*.conf",
	"sites-enabled/*",
	"vhosts.d/*.conf",
}

// apacheVersionPattern matches the `Server version: Apache/2.4.57 (Debian)` line
// `apachectl -v` prints.
var apacheVersionPattern = regexp.MustCompile(`Apache/(\S+)`)

func parseApacheVersion(text string) string {
	if m := apacheVersionPattern.FindStringSubmatch(text); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// ─────────────────────────────────────────────── the virtual host map (`-S`)

var (
	// apacheAddrPort matches the `*:80`, `10.0.0.1:443`, `[::]:8443` heading that
	// opens each block of the vhost map.
	apacheAddrPort = regexp.MustCompile(`^(?:\[[0-9A-Fa-f:.]+\]|[0-9A-Za-z_.*-]+):(\d+)$`)
	// apacheLocation matches the trailing `(/etc/apache2/sites-enabled/x.conf:12)`.
	apacheLocation = regexp.MustCompile(`\(([^()]+):(\d+)\)\s*$`)
	// apacheNameVhost matches `port 80 namevhost example.com (file:line)`.
	apacheNameVhost = regexp.MustCompile(`^port\s+(\S+)\s+namevhost\s+(\S+)`)
	// apacheDefaultServer matches `default server example.com (file:line)`.
	apacheDefaultServer = regexp.MustCompile(`^default server\s+(\S+)`)
	// apacheAlias matches `alias www.example.com` and `wild alias *.example.com` —
	// the ServerAlias entries, which the map prints without a location of their own.
	apacheAlias = regexp.MustCompile(`^(?:wild\s+)?alias\s+(\S+)`)
	// apacheServerRoot matches `ServerRoot: "/etc/apache2"`.
	apacheServerRoot = regexp.MustCompile(`^ServerRoot:\s*"?([^"]+?)"?\s*$`)
)

// parseApacheVhostMap folds `apachectl -S` output into acc and returns the
// ServerRoot it reported plus every file it attributed a vhost to.
//
// The map is the best source Apache has: it is the running server's own view, it
// resolves every Include, and it prints the file and line of each vhost — which a
// walk of the tree can only approximate.
func parseApacheVhostMap(out string, acc *accumulator) (serverRoot string, files []string) {
	seenFile := map[string]struct{}{}
	addFile := func(path string) {
		if path == "" {
			return
		}
		if _, dup := seenFile[path]; dup {
			return
		}
		seenFile[path] = struct{}{}
		files = append(files, path)
	}

	// An alias has no location of its own; it belongs to the vhost above it, and
	// that vhost's file:line is exactly where a reader has to go to change it.
	var lastFile string
	var lastLine int

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}

		file, lineNo := "", 0
		if m := apacheLocation.FindStringSubmatch(text); m != nil {
			file = strings.TrimSpace(m[1])
			lineNo, _ = strconv.Atoi(m[2])
		}

		// A block heading starts at column zero with an address:port.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			if m := apacheServerRoot.FindStringSubmatch(text); m != nil {
				serverRoot = strings.TrimSpace(m[1])
				continue
			}
			fields := strings.Fields(text)
			if m := apacheAddrPort.FindStringSubmatch(fields[0]); m != nil {
				port, _ := strconv.Atoi(m[1])
				acc.addPort(port)
				// `*:443  secure.example.com (file:2)` — a single vhost on that
				// address, as opposed to `is a NameVirtualHost`, which has none.
				if file != "" && len(fields) >= 3 {
					acc.addName(fields[1], file, lineNo)
					addFile(file)
					lastFile, lastLine = file, lineNo
				}
			}
			continue
		}

		switch {
		case apacheNameVhost.MatchString(text):
			m := apacheNameVhost.FindStringSubmatch(text)
			if port, err := strconv.Atoi(m[1]); err == nil {
				acc.addPort(port)
			}
			acc.addName(m[2], file, lineNo)
			addFile(file)
			if file != "" {
				lastFile, lastLine = file, lineNo
			}
		case apacheDefaultServer.MatchString(text):
			m := apacheDefaultServer.FindStringSubmatch(text)
			acc.addName(m[1], file, lineNo)
			addFile(file)
			if file != "" {
				lastFile, lastLine = file, lineNo
			}
		case apacheAlias.MatchString(text):
			m := apacheAlias.FindStringSubmatch(text)
			acc.addName(m[1], lastFile, lastLine)
		}
	}

	return serverRoot, files
}

// ──────────────────────────────────────────────────────── the configuration files

// scanApacheFile folds one Apache configuration file into acc and returns its
// Include patterns.
//
// Apache's configuration is line-oriented and a `#` only comments when it opens the
// line, so this is a line scanner rather than the tokeniser nginx needs.
func scanApacheFile(path, body string, acc *accumulator) []string {
	return scanApacheConfig(path, body, acc, false)
}

// scanApachePortsAndCertificates is the same scan with the server names left out. It
// is what runs when `apachectl -S` already supplied them: the map is authoritative
// for a name's location, and taking names from the files as well would only add
// near-duplicate rows pointing at a different line of the same vhost.
//
// Ports and certificates are *not* left out, and that is deliberate. The vhost map
// never names a certificate at all, and it only lists the addresses that have a
// vhost — a host with `Listen 80` and no `<VirtualHost>` prints an empty map while
// still holding port 80, which is exactly the collision a deployment walks into.
func scanApachePortsAndCertificates(path, body string, acc *accumulator) []string {
	return scanApacheConfig(path, body, acc, true)
}

func scanApacheConfig(path, body string, acc *accumulator, namesFromMap bool) []string {
	var includes []string

	for i, raw := range strings.Split(body, "\n") {
		lineNo := i + 1
		text := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		fields := apacheFields(text)
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(strings.Trim(fields[0], "<>"))
		args := fields[1:]

		switch directive {
		case "include", "includeoptional":
			if len(args) > 0 {
				includes = append(includes, args[0])
			}
		case "sslcertificatefile":
			// The certificate. `SSLCertificateKeyFile` is the private half and is
			// never collected.
			if len(args) > 0 {
				acc.addCert(args[0])
			}
		case "servername":
			if !namesFromMap && len(args) > 0 {
				acc.addName(apacheServerNameHost(args[0]), path, lineNo)
			}
		case "serveralias":
			if !namesFromMap {
				for _, alias := range args {
					acc.addName(alias, path, lineNo)
				}
			}
		case "listen":
			if len(args) > 0 {
				if port, ok := apachePort(args[0]); ok {
					acc.addPort(port)
				}
			}
		case "virtualhost":
			// `<VirtualHost *:443 10.0.0.1:443>`
			for _, spec := range args {
				if port, ok := apachePort(strings.TrimSuffix(spec, ">")); ok {
					acc.addPort(port)
				}
			}
		}
	}

	return includes
}

// apacheFields splits a configuration line, keeping a double-quoted argument whole.
func apacheFields(line string) []string {
	var (
		fields  []string
		current strings.Builder
		quoted  bool
		open    bool
	)
	flush := func() {
		if open {
			fields = append(fields, current.String())
			current.Reset()
			open = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			quoted = !quoted
			open = true
		case (c == ' ' || c == '\t') && !quoted:
			flush()
		default:
			current.WriteByte(c)
			open = true
		}
	}
	flush()
	return fields
}

// apacheServerNameHost strips what a ServerName may carry besides the host: an
// explicit scheme and an explicit port. `https://example.com:443` and `example.com`
// name the same site, and a report that lists both as separate names is noise.
func apacheServerNameHost(value string) string {
	host := strings.Trim(value, `"`)
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if strings.HasPrefix(host, "[") {
		// A bracketed IPv6 literal, optionally with a port after the bracket.
		if end := strings.Index(host, "]"); end >= 0 {
			return host[:end+1]
		}
		return host
	}
	if i := strings.LastIndex(host, ":"); i >= 0 {
		if _, err := strconv.Atoi(host[i+1:]); err == nil {
			host = host[:i]
		}
	}
	return host
}

// apachePort reads the port out of a `Listen` argument or a `<VirtualHost>` address.
//
// Unlike nginx, an address with no port is not assumed to mean 80: Apache serves a
// portless `<VirtualHost *>` on whatever its `Listen` directives bind, and those are
// collected in their own right.
func apachePort(spec string) (int, bool) {
	spec = strings.Trim(spec, `"'`)
	if spec == "" {
		return 0, false
	}
	if port, err := strconv.Atoi(spec); err == nil {
		return port, port > 0 && port <= 65535
	}
	if i := strings.LastIndex(spec, ":"); i >= 0 {
		if port, err := strconv.Atoi(spec[i+1:]); err == nil {
			return port, port > 0 && port <= 65535
		}
	}
	return 0, false
}

// walkApacheTree walks the Apache configuration from its root, following Includes.
// scan decides whether that walk contributes everything or only certificate paths.
func walkApacheTree(serverRoot, root string, scan fileScanner, extra []string, acc *accumulator) *crawler {
	base := serverRoot
	if base == "" && root != "" {
		base = filepath.Dir(filepath.Dir(root))
	}
	if base == "" {
		base = "/etc/apache2"
	}

	c := newCrawler(base, scan, acc)
	if root != "" {
		c.file(root, 0)
	}
	for _, path := range extra {
		c.file(path, 0)
	}
	for _, glob := range apacheDropInGlobs {
		c.walk(glob, 1)
	}
	return c
}

package proxy

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ─────────────────────────────────────────────────────── where nginx keeps things

// nginxConfigCandidates are the root configuration files, in the order a host is
// likely to use them. Only the fallback walk needs these: when `nginx -T` runs, it
// names its own root.
var nginxConfigCandidates = []string{
	"/etc/nginx/nginx.conf",
	"/usr/local/nginx/conf/nginx.conf",
	"/usr/local/etc/nginx/nginx.conf",
	"/opt/nginx/conf/nginx.conf",
}

// nginxDropInGlobs are walked in addition to the root configuration, relative to
// its directory. They are not redundant with the root's own `include` lines: when
// nginx.conf itself is the file that could not be read, these are the only way the
// vhosts under it are seen at all.
var nginxDropInGlobs = []string{
	"conf.d/*.conf",
	"sites-enabled/*",
	"http.d/*.conf",   // Alpine
	"vhosts.d/*.conf", // SUSE
	"streams-enabled/*",
	"stream.d/*.conf",
}

// nginxPresent reports whether the host has nginx at all.
//
// PATH alone is not enough to ask: nginx lives in /usr/sbin, which an unprivileged
// account's PATH routinely omits, and a configuration tree is just as good an
// answer to "is there an nginx here" as a binary is.
func nginxPresent() (configRoot string, present bool) {
	root := firstExisting(nginxConfigCandidates...)
	return root, root != "" || nginxBinary() != ""
}

// ────────────────────────────────────────────────────────────── the version

// nginxVersionPattern matches the version wherever it is read from: `nginx -v`
// output, or the string compiled into the binary.
var nginxVersionPattern = regexp.MustCompile(`nginx/(\d+\.\d+(?:\.\d+)?)`)

// parseNginxVersion pulls the version out of a blob of text.
func parseNginxVersion(text string) string {
	if m := nginxVersionPattern.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

// ─────────────────────────────────────────────── the configuration tokeniser

// nginxDirective is one directive, with the line each of its arguments is written
// on. Per-argument lines are not pedantry: a `server_name` listing six domains
// across three lines is normal, and sending the reader to the directive's first
// line when the name they are looking for is two lines further down is the kind of
// almost-right location that wastes their time.
type nginxDirective struct {
	name string
	args []string
	// line is where the directive starts; argLines[i] is where args[i] is written.
	line     int
	argLines []int
}

// nginxDirectives tokenises a configuration body.
//
// It is a tokeniser rather than a line matcher because `nginx -T` dumps files
// verbatim: a directive may span lines, share a line with its neighbours, quote its
// arguments, or be followed by a comment that itself contains something that looks
// like a directive. Line numbers are 1-based and relative to the body, which — for
// a `nginx -T` segment — is exactly the line number in the real file.
func nginxDirectives(body string) []nginxDirective {
	var (
		out      []nginxDirective
		tokens   []string
		tokLines []int
		line     = 1
		i        = 0
		n        = len(body)
	)

	flush := func() {
		if len(tokens) == 0 {
			return
		}
		out = append(out, nginxDirective{
			name:     tokens[0],
			args:     tokens[1:],
			line:     tokLines[0],
			argLines: tokLines[1:],
		})
		tokens, tokLines = nil, nil
	}

	for i < n {
		c := body[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			// A comment runs to the end of the line. Outside quotes nginx has no
			// other reading of `#`, so neither does this.
			for i < n && body[i] != '\n' {
				i++
			}
		case c == ';' || c == '{':
			// `{` ends a block header — `server`, `http`, `location /` — which is a
			// directive in its own right and is emitted as one.
			flush()
			i++
		case c == '}':
			tokens, tokLines = nil, nil
			i++
		case c == '"' || c == '\'':
			quote := c
			start := line
			i++
			var value strings.Builder
			for i < n {
				if body[i] == '\\' && i+1 < n {
					if body[i+1] == '\n' {
						line++
					}
					value.WriteByte(body[i+1])
					i += 2
					continue
				}
				if body[i] == quote {
					i++
					break
				}
				if body[i] == '\n' {
					line++
				}
				value.WriteByte(body[i])
				i++
			}
			tokens = append(tokens, value.String())
			tokLines = append(tokLines, start)
		default:
			j := i
			for j < n && !isNginxDelimiter(body[j]) {
				j++
			}
			tokens = append(tokens, body[i:j])
			tokLines = append(tokLines, line)
			i = j
		}
	}
	flush()
	return out
}

func isNginxDelimiter(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', ';', '{', '}', '#':
		return true
	}
	return false
}

// ────────────────────────────────────────────────────────── the directives we read

// scanNginxFile folds one configuration body into acc and returns the `include`
// patterns it referenced. It is the fileScanner the fallback walk uses, and the
// same function the `nginx -T` parser applies to each dumped file.
func scanNginxFile(path, body string, acc *accumulator) []string {
	var includes []string

	for _, d := range nginxDirectives(body) {
		switch d.name {
		case "server_name":
			for i, name := range d.args {
				acc.addName(name, path, d.argLines[i])
			}
		case "listen":
			if port, ok := nginxListenPort(d.args); ok {
				acc.addPort(port)
			}
		case "ssl_certificate":
			// Exactly this directive. `ssl_certificate_key` names the private half
			// and is deliberately not collected — not the path, not the file.
			if len(d.args) > 0 {
				acc.addCert(d.args[0])
			}
		case "include":
			if len(d.args) > 0 {
				includes = append(includes, d.args[0])
			}
		}
	}
	return includes
}

// nginxListenPort reads the port out of a `listen` directive.
//
// The forms are: a bare port (`listen 443 ssl http2`), an address with a port
// (`listen 127.0.0.1:8080`, `listen *:80`, `listen [::]:80`), an address without one
// (`listen 127.0.0.1`, which nginx serves on 80), and a unix socket, which binds no
// port at all.
func nginxListenPort(args []string) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	spec := strings.Trim(args[0], `"'`)
	if spec == "" || strings.HasPrefix(spec, "unix:") {
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
	// An address with no port: nginx's documented default is 80.
	return 80, true
}

// ──────────────────────────────────────────────────────── the `nginx -T` dump

// nginxDumpMarker matches the header `nginx -T` writes before each file it dumps.
// The body that follows starts at line 1 of that file, which is what makes the
// dump — and not a walk of /etc/nginx — the source of a trustworthy file:line.
var nginxDumpMarker = regexp.MustCompile(`^#\s*configuration file (.+):\s*$`)

// parseNginxDump folds the output of `nginx -T` into acc, and returns the root
// configuration file (the first one dumped) and every file the dump contained.
//
// Anything before the first marker is nginx's own chatter and is ignored.
func parseNginxDump(dump string, acc *accumulator) (root string, files []string) {
	var (
		current string
		body    []string
	)

	flush := func() {
		if current == "" {
			return
		}
		files = append(files, current)
		// A dumped body has no includes left to follow: `nginx -T` already resolved
		// them and dumped each target as a segment of its own.
		scanNginxFile(current, strings.Join(body, "\n"), acc)
		body = nil
	}

	for _, line := range strings.Split(dump, "\n") {
		if m := nginxDumpMarker.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			flush()
			current = strings.TrimSpace(m[1])
			if root == "" {
				root = current
			}
			continue
		}
		if current == "" {
			continue
		}
		body = append(body, line)
	}
	flush()

	return root, files
}

// walkNginxTree is the fallback: the root configuration plus the drop-in
// directories, following includes within the bounds in walk.go. It is strictly
// worse than the dump — a generated vhost outside these directories is invisible to
// it — and every caller of it says so in the report.
func walkNginxTree(root string, acc *accumulator) *crawler {
	base := "/etc/nginx"
	if root != "" {
		base = filepath.Dir(root)
	}

	c := newCrawler(base, scanNginxFile, acc)
	if root != "" {
		c.file(root, 0)
	}
	for _, glob := range nginxDropInGlobs {
		c.walk(glob, 1)
	}
	return c
}

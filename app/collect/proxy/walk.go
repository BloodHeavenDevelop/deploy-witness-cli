package proxy

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// The bounds on a configuration walk.
//
// A walk only happens when the front end's own dump is unavailable, and walking
// somebody else's /etc is exactly where a tool like this wanders off: a symlink
// loop under sites-enabled, a control panel with ten thousand vhost files, an
// include that reaches a log. Every bound below has a note attached to it where it
// is enforced — a limit that quietly trims the answer would turn "partial" into
// "clean", which is the one thing this repository does not do.
const (
	// maxWalkDepth bounds the include chain. Real trees are three deep:
	// nginx.conf → sites-enabled/* → a snippet.
	maxWalkDepth = 8
	// maxWalkFiles bounds how many files one walk reads in total.
	maxWalkFiles = 256
	// maxFileBytes bounds a single configuration file.
	maxFileBytes = 4 << 20
	// maxServerNames bounds the reported name list. A mass-hosting box can serve
	// thousands, and the report is a CSV somebody reads.
	maxServerNames = 1000
	// maxVersionScanBytes bounds the read of a binary when its version has to be
	// taken from the string compiled into it. See nginxVersion.
	maxVersionScanBytes = 16 << 20
)

// accumulator gathers what every parser in this package produces, deduplicated.
//
// A name is keyed by name *and* location: the same domain configured in two files
// is two facts, and it is precisely the interesting case — that is a host where
// somebody already lost track of which vhost wins.
type accumulator struct {
	names          []model.ProxyServerName
	seenName       map[string]struct{}
	ports          map[int]struct{}
	certs          map[string]struct{}
	namesTruncated bool
}

func newAccumulator() *accumulator {
	return &accumulator{
		seenName: map[string]struct{}{},
		ports:    map[int]struct{}{},
		certs:    map[string]struct{}{},
	}
}

// addName records one name the front end answers for, at the place it is
// configured. Names are kept verbatim: a wildcard stays a wildcard and nginx's
// catch-all `_` stays `_`, because a catch-all vhost is the reason a new domain
// silently lands on the wrong site and dropping it would hide that.
func (a *accumulator) addName(name, file string, line int) {
	name = strings.Trim(strings.TrimSpace(name), `"'`)
	if name == "" {
		return
	}
	key := name + "\x00" + file + "\x00" + strconv.Itoa(line)
	if _, dup := a.seenName[key]; dup {
		return
	}
	if len(a.names) >= maxServerNames {
		a.namesTruncated = true
		return
	}
	a.seenName[key] = struct{}{}
	a.names = append(a.names, model.ProxyServerName{Name: name, File: file, Line: line})
}

func (a *accumulator) addPort(port int) {
	if port <= 0 || port > 65535 {
		return
	}
	a.ports[port] = struct{}{}
}

// addCert records a referenced certificate file. The path only — nothing in this
// package opens a certificate, and nothing anywhere in it opens a key.
func (a *accumulator) addCert(path string) {
	path = strings.Trim(strings.TrimSpace(path), `"'`)
	if path == "" {
		return
	}
	a.certs[path] = struct{}{}
}

func (a *accumulator) sortedPorts() []int {
	out := make([]int, 0, len(a.ports))
	for port := range a.ports {
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

func (a *accumulator) sortedCerts() []string {
	out := make([]string, 0, len(a.certs))
	for path := range a.certs {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// fileScanner folds one configuration file into the accumulator and returns the
// include patterns it referenced, unresolved. Resolving them is the crawler's
// job, which is what keeps the parsers plain functions over a string.
type fileScanner func(path, body string, acc *accumulator) []string

// crawler walks a configuration tree, following includes, within the bounds above.
type crawler struct {
	scan fileScanner
	acc  *accumulator
	// base is where a relative include is resolved from — nginx's prefix, Apache's
	// ServerRoot.
	base string

	visited map[string]struct{}
	files   int

	hitFileLimit  bool
	hitDepthLimit bool
	oversize      []string
	unreadable    []string
}

func newCrawler(base string, scan fileScanner, acc *accumulator) *crawler {
	return &crawler{scan: scan, acc: acc, base: base, visited: map[string]struct{}{}}
}

// walk expands one include pattern and reads everything it names.
func (c *crawler) walk(pattern string, depth int) {
	if depth > maxWalkDepth {
		c.hitDepthLimit = true
		return
	}
	for _, path := range c.expand(pattern) {
		c.file(path, depth)
	}
}

// expand turns an include into concrete paths. A literal path that does not exist
// is still returned, so that file() can decide whether its absence is worth a note.
func (c *crawler) expand(pattern string) []string {
	pattern = strings.Trim(pattern, `"'`)
	if pattern == "" {
		return nil
	}
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(c.base, pattern)
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{pattern}
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	return matches
}

// file reads one path and recurses into whatever it includes.
func (c *crawler) file(path string, depth int) {
	// Cycles are broken on the resolved path, not the written one: sites-enabled is
	// a directory of symlinks, and two of them pointing at one file is normal.
	real := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		real = resolved
	}
	if _, done := c.visited[real]; done {
		return
	}
	c.visited[real] = struct{}{}

	info, err := os.Stat(path)
	if err != nil {
		// A missing file is ordinary — Apache's IncludeOptional and a disabled site
		// both look like this. Anything else is a gap the reader has to know about.
		if !errors.Is(err, fs.ErrNotExist) {
			c.unreadable = append(c.unreadable, path+": "+err.Error())
		}
		return
	}
	if info.IsDir() {
		// Apache's Include may name a directory. Only *.conf is taken from one: a
		// directory include is not a licence to read every file in it.
		c.walk(filepath.Join(path, "*.conf"), depth+1)
		return
	}
	if !info.Mode().IsRegular() {
		return
	}
	if c.files >= maxWalkFiles {
		c.hitFileLimit = true
		return
	}
	c.files++

	body, oversize, err := readLimited(path, maxFileBytes)
	if err != nil {
		c.unreadable = append(c.unreadable, path+": "+err.Error())
		return
	}
	if oversize {
		c.oversize = append(c.oversize, path)
	}
	for _, include := range c.scan(path, body, c.acc) {
		c.walk(include, depth+1)
	}
}

// notes reports every bound that bit and every file that could not be read. An
// empty result means the walk saw everything it set out to see.
func (c *crawler) notes() []string {
	var out []string
	if c.hitDepthLimit {
		out = append(out, "the include chain was deeper than "+strconv.Itoa(maxWalkDepth)+
			" levels; anything below that was not read")
	}
	if c.hitFileLimit {
		out = append(out, "the configuration walk stopped at "+strconv.Itoa(maxWalkFiles)+
			" files; the remaining files were not read")
	}
	if len(c.oversize) > 0 {
		out = append(out, "read only the first "+strconv.Itoa(maxFileBytes/(1<<20))+" MiB of "+
			strings.Join(c.oversize, ", "))
	}
	if n := len(c.unreadable); n > 0 {
		shown := c.unreadable
		if n > 5 {
			shown = shown[:5]
		}
		note := strconv.Itoa(n) + " configuration file(s) could not be read: " + strings.Join(shown, "; ")
		if n > len(shown) {
			note += "; …"
		}
		out = append(out, note)
	}
	return out
}

// readLimited reads at most limit bytes and reports whether the file was longer.
func readLimited(path string, limit int64) (body string, truncated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", false, err
	}
	if int64(len(data)) > limit {
		return string(data[:limit]), true, nil
	}
	return string(data), false, nil
}

// firstExisting returns the first path that is there, or "".
func firstExisting(paths ...string) string {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// appendNote joins notes into the single Note field the model gives us, without
// letting an empty one contribute a stray separator.
func appendNote(existing string, add ...string) string {
	parts := make([]string, 0, len(add)+1)
	if strings.TrimSpace(existing) != "" {
		parts = append(parts, strings.TrimSpace(existing))
	}
	for _, note := range add {
		if strings.TrimSpace(note) != "" {
			parts = append(parts, strings.TrimSpace(note))
		}
	}
	return strings.Join(parts, "; ")
}

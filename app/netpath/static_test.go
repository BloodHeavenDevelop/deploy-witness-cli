package netpath

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// networkFiles are the only source files allowed to open a connection, one per
// network path. A new entry here is a new way for this tool to reach the network,
// and it needs the flag, the documentation and the network.csv row the other
// three have — see docs/<lang>/04-cli-reference.md, "Network behaviour".
var networkFiles = map[string]string{
	"app/netpath/netpath.go": "the shared HTTP client (no redirects) used by --online and --upload",
	"app/vuln/online.go":     "--online: the OSV API",
	"app/audit/witness.go":   "--egress: one TCP connect per registry",
	"app/report/upload.go":   "--upload: one POST of the report",
}

// networkAPI matches the standard-library calls and types that resolve a name,
// open a socket or send an HTTP request. net.Interfaces (a netlink read of this
// host's own addresses) and the net.IP/ParseCIDR helpers are not on it: they never
// leave the machine.
var networkAPI = regexp.MustCompile(`\b(` +
	`net\.(Dial\w*|Dialer|Listen\w*|Lookup\w*|Resolve\w*|Resolver|DefaultResolver|FileConn|FilePacketConn)|` +
	`http\.(Client|Get|Post|Head|PostForm|DefaultClient|DefaultTransport|Transport|ListenAndServe\w*|Serve\w*)|` +
	`tls\.(Dial\w*|Client)|` +
	`netpath\.NewHTTPClient` +
	`)\b`)

// forbiddenImports reach the network through a door the pattern above does not
// cover.
var forbiddenImports = regexp.MustCompile(`"(net/smtp|net/rpc|net/http/httputil|golang\.org/x/net/[^"]*)"`)

// TestOnlyTheThreeNetworkPathsTouchTheNetwork is the static half of the offline
// promise: no production file outside networkFiles may use a network API. The
// dynamic half — that those files only run behind their flags — is covered by the
// config, runner and upload tests.
func TestOnlyTheThreeNetworkPathsTouchTheNetwork(t *testing.T) {
	root := moduleRoot(t)

	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "dist", "bin", "contract":
				// app/contract/auditv1 is generated protobuf, copied verbatim.
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if _, allowed := networkFiles[rel]; allowed {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, hit := range networkAPI.FindAllString(string(source), -1) {
			offenders = append(offenders, rel+": "+hit)
		}
		for _, hit := range forbiddenImports.FindAllString(string(source), -1) {
			offenders = append(offenders, rel+": import "+hit)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("network API outside the three network paths: %s", o)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

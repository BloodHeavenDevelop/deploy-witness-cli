package proxy

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Every fixture below is real output shape, kept verbatim down to the indentation:
// the file:line attribution this package promises is entirely a property of how the
// two commands lay their output out, so a tidied-up fixture would test nothing.
//
// Nothing here needs nginx or Apache installed. The parsers are plain functions over
// a string, which is the whole reason they are shaped that way.

// nginxDumpFixture is `nginx -T` output: the first line is the chatter nginx writes
// before the dump, then one `# configuration file …:` marker per file. Note the
// commented-out directive, the multi-line server_name, the catch-all `_`, the
// wildcard, the IPv6 listen, the unix socket, and the private key sitting right next
// to the certificate.
const nginxDumpFixture = `nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# configuration file /etc/nginx/nginx.conf:
user www-data;
worker_processes auto;

events {
    worker_connections 768;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    # server_name commented.example.com;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

# configuration file /etc/nginx/mime.types:
types {
    text/html html htm shtml;
}

# configuration file /etc/nginx/conf.d/default.conf:
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/html;
}

# configuration file /etc/nginx/sites-enabled/example.conf:
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com www.example.com
                *.example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
}

server {
    listen 8080;
    server_name "internal.example.com";  # the admin interface
}

server {
    listen unix:/var/run/nginx-status.sock;
    server_name status.example.com;
}
`

func TestParseNginxDump(t *testing.T) {
	acc := newAccumulator()
	root, files := parseNginxDump(nginxDumpFixture, acc)

	if want := "/etc/nginx/nginx.conf"; root != want {
		t.Errorf("root config = %q, want %q", root, want)
	}

	wantFiles := []string{
		"/etc/nginx/nginx.conf",
		"/etc/nginx/mime.types",
		"/etc/nginx/conf.d/default.conf",
		"/etc/nginx/sites-enabled/example.conf",
	}
	if !reflect.DeepEqual(files, wantFiles) {
		t.Errorf("dumped files = %v, want %v", files, wantFiles)
	}

	// The location is the point of the exercise: a reader has to be able to open
	// the file at that line and see the name.
	wantNames := []model.ProxyServerName{
		{Name: "_", File: "/etc/nginx/conf.d/default.conf", Line: 4},
		{Name: "example.com", File: "/etc/nginx/sites-enabled/example.conf", Line: 4},
		{Name: "www.example.com", File: "/etc/nginx/sites-enabled/example.conf", Line: 4},
		// Written on the directive's second line, and reported there.
		{Name: "*.example.com", File: "/etc/nginx/sites-enabled/example.conf", Line: 5},
		{Name: "internal.example.com", File: "/etc/nginx/sites-enabled/example.conf", Line: 13},
		{Name: "status.example.com", File: "/etc/nginx/sites-enabled/example.conf", Line: 18},
	}
	if !reflect.DeepEqual(acc.names, wantNames) {
		t.Errorf("server names =\n%+v\nwant\n%+v", acc.names, wantNames)
	}

	wantPorts := []int{80, 443, 8080}
	if got := acc.sortedPorts(); !reflect.DeepEqual(got, wantPorts) {
		t.Errorf("listen ports = %v, want %v (the unix socket binds none)", got, wantPorts)
	}

	// The certificate, and only the certificate: ssl_certificate_key names the
	// private half and must not be collected.
	wantCerts := []string{"/etc/letsencrypt/live/example.com/fullchain.pem"}
	if got := acc.sortedCerts(); !reflect.DeepEqual(got, wantCerts) {
		t.Errorf("certificate paths = %v, want %v", got, wantCerts)
	}
}

func TestParseNginxDumpIgnoresChatterAndComments(t *testing.T) {
	acc := newAccumulator()
	root, files := parseNginxDump("nginx: [emerg] unexpected end of file\n", acc)
	if root != "" || files != nil {
		t.Errorf("output with no marker yielded root %q and files %v, want neither", root, files)
	}
	if len(acc.names) != 0 {
		t.Errorf("output with no marker yielded names %+v", acc.names)
	}

	acc = newAccumulator()
	parseNginxDump(nginxDumpFixture, acc)
	for _, name := range acc.names {
		if name.Name == "commented.example.com" {
			t.Error("a commented-out server_name was collected")
		}
	}
}

func TestScanNginxFileIncludes(t *testing.T) {
	const body = `http {
    include mime.types;
    include /etc/nginx/conf.d/*.conf;
    # include /etc/nginx/disabled/*.conf;
    server {
        listen 127.0.0.1;
        server_name a.example.com b.example.com;
        include snippets/tls.conf;
    }
}
`
	acc := newAccumulator()
	includes := scanNginxFile("/etc/nginx/nginx.conf", body, acc)

	wantIncludes := []string{"mime.types", "/etc/nginx/conf.d/*.conf", "snippets/tls.conf"}
	if !reflect.DeepEqual(includes, wantIncludes) {
		t.Errorf("includes = %v, want %v", includes, wantIncludes)
	}

	wantNames := []model.ProxyServerName{
		{Name: "a.example.com", File: "/etc/nginx/nginx.conf", Line: 7},
		{Name: "b.example.com", File: "/etc/nginx/nginx.conf", Line: 7},
	}
	if !reflect.DeepEqual(acc.names, wantNames) {
		t.Errorf("names = %+v, want %+v", acc.names, wantNames)
	}
	// `listen 127.0.0.1` with no port is port 80, per nginx's documented default.
	if got := acc.sortedPorts(); !reflect.DeepEqual(got, []int{80}) {
		t.Errorf("ports = %v, want [80]", got)
	}
}

func TestNginxDirectiveLines(t *testing.T) {
	// Two directives on one line, a quoted argument spanning nothing unusual, and a
	// block header — all of which `nginx -T` can hand us verbatim.
	const body = `server { listen 8443 ssl; server_name one.example.com; }
server_name two.example.com;
`
	got := nginxDirectives(body)
	want := []nginxDirective{
		{name: "server", args: []string{}, line: 1, argLines: []int{}},
		{name: "listen", args: []string{"8443", "ssl"}, line: 1, argLines: []int{1, 1}},
		{name: "server_name", args: []string{"one.example.com"}, line: 1, argLines: []int{1}},
		{name: "server_name", args: []string{"two.example.com"}, line: 2, argLines: []int{2}},
	}
	if len(got) != len(want) {
		t.Fatalf("directives = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].name != want[i].name || got[i].line != want[i].line {
			t.Errorf("directive %d = %+v, want %+v", i, got[i], want[i])
		}
		if !reflect.DeepEqual(got[i].argLines, want[i].argLines) &&
			!(len(got[i].argLines) == 0 && len(want[i].argLines) == 0) {
			t.Errorf("directive %d arg lines = %v, want %v", i, got[i].argLines, want[i].argLines)
		}
	}
}

func TestNginxListenPort(t *testing.T) {
	cases := []struct {
		name string
		args []string
		port int
		ok   bool
	}{
		{"bare port", []string{"80", "default_server"}, 80, true},
		{"tls with http2", []string{"443", "ssl", "http2"}, 443, true},
		{"ipv6 any", []string{"[::]:80", "default_server"}, 80, true},
		{"ipv6 literal with port", []string{"[2001:db8::1]:8443", "ssl"}, 8443, true},
		{"wildcard address", []string{"*:8080"}, 8080, true},
		{"address and port", []string{"127.0.0.1:8081"}, 8081, true},
		{"hostname and port", []string{"localhost:8082"}, 8082, true},
		{"address only defaults to 80", []string{"127.0.0.1"}, 80, true},
		{"ipv6 literal only defaults to 80", []string{"[::1]"}, 80, true},
		{"unix socket binds nothing", []string{"unix:/var/run/nginx.sock"}, 0, false},
		{"no argument", nil, 0, false},
		{"out of range", []string{"70000"}, 70000, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			port, ok := nginxListenPort(c.args)
			if ok != c.ok || (ok && port != c.port) {
				t.Errorf("nginxListenPort(%v) = %d, %v; want %d, %v", c.args, port, ok, c.port, c.ok)
			}
		})
	}
}

func TestParseNginxVersion(t *testing.T) {
	cases := map[string]string{
		"nginx version: nginx/1.24.0\n":                           "1.24.0",
		"nginx version: nginx/1.25.3 (Ubuntu)\n":                  "1.25.3",
		"nginx version: nginx/1.18\n":                             "1.18",
		"nginx version: openresty/1.21.4.1\nbuilt by gcc\n":       "",
		"\x00\x00nginx/1.22.1\x00Server: nginx\x00binary strings": "1.22.1",
		"": "",
	}
	for input, want := range cases {
		if got := parseNginxVersion(input); got != want {
			t.Errorf("parseNginxVersion(%q) = %q, want %q", input, got, want)
		}
	}
}

// apacheVhostMapFixture is `apache2ctl -S` output on a Debian host: a name-based
// block with an alias and a wildcard alias, two single-vhost addresses, an IPv6
// address, and the trailer nothing in it should mistake for a vhost.
const apacheVhostMapFixture = `VirtualHost configuration:
*:80                   is a NameVirtualHost
         default server example.com (/etc/apache2/sites-enabled/000-default.conf:1)
         port 80 namevhost example.com (/etc/apache2/sites-enabled/000-default.conf:1)
                 alias www.example.com
         port 80 namevhost shop.example.net (/etc/apache2/sites-enabled/010-shop.conf:1)
                 wild alias *.shop.example.net
*:443                  secure.example.com (/etc/apache2/sites-enabled/default-ssl.conf:2)
[::]:8443              admin.example.com (/etc/apache2/sites-enabled/admin.conf:7)
ServerRoot: "/etc/apache2"
Main DocumentRoot: "/var/www/html"
Main ErrorLog: "/var/log/apache2/error.log"
Mutex ssl-stapling: using_defaults
PidFile: "/var/run/apache2/apache2.pid"
User: name="www-data" id=33
Group: name="www-data" id=33
`

func TestParseApacheVhostMap(t *testing.T) {
	acc := newAccumulator()
	serverRoot, files := parseApacheVhostMap(apacheVhostMapFixture, acc)

	if want := "/etc/apache2"; serverRoot != want {
		t.Errorf("ServerRoot = %q, want %q", serverRoot, want)
	}

	wantNames := []model.ProxyServerName{
		{Name: "example.com", File: "/etc/apache2/sites-enabled/000-default.conf", Line: 1},
		// An alias has no location of its own; it belongs to the vhost above it.
		{Name: "www.example.com", File: "/etc/apache2/sites-enabled/000-default.conf", Line: 1},
		{Name: "shop.example.net", File: "/etc/apache2/sites-enabled/010-shop.conf", Line: 1},
		{Name: "*.shop.example.net", File: "/etc/apache2/sites-enabled/010-shop.conf", Line: 1},
		{Name: "secure.example.com", File: "/etc/apache2/sites-enabled/default-ssl.conf", Line: 2},
		{Name: "admin.example.com", File: "/etc/apache2/sites-enabled/admin.conf", Line: 7},
	}
	if !reflect.DeepEqual(acc.names, wantNames) {
		t.Errorf("server names =\n%+v\nwant\n%+v", acc.names, wantNames)
	}

	wantPorts := []int{80, 443, 8443}
	if got := acc.sortedPorts(); !reflect.DeepEqual(got, wantPorts) {
		t.Errorf("listen ports = %v, want %v", got, wantPorts)
	}

	wantFiles := []string{
		"/etc/apache2/sites-enabled/000-default.conf",
		"/etc/apache2/sites-enabled/010-shop.conf",
		"/etc/apache2/sites-enabled/default-ssl.conf",
		"/etc/apache2/sites-enabled/admin.conf",
	}
	if !reflect.DeepEqual(files, wantFiles) {
		t.Errorf("vhost files = %v, want %v", files, wantFiles)
	}

	// The trailer lines are not vhosts.
	for _, name := range acc.names {
		switch name.Name {
		case "DocumentRoot:", "ErrorLog:", "using_defaults", `name="www-data"`:
			t.Errorf("the -S trailer produced a server name: %q", name.Name)
		}
	}
}

// apacheVhostFileFixture is one vhost file, as the fallback walk reads it.
const apacheVhostFileFixture = `# the secure site
<VirtualHost *:443 10.0.0.5:443>
    ServerName https://secure.example.com:443
    ServerAlias secure.example.net *.secure.example.com
    DocumentRoot /var/www/secure

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/secure.example.com.pem
    SSLCertificateKeyFile /etc/ssl/private/secure.example.com.key

    IncludeOptional /etc/apache2/snippets/*.conf
</VirtualHost>

Listen 8443 https
`

func TestScanApacheFile(t *testing.T) {
	acc := newAccumulator()
	includes := scanApacheFile("/etc/apache2/sites-enabled/secure.conf", apacheVhostFileFixture, acc)

	wantIncludes := []string{"/etc/apache2/snippets/*.conf"}
	if !reflect.DeepEqual(includes, wantIncludes) {
		t.Errorf("includes = %v, want %v", includes, wantIncludes)
	}

	wantNames := []model.ProxyServerName{
		{Name: "secure.example.com", File: "/etc/apache2/sites-enabled/secure.conf", Line: 3},
		{Name: "secure.example.net", File: "/etc/apache2/sites-enabled/secure.conf", Line: 4},
		{Name: "*.secure.example.com", File: "/etc/apache2/sites-enabled/secure.conf", Line: 4},
	}
	if !reflect.DeepEqual(acc.names, wantNames) {
		t.Errorf("server names =\n%+v\nwant\n%+v", acc.names, wantNames)
	}

	wantPorts := []int{443, 8443}
	if got := acc.sortedPorts(); !reflect.DeepEqual(got, wantPorts) {
		t.Errorf("ports = %v, want %v", got, wantPorts)
	}

	wantCerts := []string{"/etc/ssl/certs/secure.example.com.pem"}
	if got := acc.sortedCerts(); !reflect.DeepEqual(got, wantCerts) {
		t.Errorf("certificate paths = %v, want %v (never the key)", got, wantCerts)
	}
}

func TestScanApachePortsAndCertificatesLeavesNamesToTheMap(t *testing.T) {
	acc := newAccumulator()
	includes := scanApachePortsAndCertificates("/etc/apache2/sites-enabled/secure.conf",
		apacheVhostFileFixture, acc)

	if want := []string{"/etc/apache2/snippets/*.conf"}; !reflect.DeepEqual(includes, want) {
		t.Errorf("includes = %v, want %v", includes, want)
	}
	if len(acc.names) != 0 {
		t.Errorf("names were taken from the file although the vhost map supplied them: %+v", acc.names)
	}
	// Ports and certificates are still collected: `apachectl -S` lists neither a
	// certificate nor a Listen that has no vhost behind it.
	if got := acc.sortedPorts(); !reflect.DeepEqual(got, []int{443, 8443}) {
		t.Errorf("ports = %v, want [443 8443]", got)
	}
	if got := acc.sortedCerts(); !reflect.DeepEqual(got, []string{"/etc/ssl/certs/secure.example.com.pem"}) {
		t.Errorf("certificate paths = %v", got)
	}
}

func TestApacheServerNameHost(t *testing.T) {
	cases := map[string]string{
		"example.com":                "example.com",
		"example.com:80":             "example.com",
		"https://secure.example.com": "secure.example.com",
		"http://example.com:8080":    "example.com",
		`"example.org"`:              "example.org",
		"[2001:db8::1]:443":          "[2001:db8::1]",
		"[::1]":                      "[::1]",
	}
	for input, want := range cases {
		if got := apacheServerNameHost(input); got != want {
			t.Errorf("apacheServerNameHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestApachePort(t *testing.T) {
	cases := []struct {
		spec string
		port int
		ok   bool
	}{
		{"80", 80, true},
		{"*:443", 443, true},
		{"10.0.0.5:8080", 8080, true},
		{"[::]:8443", 8443, true},
		{"*", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		port, ok := apachePort(c.spec)
		if ok != c.ok || (ok && port != c.port) {
			t.Errorf("apachePort(%q) = %d, %v; want %d, %v", c.spec, port, ok, c.port, c.ok)
		}
	}
}

func TestParseApacheVersion(t *testing.T) {
	cases := map[string]string{
		"Server version: Apache/2.4.57 (Debian)\nServer built:   2023-04-13\n": "2.4.57",
		"Server version: Apache/2.4.6 (CentOS)\n":                              "2.4.6",
		"": "",
	}
	for input, want := range cases {
		if got := parseApacheVersion(input); got != want {
			t.Errorf("parseApacheVersion(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAccumulatorKeepsTheSameNameInTwoPlaces(t *testing.T) {
	acc := newAccumulator()
	acc.addName("example.com", "/etc/nginx/conf.d/a.conf", 3)
	acc.addName("example.com", "/etc/nginx/conf.d/a.conf", 3) // the same fact twice
	acc.addName("example.com", "/etc/nginx/conf.d/b.conf", 9) // a different one

	if len(acc.names) != 2 {
		t.Fatalf("names = %+v, want the duplicate collapsed and the second location kept", acc.names)
	}
	if acc.names[1].File != "/etc/nginx/conf.d/b.conf" || acc.names[1].Line != 9 {
		t.Errorf("second location = %+v", acc.names[1])
	}
}

// The fallback walk itself, on a tree built for the test — a real /etc/nginx is not
// needed and must not be.
func TestCrawlerFollowsIncludesAndBreaksCycles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "nginx.conf"), "http {\n    include conf.d/*.conf;\n}\n")
	if err := os.Mkdir(filepath.Join(dir, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "conf.d", "a.conf"),
		"server {\n    listen 443 ssl;\n    server_name a.example.com;\n"+
			"    ssl_certificate /etc/ssl/a.pem;\n    include conf.d/b.conf;\n}\n")
	// b includes the root again: a cycle, which must be stepped over rather than
	// followed forever.
	writeFile(t, filepath.Join(dir, "conf.d", "b.conf"),
		"server {\n    listen 8080;\n    server_name b.example.com;\n    include nginx.conf;\n}\n")

	acc := newAccumulator()
	c := newCrawler(dir, scanNginxFile, acc)
	c.file(filepath.Join(dir, "nginx.conf"), 0)

	if c.files != 3 {
		t.Errorf("files read = %d, want 3", c.files)
	}
	if notes := c.notes(); len(notes) != 0 {
		t.Errorf("a complete walk produced notes: %v", notes)
	}
	wantNames := []model.ProxyServerName{
		{Name: "a.example.com", File: filepath.Join(dir, "conf.d", "a.conf"), Line: 3},
		{Name: "b.example.com", File: filepath.Join(dir, "conf.d", "b.conf"), Line: 3},
	}
	if !reflect.DeepEqual(acc.names, wantNames) {
		t.Errorf("names =\n%+v\nwant\n%+v", acc.names, wantNames)
	}
	if got := acc.sortedPorts(); !reflect.DeepEqual(got, []int{443, 8080}) {
		t.Errorf("ports = %v, want [443 8080]", got)
	}
	if got := acc.sortedCerts(); !reflect.DeepEqual(got, []string{"/etc/ssl/a.pem"}) {
		t.Errorf("certificates = %v", got)
	}
}

func TestCrawlerFileBoundIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxWalkFiles+5; i++ {
		writeFile(t, filepath.Join(dir, "conf.d", "site"+strconv.Itoa(i)+".conf"),
			"server { server_name host"+strconv.Itoa(i)+".example.com; }\n")
	}

	acc := newAccumulator()
	c := newCrawler(dir, scanNginxFile, acc)
	c.walk("conf.d/*.conf", 1)

	if c.files != maxWalkFiles {
		t.Errorf("files read = %d, want the walk to stop at %d", c.files, maxWalkFiles)
	}
	if !c.hitFileLimit {
		t.Fatal("the walk stopped early without recording that it did")
	}
	if notes := c.notes(); len(notes) == 0 {
		t.Error("the file bound bit without producing a note — a silent truncation")
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestServerNameBoundIsReported(t *testing.T) {
	acc := newAccumulator()
	for i := 0; i < maxServerNames+10; i++ {
		acc.addName("host"+strconv.Itoa(i)+".example.com", "/etc/nginx/conf.d/mass.conf", i+1)
	}
	if len(acc.names) != maxServerNames {
		t.Errorf("names = %d, want the list to stop at %d", len(acc.names), maxServerNames)
	}
	if !acc.namesTruncated {
		t.Error("the list was trimmed without setting namesTruncated — a silent truncation")
	}
}

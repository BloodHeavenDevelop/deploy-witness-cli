package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Every fixture is written into t.TempDir: the parser reads one file and its
// directory, so a test needs no host state, no container runtime and no network.

const composeName = "docker-compose.yml"

// fixture writes the named files into a fresh directory and returns the path of
// the compose file inside it.
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return filepath.Join(dir, composeName)
}

// parseFixture writes one compose file (plus any extra files) and parses it.
func parseFixture(t *testing.T, compose string, extra map[string]string) (*model.Manifest, *model.SectionResult) {
	t.Helper()
	files := map[string]string{composeName: compose}
	for name, content := range extra {
		files[name] = content
	}

	result := &model.SectionResult{Section: model.SectionWitness, Status: model.StatusOk}
	manifest, err := Parse(fixture(t, files), result)
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	return manifest, result
}

// onlyService is the single service of a one-service fixture.
func onlyService(t *testing.T, manifest *model.Manifest) model.ManifestService {
	t.Helper()
	if len(manifest.Services) != 1 {
		t.Fatalf("expected exactly 1 service, got %d", len(manifest.Services))
	}
	return manifest.Services[0]
}

// hasWarning reports whether any warning mentions the fragment.
func hasWarning(warnings []string, fragment string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, fragment) {
			return true
		}
	}
	return false
}

// unsetenv guarantees a variable is absent for the duration of the test and
// restores whatever the environment had before.
func unsetenv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "")
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("unsetenv %s: %v", name, err)
	}
}

// ─────────────────────────────────────────────────────────────────── ports

func TestParsePorts(t *testing.T) {
	const template = `
services:
  web:
    image: nginx
    ports:
%s
`

	cases := []struct {
		name    string
		entries string
		want    []model.PortMapping
		warning string
	}{
		{
			name:    "container port only",
			entries: `      - "80"`,
			want:    []model.PortMapping{{ContainerPort: 80, Protocol: "tcp"}},
		},
		{
			name:    "host and container",
			entries: `      - "8080:80"`,
			want:    []model.PortMapping{{HostPort: 8080, HostPortEnd: 8080, ContainerPort: 80, Protocol: "tcp"}},
		},
		{
			name:    "explicit host ip and protocol",
			entries: `      - "127.0.0.1:8080:80/udp"`,
			want: []model.PortMapping{{
				HostIP: "127.0.0.1", HostPort: 8080, HostPortEnd: 8080, ContainerPort: 80, Protocol: "udp",
			}},
		},
		{
			name:    "bracketed ipv6 host ip",
			entries: `      - "[::1]:8080:80"`,
			want: []model.PortMapping{{
				HostIP: "::1", HostPort: 8080, HostPortEnd: 8080, ContainerPort: 80, Protocol: "tcp",
			}},
		},
		{
			name:    "range",
			entries: `      - "3000-3005:3000-3005"`,
			want: []model.PortMapping{{
				HostPort: 3000, HostPortEnd: 3005, ContainerPort: 3000, Protocol: "tcp",
			}},
		},
		{
			name: "long form",
			entries: `      - target: 5432
        published: "15432"
        protocol: tcp
        host_ip: 127.0.0.1
        mode: host`,
			want: []model.PortMapping{{
				HostIP: "127.0.0.1", HostPort: 15432, HostPortEnd: 15432, ContainerPort: 5432, Protocol: "tcp",
			}},
		},
		{
			name: "long form with a numeric published port",
			entries: `      - target: 80
        published: 8080`,
			want: []model.PortMapping{{HostPort: 8080, HostPortEnd: 8080, ContainerPort: 80, Protocol: "tcp"}},
		},
		{
			name: "long form with a published range and udp",
			entries: `      - target: 3000
        published: "3000-3005"
        protocol: udp`,
			want: []model.PortMapping{{
				HostPort: 3000, HostPortEnd: 3005, ContainerPort: 3000, Protocol: "udp",
			}},
		},
		{
			name: "long form without a published port",
			entries: `      - target: 9000
        protocol: tcp`,
			want: []model.PortMapping{{ContainerPort: 9000, Protocol: "tcp"}},
		},
		{
			name:    "both syntaxes in one list",
			entries: "      - \"8080:80\"\n      - target: 443\n        published: 8443",
			want: []model.PortMapping{
				{HostPort: 8080, HostPortEnd: 8080, ContainerPort: 80, Protocol: "tcp"},
				{HostPort: 8443, HostPortEnd: 8443, ContainerPort: 443, Protocol: "tcp"},
			},
		},
		{
			name:    "unparsable entry is dropped and reported",
			entries: "      - \"nonsense:80\"\n      - \"9000:9000\"",
			want: []model.PortMapping{
				{HostPort: 9000, HostPortEnd: 9000, ContainerPort: 9000, Protocol: "tcp"},
			},
			warning: `services.web.ports[0]`,
		},
		{
			name:    "too many colon parts",
			entries: `      - "1:2:3:4"`,
			warning: "too many colon-separated parts",
		},
		{
			name:    "out of range",
			entries: `      - "70000:80"`,
			warning: "outside the port range",
		},
		{
			name:    "reversed range",
			entries: `      - "3005-3000:3000"`,
			warning: "ends below where it starts",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest, result := parseFixture(t, fmt.Sprintf(template, tc.entries), nil)
			service := onlyService(t, manifest)

			if !reflect.DeepEqual(service.Ports, tc.want) {
				t.Errorf("ports:\n got %+v\nwant %+v", service.Ports, tc.want)
			}
			if tc.warning == "" {
				if len(manifest.Warnings) != 0 {
					t.Errorf("expected no warnings, got %v", manifest.Warnings)
				}
				return
			}
			if !hasWarning(manifest.Warnings, tc.warning) {
				t.Errorf("expected a warning mentioning %q, got %v", tc.warning, manifest.Warnings)
			}
			if result.Status != model.StatusPartial {
				t.Errorf("a warning must degrade the section, status is %q", result.Status)
			}
			if len(result.Notes) == 0 {
				t.Error("a warning must also reach the section result's notes")
			}
		})
	}
}

func TestParseExpose(t *testing.T) {
	manifest, _ := parseFixture(t, `
services:
  api:
    image: nginx
    expose:
      - "3000"
      - 9090
      - "5000/udp"
`, nil)

	want := []int{3000, 9090, 5000}
	if got := onlyService(t, manifest).Expose; !reflect.DeepEqual(got, want) {
		t.Errorf("expose: got %v, want %v", got, want)
	}
}

// ─────────────────────────────────────────────────────────────── volumes

func TestParseVolumes(t *testing.T) {
	const template = `
services:
  app:
    image: nginx
    volumes:
%s
`

	cases := []struct {
		name    string
		entries string
		want    []model.VolumeMount
		socket  bool
		warning string
	}{
		{
			name:    "short bind",
			entries: `      - /srv/app/data:/data`,
			want:    []model.VolumeMount{{Kind: model.MountBind, Source: "/srv/app/data", Target: "/data"}},
		},
		{
			name:    "short bind read-only",
			entries: `      - ./config:/etc/app:ro`,
			want: []model.VolumeMount{
				{Kind: model.MountBind, Source: "./config", Target: "/etc/app", ReadOnly: true},
			},
		},
		{
			name:    "short named volume",
			entries: `      - pgdata:/var/lib/postgresql/data`,
			want: []model.VolumeMount{
				{Kind: model.MountVolume, Source: "pgdata", Target: "/var/lib/postgresql/data"},
			},
		},
		{
			name:    "short anonymous volume",
			entries: `      - /cache`,
			want:    []model.VolumeMount{{Kind: model.MountVolume, Target: "/cache"}},
		},
		{
			name:    "home-relative source is a bind",
			entries: `      - ~/certs:/certs:ro`,
			want: []model.VolumeMount{
				{Kind: model.MountBind, Source: "~/certs", Target: "/certs", ReadOnly: true},
			},
		},
		{
			name: "long bind with read_only",
			entries: `      - type: bind
        source: /srv/app/logs
        target: /var/log/app
        read_only: true`,
			want: []model.VolumeMount{
				{Kind: model.MountBind, Source: "/srv/app/logs", Target: "/var/log/app", ReadOnly: true},
			},
		},
		{
			name: "long volume",
			entries: `      - type: volume
        source: pgdata
        target: /var/lib/postgresql/data`,
			want: []model.VolumeMount{
				{Kind: model.MountVolume, Source: "pgdata", Target: "/var/lib/postgresql/data"},
			},
		},
		{
			name: "long tmpfs",
			entries: `      - type: tmpfs
        target: /run
        tmpfs:
          size: 1024`,
			want: []model.VolumeMount{{Kind: model.MountTmpfs, Target: "/run"}},
		},
		{
			name: "long form without a type infers from the source",
			entries: `      - source: ./html
        target: /usr/share/nginx/html`,
			want: []model.VolumeMount{
				{Kind: model.MountBind, Source: "./html", Target: "/usr/share/nginx/html"},
			},
		},
		{
			name:    "both syntaxes in one list",
			entries: "      - /srv/a:/a\n      - type: volume\n        source: b\n        target: /b",
			want: []model.VolumeMount{
				{Kind: model.MountBind, Source: "/srv/a", Target: "/a"},
				{Kind: model.MountVolume, Source: "b", Target: "/b"},
			},
		},
		{
			name:    "docker socket, short form",
			entries: `      - /var/run/docker.sock:/var/run/docker.sock:ro`,
			want: []model.VolumeMount{{
				Kind: model.MountBind, Source: "/var/run/docker.sock",
				Target: "/var/run/docker.sock", ReadOnly: true,
			}},
			socket: true,
		},
		{
			name: "podman socket, long form",
			entries: `      - type: bind
        source: /run/podman/podman.sock
        target: /run/docker.sock`,
			want: []model.VolumeMount{{
				Kind: model.MountBind, Source: "/run/podman/podman.sock", Target: "/run/docker.sock",
			}},
			socket: true,
		},
		{
			name:    "unknown mount type is reported and inferred",
			entries: "      - type: sorcery\n        source: /srv/x\n        target: /x",
			want: []model.VolumeMount{
				{Kind: model.MountBind, Source: "/srv/x", Target: "/x"},
			},
			warning: "not a mount type",
		},
		{
			name:    "too many colon parts",
			entries: `      - "a:b:c:d"`,
			warning: "too many colon-separated parts",
		},
		{
			name:    "long form without a target",
			entries: "      - type: bind\n        source: /srv/x",
			warning: "no target path",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest, _ := parseFixture(t, fmt.Sprintf(template, tc.entries), nil)
			service := onlyService(t, manifest)

			if !reflect.DeepEqual(service.Volumes, tc.want) {
				t.Errorf("volumes:\n got %+v\nwant %+v", service.Volumes, tc.want)
			}
			if service.MountsContainerSocket != tc.socket {
				t.Errorf("MountsContainerSocket: got %v, want %v", service.MountsContainerSocket, tc.socket)
			}
			if tc.warning == "" {
				if len(manifest.Warnings) != 0 {
					t.Errorf("expected no warnings, got %v", manifest.Warnings)
				}
			} else if !hasWarning(manifest.Warnings, tc.warning) {
				t.Errorf("expected a warning mentioning %q, got %v", tc.warning, manifest.Warnings)
			}
		})
	}
}

func TestMountsContainerSocketOnlyForBinds(t *testing.T) {
	// A *named volume* that happens to be called docker.sock hands over nothing.
	manifest, _ := parseFixture(t, `
services:
  app:
    image: nginx
    volumes:
      - docker.sock:/var/run/docker.sock
`, nil)

	service := onlyService(t, manifest)
	if service.Volumes[0].Kind != model.MountVolume {
		t.Fatalf("expected a named volume, got %q", service.Volumes[0].Kind)
	}
	if service.MountsContainerSocket {
		t.Error("a named volume must not be reported as mounting the container socket")
	}
}

// ────────────────────────────────────────────────────────── environment

func TestParseEnvironmentNeverStoresValues(t *testing.T) {
	const secret = "s3cr3t-must-never-appear"
	t.Setenv("SA_TEST_DB_PASSWORD", secret)

	cases := []struct {
		name    string
		block   string
		want    []string
		warning string
	}{
		{
			name: "list form",
			block: `    environment:
      - POSTGRES_USER=admin
      - POSTGRES_PASSWORD=${SA_TEST_DB_PASSWORD}
      - INHERITED_FROM_HOST
      - SPACED = value`,
			want: []string{"POSTGRES_USER", "POSTGRES_PASSWORD", "INHERITED_FROM_HOST", "SPACED"},
		},
		{
			name: "map form",
			block: `    environment:
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: ${SA_TEST_DB_PASSWORD}
      EMPTY:`,
			want: []string{"POSTGRES_USER", "POSTGRES_PASSWORD", "EMPTY"},
		},
		{
			name: "unexpected shape is reported",
			block: `    environment:
      - [nested]`,
			warning: "services.db.environment[0]",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compose := "services:\n  db:\n    image: postgres:16\n" + tc.block + "\n"
			manifest, _ := parseFixture(t, compose, nil)
			service := onlyService(t, manifest)

			if tc.want != nil && !reflect.DeepEqual(service.EnvNames, tc.want) {
				t.Errorf("EnvNames: got %v, want %v", service.EnvNames, tc.want)
			}
			if tc.warning != "" && !hasWarning(manifest.Warnings, tc.warning) {
				t.Errorf("expected a warning mentioning %q, got %v", tc.warning, manifest.Warnings)
			}

			// The whole manifest is serialised and searched: it is not enough for the
			// value to be missing from EnvNames, it must be nowhere at all.
			encoded, err := json.Marshal(manifest)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("an environment value reached the manifest: %s", encoded)
			}
			if strings.Contains(string(encoded), "admin") {
				t.Fatalf("a literal environment value reached the manifest: %s", encoded)
			}
		})
	}
}

func TestParseEnvFile(t *testing.T) {
	compose := `
services:
  present:
    image: nginx
    env_file: app.env
  listed:
    image: nginx
    env_file:
      - app.env
      - conf/extra.env
      - missing.env
  long:
    image: nginx
    env_file:
      - path: app.env
        required: true
      - path: nowhere.env
        required: false
  absolute:
    image: nginx
    env_file: /definitely/not/here.env
`
	manifest, _ := parseFixture(t, compose, map[string]string{
		"app.env":        "KEY=value\n",
		"conf/extra.env": "OTHER=value\n",
	})

	want := map[string][]model.EnvFileRef{
		"present": {{Path: "app.env", Exists: true}},
		"listed": {
			{Path: "app.env", Exists: true},
			{Path: "conf/extra.env", Exists: true},
			{Path: "missing.env", Exists: false},
		},
		"long": {
			{Path: "app.env", Exists: true},
			{Path: "nowhere.env", Exists: false},
		},
		"absolute": {{Path: "/definitely/not/here.env", Exists: false}},
	}

	if len(manifest.Services) != 4 {
		t.Fatalf("expected 4 services, got %d", len(manifest.Services))
	}
	for _, service := range manifest.Services {
		if !reflect.DeepEqual(service.EnvFiles, want[service.Name]) {
			t.Errorf("%s env_file:\n got %+v\nwant %+v", service.Name, service.EnvFiles, want[service.Name])
		}
	}
	if len(manifest.Warnings) != 0 {
		t.Errorf("a missing env_file is an answer, not a parse failure: %v", manifest.Warnings)
	}
}

// ─────────────────────────────────────────────────────── substitution

func TestInterpolation(t *testing.T) {
	t.Run("from the process environment", func(t *testing.T) {
		t.Setenv("SA_TEST_TAG", "1.2.3")
		manifest, result := parseFixture(t, "services:\n  web:\n    image: nginx:${SA_TEST_TAG}\n", nil)

		service := onlyService(t, manifest)
		if service.Image.Raw != "nginx:1.2.3" || service.Image.Tag != "1.2.3" {
			t.Errorf("image: got %+v", service.Image)
		}
		if result.Status != model.StatusOk {
			t.Errorf("a resolved variable must not degrade the section, status is %q", result.Status)
		}
	})

	t.Run("from a .env file beside the compose file", func(t *testing.T) {
		unsetenv(t, "SA_TEST_DOTENV_TAG")
		manifest, _ := parseFixture(t,
			"services:\n  web:\n    image: nginx:${SA_TEST_DOTENV_TAG}\n",
			map[string]string{".env": "# a comment\nexport SA_TEST_DOTENV_TAG=\"4.5.6\"\n"})

		if got := onlyService(t, manifest).Image.Tag; got != "4.5.6" {
			t.Errorf("tag: got %q, want %q", got, "4.5.6")
		}
	})

	t.Run("the process environment wins over .env", func(t *testing.T) {
		t.Setenv("SA_TEST_PRECEDENCE", "from-env")
		manifest, _ := parseFixture(t,
			"services:\n  web:\n    container_name: ${SA_TEST_PRECEDENCE}\n    image: nginx\n",
			map[string]string{".env": "SA_TEST_PRECEDENCE=from-dotenv\n"})

		if got := onlyService(t, manifest).ContainerName; got != "from-env" {
			t.Errorf("container_name: got %q, want %q", got, "from-env")
		}
	})

	t.Run("defaults", func(t *testing.T) {
		unsetenv(t, "SA_TEST_UNSET_A")
		unsetenv(t, "SA_TEST_UNSET_B")
		t.Setenv("SA_TEST_EMPTY", "")

		manifest, result := parseFixture(t, `
services:
  a:
    image: nginx:${SA_TEST_UNSET_A:-colon-dash}
  b:
    image: nginx:${SA_TEST_UNSET_B-plain-dash}
  c:
    image: nginx:${SA_TEST_EMPTY:-empty-falls-back}
  d:
    image: nginx:${SA_TEST_EMPTY-empty-is-set}
`, nil)

		want := map[string]string{
			"a": "colon-dash",
			"b": "plain-dash",
			"c": "empty-falls-back",
			"d": "",
		}
		for _, service := range manifest.Services {
			if service.Image.Tag != want[service.Name] {
				t.Errorf("%s: tag got %q, want %q", service.Name, service.Image.Tag, want[service.Name])
			}
		}
		if len(manifest.Warnings) != 0 {
			t.Errorf("a defaulted variable is resolved, not a warning: %v", manifest.Warnings)
		}
		if result.Status != model.StatusOk {
			t.Errorf("status: got %q, want ok", result.Status)
		}
	})

	t.Run("unresolved leaves the literal and warns", func(t *testing.T) {
		unsetenv(t, "SA_TEST_DB_PORT")
		manifest, result := parseFixture(t, `
services:
  db:
    image: postgres:16
    ports:
      - "${SA_TEST_DB_PORT}:5432"
`, nil)

		if !hasWarning(manifest.Warnings, "SA_TEST_DB_PORT") {
			t.Errorf("expected a warning naming the variable, got %v", manifest.Warnings)
		}
		if got := onlyService(t, manifest).Ports; len(got) != 0 {
			t.Errorf("an unresolved host port must not become a port mapping, got %+v", got)
		}
		if !hasWarning(manifest.Warnings, "services.db.ports[0]") {
			t.Errorf("expected the dropped port entry to be reported too, got %v", manifest.Warnings)
		}
		if result.Status != model.StatusPartial {
			t.Errorf("status: got %q, want partial", result.Status)
		}
	})

	t.Run("$VAR without braces and the $$ escape", func(t *testing.T) {
		t.Setenv("SA_TEST_BARE", "bare-value")
		manifest, _ := parseFixture(t, `
services:
  web:
    image: nginx
    container_name: $SA_TEST_BARE
    platform: $${LITERAL}
`, nil)

		service := onlyService(t, manifest)
		if service.ContainerName != "bare-value" {
			t.Errorf("container_name: got %q", service.ContainerName)
		}
		if service.Platform != "${LITERAL}" {
			t.Errorf("platform: got %q, want %q", service.Platform, "${LITERAL}")
		}
	})

	t.Run("a .env value is never stored", func(t *testing.T) {
		unsetenv(t, "SA_TEST_DOTENV_SECRET")
		const secret = "dotenv-secret-must-never-appear"
		manifest, _ := parseFixture(t, `
services:
  db:
    image: postgres:16
    environment:
      - POSTGRES_PASSWORD=${SA_TEST_DOTENV_SECRET}
`, map[string]string{".env": "SA_TEST_DOTENV_SECRET=" + secret + "\n"})

		encoded, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("a .env value reached the manifest: %s", encoded)
		}
		if got := onlyService(t, manifest).EnvNames; !reflect.DeepEqual(got, []string{"POSTGRES_PASSWORD"}) {
			t.Errorf("EnvNames: got %v", got)
		}
	})

	t.Run("a required variable that is not set", func(t *testing.T) {
		unsetenv(t, "SA_TEST_REQUIRED")
		manifest, _ := parseFixture(t,
			"services:\n  web:\n    image: nginx:${SA_TEST_REQUIRED:?tag is mandatory}\n", nil)

		if !hasWarning(manifest.Warnings, "SA_TEST_REQUIRED") {
			t.Errorf("expected a warning naming the variable, got %v", manifest.Warnings)
		}
		if got := onlyService(t, manifest).Image.Raw; got != "nginx:${SA_TEST_REQUIRED:?tag is mandatory}" {
			t.Errorf("the literal must be left in place, got %q", got)
		}
	})
}

// ────────────────────────────────────────────────────────── depends_on

func TestParseDependsOn(t *testing.T) {
	cases := []struct {
		name  string
		block string
		want  []string
	}{
		{
			name: "list form",
			block: `    depends_on:
      - db
      - cache`,
			want: []string{"db", "cache"},
		},
		{
			name: "map form with conditions",
			block: `    depends_on:
      db:
        condition: service_healthy
      cache:
        condition: service_started
        restart: true`,
			want: []string{"db", "cache"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compose := "services:\n  web:\n    image: nginx\n" + tc.block + "\n"
			manifest, _ := parseFixture(t, compose, nil)

			if got := onlyService(t, manifest).DependsOn; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("depends_on: got %v, want %v", got, tc.want)
			}
			if len(manifest.Warnings) != 0 {
				t.Errorf("expected no warnings, got %v", manifest.Warnings)
			}
		})
	}
}

// ───────────────────────────────────────────────────────── healthcheck

func TestParseHealthcheck(t *testing.T) {
	cases := []struct {
		name  string
		block string
		want  bool
	}{
		{
			name:  "absent",
			block: "",
			want:  false,
		},
		{
			name: "declared",
			block: `    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
      interval: 30s`,
			want: true,
		},
		{
			name: "explicitly disabled",
			block: `    healthcheck:
      disable: true`,
			want: false,
		},
		{
			name: "disabled through a NONE test",
			block: `    healthcheck:
      test: ["NONE"]`,
			want: false,
		},
		{
			name: "disable false still counts as declared",
			block: `    healthcheck:
      disable: false
      test: CMD-SHELL curl -f http://localhost/ || exit 1`,
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compose := "services:\n  web:\n    image: nginx\n" + tc.block + "\n"
			manifest, _ := parseFixture(t, compose, nil)

			if got := onlyService(t, manifest).HasHealthcheck; got != tc.want {
				t.Errorf("HasHealthcheck: got %v, want %v", got, tc.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────── images

func TestParseImages(t *testing.T) {
	manifest, _ := parseFixture(t, `
services:
  bare:
    image: nginx
  tagged:
    image: nginx:1.25-alpine
  digested:
    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001
  both:
    image: nginx:1.25@sha256:0000000000000000000000000000000000000000000000000000000000000002
  registry_with_port:
    image: registry.example.com:5000/team/app:1.2
  registry_host:
    image: ghcr.io/bloodheaven/app:main
  localhost_registry:
    image: localhost:5000/app
  namespaced:
    image: bitnami/postgresql:16
`, nil)

	want := map[string]model.ImageRef{
		"bare": {Raw: "nginx", Repository: "nginx"},
		"tagged": {
			Raw: "nginx:1.25-alpine", Repository: "nginx", Tag: "1.25-alpine",
		},
		"digested": {
			Raw:        "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001",
			Repository: "nginx",
			Digest:     "sha256:0000000000000000000000000000000000000000000000000000000000000001",
		},
		"both": {
			Raw:        "nginx:1.25@sha256:0000000000000000000000000000000000000000000000000000000000000002",
			Repository: "nginx",
			Tag:        "1.25",
			Digest:     "sha256:0000000000000000000000000000000000000000000000000000000000000002",
		},
		"registry_with_port": {
			Raw:      "registry.example.com:5000/team/app:1.2",
			Registry: "registry.example.com:5000", Repository: "team/app", Tag: "1.2",
		},
		"registry_host": {
			Raw:      "ghcr.io/bloodheaven/app:main",
			Registry: "ghcr.io", Repository: "bloodheaven/app", Tag: "main",
		},
		"localhost_registry": {
			Raw:      "localhost:5000/app",
			Registry: "localhost:5000", Repository: "app",
		},
		"namespaced": {
			Raw: "bitnami/postgresql:16", Repository: "bitnami/postgresql", Tag: "16",
		},
	}

	if len(manifest.Services) != len(want) {
		t.Fatalf("expected %d services, got %d", len(want), len(manifest.Services))
	}
	for _, service := range manifest.Services {
		if got := service.Image; !reflect.DeepEqual(got, want[service.Name]) {
			t.Errorf("%s image:\n got %+v\nwant %+v", service.Name, got, want[service.Name])
		}
	}

	// Only a digest pins an image; the model says so and the parser must feed it
	// the right parts for that to hold.
	for _, service := range manifest.Services {
		wantPinned := service.Name == "digested" || service.Name == "both"
		if service.Image.Pinned() != wantPinned {
			t.Errorf("%s: Pinned() = %v, want %v", service.Name, service.Image.Pinned(), wantPinned)
		}
	}
}

// ───────────────────────────────────────────────────────────── resources

func TestParseMemory(t *testing.T) {
	cases := []struct {
		text string
		want int64
		fail bool
	}{
		{text: "512m", want: 512 * 1024 * 1024},
		{text: "2G", want: 2 * 1024 * 1024 * 1024},
		{text: "1.5g", want: 1610612736},
		{text: "1024k", want: 1024 * 1024},
		{text: "1024", want: 1024},
		{text: "64b", want: 64},
		{text: "256mb", want: 256 * 1024 * 1024},
		{text: "1gib", want: 1024 * 1024 * 1024},
		{text: " 128m ", want: 128 * 1024 * 1024},
		{text: "", fail: true},
		{text: "lots", fail: true},
		{text: "512q", fail: true},
		{text: "-1g", fail: true},
	}

	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			got, err := parseMemory(tc.text)
			if tc.fail {
				if err == nil {
					t.Fatalf("expected an error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseDeployResources(t *testing.T) {
	manifest, _ := parseFixture(t, `
services:
  api:
    image: nginx
    deploy:
      resources:
        limits:
          cpus: "1.50"
          memory: 512m
        reservations:
          cpus: "0.25"
          memory: 1.5g
  legacy:
    image: nginx
    mem_limit: 256m
    mem_reservation: 64m
    cpus: 0.5
  broken:
    image: nginx
    deploy:
      resources:
        limits:
          memory: plenty
`, nil)

	byName := map[string]model.ManifestService{}
	for _, service := range manifest.Services {
		byName[service.Name] = service
	}

	api := byName["api"]
	if api.MemLimitBytes != 512*1024*1024 {
		t.Errorf("api MemLimitBytes: got %d", api.MemLimitBytes)
	}
	if api.MemReservationBytes != 1610612736 {
		t.Errorf("api MemReservationBytes: got %d", api.MemReservationBytes)
	}
	if api.CPULimit != "1.50" || api.CPUReservation != "0.25" {
		t.Errorf("api cpus: limit %q reservation %q", api.CPULimit, api.CPUReservation)
	}

	legacy := byName["legacy"]
	if legacy.MemLimitBytes != 256*1024*1024 || legacy.MemReservationBytes != 64*1024*1024 {
		t.Errorf("legacy memory: limit %d reservation %d", legacy.MemLimitBytes, legacy.MemReservationBytes)
	}
	if legacy.CPULimit != "0.5" {
		t.Errorf("legacy CPULimit: got %q", legacy.CPULimit)
	}

	broken := byName["broken"]
	if broken.MemLimitBytes != 0 {
		t.Errorf("an unparsable memory size must not become a number: got %d", broken.MemLimitBytes)
	}
	if !hasWarning(manifest.Warnings, "plenty") {
		t.Errorf("expected a warning about the unparsable size, got %v", manifest.Warnings)
	}
}

// ──────────────────────────────────────────────────── the rest of a service

func TestParseServiceFields(t *testing.T) {
	manifest, result := parseFixture(t, `
version: "3.9"
services:
  worker:
    image: registry.example.com:5000/team/worker:2.0
    container_name: bh-worker
    platform: linux/amd64
    restart: unless-stopped
    network_mode: host
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_TIME
    devices:
      - /dev/ttyUSB0:/dev/ttyUSB0
    dns: 1.1.1.1
    extra_hosts:
      - "db.internal:10.0.0.5"
    networks:
      - backend
  builder:
    build: ./worker
    dns:
      - 9.9.9.9
      - 8.8.8.8
    extra_hosts:
      api.internal: 10.0.0.9
    networks:
      backend:
        aliases:
          - builder
  builder_long:
    build:
      context: ./api
      dockerfile: Dockerfile.prod
  builder_no_context:
    build:
      dockerfile: Dockerfile
networks:
  backend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
        - subnet: 172.31.0.0/24
  shared:
    external: true
  legacy_external:
    external:
      name: really-shared
  plain:
volumes:
  pgdata:
    driver: local
  outside:
    external: true
  bare:
`, nil)

	if manifest.Version != "3.9" {
		t.Errorf("version: got %q", manifest.Version)
	}
	if manifest.Path == "" || filepath.Base(manifest.Path) != composeName {
		t.Errorf("path: got %q", manifest.Path)
	}

	// Services keep the order the file declares them in.
	var order []string
	for _, service := range manifest.Services {
		order = append(order, service.Name)
	}
	wantOrder := []string{"worker", "builder", "builder_long", "builder_no_context"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Errorf("service order: got %v, want %v", order, wantOrder)
	}

	worker := manifest.Services[0]
	if worker.ContainerName != "bh-worker" || worker.Platform != "linux/amd64" ||
		worker.Restart != "unless-stopped" || worker.NetworkMode != "host" {
		t.Errorf("worker scalars: %+v", worker)
	}
	if !worker.Privileged {
		t.Error("worker: privileged was not read")
	}
	if !reflect.DeepEqual(worker.CapAdd, []string{"NET_ADMIN", "SYS_TIME"}) {
		t.Errorf("worker cap_add: %v", worker.CapAdd)
	}
	if !reflect.DeepEqual(worker.Devices, []string{"/dev/ttyUSB0:/dev/ttyUSB0"}) {
		t.Errorf("worker devices: %v", worker.Devices)
	}
	if !reflect.DeepEqual(worker.DNS, []string{"1.1.1.1"}) {
		t.Errorf("worker dns: %v", worker.DNS)
	}
	if !reflect.DeepEqual(worker.ExtraHosts, []string{"db.internal:10.0.0.5"}) {
		t.Errorf("worker extra_hosts: %v", worker.ExtraHosts)
	}
	if !reflect.DeepEqual(worker.Networks, []string{"backend"}) {
		t.Errorf("worker networks: %v", worker.Networks)
	}

	builder := manifest.Services[1]
	if builder.Build != "./worker" {
		t.Errorf("builder build: got %q", builder.Build)
	}
	if !reflect.DeepEqual(builder.DNS, []string{"9.9.9.9", "8.8.8.8"}) {
		t.Errorf("builder dns: %v", builder.DNS)
	}
	if !reflect.DeepEqual(builder.ExtraHosts, []string{"api.internal:10.0.0.9"}) {
		t.Errorf("builder extra_hosts: %v", builder.ExtraHosts)
	}
	if !reflect.DeepEqual(builder.Networks, []string{"backend"}) {
		t.Errorf("builder networks (map form): %v", builder.Networks)
	}

	if got := manifest.Services[2].Build; got != "./api" {
		t.Errorf("long build context: got %q", got)
	}
	if got := manifest.Services[3].Build; got != "." {
		t.Errorf("build without a context: got %q, want the reported assumption %q", got, ".")
	}
	if !hasWarning(manifest.Warnings, "builder_no_context") {
		t.Errorf("the assumed build context must be reported, got %v", manifest.Warnings)
	}
	if result.Status != model.StatusPartial {
		t.Errorf("status: got %q, want partial", result.Status)
	}

	wantNetworks := []model.ManifestNetwork{
		{Name: "backend", Driver: "bridge", Subnets: []string{"172.30.0.0/24", "172.31.0.0/24"}},
		{Name: "shared", External: true},
		{Name: "legacy_external", External: true},
		{Name: "plain"},
	}
	if !reflect.DeepEqual(manifest.Networks, wantNetworks) {
		t.Errorf("networks:\n got %+v\nwant %+v", manifest.Networks, wantNetworks)
	}

	wantVolumes := []model.ManifestVolume{
		{Name: "pgdata", Driver: "local"},
		{Name: "outside", External: true},
		{Name: "bare"},
	}
	if !reflect.DeepEqual(manifest.Volumes, wantVolumes) {
		t.Errorf("volumes:\n got %+v\nwant %+v", manifest.Volumes, wantVolumes)
	}
}

func TestMergeKeysAndAnchors(t *testing.T) {
	manifest, _ := parseFixture(t, `
x-base: &base
  image: nginx:1.25
  restart: always
  environment:
    - SHARED_KEY=shared
services:
  web:
    <<: *base
    container_name: web
  api:
    <<: *base
    image: nginx:1.26
`, nil)

	if len(manifest.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(manifest.Services))
	}
	web, api := manifest.Services[0], manifest.Services[1]
	if web.Image.Tag != "1.25" || web.Restart != "always" || web.ContainerName != "web" {
		t.Errorf("web: %+v", web)
	}
	if !reflect.DeepEqual(web.EnvNames, []string{"SHARED_KEY"}) {
		t.Errorf("web EnvNames: %v", web.EnvNames)
	}
	if api.Image.Tag != "1.26" {
		t.Errorf("a key written on the service must win over the merged one: %+v", api.Image)
	}
}

// ─────────────────────────────────────────────────────── degradation

func TestOneBadFieldDoesNotCostTheFile(t *testing.T) {
	manifest, result := parseFixture(t, `
services:
  web:
    image: nginx:1.25
    ports: 8080
    restart: always
    volumes:
      - /srv/data:/data
  broken: "not a mapping"
`, nil)

	if len(manifest.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(manifest.Services))
	}
	web := manifest.Services[0]
	if web.Image.Tag != "1.25" || web.Restart != "always" || len(web.Volumes) != 1 {
		t.Errorf("the fields around the bad one must still be read: %+v", web)
	}
	if len(web.Ports) != 0 {
		t.Errorf("a malformed ports field must not produce mappings: %+v", web.Ports)
	}
	if !hasWarning(manifest.Warnings, "services.web.ports") {
		t.Errorf("expected a warning about ports, got %v", manifest.Warnings)
	}
	if !hasWarning(manifest.Warnings, "services.broken") {
		t.Errorf("expected a warning about the broken service, got %v", manifest.Warnings)
	}
	if result.Status != model.StatusPartial {
		t.Errorf("status: got %q, want partial", result.Status)
	}
	if len(result.Notes) != len(manifest.Warnings) {
		t.Errorf("every warning must reach the section result: %d notes, %d warnings",
			len(result.Notes), len(manifest.Warnings))
	}
}

func TestUnreadFilesAreReported(t *testing.T) {
	manifest, result := parseFixture(t, `
include:
  - other-compose.yml
services:
  web:
    image: nginx
    extends:
      file: base.yml
      service: base
`, nil)

	if !hasWarning(manifest.Warnings, "include") {
		t.Errorf("expected a warning about the unread include, got %v", manifest.Warnings)
	}
	if !hasWarning(manifest.Warnings, "services.web.extends") {
		t.Errorf("expected a warning about the unfollowed extends, got %v", manifest.Warnings)
	}
	if result.Status != model.StatusPartial {
		t.Errorf("status: got %q, want partial", result.Status)
	}
}

func TestWarningsAreNotRepeated(t *testing.T) {
	unsetenv(t, "SA_TEST_REPEATED")
	manifest, _ := parseFixture(t, `
services:
  a:
    image: nginx:${SA_TEST_REPEATED}
  b:
    image: nginx:${SA_TEST_REPEATED}
`, nil)

	count := 0
	for _, warning := range manifest.Warnings {
		if strings.Contains(warning, "SA_TEST_REPEATED") && strings.Contains(warning, "unresolved") {
			count++
		}
	}
	// Two lines, two warnings — each names its own line. The same line reported
	// twice is what the deduplication is for.
	if count != 2 {
		t.Errorf("expected one warning per source line, got %d: %v", count, manifest.Warnings)
	}
}

func TestNilResultIsSafe(t *testing.T) {
	path := fixture(t, map[string]string{composeName: "services:\n  web:\n    ports: nonsense\n"})
	manifest, err := Parse(path, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(manifest.Warnings) == 0 {
		t.Error("expected the warning to still be collected on the manifest")
	}
}

func TestParseErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		if _, err := Parse(filepath.Join(t.TempDir(), "nope.yml"), nil); err == nil {
			t.Fatal("expected an error for a missing file")
		}
	})

	t.Run("not yaml", func(t *testing.T) {
		path := fixture(t, map[string]string{composeName: "services: [unclosed\n"})
		if _, err := Parse(path, nil); err == nil {
			t.Fatal("expected an error for malformed YAML")
		}
	})

	t.Run("top level is not a mapping", func(t *testing.T) {
		path := fixture(t, map[string]string{composeName: "- web\n- db\n"})
		if _, err := Parse(path, nil); err == nil {
			t.Fatal("expected an error for a sequence at the top level")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := fixture(t, map[string]string{composeName: ""})
		if _, err := Parse(path, nil); err == nil {
			t.Fatal("expected an error for an empty file")
		}
	})

	t.Run("no services", func(t *testing.T) {
		result := &model.SectionResult{Status: model.StatusOk}
		path := fixture(t, map[string]string{composeName: "version: \"3\"\n"})
		manifest, err := Parse(path, result)
		if err != nil {
			t.Fatalf("a file without services is readable, not fatal: %v", err)
		}
		if !hasWarning(manifest.Warnings, "no services") {
			t.Errorf("expected a warning, got %v", manifest.Warnings)
		}
		if result.Status != model.StatusPartial {
			t.Errorf("status: got %q, want partial", result.Status)
		}
	})
}

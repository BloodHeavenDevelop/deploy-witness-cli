package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// A model as `docker compose config --format json` prints it (Compose 5.5),
// trimmed to what the audit reads plus the parts it must drop.
const resolvedFixture = `{
  "name": "shop",
  "networks": {
    "default": {"name": "shop_default", "ipam": {}},
    "edge": {"name": "edge", "external": true},
    "back": {"name": "shop_back", "ipam": {"config": [{"subnet": "10.99.0.0/24"}]}}
  },
  "services": {
    "web": {
      "image": "nginx:1.27",
      "command": ["nginx", "-g", "daemon off;"],
      "environment": {"DB_PASSWORD": "hunter2-do-not-keep", "BARE": null},
      "env_file": [{"path": "/srv/shop/.env"}, {"path": "/srv/shop/missing.env", "required": false}],
      "ports": [
        {"mode": "ingress", "target": 80, "published": "8080", "protocol": "tcp"},
        {"mode": "ingress", "host_ip": "127.0.0.1", "target": 81, "protocol": "tcp"},
        {"mode": "ingress", "target": 80, "published": "7000-7002", "protocol": "udp"}
      ],
      "expose": ["9000-9001"],
      "volumes": [
        {"type": "bind", "source": "/srv/shop/data", "target": "/data", "read_only": true, "bind": {}},
        {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"},
        {"type": "volume", "source": "cache", "target": "/cache", "volume": {}}
      ],
      "networks": {"default": null, "edge": null},
      "depends_on": {"db": {"condition": "service_started", "required": true}},
      "healthcheck": {"test": ["CMD", "true"]},
      "deploy": {"resources": {"limits": {"memory": "536870912"}, "reservations": {"memory": "268435456", "cpus": 0.5}}},
      "devices": [{"source": "/dev/fuse", "target": "/dev/fuse", "permissions": "rwm"}],
      "labels": {"traefik.http.routers.web.rule": "Host(` + "`shop.example.com`" + `)"},
      "user": "1000:1000"
    },
    "db": {
      "image": "postgres:16",
      "healthcheck": {"disable": true},
      "mem_limit": "314572800",
      "secrets": [{"source": "dbpass"}]
    }
  },
  "volumes": {"cache": {"name": "shop_cache"}, "ext": {"name": "real-ext", "external": true}},
  "secrets": {"dbpass": {"file": "/srv/shop/secret.txt"}}
}`

func TestFromComposeConfig(t *testing.T) {
	m, err := FromComposeConfig([]byte(resolvedFixture), "/srv/shop/compose.yml", "5.5.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "shop" || m.Path != "/srv/shop/compose.yml" || len(m.Services) != 2 {
		t.Fatalf("manifest = %+v", m)
	}
	db, web := m.Services[0], m.Services[1]
	if db.Name != "db" || web.Name != "web" {
		t.Fatalf("services out of order: %s, %s", db.Name, web.Name)
	}
	if web.Image.Repository != "nginx" || web.Image.Tag != "1.27" {
		t.Errorf("image = %+v", web.Image)
	}
	if len(web.Ports) != 3 || web.Ports[0].HostPort != 8080 || web.Ports[1].HostPort != 0 ||
		web.Ports[1].HostIP != "127.0.0.1" || web.Ports[2].HostPortEnd != 7002 || web.Ports[2].Protocol != "udp" {
		t.Errorf("ports = %+v", web.Ports)
	}
	if len(web.Expose) != 2 {
		t.Errorf("expose = %v", web.Expose)
	}
	if !web.MountsContainerSocket || len(web.Volumes) != 3 || !web.Volumes[0].ReadOnly {
		t.Errorf("volumes = %+v", web.Volumes)
	}
	if !web.HasHealthcheck || db.HasHealthcheck {
		t.Errorf("healthcheck: web %v db %v (disable: true is none)", web.HasHealthcheck, db.HasHealthcheck)
	}
	if web.MemReservationBytes != 256<<20 || web.MemLimitBytes != 512<<20 || db.MemLimitBytes != 300<<20 {
		t.Errorf("memory: %d %d %d", web.MemReservationBytes, web.MemLimitBytes, db.MemLimitBytes)
	}
	if strings.Join(web.DependsOn, ",") != "db" || strings.Join(web.Networks, ",") != "default,edge" {
		t.Errorf("depends_on %v networks %v", web.DependsOn, web.Networks)
	}
	if len(web.EnvFiles) != 2 || web.EnvFiles[0].Optional || !web.EnvFiles[1].Optional {
		t.Errorf("env files = %+v", web.EnvFiles)
	}
	if strings.Join(web.EnvNames, ",") != "BARE,DB_PASSWORD" || len(web.Devices) != 1 {
		t.Errorf("env names %v devices %v", web.EnvNames, web.Devices)
	}

	var external, subnet bool
	for _, n := range m.Networks {
		external = external || (n.Name == "edge" && n.External)
		subnet = subnet || (n.Name == "back" && len(n.Subnets) == 1)
	}
	if !external || !subnet {
		t.Errorf("networks = %+v", m.Networks)
	}

	// The values the model carried never reach the manifest.
	encoded, _ := json.Marshal(m)
	for _, secret := range []string{"hunter2-do-not-keep", "secret.txt", "daemon off"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("the manifest keeps %q from the resolved model", secret)
		}
	}
}

func TestFromComposeConfigRejectsWhatIsNotAModel(t *testing.T) {
	for _, raw := range []string{"", "not json", `{"name": "x"}`} {
		if _, err := FromComposeConfig([]byte(raw), "/c.yml", "5.5.0", &model.SectionResult{}); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
}

func TestRemoteIncludes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yml")
	content := "include:\n  - ./local.yml\n  - git@github.com:org/repo.git\n  - path: [oci://registry/x, ../base.yml]\n" +
		"  - path: https://example.com/c.yml\nservices: {}\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := RemoteIncludes(path)
	if err != nil || strings.Join(got, " ") != "git@github.com:org/repo.git oci://registry/x https://example.com/c.yml" {
		t.Errorf("RemoteIncludes = %v, %v", got, err)
	}
}

// DW-87: Compose's naming — <project>_<key> for what it creates, the key (or
// `name:`) for what is external.
func TestResolveEngineNames(t *testing.T) {
	m := &model.Manifest{
		Networks: []model.ManifestNetwork{{Name: "back"}, {Name: "edge", External: true}, {Name: "x", EngineName: "custom"}},
		Volumes:  []model.ManifestVolume{{Name: "data"}, {Name: "pg", External: true}},
	}
	ResolveEngineNames(m, "shop")
	got := []string{m.Networks[0].EngineName, m.Networks[1].EngineName, m.Networks[2].EngineName,
		m.Volumes[0].EngineName, m.Volumes[1].EngineName}
	if strings.Join(got, ",") != "shop_back,edge,custom,shop_data,pg" {
		t.Errorf("engine names = %v", got)
	}
}

// DW-83 (found by the bench): Compose 2.x and 5.x encode create_host_path in
// opposite ways in the resolved model, and an absent key means the version's default.
func TestCreateHostPathByComposeVersion(t *testing.T) {
	model2 := `{"services":{"a":{"volumes":[
	  {"type":"bind","source":"/s","target":"/s","bind":{"create_host_path":true}},
	  {"type":"bind","source":"/l","target":"/l"},
	  {"type":"bind","source":"/f","target":"/f","bind":{}}]}}}`
	model5 := `{"services":{"a":{"volumes":[
	  {"type":"bind","source":"/s","target":"/s","bind":{}},
	  {"type":"bind","source":"/l","target":"/l"},
	  {"type":"bind","source":"/f","target":"/f","bind":{"create_host_path":false}}]}}}`
	for _, tc := range []struct {
		version, raw string
		want       []string
	}{
		{"2.33.0", model2, []string{"true", "false", "false"}},
		{"5.5.0", model5, []string{"true", "true", "false"}},
		{"", model5, []string{"nil", "nil", "false"}},
	} {
		m, err := FromComposeConfig([]byte(tc.raw), "/c.yml", tc.version, nil)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, v := range m.Services[0].Volumes {
			if v.CreateHostPath == nil {
				got = append(got, "nil")
			} else {
				got = append(got, fmt.Sprint(*v.CreateHostPath))
			}
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("compose %q: %v, want %v", tc.version, got, tc.want)
		}
	}
}

package docker

import (
	"reflect"
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// The fixtures below are the output shapes of docker and podman as they actually
// print them. Nothing in this file needs a container runtime, a daemon or a
// network: every parser takes a string, which is the whole reason they are
// separate from the collector.

// ─────────────────────────────────────────────────────── container fixtures

// dockerPS is `docker ps -a --format '{{json .}}'`: one object per line, with
// Labels, Networks and Ports flattened into strings.
const dockerPS = `
{"Command":"\"/docker-entrypoint.…\"","CreatedAt":"2026-06-01 10:12:03 +0000 UTC","ID":"9c0f1b2d3e4a","Image":"nginx:1.27-alpine","Labels":"com.docker.compose.config-hash=8f1cd2,com.docker.compose.project=shop,com.docker.compose.service=web,com.docker.compose.version=2.24.5","LocalVolumes":"0","Mounts":"","Names":"shop-web-1","Networks":"shop_default,shop_edge","Ports":"0.0.0.0:8080->80/tcp, [::]:8080->80/tcp","RunningFor":"2 days ago","Size":"0B","State":"running","Status":"Up 2 days"}
{"Command":"\"docker-entrypoint.s…\"","CreatedAt":"2026-05-30 08:00:00 +0000 UTC","ID":"1a2b3c4d5e6f","Image":"postgres:16","Labels":"","LocalVolumes":"1","Mounts":"pgdata","Names":"legacy-pg","Networks":"bridge","Ports":"127.0.0.1:5432->5432/tcp","RunningFor":"3 weeks ago","Size":"0B","State":"exited","Status":"Exited (0) 3 hours ago"}
{"Command":"\"/bin/sh\"","CreatedAt":"2026-06-02 09:00:00 +0000 UTC","ID":"aaaabbbbcccc","Image":"alpine:3.20","Labels":"maintainer=ops","LocalVolumes":"0","Mounts":"","Names":"udp-range","Networks":"host","Ports":"0.0.0.0:9000-9002->9000-9002/udp","RunningFor":"1 hour ago","Size":"0B","State":"running","Status":"Up 1 hour"}
{"Command":"\"/entry\"","CreatedAt":"2026-06-02 09:30:00 +0000 UTC","ID":"ddddeeeeffff","Image":"internal/api:dev","Labels":"","LocalVolumes":"0","Mounts":"","Names":"unpublished","Networks":"","Ports":"80/tcp, 443/tcp","RunningFor":"30 minutes ago","Size":"0B","State":"created","Status":"Created"}
`

// podmanPS is `podman ps -a --format '{{json .}}'`: Names, Networks and Ports are
// arrays, Labels is an object, and Status is often empty because podman answers
// with the State field instead.
const podmanPS = `
{"AutoRemove":false,"Command":["nginx","-g","daemon off;"],"Created":1780000000,"CreatedAt":"","Exited":false,"ExitedAt":-1,"ExitCode":0,"Id":"3f1b9c0d2e5a","Image":"docker.io/library/nginx:1.27-alpine","ImageID":"sha256:aa11","IsInfra":false,"Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web","io.podman.compose.project":"shop"},"Mounts":[],"Names":["shop_web_1"],"Networks":["shop_default"],"Pid":4242,"Pod":"","PodName":"","Ports":[{"host_ip":"0.0.0.0","container_port":80,"host_port":8080,"range":1,"protocol":"tcp"}],"Restarts":0,"Size":null,"StartedAt":1780000001,"State":"running","Status":""}
{"AutoRemove":false,"Command":["/bin/sh"],"Created":1779000000,"CreatedAt":"","Exited":true,"ExitedAt":1779000900,"ExitCode":0,"Id":"7c8d9e0f1a2b","Image":"quay.io/podman/hello:latest","ImageID":"sha256:bb22","IsInfra":false,"Labels":{"io.podman.compose.project":"lab","io.podman.compose.service":"greeter"},"Mounts":[],"Names":["lab_greeter_1","greeter-alias"],"Networks":[],"Pid":0,"Pod":"","PodName":"","Ports":[{"host_ip":"","container_port":7000,"host_port":7000,"range":3,"protocol":""},{"host_ip":"127.0.0.1","container_port":53,"host_port":5353,"range":1,"protocol":"udp"}],"Restarts":0,"Size":null,"StartedAt":1779000100,"State":"","Status":"Exited (0) 5 minutes ago"}
`

func TestParseContainersDocker(t *testing.T) {
	containers, warnings := parseContainers(dockerPS)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(containers) != 4 {
		t.Fatalf("got %d containers, want 4", len(containers))
	}

	web := containers[0]
	if web.Name != "shop-web-1" || web.Image != "nginx:1.27-alpine" {
		t.Errorf("identity: %+v", web)
	}
	if web.State != "running" || web.Status != "Up 2 days" {
		t.Errorf("state: %q / %q", web.State, web.Status)
	}
	// The compose labels are the load-bearing pair: they are how a port conflict is
	// told from a redeploy of the same project.
	if web.Project != "shop" || web.Service != "web" {
		t.Errorf("compose labels: project=%q service=%q", web.Project, web.Service)
	}
	if want := []string{"shop_default", "shop_edge"}; !reflect.DeepEqual(web.Networks, want) {
		t.Errorf("networks: %v, want %v", web.Networks, want)
	}
	// The IPv4 and IPv6 halves stay separate: they differ in HostIP, which is what
	// an exposure rule reads.
	wantPorts := []model.PortMapping{
		{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		{HostIP: "::", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
	}
	if !reflect.DeepEqual(web.Ports, wantPorts) {
		t.Errorf("ports: %+v, want %+v", web.Ports, wantPorts)
	}

	pg := containers[1]
	if pg.Project != "" || pg.Service != "" {
		t.Errorf("a container outside compose must carry no project: %+v", pg)
	}
	if pg.State != "exited" || pg.Status != "Exited (0) 3 hours ago" {
		t.Errorf("exited container: %+v", pg)
	}
	wantPG := []model.PortMapping{{HostIP: "127.0.0.1", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"}}
	if !reflect.DeepEqual(pg.Ports, wantPG) {
		t.Errorf("loopback publication: %+v", pg.Ports)
	}

	wantRange := []model.PortMapping{
		{HostIP: "0.0.0.0", HostPort: 9000, HostPortEnd: 9002, ContainerPort: 9000, Protocol: "udp"},
	}
	if !reflect.DeepEqual(containers[2].Ports, wantRange) {
		t.Errorf("range publication: %+v, want %+v", containers[2].Ports, wantRange)
	}

	// An exposed-but-unpublished port claims no host port, and HostPorts() must
	// agree.
	unpublished := containers[3]
	wantUnpublished := []model.PortMapping{
		{ContainerPort: 80, Protocol: "tcp"},
		{ContainerPort: 443, Protocol: "tcp"},
	}
	if !reflect.DeepEqual(unpublished.Ports, wantUnpublished) {
		t.Errorf("unpublished ports: %+v, want %+v", unpublished.Ports, wantUnpublished)
	}
	if got := unpublished.Ports[0].HostPorts(); got != nil {
		t.Errorf("an unpublished port claims no host port, got %v", got)
	}
}

func TestParseContainersPodman(t *testing.T) {
	containers, warnings := parseContainers(podmanPS)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(containers) != 2 {
		t.Fatalf("got %d containers, want 2", len(containers))
	}

	web := containers[0]
	if web.Name != "shop_web_1" {
		t.Errorf("podman reports Names as an array; got name %q", web.Name)
	}
	if web.Project != "shop" || web.Service != "web" {
		t.Errorf("labels from a JSON object: project=%q service=%q", web.Project, web.Service)
	}
	wantWeb := []model.PortMapping{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}}
	if !reflect.DeepEqual(web.Ports, wantWeb) {
		t.Errorf("structured ports: %+v, want %+v", web.Ports, wantWeb)
	}

	greeter := containers[1]
	if greeter.Name != "lab_greeter_1" {
		t.Errorf("first of several names wins; got %q", greeter.Name)
	}
	// State is empty in this shape and has to be recovered from Status rather than
	// reported as unknown.
	if greeter.State != "exited" {
		t.Errorf("state inferred from status: %q", greeter.State)
	}
	// podman-compose's own label prefix is read when the docker one is absent.
	if greeter.Project != "lab" || greeter.Service != "greeter" {
		t.Errorf("podman compose labels: %+v", greeter)
	}
	wantGreeter := []model.PortMapping{
		{HostPort: 7000, HostPortEnd: 7002, ContainerPort: 7000, Protocol: "tcp"},
		{HostIP: "127.0.0.1", HostPort: 5353, ContainerPort: 53, Protocol: "udp"},
	}
	if !reflect.DeepEqual(greeter.Ports, wantGreeter) {
		t.Errorf("range as a count, default protocol: %+v, want %+v", greeter.Ports, wantGreeter)
	}
	if got := greeter.Ports[0].HostPorts(); !reflect.DeepEqual(got, []int{7000, 7001, 7002}) {
		t.Errorf("range expansion: %v", got)
	}
}

func TestParseContainersArrayShape(t *testing.T) {
	// `--format json` — and podman for some subcommands even when asked for the
	// template — answers with a single array instead of one object per line.
	const arrayShape = `[{"Names":["only"],"Image":"busybox","State":"running","Status":"Up 1 second","Ports":[],"Networks":["podman"],"Labels":{}}]`
	containers, warnings := parseContainers(arrayShape)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(containers) != 1 || containers[0].Name != "only" {
		t.Fatalf("array shape: %+v", containers)
	}
}

func TestParseContainersReportsUnreadableLines(t *testing.T) {
	const noisy = "Cannot connect to anything\n{\"Names\":\"web\",\"State\":\"running\"}\n{oops\n"
	containers, warnings := parseContainers(noisy)
	if len(containers) != 1 {
		t.Fatalf("got %d containers, want the one readable line", len(containers))
	}
	if len(warnings) != 2 {
		t.Fatalf("output that was not understood must be reported: %v", warnings)
	}
}

func TestParseContainersEmpty(t *testing.T) {
	// A reachable daemon with no containers is a legitimate empty answer; the
	// collector, not the parser, is what distinguishes it from a failed probe.
	containers, warnings := parseContainers("\n")
	if containers != nil || warnings != nil {
		t.Fatalf("empty output: %+v %v", containers, warnings)
	}
}

// ──────────────────────────────────────────────────────────── port strings

func TestParsePortString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []model.PortMapping
	}{
		{
			name: "ipv4 publication",
			in:   "0.0.0.0:8080->80/tcp",
			want: []model.PortMapping{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		},
		{
			name: "bracketed ipv6",
			in:   "[::]:8080->80/tcp",
			want: []model.PortMapping{{HostIP: "::", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		},
		{
			name: "bare ipv6, as older docker prints it",
			in:   ":::8080->80/tcp",
			want: []model.PortMapping{{HostIP: "::", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		},
		{
			name: "explicit ipv6 address",
			in:   "[fd00::1]:443->443/tcp",
			want: []model.PortMapping{{HostIP: "fd00::1", HostPort: 443, ContainerPort: 443, Protocol: "tcp"}},
		},
		{
			name: "host range",
			in:   "0.0.0.0:8000-8010->8000-8010/tcp",
			want: []model.PortMapping{{HostIP: "0.0.0.0", HostPort: 8000, HostPortEnd: 8010, ContainerPort: 8000, Protocol: "tcp"}},
		},
		{
			name: "no address",
			in:   "8080->80/tcp",
			want: []model.PortMapping{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		},
		{
			name: "exposed only",
			in:   "80/tcp",
			want: []model.PortMapping{{ContainerPort: 80, Protocol: "tcp"}},
		},
		{
			name: "protocol omitted defaults to tcp",
			in:   "0.0.0.0:8080->80",
			want: []model.PortMapping{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		},
		{
			name: "several entries",
			in:   "0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp, 5353/udp",
			want: []model.PortMapping{
				{HostIP: "0.0.0.0", HostPort: 80, ContainerPort: 80, Protocol: "tcp"},
				{HostIP: "0.0.0.0", HostPort: 443, ContainerPort: 443, Protocol: "tcp"},
				{ContainerPort: 5353, Protocol: "udp"},
			},
		},
		{name: "empty", in: "", want: nil},
		{name: "nonsense is dropped rather than guessed at", in: "not-a-port", want: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePortString(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parsePortString(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────── networks

const dockerNetworkLS = `
{"CreatedAt":"2026-06-01 10:12:00.123456789 +0000 UTC","Driver":"bridge","ID":"a1b2c3d4e5f6","IPv6":"false","Internal":"false","Labels":"com.docker.compose.network=default,com.docker.compose.project=shop,com.docker.compose.version=2.24.5","Name":"shop_default","Scope":"local"}
{"CreatedAt":"2026-01-04 07:00:00.000000000 +0000 UTC","Driver":"bridge","ID":"0f0f0f0f0f0f","IPv6":"false","Internal":"false","Labels":"","Name":"bridge","Scope":"local"}
{"CreatedAt":"2026-01-04 07:00:00.000000000 +0000 UTC","Driver":"host","ID":"1e1e1e1e1e1e","IPv6":"false","Internal":"false","Labels":"","Name":"host","Scope":"local"}
`

const podmanNetworkLS = `
{"Name":"podman","ID":"2f259bab93aaaaa","Driver":"bridge","Labels":{},"NetworkInterface":"podman0","Created":"2026-05-01T10:00:00Z","Subnets":null,"IPv6Enabled":false,"Internal":false,"DNSEnabled":false}
{"Name":"lab_default","ID":"9911bb22cc33dd","Driver":"bridge","Labels":{"io.podman.compose.project":"lab"},"NetworkInterface":"podman1","Created":"2026-05-02T10:00:00Z","IPv6Enabled":false,"Internal":false,"DNSEnabled":true}
`

func TestParseNetworkList(t *testing.T) {
	networks, warnings := parseNetworkList(dockerNetworkLS)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	want := []model.ContainerNetwork{
		{Name: "shop_default", Driver: "bridge", Project: "shop"},
		{Name: "bridge", Driver: "bridge"},
		{Name: "host", Driver: "host"},
	}
	if !reflect.DeepEqual(networks, want) {
		t.Fatalf("docker networks: %+v, want %+v", networks, want)
	}

	podmanNetworks, warnings := parseNetworkList(podmanNetworkLS)
	if len(warnings) != 0 {
		t.Fatalf("unexpected podman warnings: %v", warnings)
	}
	wantPodman := []model.ContainerNetwork{
		{Name: "podman", Driver: "bridge"},
		{Name: "lab_default", Driver: "bridge", Project: "lab"},
	}
	if !reflect.DeepEqual(podmanNetworks, wantPodman) {
		t.Fatalf("podman networks: %+v, want %+v", podmanNetworks, wantPodman)
	}
}

func TestParseSubnets(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "docker network inspect --format {{json .IPAM}}",
			in:   `{"Driver":"default","Options":null,"Config":[{"Subnet":"172.19.0.0/16","Gateway":"172.19.0.1"}]}`,
			want: []string{"172.19.0.0/16"},
		},
		{
			name: "docker, dual stack",
			in:   `{"Driver":"default","Options":{},"Config":[{"Subnet":"172.20.0.0/16","Gateway":"172.20.0.1"},{"Subnet":"fd00:dead:beef::/64"}]}`,
			want: []string{"172.20.0.0/16", "fd00:dead:beef::/64"},
		},
		{
			name: "docker host network has no IPAM configuration",
			in:   `{"Driver":"default","Options":null,"Config":[]}`,
			want: nil,
		},
		{
			name: "podman with netavark",
			in:   `{"name":"lab_default","id":"9911bb22cc33dd","driver":"bridge","network_interface":"podman1","subnets":[{"subnet":"10.89.1.0/24","gateway":"10.89.1.1"}],"ipv6_enabled":false,"internal":false,"dns_enabled":true,"labels":{"io.podman.compose.project":"lab"}}`,
			want: []string{"10.89.1.0/24"},
		},
		{
			name: "podman with CNI, as podman 3 printed it",
			in:   `{"cniVersion":"0.4.0","name":"podman","plugins":[{"type":"bridge","bridge":"cni-podman0","ipam":{"type":"host-local","routes":[{"dst":"0.0.0.0/0"}],"ranges":[[{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}]]}}]}`,
			want: []string{"10.88.0.0/16"},
		},
		{
			name: "a whole docker network object, IPAM nested",
			in:   `{"Name":"shop_default","Driver":"bridge","IPAM":{"Driver":"default","Config":[{"Subnet":"172.21.0.0/16"}]}}`,
			want: []string{"172.21.0.0/16"},
		},
		{name: "empty output", in: "", want: nil},
		{name: "null IPAM", in: "null", want: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSubnets(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseSubnets() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────── volumes

const dockerVolumeLS = `
{"Availability":"N/A","Driver":"local","Group":"N/A","Labels":"com.docker.compose.project=shop,com.docker.compose.volume=pgdata","Links":"N/A","Mountpoint":"/var/lib/docker/volumes/shop_pgdata/_data","Name":"shop_pgdata","Scope":"local","Size":"N/A","Status":"N/A"}
{"Availability":"N/A","Driver":"local","Group":"N/A","Labels":"","Links":"N/A","Mountpoint":"/var/lib/docker/volumes/orphan/_data","Name":"orphan","Scope":"local","Size":"N/A","Status":"N/A"}
`

const podmanVolumeLS = `[{"Name":"lab_data","Driver":"local","Mountpoint":"/home/deploy/.local/share/containers/storage/volumes/lab_data/_data","CreatedAt":"2026-05-02T10:00:01Z","Labels":{"io.podman.compose.project":"lab"},"Scope":"local","Options":{},"MountCount":0}]`

func TestParseVolumeList(t *testing.T) {
	volumes, warnings := parseVolumeList(dockerVolumeLS)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	want := []model.ContainerVolume{
		{Name: "shop_pgdata", Driver: "local", Mountpoint: "/var/lib/docker/volumes/shop_pgdata/_data", Project: "shop"},
		{Name: "orphan", Driver: "local", Mountpoint: "/var/lib/docker/volumes/orphan/_data"},
	}
	if !reflect.DeepEqual(volumes, want) {
		t.Fatalf("docker volumes: %+v, want %+v", volumes, want)
	}

	podmanVolumes, warnings := parseVolumeList(podmanVolumeLS)
	if len(warnings) != 0 {
		t.Fatalf("unexpected podman warnings: %v", warnings)
	}
	wantPodman := []model.ContainerVolume{{
		Name:       "lab_data",
		Driver:     "local",
		Mountpoint: "/home/deploy/.local/share/containers/storage/volumes/lab_data/_data",
		Project:    "lab",
	}}
	if !reflect.DeepEqual(podmanVolumes, wantPodman) {
		t.Fatalf("podman volumes: %+v, want %+v", podmanVolumes, wantPodman)
	}
}

// ───────────────────────────────────────────────────────────────── images

const dockerImageLS = `
{"Containers":"N/A","CreatedAt":"2026-05-20 12:00:00 +0000 UTC","CreatedSince":"3 weeks ago","Digest":"sha256:11aa22bb33cc44dd55ee66ff77889900aabbccddeeff00112233445566778899","ID":"c1a2b3c4d5e6","Repository":"nginx","SharedSize":"N/A","Size":"48.1MB","Tag":"1.27-alpine","UniqueSize":"N/A","VirtualSize":"48.1MB"}
{"Containers":"N/A","CreatedAt":"2026-05-20 12:00:00 +0000 UTC","CreatedSince":"3 weeks ago","Digest":"<none>","ID":"c1a2b3c4d5e6","Repository":"nginx","SharedSize":"N/A","Size":"48.1MB","Tag":"latest","UniqueSize":"N/A","VirtualSize":"48.1MB"}
{"Containers":"N/A","CreatedAt":"2026-04-01 08:00:00 +0000 UTC","CreatedSince":"2 months ago","Digest":"<none>","ID":"deadbeef0001","Repository":"<none>","SharedSize":"N/A","Size":"120MB","Tag":"<none>","UniqueSize":"N/A","VirtualSize":"120MB"}
`

const podmanImageLS = `[{"Id":"aa11bb22cc33","Names":["docker.io/library/nginx:1.27-alpine"],"Digest":"sha256:11aa22bb33cc44dd55ee66ff77889900aabbccddeeff00112233445566778899","Created":1779000000,"CreatedAt":"2026-05-20T12:00:00Z","Size":50331648,"SharedSize":0,"VirtualSize":50331648,"Labels":{},"Containers":1,"History":["docker.io/library/nginx:1.27-alpine"],"Dangling":false},{"Id":"bb22cc33dd44","Names":[],"Digest":"sha256:99887766554433221100ffeeddccbbaa00112233445566778899aabbccddeeff","Created":1770000000,"CreatedAt":"2026-02-01T09:00:00Z","Size":10485760,"Labels":null,"Containers":0,"Dangling":true}]`

func TestParseImageListDocker(t *testing.T) {
	entries, warnings := parseImageList(dockerImageLS)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}

	if got, want := entries[0].Image.Reference, "nginx:1.27-alpine"; got != want {
		t.Errorf("reference: %q, want %q", got, want)
	}
	if entries[0].Image.Digest == "" {
		t.Error("a digest that was printed must be kept")
	}
	if entries[0].Ref != "nginx:1.27-alpine" || entries[0].ID != "c1a2b3c4d5e6" {
		t.Errorf("inspect handle: %+v", entries[0])
	}
	// docker's human size is deliberately not parsed: it is rounded to three
	// significant digits, and image inspect provides the exact figure.
	if entries[0].Image.SizeBytes != 0 {
		t.Errorf("human size must not be guessed at: %d", entries[0].Image.SizeBytes)
	}
	// <none> is a placeholder, not a digest.
	if entries[1].Image.Digest != "" {
		t.Errorf("<none> digest leaked: %q", entries[1].Image.Digest)
	}
	// A dangling image has no name, so its id stands in for the reference and is
	// the inspect handle — and the allowlist accepts an id where it would refuse
	// "<none>:<none>".
	dangling := entries[2]
	if dangling.Image.Reference != "deadbeef0001" || dangling.Ref != "deadbeef0001" {
		t.Errorf("dangling image: %+v", dangling)
	}
}

func TestParseImageListPodman(t *testing.T) {
	entries, warnings := parseImageList(podmanImageLS)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if got, want := entries[0].Image.Reference, "docker.io/library/nginx:1.27-alpine"; got != want {
		t.Errorf("reference from the Names array: %q, want %q", got, want)
	}
	// podman reports the size as a number of bytes, which is exact and is kept.
	if got, want := entries[0].Image.SizeBytes, int64(50331648); got != want {
		t.Errorf("numeric size: %d, want %d", got, want)
	}
	if entries[1].Image.Reference != "bb22cc33dd44" || entries[1].Ref != "bb22cc33dd44" {
		t.Errorf("dangling podman image: %+v", entries[1])
	}
}

func TestParseImageInspect(t *testing.T) {
	const dockerInspect = `{"Id":"sha256:c1a2b3c4d5e6f7","RepoTags":["nginx:1.27-alpine"],"RepoDigests":["nginx@sha256:11aa22bb33cc44dd55ee66ff77889900aabbccddeeff00112233445566778899"],"Architecture":"amd64","Os":"linux","Size":50448291,"GraphDriver":{"Name":"overlay2"}}`
	detail, ok := parseImageInspect(dockerInspect)
	if !ok {
		t.Fatal("docker inspect was not read")
	}
	want := imageDetail{
		Architecture: "amd64",
		OS:           "linux",
		SizeBytes:    50448291,
		Digest:       "sha256:11aa22bb33cc44dd55ee66ff77889900aabbccddeeff00112233445566778899",
	}
	if detail != want {
		t.Errorf("docker inspect: %+v, want %+v", detail, want)
	}

	const podmanInspect = `[{"Id":"aa11bb22cc33","Digest":"sha256:99887766554433221100ffeeddccbbaa00112233445566778899aabbccddeeff","RepoTags":["docker.io/library/nginx:1.27-alpine"],"RepoDigests":["docker.io/library/nginx@sha256:998877"],"Architecture":"arm64","Os":"linux","Size":48234567,"Variant":"v8"}]`
	podmanDetail, ok := parseImageInspect(podmanInspect)
	if !ok {
		t.Fatal("podman inspect was not read")
	}
	if podmanDetail.Architecture != "arm64" || podmanDetail.OS != "linux" {
		t.Errorf("an arm64 image on an amd64 host is the mismatch this field exists for: %+v", podmanDetail)
	}
	if podmanDetail.SizeBytes != 48234567 {
		t.Errorf("size: %d", podmanDetail.SizeBytes)
	}
	if podmanDetail.Digest != "sha256:99887766554433221100ffeeddccbbaa00112233445566778899aabbccddeeff" {
		t.Errorf("digest: %q", podmanDetail.Digest)
	}

	if _, ok := parseImageInspect(""); ok {
		t.Error("empty output must not read as a successful inspect")
	}
	if _, ok := parseImageInspect("{}"); ok {
		t.Error("an object with nothing in it must not read as a successful inspect")
	}
}

// ──────────────────────────────────────────────────────── info and version

func TestParseStorageDriver(t *testing.T) {
	const dockerInfo = `{"ID":"ABCD:EFGH","Containers":7,"ContainersRunning":5,"Images":42,"Driver":"overlay2","DriverStatus":[["Backing Filesystem","extfs"]],"DockerRootDir":"/var/lib/docker","ServerVersion":"26.1.4","OperatingSystem":"Debian GNU/Linux 12 (bookworm)"}`
	if got, want := parseStorageDriver(dockerInfo), "overlay2"; got != want {
		t.Errorf("docker: %q, want %q", got, want)
	}

	const podmanInfo = `{"host":{"arch":"amd64","os":"linux"},"store":{"configFile":"/etc/containers/storage.conf","graphDriverName":"overlay","graphRoot":"/var/lib/containers/storage","imageStore":{"number":12}},"version":{"Version":"4.9.4"}}`
	if got, want := parseStorageDriver(podmanInfo), "overlay"; got != want {
		t.Errorf("podman: %q, want %q", got, want)
	}

	if got := parseStorageDriver("Cannot connect to the Docker daemon"); got != "" {
		t.Errorf("unparseable info: %q", got)
	}
}

func TestParseEngineVersion(t *testing.T) {
	const withServer = `{"Client":{"Version":"26.1.4","ApiVersion":"1.45","Os":"linux","Arch":"amd64"},"Server":{"Platform":{"Name":"Docker Engine - Community"},"Version":"26.1.3","ApiVersion":"1.45"}}`
	if got, want := parseEngineVersion(withServer), "26.1.3"; got != want {
		t.Errorf("the engine version is the server's: %q, want %q", got, want)
	}

	// With the daemon unreachable the CLI still prints its own half, and the client
	// version is better than nothing.
	const clientOnly = `{"Client":{"Version":"26.1.4","ApiVersion":"1.45","Os":"linux","Arch":"amd64"}}`
	if got, want := parseEngineVersion(clientOnly), "26.1.4"; got != want {
		t.Errorf("client fallback: %q, want %q", got, want)
	}

	const podmanVersion = `{"Client":{"APIVersion":"4.9.4","Version":"4.9.4","GoVersion":"go1.21.7","Os":"linux","Arch":"amd64"}}`
	if got, want := parseEngineVersion(podmanVersion), "4.9.4"; got != want {
		t.Errorf("podman: %q, want %q", got, want)
	}

	if got := parseEngineVersion("Cannot connect to the Docker daemon\n"); got != "" {
		t.Errorf("unparseable version: %q", got)
	}
}

func TestParseVersionShort(t *testing.T) {
	cases := map[string]string{
		"v2.24.5\n":                         "2.24.5",
		"2.24.5":                            "2.24.5",
		"docker-compose version 1.29.2\n":   "1.29.2",
		"podman-compose version 1.0.6\n":    "1.0.6",
		"":                                  "",
		"could not determine the version\n": "",
	}
	for in, want := range cases {
		if got := parseVersionShort(in); got != want {
			t.Errorf("parseVersionShort(%q) = %q, want %q", in, got, want)
		}
	}
}

// ─────────────────────────────────────────────────────────────── plumbing

func TestNormalizeState(t *testing.T) {
	cases := []struct{ state, status, want string }{
		{"running", "Up 2 days", "running"},
		{"Exited", "Exited (0) 3 hours ago", "exited"},
		{"", "Up 3 minutes", "running"},
		{"", "Exited (137) 1 day ago", "exited"},
		{"", "Created", "created"},
		{"", "Paused", "paused"},
		{"", "Restarting (1) 2 seconds ago", "restarting"},
		// Neither field said anything, and inventing "exited" here would be the
		// exact failure this tool is built to avoid.
		{"", "", ""},
	}
	for _, tc := range cases {
		if got := normalizeState(tc.state, tc.status); got != tc.want {
			t.Errorf("normalizeState(%q, %q) = %q, want %q", tc.state, tc.status, got, tc.want)
		}
	}
}

func TestLabelsFromEitherShape(t *testing.T) {
	var packed flexLabels
	if err := packed.UnmarshalJSON([]byte(`"com.docker.compose.project=shop,solo,empty="`)); err != nil {
		t.Fatalf("string labels: %v", err)
	}
	if packed["com.docker.compose.project"] != "shop" {
		t.Errorf("packed labels: %+v", packed)
	}
	if _, ok := packed["solo"]; !ok {
		t.Errorf("a label with no value is still a label: %+v", packed)
	}

	var object flexLabels
	if err := object.UnmarshalJSON([]byte(`{"io.podman.compose.project":"lab"}`)); err != nil {
		t.Fatalf("object labels: %v", err)
	}
	if object["io.podman.compose.project"] != "lab" {
		t.Errorf("object labels: %+v", object)
	}
}

func TestUnreachableNoteNamesTheCause(t *testing.T) {
	// The wording is the point: an unreachable daemon must not be readable as a
	// host with nothing on it, and the reader has to know what to do next.
	docker := unreachableNote(kindDocker, errString("permission denied while trying to connect to the Docker daemon socket"))
	for _, want := range []string{"unknown rather than empty", "docker group", "permission denied"} {
		if !strings.Contains(docker, want) {
			t.Errorf("docker note is missing %q: %s", want, docker)
		}
	}
	podman := unreachableNote(kindPodman, errString("cannot connect to the Podman socket"))
	if !strings.Contains(podman, "unknown rather than empty") {
		t.Errorf("podman note: %s", podman)
	}
}

func TestShortenKeepsOneLine(t *testing.T) {
	got := shorten("docker exited 1:\n  permission   denied\n")
	if got != "docker exited 1: permission denied" {
		t.Errorf("shorten: %q", got)
	}
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'x'
	}
	if len(shorten(string(long))) > 210 {
		t.Errorf("shorten did not bound the message: %d", len(shorten(string(long))))
	}
}

type errString string

func (e errString) Error() string { return string(e) }

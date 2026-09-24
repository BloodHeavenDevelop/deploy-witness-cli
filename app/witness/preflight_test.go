package witness

import (
	"strings"
	"testing"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

var fixedNow = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

func baseInput() Input {
	return Input{
		Manifest: &model.Manifest{Path: "/srv/app/docker-compose.yml"},
		Caps: &model.Capabilities{
			Arch:              "x86_64",
			MemTotalBytes:     8 << 30,
			MemAvailableBytes: 6 << 30,
			Runtime: &model.ContainerRuntime{
				Kind: "docker", Version: "27.0.3", ComposeKind: "plugin",
				ComposeVersion: "2.29.0", Reachable: true,
			},
			Filesystems: []model.Filesystem{{
				Mount: "/", Device: "/dev/sda1", FSType: "ext4",
				TotalBytes: 100 << 30, UsedBytes: 40 << 30, AvailableBytes: 60 << 30,
				InodesTotal: 6000000, InodesFree: 5000000,
			}},
			RebootRequired: "no",
		},
		Now:     fixedNow,
		Project: "app",
	}
}

func codes(findings []model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Code)
	}
	return out
}

func find(findings []model.Finding, code string) (model.Finding, bool) {
	for _, f := range findings {
		if f.Code == code {
			return f, true
		}
	}
	return model.Finding{}, false
}

func has(findings []model.Finding, code string) bool {
	_, ok := find(findings, code)
	return ok
}

// The invariant the whole product rests on. It is asserted over every rule at once
// rather than per rule, so a rule added later cannot quietly skip it.
func TestEveryFindingIsComplete(t *testing.T) {
	in := busyHost()
	findings, _, _, notes := Evaluate(in)

	if len(findings) == 0 {
		t.Fatal("the fixture is meant to trip many rules; none fired")
	}
	for _, note := range notes {
		if strings.Contains(note, "discarded") {
			t.Fatalf("a rule produced a finding with no evidence: %s", note)
		}
	}
	for _, f := range findings {
		switch {
		case len(f.Evidence) == 0:
			t.Errorf("%s has no evidence", f.Code)
		case f.Code == "":
			t.Errorf("a finding has no code: %+v", f)
		case f.Title == "":
			t.Errorf("%s has no title", f.Code)
		case f.Description == "":
			t.Errorf("%s has no description", f.Code)
		case f.WhyItMatters == "":
			t.Errorf("%s does not say why it matters", f.Code)
		case f.WhatToDo == "":
			t.Errorf("%s does not say what to do", f.Code)
		case f.Severity == "":
			t.Errorf("%s has no severity", f.Code)
		case f.Confidence == "":
			t.Errorf("%s has no confidence", f.Code)
		}
		for _, e := range f.Evidence {
			if e.Command == "" || e.Output == "" {
				t.Errorf("%s carries empty evidence: %+v", f.Code, e)
			}
			if e.CapturedAt == "" {
				t.Errorf("%s carries evidence with no timestamp", f.Code)
			}
		}
	}
}

// A host where everything is in order must produce no blockers. This is the test
// that keeps the product honest in the expensive direction: a false blocker stops a
// deployment that would have been fine.
func TestQuietHostProducesNoBlockers(t *testing.T) {
	in := baseInput()
	in.Manifest.Services = []model.ManifestService{{
		Name:           "web",
		Image:          model.ImageRef{Raw: "nginx@sha256:abc", Repository: "nginx", Digest: "sha256:abc"},
		HasHealthcheck: true,
		Ports:          []model.PortMapping{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
	}}

	findings, _, _, _ := Evaluate(in)
	for _, f := range findings {
		if f.Severity == model.FindingBlocker {
			t.Errorf("unexpected blocker on a healthy host: %s — %s", f.Code, f.Title)
		}
	}
}

func TestPortConflict(t *testing.T) {
	t.Run("a port held by an unrelated process blocks", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "db",
			Image: model.ImageRef{Raw: "postgres:16", Repository: "postgres", Tag: "16"},
			Ports: []model.PortMapping{{HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"}},
		}}
		in.Caps.Ports = []model.Port{{
			Protocol: "tcp", Address: "0.0.0.0", Port: 5432, State: "LISTEN",
			Pid: 1234, Process: "postgres", Exposure: model.ExposureAll,
		}}

		findings := portConflicts(in)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		f := findings[0]
		if f.Severity != model.FindingBlocker {
			t.Errorf("severity = %s, want blocker", f.Severity)
		}
		// The evidence must name the process and the pid: "port 5432 is in use" that
		// does not say by what is not actionable.
		joined := f.Evidence[len(f.Evidence)-1].Output
		if !strings.Contains(joined, "pid=1234") || !strings.Contains(joined, "postgres") {
			t.Errorf("evidence does not identify the holder: %q", joined)
		}
	})

	t.Run("a port held by this deployment's own container is information", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		}}
		in.Caps.Containers = []model.Container{{
			Name: "app-web-1", Project: "app", Service: "web", State: "running",
			Ports: []model.PortMapping{{HostPort: 8080, ContainerPort: 80}},
		}}
		in.Caps.Ports = []model.Port{{Protocol: "tcp", Address: "0.0.0.0", Port: 8080, State: "LISTEN"}}

		findings := portConflicts(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingInfo {
			t.Fatalf("a redeployment of the same project must not be a conflict: %+v", codes(findings))
		}
	})

	t.Run("the project name is normalised the way compose normalises it", func(t *testing.T) {
		in := baseInput()
		in.Project = "My App"
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostPort: 8080, ContainerPort: 80}},
		}}
		in.Caps.Containers = []model.Container{{
			Name: "myapp-web-1", Project: "myapp", Service: "web",
			Ports: []model.PortMapping{{HostPort: 8080, ContainerPort: 80}},
		}}

		findings := portConflicts(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingInfo {
			t.Fatalf("a directory called \"My App\" must match the project label myapp: %+v", findings)
		}
	})

	t.Run("a port range claims every port in it", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "media",
			Ports: []model.PortMapping{{HostPort: 3000, HostPortEnd: 3002, ContainerPort: 3000}},
		}}
		in.Caps.Ports = []model.Port{
			{Protocol: "tcp", Address: "0.0.0.0", Port: 3001, State: "LISTEN", Process: "node"},
		}

		findings := portConflicts(in)
		if len(findings) != 1 || findings[0].Subject != "3001/tcp" {
			t.Fatalf("the conflict inside the range was missed: %+v", findings)
		}
	})

	t.Run("an unattributable socket is not given an invented owner", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostPort: 80, ContainerPort: 80}},
		}}
		in.Caps.Ports = []model.Port{{Protocol: "tcp", Address: "0.0.0.0", Port: 80, State: "LISTEN"}}

		findings := portConflicts(in)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		if !strings.Contains(findings[0].Description, "unidentified") {
			t.Errorf("an unattributed socket must be described as such: %q", findings[0].Description)
		}
	})

	// DW-24: the comparison is between bindings, not port numbers. Each of these
	// used to be a blocker that stopped a deployment which would have worked.

	t.Run("udp and tcp on the same number are different sockets", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "dns",
			Ports: []model.PortMapping{{HostPort: 53, ContainerPort: 53, Protocol: "udp"}},
		}}
		in.Caps.Ports = []model.Port{{
			Protocol: "tcp", Address: "0.0.0.0", Port: 53, State: "LISTEN", Pid: 7, Process: "unbound",
		}}

		if findings := portConflicts(in); len(findings) != 0 {
			t.Fatalf("a TCP listener must not block a UDP publish: %+v", findings)
		}
	})

	t.Run("two different host addresses do not collide", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		}}
		in.Caps.Ports = []model.Port{{
			Protocol: "tcp", Address: "192.168.1.10", Port: 8080, State: "LISTEN", Process: "caddy",
		}}

		if findings := portConflicts(in); len(findings) != 0 {
			t.Fatalf("distinct addresses must not conflict: %+v", findings)
		}
	})

	t.Run("a wildcard listener holds every address of its family", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80}},
		}}
		in.Caps.Ports = []model.Port{{
			Protocol: "tcp", Address: "0.0.0.0", Port: 8080, State: "LISTEN", Process: "caddy",
		}}

		findings := portConflicts(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingBlocker {
			t.Fatalf("0.0.0.0 covers 127.0.0.1: %+v", findings)
		}
		if findings[0].Subject != "127.0.0.1:8080/tcp" {
			t.Errorf("subject = %q, want the full binding", findings[0].Subject)
		}
	})

	t.Run("a wildcard publish collides with a specific listener", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80}},
		}}
		in.Caps.Ports = []model.Port{{
			Protocol: "tcp", Address: "192.168.1.10", Port: 8080, State: "LISTEN", Process: "caddy",
		}}

		findings := portConflicts(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingBlocker {
			t.Fatalf("a wildcard publish takes every address: %+v", findings)
		}
	})

	t.Run("the IPv6 wildcard against an IPv4 publish is a question, not a blocker", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80}},
		}}
		in.Caps.Ports = []model.Port{{
			Protocol: "tcp6", Address: "::", Port: 8080, State: "LISTEN", Process: "caddy",
		}}

		findings := portConflicts(in)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		f := findings[0]
		if f.Severity != model.FindingWarning || f.Confidence != model.ConfidenceMedium {
			t.Errorf("severity/confidence = %s/%s, want warning/medium", f.Severity, f.Confidence)
		}
		if !strings.Contains(f.Description, "bindv6only") {
			t.Errorf("the description must name what decides it: %q", f.Description)
		}
		if !strings.Contains(f.WhatToDo, "bindv6only") || !strings.Contains(f.WhatToDo, "ss -lntup") {
			t.Errorf("the reader must be told how to settle it: %q", f.WhatToDo)
		}
	})

	t.Run("a specific IPv6 listener does not touch an IPv4 publish", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80}},
		}}
		in.Caps.Ports = []model.Port{{
			Protocol: "tcp6", Address: "fd00::1", Port: 8080, State: "LISTEN", Process: "caddy",
		}}

		if findings := portConflicts(in); len(findings) != 0 {
			t.Fatalf("different families, different sockets: %+v", findings)
		}
	})

	t.Run("a publish naming no address is uncertain against a specific IPv6 listener", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostPort: 8080, ContainerPort: 80}},
		}}
		in.Caps.Ports = []model.Port{{
			Protocol: "tcp6", Address: "fd00::1", Port: 8080, State: "LISTEN", Process: "caddy",
		}}

		findings := portConflicts(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingWarning {
			t.Fatalf("whether the engine binds IPv6 is not knowable offline: %+v", findings)
		}
		// The old form of the subject survives when no address was named, because
		// there is nothing more to say about it.
		if findings[0].Subject != "8080/tcp" {
			t.Errorf("subject = %q, want 8080/tcp", findings[0].Subject)
		}
	})

	t.Run("an unresolved host_ip is a question, never silence", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostIP: "${HOST_IP}", HostPort: 8080, ContainerPort: 80}},
		}}
		in.Caps.Ports = []model.Port{{
			Protocol: "tcp", Address: "10.0.0.5", Port: 8080, State: "LISTEN", Process: "caddy",
		}}

		findings := portConflicts(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingWarning {
			t.Fatalf("an address the tool cannot read must be reported, not assumed: %+v", findings)
		}
		if !strings.Contains(findings[0].Description, "${HOST_IP}") {
			t.Errorf("the description must quote what could not be read: %q", findings[0].Description)
		}
	})

	t.Run("the * address ss prints is a wildcard, not an unreadable address", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostIP: "192.168.1.10", HostPort: 8080, ContainerPort: 80}},
		}}
		in.Caps.Ports = []model.Port{{
			Protocol: "tcp", Address: "*", Port: 8080, State: "LISTEN", Process: "caddy",
			Exposure: model.ExposureAll,
		}}

		findings := portConflicts(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingBlocker {
			t.Fatalf("`ss` prints * for every interface: %+v", findings)
		}
	})

	t.Run("an IPv4-mapped socket from the tcp6 table matches an IPv4 publish", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80}},
		}}
		// The collector normalises ::ffff:127.0.0.1 to dotted form, so the family
		// has to be read off the address rather than off the table's name.
		in.Caps.Ports = []model.Port{{
			Protocol: "tcp6", Address: "127.0.0.1", Port: 8080, State: "LISTEN", Process: "caddy",
		}}

		findings := portConflicts(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingBlocker {
			t.Fatalf("tcp6 names the table, not the collision: %+v", findings)
		}
	})

	t.Run("a protocol with no socket table is reported as unchecked", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "sig",
			Ports: []model.PortMapping{{HostPort: 2905, ContainerPort: 2905, Protocol: "sctp"}},
		}}

		findings := portConflicts(in)
		if len(findings) != 1 {
			t.Fatalf("a port that was not looked at must still be reported: %+v", findings)
		}
		f := findings[0]
		if f.Severity != model.FindingWarning || f.Confidence != model.ConfidenceLow {
			t.Errorf("severity/confidence = %s/%s, want warning/low", f.Severity, f.Confidence)
		}
		if !strings.Contains(f.Title, "not checked") {
			t.Errorf("the title must say the port was not checked: %q", f.Title)
		}
		if len(f.Evidence) == 0 {
			t.Error("a finding without evidence is dropped by the engine")
		}
	})

	t.Run("an unrelated container holding the binding names the container", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostPort: 8080, ContainerPort: 80}},
		}}
		in.Caps.Containers = []model.Container{{
			Name: "other-web-1", Project: "other", Service: "web", State: "running",
			Ports: []model.PortMapping{{HostPort: 8080, ContainerPort: 80}},
		}}

		findings := portConflicts(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingBlocker {
			t.Fatalf("got %+v", findings)
		}
		if !strings.Contains(findings[0].Description, "other-web-1") {
			t.Errorf("the holder must be named: %q", findings[0].Description)
		}
	})

	t.Run("a container of another project on another address does not collide", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80}},
		}}
		in.Caps.Containers = []model.Container{{
			Name: "other-web-1", Project: "other", Service: "web", State: "running",
			Ports: []model.PortMapping{{HostIP: "10.0.0.5", HostPort: 8080, ContainerPort: 80}},
		}}

		if findings := portConflicts(in); len(findings) != 0 {
			t.Fatalf("distinct addresses must not conflict: %+v", findings)
		}
	})
}

// The same class of error in the rule about the front of the machine: a QUIC
// publish on 443/udp does not take 443/tcp away from nginx.
func TestProxyPortConflictProtocol(t *testing.T) {
	withPublish := func(protocol string) Input {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{
			Name:  "web",
			Ports: []model.PortMapping{{HostPort: 443, ContainerPort: 443, Protocol: protocol}},
		}}
		in.Caps.Proxy = &model.Proxy{
			Kind: "nginx", Version: "1.24.0", ConfigRoot: "/etc/nginx", ListenPorts: []int{80, 443},
		}
		return in
	}

	t.Run("a TCP publish is still a blocker", func(t *testing.T) {
		findings := proxyPortConflict(withPublish("tcp"))
		if len(findings) != 1 || findings[0].Severity != model.FindingBlocker {
			t.Fatalf("got %+v", findings)
		}
	})

	t.Run("a QUIC publish is a warning, because the listen protocol was not recorded", func(t *testing.T) {
		findings := proxyPortConflict(withPublish("udp"))
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		f := findings[0]
		if f.Severity != model.FindingWarning || f.Confidence != model.ConfidenceLow {
			t.Errorf("severity/confidence = %s/%s, want warning/low", f.Severity, f.Confidence)
		}
		if !strings.Contains(f.Description, "not over TCP") {
			t.Errorf("the caveat must be stated: %q", f.Description)
		}
	})

	t.Run("publishing both protocols states the TCP collision once", func(t *testing.T) {
		in := withPublish("tcp")
		in.Manifest.Services[0].Ports = append(in.Manifest.Services[0].Ports,
			model.PortMapping{HostPort: 443, ContainerPort: 443, Protocol: "udp"})

		findings := proxyPortConflict(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingBlocker {
			t.Fatalf("got %+v", findings)
		}
	})
}

func TestExternalResourcesMustExist(t *testing.T) {
	in := baseInput()
	in.Manifest.Volumes = []model.ManifestVolume{{Name: "shared-data", External: true}}
	in.Manifest.Networks = []model.ManifestNetwork{{Name: "shared-net", External: true}}

	volumes := volumeNameConflicts(in)
	if len(volumes) != 1 || volumes[0].Severity != model.FindingBlocker {
		t.Fatalf("a missing external volume must block: %+v", volumes)
	}

	networks := networkNameConflicts(in)
	if len(networks) != 1 || networks[0].Severity != model.FindingBlocker {
		t.Fatalf("a missing external network must block: %+v", networks)
	}

	// And an existing one belonging to somebody else is a warning about data, not a
	// blocker: the deployment succeeds, which is the dangerous part.
	in.Caps.ContainerVolumes = []model.ContainerVolume{{
		Name: "shared-data", Driver: "local", Mountpoint: "/var/lib/docker/volumes/shared-data/_data",
		Project: "other-stack",
	}}
	volumes = volumeNameConflicts(in)
	if len(volumes) != 1 || volumes[0].Severity != model.FindingWarning {
		t.Fatalf("an existing foreign volume must warn: %+v", volumes)
	}
	if !strings.Contains(volumes[0].WhyItMatters, "succeeds") {
		t.Errorf("the finding should say the deployment succeeds with the wrong data: %q", volumes[0].WhyItMatters)
	}
}

func TestSubnetOverlap(t *testing.T) {
	cases := []struct {
		name      string
		want, has string
		overlap   bool
	}{
		{name: "identical", want: "172.20.0.0/16", has: "172.20.0.0/16", overlap: true},
		{name: "contained", want: "172.20.1.0/24", has: "172.20.0.0/16", overlap: true},
		{name: "containing", want: "172.16.0.0/12", has: "172.20.0.0/16", overlap: true},
		{name: "adjacent but distinct", want: "172.21.0.0/16", has: "172.20.0.0/16"},
		{name: "unrelated", want: "10.8.0.0/24", has: "172.20.0.0/16"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			in.Manifest.Networks = []model.ManifestNetwork{{Name: "app-net", Subnets: []string{tc.want}}}
			in.Caps.ContainerNetworks = []model.ContainerNetwork{{
				Name: "other-net", Driver: "bridge", Subnets: []string{tc.has}, Project: "other",
			}}

			findings := subnetOverlaps(in)
			if (len(findings) > 0) != tc.overlap {
				t.Fatalf("%s vs %s: got %d findings, want overlap = %v", tc.want, tc.has, len(findings), tc.overlap)
			}
		})
	}
}

func TestArchitectureMismatchFoldsArchitectureNames(t *testing.T) {
	cases := []struct {
		host, image string
		mismatch    bool
	}{
		{host: "x86_64", image: "amd64"},
		{host: "aarch64", image: "arm64"},
		{host: "x86_64", image: "arm64", mismatch: true},
		{host: "aarch64", image: "amd64", mismatch: true},
	}

	for _, tc := range cases {
		t.Run(tc.host+"/"+tc.image, func(t *testing.T) {
			in := baseInput()
			in.Caps.Arch = tc.host
			in.Manifest.Services = []model.ManifestService{{
				Name: "web", Image: model.ImageRef{Raw: "nginx:1.27", Repository: "nginx", Tag: "1.27"},
			}}
			in.Caps.Images = []model.ContainerImage{{
				Reference: "nginx:1.27", Architecture: tc.image, OS: "linux",
			}}

			findings := architectureMismatch(in)
			if (len(findings) > 0) != tc.mismatch {
				t.Fatalf("host %s, image %s: got %d findings, want mismatch = %v",
					tc.host, tc.image, len(findings), tc.mismatch)
			}
		})
	}
}

func TestMemoryShortfall(t *testing.T) {
	t.Run("more than the machine has is a blocker", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{
			{Name: "a", MemReservationBytes: 6 << 30},
			{Name: "b", MemReservationBytes: 6 << 30},
		}
		findings := memoryShortfall(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingBlocker {
			t.Fatalf("12 GiB reserved on an 8 GiB host must block: %+v", findings)
		}
		// The assumption has to be stated, or the reader cannot judge the finding.
		if !strings.Contains(findings[0].Description, "not from measured usage") {
			t.Errorf("the assumption is not stated: %q", findings[0].Description)
		}
	})

	t.Run("more than is free right now is a warning", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{Name: "a", MemReservationBytes: 7 << 30}}
		findings := memoryShortfall(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingWarning {
			t.Fatalf("7 GiB against 6 GiB available on an 8 GiB host must warn: %+v", findings)
		}
	})

	t.Run("a manifest that declares nothing is reported as such", func(t *testing.T) {
		in := baseInput()
		in.Manifest.Services = []model.ManifestService{{Name: "a"}}
		findings := memoryShortfall(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingInfo {
			t.Fatalf("no declared requirement must be stated, not passed over: %+v", findings)
		}
	})
}

func TestInodesAreNotConfusedWithBytes(t *testing.T) {
	in := baseInput()
	// Plenty of space, almost no inodes: the case a capacity-only report calls healthy.
	in.Caps.Filesystems = []model.Filesystem{{
		Mount: "/", Device: "/dev/sda1", FSType: "ext4",
		TotalBytes: 100 << 30, UsedBytes: 10 << 30, AvailableBytes: 90 << 30,
		InodesTotal: 1000000, InodesFree: 20000,
	}}

	findings := inodeShortfall(in)
	if len(findings) != 1 || findings[0].Severity != model.FindingBlocker {
		t.Fatalf("98%% of inodes used must be reported: %+v", findings)
	}

	// And a filesystem with dynamic inodes reports zero, which is not scarcity.
	in.Caps.Filesystems[0].InodesTotal = 0
	in.Caps.Filesystems[0].InodesFree = 0
	if findings := inodeShortfall(in); len(findings) != 0 {
		t.Fatalf("a dynamic-inode filesystem must not be reported as exhausted: %+v", findings)
	}
}

func TestRegistryReachabilityIsHonestWhenNotChecked(t *testing.T) {
	in := baseInput()
	in.Manifest.Services = []model.ManifestService{{
		Name: "web", Image: model.ImageRef{Raw: "ghcr.io/acme/web:1.2", Registry: "ghcr.io", Repository: "acme/web"},
	}}

	findings := registryReachability(in)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 stating the check did not run", len(findings))
	}
	if findings[0].Severity != model.FindingInfo || !strings.Contains(findings[0].Title, "not checked") {
		t.Errorf("an unchecked registry must say so rather than pass silently: %+v", findings[0])
	}

	in.EgressChecked = true
	in.RegistryResults = map[string]string{"ghcr.io": "dial tcp 140.82.121.34:443: i/o timeout"}
	findings = registryReachability(in)
	if len(findings) != 1 || findings[0].Severity != model.FindingBlocker {
		t.Fatalf("a registry that was tested and failed must block: %+v", findings)
	}
}

func TestDatabaseVersionMismatch(t *testing.T) {
	in := baseInput()
	in.Caps.Databases = []model.Database{{
		Kind: "postgres", Version: "15", Port: 5432, DataDir: "/var/lib/postgresql/15/main",
		Exposure: model.ExposureLoopback,
	}}

	t.Run("without a mount it is a warning", func(t *testing.T) {
		in := in
		in.Manifest = &model.Manifest{Path: in.Manifest.Path, Services: []model.ManifestService{{
			Name: "db", Image: model.ImageRef{Raw: "postgres:16", Repository: "postgres", Tag: "16"},
		}}}
		findings := databaseVersionMismatch(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingWarning {
			t.Fatalf("got %+v", findings)
		}
	})

	t.Run("with the host data directory mounted it blocks", func(t *testing.T) {
		in := in
		in.Manifest = &model.Manifest{Path: in.Manifest.Path, Services: []model.ManifestService{{
			Name:  "db",
			Image: model.ImageRef{Raw: "postgres:16", Repository: "postgres", Tag: "16"},
			Volumes: []model.VolumeMount{{
				Kind: model.MountBind, Source: "/var/lib/postgresql/15/main", Target: "/var/lib/postgresql/data",
			}},
		}}}
		findings := databaseVersionMismatch(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingBlocker {
			t.Fatalf("running 16 against a mounted 15 data directory must block: %+v", findings)
		}
	})

	t.Run("a tag with no version is not compared", func(t *testing.T) {
		in := in
		in.Manifest = &model.Manifest{Path: in.Manifest.Path, Services: []model.ManifestService{{
			Name: "db", Image: model.ImageRef{Raw: "postgres:latest", Repository: "postgres", Tag: "latest"},
		}}}
		if findings := databaseVersionMismatch(in); len(findings) != 0 {
			t.Fatalf("`latest` carries no version to compare: %+v", findings)
		}
	})
}

func TestDomainConflict(t *testing.T) {
	in := baseInput()
	in.Manifest.Services = []model.ManifestService{{
		Name: "web",
		Labels: map[string]string{
			"traefik.http.routers.web.rule": "Host(`shop.example.com`)",
		},
	}}

	t.Run("a name the proxy already serves", func(t *testing.T) {
		in := in
		in.Caps.Proxy = &model.Proxy{Kind: "nginx", ServerNames: []model.ProxyServerName{
			{Name: "shop.example.com", File: "/etc/nginx/sites-enabled/shop", Line: 4},
		}}
		findings := domainConflict(in)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		// The location is the whole value of this finding.
		if !strings.Contains(findings[0].WhatToDo, "/etc/nginx/sites-enabled/shop:4") {
			t.Errorf("the existing vhost's location is missing: %q", findings[0].WhatToDo)
		}
	})

	t.Run("a catch-all vhost is reported as where the traffic will land", func(t *testing.T) {
		in := in
		in.Caps.Proxy = &model.Proxy{Kind: "nginx", ServerNames: []model.ProxyServerName{
			{Name: "_", File: "/etc/nginx/sites-enabled/default", Line: 2},
		}}
		findings := domainConflict(in)
		if len(findings) != 1 || findings[0].Severity != model.FindingInfo {
			t.Fatalf("got %+v", findings)
		}
	})
}

func TestSecurityFlags(t *testing.T) {
	in := baseInput()
	in.Manifest.Services = []model.ManifestService{
		{Name: "agent", MountsContainerSocket: true},
		{Name: "tuner", CapAdd: []string{"SYS_ADMIN"}},
		{Name: "plain"},
	}

	findings := securityFlags(in)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), codes(findings))
	}

	socket, _ := find(findings, "witness.privileged_container")
	if socket.Severity != model.FindingBlocker {
		t.Errorf("mounting the runtime socket must be a blocker, got %s", socket.Severity)
	}
	// cap_add alone is a warning: it is often legitimate, and calling it a blocker
	// is how a check gets switched off.
	for _, f := range findings {
		if f.Subject == "tuner" && f.Severity != model.FindingWarning {
			t.Errorf("cap_add alone should warn, got %s", f.Severity)
		}
	}
}

func TestBackupGapOnlyAppliesWhenThereIsDataToLose(t *testing.T) {
	in := baseInput()
	in.Manifest.Services = []model.ManifestService{{Name: "stateless"}}
	if findings := backupGap(in); len(findings) != 0 {
		t.Fatalf("a stateless stack needs no backup advice: %+v", findings)
	}

	in.Manifest.Services = []model.ManifestService{{
		Name:    "db",
		Volumes: []model.VolumeMount{{Kind: model.MountVolume, Source: "pgdata", Target: "/var/lib/postgresql/data"}},
	}}
	findings := backupGap(in)
	if len(findings) != 1 || findings[0].Severity != model.FindingWarning {
		t.Fatalf("persistent data with no backup must warn: %+v", findings)
	}

	// A stale backup directory is worse than none, and must still be reported.
	in.Caps.Backup = model.BackupPosture{
		Tools: []string{"restic"},
		Locations: []model.BackupLocation{{
			Path: "/backup", NewestFileAt: "2025-02-01T03:00:00Z", AgeDays: 562, FileCount: 12,
		}},
	}
	findings = backupGap(in)
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "stale") {
		t.Fatalf("a stale backup must be reported: %+v", findings)
	}
}

func TestCertificateExpiry(t *testing.T) {
	cases := []struct {
		days     int
		severity model.FindingSeverity
		present  bool
	}{
		{days: 89, present: false},
		{days: 25, severity: model.FindingWarning, present: true},
		{days: 3, severity: model.FindingBlocker, present: true},
		{days: -2, severity: model.FindingBlocker, present: true},
	}

	for _, tc := range cases {
		in := baseInput()
		in.Caps.Certificates = []model.Certificate{{
			Path: "/etc/letsencrypt/live/example.com/fullchain.pem",
			SANs: []string{"example.com"}, Issuer: "R3",
			NotAfter: fixedNow.AddDate(0, 0, tc.days).Format(time.RFC3339),
			DaysLeft: tc.days, Manager: "certbot",
		}}
		findings := certificateExpiry(in)
		if (len(findings) > 0) != tc.present {
			t.Fatalf("%d days left: got %d findings, want present = %v", tc.days, len(findings), tc.present)
		}
		if tc.present && findings[0].Severity != tc.severity {
			t.Errorf("%d days left: severity = %s, want %s", tc.days, findings[0].Severity, tc.severity)
		}
	}

	// A certificate whose file would not parse must never read as "no expiry".
	in := baseInput()
	in.Caps.Certificates = []model.Certificate{{Path: "/etc/ssl/broken.pem"}}
	if findings := certificateExpiry(in); len(findings) != 0 {
		t.Fatalf("an unparsed certificate must not produce an expiry claim: %+v", findings)
	}
}

// An installed renewal tool is not a renewal. The finding has to say which of the
// two it observed, because that is the difference between "fine" and "expires in
// three weeks and nobody is watching".
func TestCertificateFindingSeparatesToolFromSchedule(t *testing.T) {
	in := baseInput()
	in.Caps.Certificates = []model.Certificate{{
		Path: "/etc/letsencrypt/live/a/fullchain.pem", SANs: []string{"a.example.com"},
		NotAfter: fixedNow.AddDate(0, 0, 20).Format(time.RFC3339), DaysLeft: 20,
		Manager: "certbot", AutoRenew: false,
	}}
	findings := certificateExpiry(in)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Description, "no renewal job") {
		t.Errorf("the finding must distinguish the tool from the schedule: %q", findings[0].Description)
	}
}

func TestRollbackMarksWhatIsMissing(t *testing.T) {
	in := baseInput()
	in.Manifest.Services = []model.ManifestService{{
		Name:    "db",
		Image:   model.ImageRef{Raw: "postgres:16", Repository: "postgres", Tag: "16"},
		Volumes: []model.VolumeMount{{Kind: model.MountVolume, Source: "pgdata", Target: "/data"}},
	}}
	in.Caps.Containers = []model.Container{{
		Name: "app-db-1", Project: "app", Service: "db", Image: "postgres:15", State: "running",
	}}

	plan := Rollback(in)
	var unavailable int
	for _, item := range plan {
		if !item.Available {
			unavailable++
		}
	}
	if unavailable == 0 {
		t.Fatal("a host with no backup and no recorded digest must report an incomplete rollback plan")
	}

	// And the finding that reads the plan must fire.
	if !has(rollbackGap(in), "witness.no_rollback_plan") {
		t.Error("no_rollback_plan did not fire on an incomplete plan")
	}

	// The snapshot line must always be present and honest about what cannot be seen
	// from inside the machine.
	found := false
	for _, item := range plan {
		if item.Kind == "snapshot" {
			found = true
			if item.Available {
				t.Error("a snapshot cannot be confirmed from inside the host, so it must not be claimed as available")
			}
		}
	}
	if !found {
		t.Error("the rollback plan does not mention a host snapshot")
	}
}

func TestChangesNameEverythingSpecifically(t *testing.T) {
	in := baseInput()
	in.Manifest.Services = []model.ManifestService{{
		Name:  "web",
		Image: model.ImageRef{Raw: "ghcr.io/acme/web:1.2", Registry: "ghcr.io", Repository: "acme/web", Tag: "1.2"},
		Ports: []model.PortMapping{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		Volumes: []model.VolumeMount{
			{Kind: model.MountBind, Source: "/srv/app/data", Target: "/data"},
			{Kind: model.MountVolume, Source: "cache", Target: "/cache"},
		},
	}}
	in.Manifest.Networks = []model.ManifestNetwork{{Name: "app-net", Subnets: []string{"172.28.0.0/16"}}}

	changes := Changes(in)
	want := []string{
		"app-web-1",            // the container it will create
		"8080/tcp",             // the port it will open
		"/srv/app/data",        // the host path it will write to
		"ghcr.io/acme/web:1.2", // the image it will pull
		"network app-net",      // the network it will create
	}
	for _, target := range want {
		found := false
		for _, change := range changes {
			if change.Target == target {
				found = true
			}
		}
		if !found {
			t.Errorf("the change list does not mention %q: %+v", target, changes)
		}
	}
}

// busyHost is a machine where a great deal is already in the way. It exists so the
// completeness test above has many findings to inspect at once.
func busyHost() Input {
	in := baseInput()
	in.Caps.Arch = "aarch64"
	in.Caps.MemAvailableBytes = 1 << 30
	in.Caps.RebootRequired = "yes"
	in.Caps.Ports = []model.Port{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 443, State: "LISTEN", Pid: 900, Process: "nginx"},
		{Protocol: "tcp", Address: "127.0.0.1", Port: 5432, State: "LISTEN", Pid: 901, Process: "postgres"},
	}
	in.Caps.Proxy = &model.Proxy{
		Kind: "nginx", Version: "1.24.0", ConfigRoot: "/etc/nginx",
		ListenPorts: []int{80, 443},
		ServerNames: []model.ProxyServerName{
			{Name: "shop.example.com", File: "/etc/nginx/sites-enabled/shop", Line: 4},
		},
	}
	in.Caps.Panels = []model.Panel{{
		Name: "Plesk", Evidence: "/usr/local/psa", Running: true, OwnsPorts: []int{80, 443, 8443},
	}}
	in.Caps.Databases = []model.Database{{
		Kind: "postgres", Version: "15", Port: 5432, DataDir: "/var/lib/postgresql/15/main",
	}}
	in.Caps.Certificates = []model.Certificate{{
		Path: "/etc/letsencrypt/live/shop.example.com/fullchain.pem",
		SANs: []string{"shop.example.com"}, Issuer: "R3",
		NotAfter: fixedNow.AddDate(0, 0, 4).Format(time.RFC3339), DaysLeft: 4, Manager: "certbot",
	}}
	in.Caps.Filesystems = []model.Filesystem{{
		Mount: "/", Device: "/dev/sda1", FSType: "ext4",
		TotalBytes: 50 << 30, UsedBytes: 49 << 30, AvailableBytes: 1 << 29,
		InodesTotal: 1000000, InodesFree: 10000,
	}}
	in.Caps.Images = []model.ContainerImage{{
		Reference: "shop:latest", Architecture: "amd64", OS: "linux",
	}}
	in.Manifest.Services = []model.ManifestService{
		{
			Name:  "shop",
			Image: model.ImageRef{Raw: "shop:latest", Repository: "shop", Tag: "latest"},
			Ports: []model.PortMapping{{HostPort: 443, ContainerPort: 443, Protocol: "tcp"}},
			Labels: map[string]string{
				"traefik.http.routers.shop.rule": "Host(`shop.example.com`)",
			},
			EnvFiles:            []model.EnvFileRef{{Path: "/srv/app/.env", Exists: false}},
			MemReservationBytes: 4 << 30,
			Privileged:          true,
			Volumes: []model.VolumeMount{
				{Kind: model.MountBind, Source: "/etc", Target: "/host-etc"},
				{Kind: model.MountVolume, Source: "shopdata", Target: "/data"},
			},
		},
		{
			Name:    "db",
			Image:   model.ImageRef{Raw: "postgres:16", Repository: "postgres", Tag: "16"},
			Volumes: []model.VolumeMount{{Kind: model.MountBind, Source: "/var/lib/postgresql/15/main", Target: "/var/lib/postgresql/data"}},
		},
	}
	in.Manifest.Networks = []model.ManifestNetwork{{Name: "missing-net", External: true}}
	return in
}

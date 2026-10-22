package witness

import (
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

func socket(proto, addr string, port int, process string) model.Port {
	return model.Port{Protocol: proto, Address: addr, Port: port, State: "LISTEN", Pid: 9, Process: process}
}

// DW-86: a port number alone is never a conflict. Each case is a binding the plan
// asks for, what already holds the number, and the outcome the kernel would agree with.
func TestPortBindingsNotNumbers(t *testing.T) {
	v6 := func(only string) model.Port {
		p := socket("tcp6", "::", 8080, "java")
		p.V6Only = only
		return p
	}
	cases := []struct {
		name    string
		publish model.PortMapping
		held    []model.Port
		ipv6    string
		want    model.Outcome // "" = no finding at all
	}{
		{"tcp publish vs udp listener", model.PortMapping{HostPort: 53, ContainerPort: 53, Protocol: "tcp"},
			[]model.Port{socket("udp", "0.0.0.0", 53, "dnsmasq")}, "", ""},
		{"loopback publish vs another address", model.PortMapping{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80},
			[]model.Port{socket("tcp", "192.0.2.10", 8080, "nginx")}, "", ""},
		{"wildcard publish vs a specific address", model.PortMapping{HostPort: 8080, ContainerPort: 80},
			[]model.Port{socket("tcp", "192.0.2.10", 8080, "nginx")}, "", model.OutcomeProblem},
		{"IPv4 publish vs dual-stack [::] (ss: *)", model.PortMapping{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80},
			[]model.Port{v6("no")}, "", model.OutcomeProblem},
		{"IPv4 publish vs IPv6-only [::] (ss: [::])", model.PortMapping{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80},
			[]model.Port{v6("yes")}, "", ""},
		{"IPv4 publish vs [::] of unknown kind", model.PortMapping{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80},
			[]model.Port{v6("")}, "", model.OutcomeUnknown},
		{"no host_ip vs a specific IPv6 listener, IPv6 enabled", model.PortMapping{HostPort: 8080, ContainerPort: 80},
			[]model.Port{socket("tcp6", "2001:db8::5", 8080, "java")}, "enabled", model.OutcomeProblem},
		{"no host_ip vs a specific IPv6 listener, IPv6 unknown", model.PortMapping{HostPort: 8080, ContainerPort: 80},
			[]model.Port{socket("tcp6", "2001:db8::5", 8080, "java")}, "", model.OutcomeUnknown},
		{"container port is not a host port", model.PortMapping{HostPort: 18080, ContainerPort: 8080},
			[]model.Port{socket("tcp", "0.0.0.0", 8080, "java")}, "", ""},
		{"ephemeral publish never collides", model.PortMapping{ContainerPort: 8080},
			[]model.Port{socket("tcp", "0.0.0.0", 8080, "java")}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := cleanInput()
			in.Caps.IPv6 = tc.ipv6
			in.Manifest.Services[0].Ports = []model.PortMapping{tc.publish}
			in.Caps.Ports = tc.held
			findings := portConflicts(in)
			switch {
			case tc.want == "" && len(findings) > 0:
				t.Errorf("no finding expected, got %s: %s", findings[0].Outcome, findings[0].Description)
			case tc.want != "" && (len(findings) != 1 || findings[0].Outcome != tc.want):
				t.Errorf("want %s, got %+v", tc.want, findings)
			}
		})
	}
}

// DW-86: a host range published to one container port binds one free port of it.
func TestDynamicRange(t *testing.T) {
	in := cleanInput()
	in.Manifest.Services[0].Ports = []model.PortMapping{{HostPort: 8000, HostPortEnd: 8002, ContainerPort: 80, Protocol: "tcp"}}
	in.Caps.Ports = []model.Port{socket("tcp", "0.0.0.0", 8000, "a"), socket("tcp", "0.0.0.0", 8001, "b")}
	if f := portConflicts(in); len(f) != 0 {
		t.Errorf("8002 is free, so the range is not a conflict: %+v", f)
	}
	row, _ := changeFor(Changes(in), "firewall-port", "8000-8002/tcp")
	if !strings.Contains(row.Detail, "1 free, 2 held") {
		t.Errorf("change row = %+v", row)
	}

	in.Caps.Ports = append(in.Caps.Ports, socket("tcp", "0.0.0.0", 8002, "c"))
	f := portConflicts(in)
	if len(f) != 1 || f[0].Outcome != model.OutcomeProblem || f[0].Subject != "8000-8002/tcp" {
		t.Errorf("every port held is a conflict: %+v", f)
	}

	in.Caps.Ports[2] = socket("tcp6", "::", 8002, "c")
	f = portConflicts(in)
	if len(f) != 1 || f[0].Outcome != model.OutcomeUnknown {
		t.Errorf("one undecided port and none free is unknown: %+v", f)
	}
}

// DW-86: a service on the host network publishes nothing; it binds its declared
// ports itself.
func TestHostNetworkService(t *testing.T) {
	in := cleanInput()
	in.Manifest.Services[0].NetworkMode = "host"
	in.Manifest.Services[0].Ports = nil
	in.Manifest.Services[0].Expose = []int{9100}
	if f := portConflicts(in); len(f) != 0 {
		t.Errorf("nothing holds 9100: %+v", f)
	}
	in.Caps.Ports = []model.Port{socket("tcp", "0.0.0.0", 9100, "node_exporter")}
	if f := portConflicts(in); len(f) != 1 || f[0].Outcome != model.OutcomeProblem {
		t.Errorf("a wildcard holder blocks every address: %+v", f)
	}
	in.Caps.Ports = []model.Port{socket("tcp", "127.0.0.1", 9100, "node_exporter")}
	if f := portConflicts(in); len(f) != 1 || f[0].Outcome != model.OutcomeUnknown {
		t.Errorf("a specific holder depends on the application's address: %+v", f)
	}
	in.Manifest.Services[0].Expose = nil
	if f := portConflicts(in); len(f) != 1 || f[0].Outcome != model.OutcomeManualCheck {
		t.Errorf("no declared port is a manual check: %+v", f)
	}
}

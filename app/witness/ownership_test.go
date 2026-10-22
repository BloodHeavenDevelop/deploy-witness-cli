package witness

import (
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// DW-85: the four situations a port held by a container can be in, and what the
// planned run does about each — decided from Compose's own labels.
func TestOwnershipDecidesWhetherAHeldPortIsAConflict(t *testing.T) {
	published := []model.PortMapping{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}}
	cases := []struct {
		name      string
		container model.Container
		plan      func(*model.LaunchPlan)
		want      model.Outcome
		severity  model.FindingSeverity
		phrase    string
	}{
		{"routine update of this deployment",
			model.Container{Name: "app-web-1", Project: "app", Service: "web", WorkingDir: "/srv/app", ConfigHash: "old"},
			func(p *model.LaunchPlan) { p.ConfigHashes = map[string]string{"web": "new"} },
			model.OutcomeNoProblem, model.FindingInfo, "recreated: its configuration changed"},
		{"unchanged container of this deployment",
			model.Container{Name: "app-web-1", Project: "app", Service: "web", WorkingDir: "/srv/app", ConfigHash: "same"},
			func(p *model.LaunchPlan) { p.ConfigHashes = map[string]string{"web": "same"} },
			model.OutcomeNoProblem, model.FindingInfo, "kept: its configuration is unchanged"},
		{"a foreign project",
			model.Container{Name: "billing-api-1", Project: "billing", Service: "api", WorkingDir: "/srv/billing"},
			nil, model.OutcomeProblem, model.FindingBlocker, `Compose project "billing"`},
		{"this directory under its previous project name",
			model.Container{Name: "shop-web-1", Project: "shop", Service: "web", WorkingDir: "/srv/app"},
			nil, model.OutcomeProblem, model.FindingBlocker, "under another project name"},
		{"an orphan of this project, left running",
			model.Container{Name: "app-legacy-1", Project: "app", Service: "legacy", WorkingDir: "/srv/app"},
			nil, model.OutcomeProblem, model.FindingBlocker, "an orphan"},
		{"an orphan removed by --remove-orphans",
			model.Container{Name: "app-legacy-1", Project: "app", Service: "legacy", WorkingDir: "/srv/app"},
			func(p *model.LaunchPlan) { p.RemoveOrphans = true },
			model.OutcomeNoProblem, model.FindingInfo, "removed (--remove-orphans)"},
		{"a one-off run of this project",
			model.Container{Name: "app-web-run-1", Project: "app", Service: "web", WorkingDir: "/srv/app", OneOff: true},
			nil, model.OutcomeProblem, model.FindingBlocker, "one-off"},
		{"a parallel checkout with the same project name",
			model.Container{Name: "app-web-1", Project: "app", Service: "web", WorkingDir: "/home/dev/app"},
			nil, model.OutcomeNoProblem, model.FindingInfo, "taken over"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := cleanInput()
			planAt(&in, "/srv/app")
			if tc.plan != nil {
				tc.plan(in.Plan)
			}
			c := tc.container
			c.State, c.Labelled, c.Ports = "running", true, published
			in.Caps.Containers = []model.Container{c}
			in.Caps.Ports = []model.Port{{Protocol: "tcp", Address: "0.0.0.0", Port: 8080, State: "LISTEN", Process: "docker-proxy"}}

			f, ok := find(portConflicts(in), "witness.port_conflict")
			if !ok {
				t.Fatal("no port finding")
			}
			if f.Outcome != tc.want || f.Severity != tc.severity || !strings.Contains(f.Description, tc.phrase) {
				t.Errorf("%s/%s: %s", f.Outcome, f.Severity, f.Description)
			}

			// The change list agrees with the finding about whether the port opens.
			for _, change := range Changes(in) {
				if change.Kind == "firewall-port" && change.Target == "8080/tcp" {
					blocked := strings.HasPrefix(change.Detail, "not opened")
					if blocked != (tc.want == model.OutcomeProblem) {
						t.Errorf("firewall-port row disagrees with the finding: %s", change.Detail)
					}
				}
			}
		})
	}
}

// DW-85: a foreign container_name is a blocker; the deployment's own is not; and
// one whose labels the engine did not report is undecided.
func TestContainerNameOwnership(t *testing.T) {
	for _, tc := range []struct {
		container model.Container
		want      model.Outcome
	}{
		{model.Container{Name: "web", Project: "app", Service: "web", Labelled: true}, model.OutcomeNoProblem},
		{model.Container{Name: "web", Project: "app", Service: "worker", Labelled: true}, model.OutcomeProblem},
		{model.Container{Name: "web", Labelled: true}, model.OutcomeProblem},
		{model.Container{Name: "web"}, model.OutcomeUnknown},
	} {
		in := cleanInput()
		in.Manifest.Services[0].ContainerName = "web"
		in.Caps.Containers = []model.Container{tc.container}
		f, ok := find(containerNameConflicts(in), "witness.container_name_conflict")
		if !ok || f.Outcome != tc.want {
			t.Errorf("%+v: %+v", tc.container, f)
		}
	}
}

// DW-85: the change list says what Compose will do to each existing container.
func TestChangesFollowComposeActions(t *testing.T) {
	in := cleanInput()
	planAt(&in, "/srv/app")
	in.Plan.ConfigHashes = map[string]string{"web": "h2"}
	in.Caps.Containers = []model.Container{{Name: "app-web-1", Project: "app", Service: "web", WorkingDir: "/srv/app",
		ConfigHash: "h1", State: "running", Image: "nginx:old", Labelled: true}}
	row, ok := changeFor(Changes(in), "container", "app-web-1")
	if !ok || !strings.Contains(row.Detail, "replaced (currently running, image nginx:old)") ||
		!strings.Contains(row.Detail, "config hash h1 → h2") {
		t.Errorf("recreate: %+v", row)
	}

	in.Plan.ConfigHashes["web"] = "h1"
	row, _ = changeFor(Changes(in), "container", "app-web-1")
	if !strings.HasPrefix(row.Detail, "kept: its configuration is unchanged") {
		t.Errorf("keep: %+v", row)
	}

	in.Plan.NoRecreate, in.Plan.ConfigHashes = true, nil
	row, _ = changeFor(Changes(in), "container", "app-web-1")
	if !strings.HasPrefix(row.Detail, "kept as it is (--no-recreate)") {
		t.Errorf("--no-recreate: %+v", row)
	}
}

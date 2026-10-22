package witness

import (
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// DW-87: a volume is matched by its name in the engine, and presence, ownership and
// the completeness of the list are separate questions.
func TestVolumesByEngineName(t *testing.T) {
	mount := func(in *Input, vol model.ManifestVolume) {
		in.Manifest.Volumes = []model.ManifestVolume{vol}
		in.Manifest.Services[0].Volumes = []model.VolumeMount{{Kind: model.MountVolume, Source: vol.Name, Target: "/d"}}
		in.Caps.Runtime.EngineID, in.Caps.Runtime.EngineName = "ENGINE-A", "build-01"
	}
	cases := []struct {
		name     string
		vol      model.ManifestVolume
		existing []model.ContainerVolume
		failed   bool
		want     model.Outcome
		change   string
	}{
		{"not yet created by Compose", model.ManifestVolume{Name: "data", EngineName: "app_data"}, nil, false,
			"", "created empty by Compose"},
		{"this project's own", model.ManifestVolume{Name: "data", EngineName: "app_data"},
			[]model.ContainerVolume{{Name: "app_data", Project: "app"}}, false, "", "created by this project"},
		{"same name, not created by Compose", model.ManifestVolume{Name: "data", EngineName: "app_data"},
			[]model.ContainerVolume{{Name: "app_data"}}, false, model.OutcomeProblem, "not created by Compose"},
		{"a name: override matches the engine name, not the key", model.ManifestVolume{Name: "data", EngineName: "shared-pg"},
			[]model.ContainerVolume{{Name: "app_data", Project: "app"}, {Name: "shared-pg", Project: "billing"}}, false,
			model.OutcomeProblem, "not created by Compose for this project"},
		{"external, missing from a complete list", model.ManifestVolume{Name: "data", EngineName: "pg", External: true},
			nil, false, model.OutcomeProblem, "external and missing"},
		{"external, the engine refused to list volumes", model.ManifestVolume{Name: "data", EngineName: "pg", External: true},
			nil, true, model.OutcomeUnknown, "could not be listed"},
		{"external, present", model.ManifestVolume{Name: "data", EngineName: "pg", External: true},
			[]model.ContainerVolume{{Name: "pg"}}, false, "", "external, exists"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := cleanInput()
			mount(&in, tc.vol)
			in.Caps.ContainerVolumes = tc.existing
			if tc.failed {
				in.Caps.Observe(model.SourceVolumes, model.ObservedFailed, "docker volume ls: permission denied")
			}
			findings := volumeNameConflicts(in)
			switch {
			case tc.want == "" && len(findings) > 0:
				t.Errorf("no finding expected: %+v", findings)
			case tc.want != "" && (len(findings) != 1 || findings[0].Outcome != tc.want):
				t.Errorf("want %s: %+v", tc.want, findings)
			}
			if len(findings) == 1 && findings[0].Outcome == model.OutcomeProblem {
				last := findings[0].Evidence[len(findings[0].Evidence)-1]
				if !strings.Contains(last.Output, "engine ENGINE-A") {
					t.Errorf("the evidence must name the engine it came from: %+v", last)
				}
			}
			row, _ := changeFor(Changes(in), "file", "volume "+tc.vol.EngineName)
			if !strings.Contains(row.Detail, tc.change) {
				t.Errorf("change row = %q, want %q", row.Detail, tc.change)
			}
		})
	}
}

// DW-87: networks the same way, plus a swarm network a standalone container cannot
// join.
func TestNetworksByEngineName(t *testing.T) {
	cases := []struct {
		name     string
		net      model.ManifestNetwork
		existing []model.ContainerNetwork
		want     model.Outcome
	}{
		{"created by Compose", model.ManifestNetwork{Name: "back", EngineName: "app_back"}, nil, ""},
		{"exists, created for another project", model.ManifestNetwork{Name: "back", EngineName: "app_back"},
			[]model.ContainerNetwork{{Name: "app_back", Project: "old"}}, model.OutcomeProblem},
		{"external, attachable overlay", model.ManifestNetwork{Name: "edge", EngineName: "edge", External: true},
			[]model.ContainerNetwork{{Name: "edge", Scope: "swarm", Attachable: "yes", Project: "app"}}, ""},
		{"external, non-attachable overlay", model.ManifestNetwork{Name: "edge", EngineName: "edge", External: true},
			[]model.ContainerNetwork{{Name: "edge", Scope: "swarm", Attachable: "no"}}, model.OutcomeProblem},
		{"external overlay, attachability not read", model.ManifestNetwork{Name: "edge", EngineName: "edge", External: true},
			[]model.ContainerNetwork{{Name: "edge", Scope: "swarm"}}, model.OutcomeUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := cleanInput()
			in.Manifest.Networks = []model.ManifestNetwork{tc.net}
			in.Caps.ContainerNetworks = tc.existing
			findings := networkNameConflicts(in)
			switch {
			case tc.want == "" && len(findings) > 0:
				t.Errorf("no finding expected: %+v", findings)
			case tc.want != "" && (len(findings) != 1 || findings[0].Outcome != tc.want):
				t.Errorf("want %s: %+v", tc.want, findings)
			}
		})
	}
}

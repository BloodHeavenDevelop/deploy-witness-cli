package witness

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Changes and Rollback are the two sections that are not findings.
//
// A finding says something might go wrong. These two say what is about to happen
// and how to undo it, and they exist because that is the document somebody shows
// their own client when asked "what did you do to our server?". So they are
// specific: full paths, exact ports, named containers. A change list that says
// "configuration will be updated" is worth nothing to the person who has to answer
// for it.

// Changes describes what deploying this manifest will do to this host.
func Changes(in Input) []model.ChangeItem {
	if in.Manifest == nil {
		return nil
	}
	var out []model.ChangeItem

	// Containers, and whether each one replaces something.
	existing := map[string]model.Container{}
	for _, c := range in.Caps.Containers {
		existing[c.Name] = c
	}
	for _, svc := range in.Manifest.Services {
		name := svc.ContainerName
		if name == "" {
			name = fmt.Sprintf("%s-%s-1", normaliseProject(in.Project), svc.Name)
		}
		detail := fmt.Sprintf("created from %s", imageOrBuild(svc))
		if found, ok := existing[name]; ok {
			detail = fmt.Sprintf("replaced (currently %s, image %s) with %s",
				found.State, found.Image, imageOrBuild(svc))
		}
		out = append(out, model.ChangeItem{Kind: "container", Target: name, Detail: detail})
	}

	// Images that have to be pulled. Naming them is the difference between "images
	// will be downloaded" and a list somebody can check against a registry.
	present := map[string]bool{}
	for _, image := range in.Caps.Images {
		present[image.Reference] = true
	}
	for _, svc := range in.Manifest.Services {
		switch {
		case svc.Build != "":
			out = append(out, model.ChangeItem{
				Kind:   "command",
				Target: svc.Name,
				Detail: fmt.Sprintf("image built locally from %s", svc.Build),
			})
		case svc.Image.Raw != "" && !present[svc.Image.Raw]:
			out = append(out, model.ChangeItem{
				Kind:   "command",
				Target: svc.Image.Raw,
				Detail: "pulled from " + registryOf(svc.Image),
			})
		}
	}

	// Ports that will start listening, and how far they will be reachable. A port
	// published without a host IP is on every interface, which is the part people
	// do not expect.
	for _, svc := range in.Manifest.Services {
		for _, mapping := range svc.Ports {
			for _, port := range mapping.HostPorts() {
				reach := "all interfaces"
				if mapping.HostIP != "" {
					reach = mapping.HostIP
				}
				out = append(out, model.ChangeItem{
					Kind:   "firewall-port",
					Target: fmt.Sprintf("%d/%s", port, protocolOf(mapping)),
					Detail: fmt.Sprintf("opened by %s on %s → container port %d",
						svc.Name, reach, mapping.ContainerPort),
				})
			}
		}
	}

	// Filesystem paths that will be written to.
	for _, svc := range in.Manifest.Services {
		for _, mount := range svc.Volumes {
			switch mount.Kind {
			case model.MountBind:
				access := "read/write"
				if mount.ReadOnly {
					access = "read only"
				}
				out = append(out, model.ChangeItem{
					Kind:   "file",
					Target: mount.Source,
					Detail: fmt.Sprintf("bind-mounted into %s at %s (%s)", svc.Name, mount.Target, access),
				})
			case model.MountVolume:
				out = append(out, model.ChangeItem{
					Kind:   "file",
					Target: "volume " + mount.Source,
					Detail: fmt.Sprintf("mounted into %s at %s", svc.Name, mount.Target),
				})
			}
		}
	}

	// Networks.
	for _, network := range in.Manifest.Networks {
		if network.External {
			continue
		}
		detail := "created"
		if len(network.Subnets) > 0 {
			detail = "created with subnet " + strings.Join(network.Subnets, ", ")
		}
		out = append(out, model.ChangeItem{
			Kind:   "container",
			Target: "network " + network.Name,
			Detail: detail,
		})
	}

	// Disk space. The honest form: what is known, and that the rest is not.
	if target, ok := deploymentFilesystem(in); ok {
		var toPull []string
		for _, svc := range in.Manifest.Services {
			if svc.Build == "" && svc.Image.Raw != "" && !present[svc.Image.Raw] {
				toPull = append(toPull, svc.Image.Raw)
			}
		}
		detail := fmt.Sprintf("%s available before deploying; every image is already present",
			humanBytes(int64(target.AvailableBytes)))
		if len(toPull) > 0 {
			detail = fmt.Sprintf(
				"%s available before deploying; %d image(s) still to pull, whose size cannot be known without "+
					"contacting a registry",
				humanBytes(int64(target.AvailableBytes)), len(toPull))
		}
		out = append(out, model.ChangeItem{Kind: "disk-space", Target: target.Mount, Detail: detail})
	}

	sortChanges(out)
	return out
}

func imageOrBuild(svc model.ManifestService) string {
	if svc.Image.Raw != "" {
		return svc.Image.Raw
	}
	if svc.Build != "" {
		return "a local build of " + svc.Build
	}
	return "an unspecified image"
}

func registryOf(image model.ImageRef) string {
	if image.Registry != "" {
		return image.Registry
	}
	return "docker.io"
}

func sortChanges(items []model.ChangeItem) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Target < items[j].Target
	})
}

// Rollback states what would be needed to undo the deployment, and — the part that
// makes this section worth having — whether each of those things exists right now.
//
// `Available: false` is the interesting value. A rollback plan made of instructions
// nobody can follow is not a plan, and the finding that reads this section
// (witness.no_rollback_plan) exists because of exactly that.
func Rollback(in Input) []model.RollbackItem {
	if in.Manifest == nil {
		return nil
	}
	var out []model.RollbackItem

	// Returning to the images currently running requires knowing which they are, by
	// digest — a tag is not enough, because the tag is what moved.
	running := map[string]model.Container{}
	for _, c := range in.Caps.Containers {
		if sameProject(in, c.Project) {
			running[c.Service] = c
		}
	}
	digests := map[string]string{}
	for _, image := range in.Caps.Images {
		if image.Digest != "" {
			digests[image.Reference] = image.Digest
		}
	}

	for _, svc := range in.Manifest.Services {
		current, isRunning := running[svc.Name]
		switch {
		case !isRunning:
			out = append(out, model.RollbackItem{
				Kind:      "image-tag",
				Available: true,
				Detail: fmt.Sprintf("%s is not running here yet, so undoing it means removing it — "+
					"there is no previous version to return to", svc.Name),
			})
		case digests[current.Image] != "":
			out = append(out, model.RollbackItem{
				Kind:      "image-tag",
				Available: true,
				Detail: fmt.Sprintf("%s currently runs %s (%s); that digest is the version to return to",
					svc.Name, current.Image, digests[current.Image]),
			})
		default:
			out = append(out, model.RollbackItem{
				Kind:      "image-tag",
				Available: false,
				Detail: fmt.Sprintf("%s currently runs %s, and no digest for that image is recorded on this host — "+
					"after the deployment moves the tag there will be no way to name the version that worked",
					svc.Name, current.Image),
			})
		}
	}

	// The data. A volume can be restored only from a backup that exists.
	data := persistentData(in.Manifest)
	switch {
	case len(data) == 0:
		out = append(out, model.RollbackItem{
			Kind: "volume-backup", Available: true,
			Detail: "the deployment declares no persistent data, so there is nothing to restore",
		})
	case len(in.Caps.Backup.Locations) == 0:
		out = append(out, model.RollbackItem{
			Kind: "volume-backup", Available: false,
			Detail: fmt.Sprintf("the deployment writes to %s and no backup location was found on this host, "+
				"so a bad migration cannot be undone", strings.Join(data, ", ")),
		})
	default:
		fresh := false
		var newest string
		for _, location := range in.Caps.Backup.Locations {
			if location.NewestFileAt != "" && location.AgeDays <= backupStaleDays {
				fresh = true
				newest = fmt.Sprintf("%s (newest file %s)", location.Path, location.NewestFileAt)
				break
			}
		}
		if fresh {
			out = append(out, model.RollbackItem{
				Kind: "volume-backup", Available: true,
				Detail: "a recent backup exists at " + newest,
			})
		} else {
			out = append(out, model.RollbackItem{
				Kind: "volume-backup", Available: false,
				Detail: "backup directories exist but none has been written to recently, so restoring would " +
					"return the data to a state older than anyone expects",
			})
		}
	}

	// The web server configuration, when there is one to break.
	if in.Caps.Proxy != nil {
		out = append(out, model.RollbackItem{
			Kind: "proxy-config", Available: false,
			Detail: fmt.Sprintf("%s configuration under %s is not copied anywhere by this audit; "+
				"take a copy before changing it, since a proxy that fails to start takes every site on this host "+
				"down, not only the new one", in.Caps.Proxy.Kind, orUnknown(in.Caps.Proxy.ConfigRoot)),
		})
	}

	// A host-level snapshot is the one thing this tool cannot establish from inside
	// the machine, and saying so is better than omitting the line.
	out = append(out, model.RollbackItem{
		Kind: "snapshot", Available: false,
		Detail: "whether a hypervisor or provider snapshot of this host exists cannot be seen from inside it — " +
			"confirm with whoever runs the infrastructure before deploying",
	})

	return out
}

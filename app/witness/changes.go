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

	// Containers, and whether each one replaces something. Only a container of this
	// deployment's own Compose project is replaced: one that belongs to anything else
	// — another project, or a container created by hand, running or not — makes
	// `docker compose up` fail on the name, which is what the row has to say
	// (witness.container_name_conflict is the blocker for it).
	existing := map[string]model.Container{}
	for _, c := range in.Caps.Containers {
		existing[c.Name] = c
	}
	for _, svc := range in.Manifest.Services {
		name := svc.ContainerName
		if name == "" {
			name = fmt.Sprintf("%s-%s-1", normaliseProject(in.Project), svc.Name)
		}
		out = append(out, model.ChangeItem{Kind: "container", Target: name, Detail: containerChange(in, svc, name, existing)})
	}

	// The containers already there that the plan does not name but does affect: the
	// orphans of this project, another checkout's containers it takes over, and this
	// directory's containers under an older project name, which it leaves running.
	planned := map[string]bool{}
	for _, item := range out {
		planned[item.Target] = true
	}
	for _, c := range in.Caps.Containers {
		if planned[c.Name] {
			continue
		}
		owner := ownerOf(in, c)
		switch owner.kind {
		case ownOrphan, otherCheckout, renamedProject, ownOneOff:
			out = append(out, model.ChangeItem{Kind: "container", Target: c.Name, Detail: fmt.Sprintf(
				"%s — %s, currently %s (see witness.project_ownership)", owner.action, describeOwner(in, c), c.State)})
		}
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
				opened := fmt.Sprintf("opened by %s on %s → container port %d", svc.Name, reach, mapping.ContainerPort)
				switch state, holders := portState(in, mapping, port); state {
				case portTaken:
					opened = fmt.Sprintf("not opened: %s cannot bind it on %s, because it is already held by %s "+
						"(see witness.port_conflict)", svc.Name, reach, holders)
				case portMaybeTaken:
					opened += fmt.Sprintf(" — if the binding is free, which could not be established: %s "+
						"(see witness.port_conflict)", holders)
				case portUnchecked:
					opened += " — if the binding is free, which was not checked: the ports section was not " +
						"selected, so the listening sockets were not read"
				}
				out = append(out, model.ChangeItem{
					Kind:   "firewall-port",
					Target: fmt.Sprintf("%d/%s", port, protocolOf(mapping)),
					Detail: opened,
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

// containerChange is the change-list line for one service's container.
func containerChange(in Input, svc model.ManifestService, name string, existing map[string]model.Container) string {
	image := imageOrBuild(svc)
	if in.Caps.Runtime != nil && !in.Caps.Runtime.Reachable {
		return fmt.Sprintf("created from %s, unless a container named %s already exists — the container engine "+
			"did not answer, so that could not be checked", image, name)
	}
	if found, ok := existing[name]; ok {
		owner := ownerOf(in, found)
		switch {
		case owner.kind == ownService && (found.Service == "" || found.Service == svc.Name):
			if strings.HasPrefix(owner.action, "kept") {
				return fmt.Sprintf("%s (currently %s, image %s)", owner.action, found.State, found.Image)
			}
			detail := fmt.Sprintf("replaced (currently %s, image %s) with %s", found.State, found.Image, image)
			if in.Plan != nil {
				detail += " — " + owner.action
			}
			return detail
		case owner.kind == otherCheckout && found.Service == svc.Name:
			return fmt.Sprintf("%s (currently %s, image %s), replaced with %s (see witness.project_ownership)",
				owner.action, found.State, found.Image, image)
		case owner.kind == unlabelled:
			return fmt.Sprintf("created from %s only if the existing container named %s is this deployment's — "+
				"the engine reported no labels for it, so that could not be established", image, name)
		}
		return fmt.Sprintf("not created: a container named %s already exists (state %s, image %s, %s) and does "+
			"not belong to this deployment, so docker compose up fails on the name and leaves it as it is "+
			"(see witness.container_name_conflict)", name, found.State, found.Image, describeOwner(in, found))
	}

	detail := "created from " + image
	var blocked []string
	for _, mapping := range svc.Ports {
		for _, port := range mapping.HostPorts() {
			if state, _ := portState(in, mapping, port); state == portTaken {
				blocked = append(blocked, fmt.Sprintf("%d/%s", port, protocolOf(mapping)))
			}
		}
	}
	if len(blocked) > 0 {
		detail += fmt.Sprintf(", but it cannot start: host port %s is already held (see witness.port_conflict)",
			strings.Join(blocked, ", "))
	}
	return detail
}

type portAvailability int

const (
	portFree portAvailability = iota
	portMaybeTaken
	portTaken
	portUnchecked
)

// portState answers, for the change list, the question witness.port_conflict
// answers for the findings — with the same matching, so the two never disagree.
// A binding held by this deployment's own container is free for this purpose:
// Compose stops that container first.
func portState(in Input, mapping model.PortMapping, port int) (portAvailability, string) {
	want := claimFromMapping(mapping, port)
	if !observableProtocol(want.protocol) {
		return portFree, ""
	}
	holders := portHolders(in, want)
	if len(holders) == 0 {
		if in.PortsUnchecked {
			return portUnchecked, ""
		}
		return portFree, ""
	}
	own := ownHolder(in, holders)
	certain := certainHolders(holders)
	switch {
	case len(certain) > 0 && (own == nil || foreignContainer(in, certain)) && !ownershipKnown(in, certain):
		return portMaybeTaken, describeHolders(in, certain) + " — which may be this deployment's own container: the " +
			"engine's containers were not listed"
	case len(certain) > 0 && (own == nil || foreignContainer(in, certain)):
		return portTaken, describeHolders(in, certain)
	case own != nil:
		return portFree, ""
	default:
		return portMaybeTaken, describeHolders(in, holders)
	}
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

// unverifiedPrefix opens the detail of every rollback item that could not be
// verified, so the boolean the contract carries is not the only signal.
const unverifiedPrefix = "unable to verify: "

// Rollback states what would be needed to undo the deployment, and — the part that
// makes this section worth having — whether each of those things exists right now.
//
// Each item is available, unavailable or unable-to-verify. `unavailable` is the
// interesting value: a rollback plan made of instructions nobody can follow is not a
// plan, and the finding that reads this section (witness.no_rollback_plan) exists
// because of exactly that. `unable-to-verify` is kept apart from it on purpose: a
// provider snapshot or an off-host copy of a configuration cannot be seen from inside
// the machine, and reporting what cannot be seen as missing would be a claim the
// audit has no evidence for.
func Rollback(in Input) []model.RollbackItem {
	if in.Manifest == nil {
		return nil
	}
	var out []model.RollbackItem

	// Returning to the images currently running requires knowing which they are, by
	// digest — a tag is not enough, because the tag is what moved.
	running := map[string]model.Container{}
	for _, c := range in.Caps.Containers {
		if ownerOf(in, c).kind == ownService {
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
			out = append(out, model.NewRollbackItem("image-tag", model.RollbackAvailable, fmt.Sprintf(
				"%s is not running here yet, so undoing it means removing it — "+
					"there is no previous version to return to", svc.Name)))
		case digests[current.Image] != "":
			out = append(out, model.NewRollbackItem("image-tag", model.RollbackAvailable, fmt.Sprintf(
				"%s currently runs %s (%s); that digest is the version to return to",
				svc.Name, current.Image, digests[current.Image])))
		default:
			out = append(out, model.NewRollbackItem("image-tag", model.RollbackUnavailable, fmt.Sprintf(
				"%s currently runs %s, and no digest for that image is recorded on this host — "+
					"after the deployment moves the tag there will be no way to name the version that worked",
				svc.Name, current.Image)))
		}
	}

	// The data. A volume can be restored only from a backup that exists.
	data := persistentData(in.Manifest)
	switch {
	case len(data) == 0:
		out = append(out, model.NewRollbackItem("volume-backup", model.RollbackAvailable,
			"the deployment declares no persistent data, so there is nothing to restore"))
	case len(in.Caps.Backup.Locations) == 0:
		out = append(out, model.NewRollbackItem("volume-backup", model.RollbackUnavailable, fmt.Sprintf(
			"the deployment writes to %s and no backup location was found on this host, "+
				"so a bad migration cannot be undone from here", strings.Join(data, ", "))))
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
			out = append(out, model.NewRollbackItem("volume-backup", model.RollbackAvailable,
				"a recent backup exists at "+newest))
		} else {
			out = append(out, model.NewRollbackItem("volume-backup", model.RollbackUnavailable,
				"backup directories exist but none has been written to recently, so restoring would "+
					"return the data to a state older than anyone expects"))
		}
	}

	// The web server configuration, when there is one to break. Whether somebody
	// keeps a copy of it elsewhere is not something this host can show.
	if in.Caps.Proxy != nil {
		out = append(out, model.NewRollbackItem("proxy-config", model.RollbackUnverified, fmt.Sprintf(
			unverifiedPrefix+"whether a copy of the %s configuration under %s is kept outside this host cannot "+
				"be seen from inside it; take one before changing it, since a proxy that fails to start takes "+
				"every site on this host down, not only the new one",
			in.Caps.Proxy.Kind, orUnknown(in.Caps.Proxy.ConfigRoot))))
	}

	// A host-level snapshot is the one thing this tool cannot establish from inside
	// the machine, and saying so is better than omitting the line — or than calling
	// it missing.
	out = append(out, model.NewRollbackItem("snapshot", model.RollbackUnverified,
		unverifiedPrefix+"whether a hypervisor or provider snapshot of this host exists cannot be seen from "+
			"inside it — confirm with whoever runs the infrastructure before deploying"))

	return out
}

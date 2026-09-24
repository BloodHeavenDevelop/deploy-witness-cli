package witness

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// The six conflict rules: two things claiming the same name, port, path or address
// range. They share one shape — for each thing the manifest asks for, is somebody
// already holding it? — and one caveat: the previous version of this very deployment
// holds all of them, and saying so is not a conflict.

// 1. witness.port_conflict
//
// The comparison is between bindings, not port numbers — see portmatch.go. Each
// published host port produces at most one finding, so a container of this
// deployment that is also visible as a raw socket (its own docker-proxy) is
// stated once, not twice.
func portConflicts(in Input) []model.Finding {
	var out []model.Finding

	for _, svc := range in.Manifest.Services {
		for _, mapping := range svc.Ports {
			for _, port := range mapping.HostPorts() {
				want := claimFromMapping(mapping, port)
				if !observableProtocol(want.protocol) {
					out = append(out, unobservableProtocol(in, svc, mapping, want))
					continue
				}
				holders := portHolders(in, want)
				if len(holders) == 0 {
					continue
				}
				out = append(out, portConflictFinding(in, svc, mapping, want, holders))
			}
		}
	}
	return out
}

// portHolder is one thing already bound to the binding a service asks for.
type portHolder struct {
	overlap   overlap
	why       string // why the overlap is unknown; empty when it is certain
	claim     portClaim
	container model.Container
	socket    model.Port
	isSocket  bool
}

// portHolders collects everything that overlaps the wanted binding. Containers
// come first: they carry the project label a raw socket does not, and the raw
// socket behind a published port is the container's own proxy.
func portHolders(in Input, want portClaim) []portHolder {
	var out []portHolder

	for _, container := range in.Caps.Containers {
		best := portHolder{container: container}
		for _, mapping := range container.Ports {
			for _, port := range mapping.HostPorts() {
				held := claimFromMapping(mapping, port)
				result, why := collides(want, held)
				if result > best.overlap {
					best.overlap, best.why, best.claim = result, why, held
				}
			}
		}
		if best.overlap != overlapNone {
			out = append(out, best)
		}
	}

	for _, socket := range in.Caps.Ports {
		held := claimFromSocket(socket)
		result, why := collides(want, held)
		if result == overlapNone {
			continue
		}
		out = append(out, portHolder{
			overlap: result, why: why, claim: held, socket: socket, isSocket: true,
		})
	}
	return out
}

func portConflictFinding(
	in Input, svc model.ManifestService, mapping model.PortMapping, want portClaim, holders []portHolder,
) model.Finding {
	finding := model.Finding{
		Code:       "witness.port_conflict",
		Category:   model.CategoryConflict,
		Subject:    want.subject(),
		Confidence: model.ConfidenceHigh,
		SortOrder:  want.port,
		Evidence: []model.Evidence{
			manifestEvidence(in, svc.Name, fmt.Sprintf(
				"ports: publishes host %s → container port %d", want.describe(), mapping.ContainerPort)),
		},
	}

	own := ownHolder(in, holders)
	certain := certainHolders(holders)
	// A container belonging to somebody else outranks "our own container": both
	// cannot hold the binding at once, so the other one is stopped and the new
	// deployment still cannot have it.
	blocked := len(certain) > 0 && (own == nil || foreignContainer(in, certain))

	switch {
	case blocked:
		// Something unrelated holds the binding, and the tool is sure of it.
		finding.Severity = model.FindingBlocker
		finding.Title = fmt.Sprintf("Port %d is already in use", want.port)
		finding.Description = fmt.Sprintf(
			"Service %q publishes %s, and that binding is already held on this host by %s.",
			svc.Name, want.describe(), describeHolders(certain))
		finding.WhyItMatters = "The container will fail to start: the engine cannot bind a port another " +
			"process already holds. On a deployment that stops the old stack first, the failure lands after " +
			"the old one is already down."
		finding.WhatToDo = fmt.Sprintf(
			"Publish a different host port for %q, or stop whatever currently holds %d before deploying.",
			svc.Name, want.port)
		finding.Evidence = append(finding.Evidence, holderEvidence(in, certain)...)

	case own != nil:
		// The deployment's own previous container. Compose stops it before
		// starting the new one, so this is not an obstacle — but it is worth
		// stating, because "the port is in use" is what the reader would
		// otherwise see in the engine's error.
		container := own.container
		holds := "is currently published by"
		if own.overlap == overlapUnknown {
			holds = "may be published by"
		}
		finding.Severity = model.FindingInfo
		finding.Title = fmt.Sprintf("Port %d is held by this deployment's own container", want.port)
		finding.Description = fmt.Sprintf(
			"Host %s %s container %q, which belongs to the same Compose "+
				"project (%s). Deploying replaces it.", want.describe(), holds, container.Name, container.Project)
		finding.WhyItMatters = "Nothing is blocked. This line exists so that the engine's " +
			"\"port is already allocated\" message, if it appears, is not mistaken for a conflict with an " +
			"unrelated service."
		finding.WhatToDo = "No action needed."
		finding.Evidence = append(finding.Evidence, holderEvidence(in, []portHolder{*own})...)

	default:
		// Only unknown holders. The binding may or may not be taken, and which one
		// it is depends on host configuration this tool deliberately does not read.
		// A warning that names the command settling it is the honest answer; a
		// blocker here is the false blocker, and silence is the dishonest one.
		finding.Severity = model.FindingWarning
		finding.Confidence = model.ConfidenceMedium
		finding.Title = fmt.Sprintf("Port %d may already be in use — this could not be established", want.port)
		finding.Description = fmt.Sprintf(
			"Service %q publishes %s. Something is bound to that port on this host — %s — and whether the two "+
				"bindings actually overlap could not be decided offline. %s",
			svc.Name, want.describe(), describeHolders(holders), unknownReasons(holders))
		finding.WhyItMatters = "If they do overlap the container will not start, and the failure lands during " +
			"the deployment rather than before it. This is reported as an open question rather than a blocker " +
			"because stopping a deployment that would have worked is the more expensive mistake of the two."
		finding.WhatToDo = fmt.Sprintf(
			"Settle it before deploying: `ss -lntup | grep ':%d '` shows the protocol and address of everything "+
				"on that port, and `cat /proc/sys/net/ipv6/bindv6only` says whether an IPv6 wildcard also answers "+
				"IPv4 (0 means it does). If the binding is taken, publish a different host port for %q.",
			want.port, svc.Name)
		finding.Evidence = append(finding.Evidence, holderEvidence(in, holders)...)
	}
	return finding
}

// unobservableProtocol is the finding for a publish this tool cannot check at
// all. It is never silence: an unchecked port reported as clean is exactly the
// result the second promise forbids.
func unobservableProtocol(in Input, svc model.ManifestService, mapping model.PortMapping, want portClaim) model.Finding {
	return model.Finding{
		Code:       "witness.port_conflict",
		Category:   model.CategoryConflict,
		Subject:    want.subject(),
		Severity:   model.FindingWarning,
		Confidence: model.ConfidenceLow,
		SortOrder:  want.port,
		Title:      fmt.Sprintf("Port %d/%s was not checked for conflicts", want.port, want.protocol),
		Description: fmt.Sprintf(
			"Service %q publishes %s. This tool reads listening sockets from /proc/net/tcp, /proc/net/tcp6, "+
				"/proc/net/udp and /proc/net/udp6, and the kernel publishes no such table for %s, so whether "+
				"anything already holds that binding is unknown.",
			svc.Name, want.describe(), want.protocol),
		WhyItMatters: "A port that was not looked at is not a port that is free. Reporting it as clean would " +
			"hide the one case this section exists to catch.",
		WhatToDo: fmt.Sprintf(
			"Check by hand before deploying — `ss -lna | grep ':%d '` covers protocols /proc/net does not.",
			want.port),
		Evidence: []model.Evidence{
			manifestEvidence(in, svc.Name, fmt.Sprintf(
				"ports: publishes host %s → container port %d", want.describe(), mapping.ContainerPort)),
			evidence(in, "/proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6", fmt.Sprintf(
				"%d listening sockets read, none of them %s: the kernel has no %s socket table here",
				len(in.Caps.Ports), want.protocol, want.protocol)),
		},
	}
}

// ownHolder returns the holder that is this deployment's own container, if any.
// It is consulted before the certain holders because a published port's raw
// socket belongs to that same container's proxy and carries no project label.
func ownHolder(in Input, holders []portHolder) *portHolder {
	for i, h := range holders {
		if !h.isSocket && sameProject(in, h.container.Project) {
			return &holders[i]
		}
	}
	return nil
}

func certainHolders(holders []portHolder) []portHolder {
	var out []portHolder
	for _, h := range holders {
		if h.overlap == overlapYes {
			out = append(out, h)
		}
	}
	return out
}

// foreignContainer reports whether one of the holders is a container belonging to
// something other than this deployment — the case where a blocker outranks the
// "our own container" reading.
func foreignContainer(in Input, holders []portHolder) bool {
	for _, h := range holders {
		if !h.isSocket && !sameProject(in, h.container.Project) {
			return true
		}
	}
	return false
}

func unknownReasons(holders []portHolder) string {
	var out []string
	for _, h := range holders {
		if h.overlap != overlapUnknown || h.why == "" {
			continue
		}
		if !contains(out, h.why) {
			out = append(out, h.why)
		}
	}
	return strings.Join(out, " ")
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func describeHolders(holders []portHolder) string {
	var parts []string
	for _, h := range holders {
		parts = append(parts, describeHolder(h))
	}
	if len(parts) == 0 {
		return "another process"
	}
	return strings.Join(parts, "; ")
}

func describeHolder(h portHolder) string {
	if !h.isSocket {
		return fmt.Sprintf("container %q (project %s), publishing %s",
			h.container.Name, h.container.Project, h.claim.describe())
	}
	s := h.socket
	switch {
	case s.Process != "" && s.Pid > 0:
		return fmt.Sprintf("%s (pid %d), listening on %s", s.Process, s.Pid, h.claim.describe())
	case s.Process != "":
		return fmt.Sprintf("%s, listening on %s", s.Process, h.claim.describe())
	default:
		// The socket exists but could not be attributed. Saying "an unidentified
		// process" is the honest form: running unprivileged, /proc hides the owner
		// of somebody else's socket, and naming a guess would be worse than naming
		// nothing.
		return fmt.Sprintf("an unidentified process listening on %s (the owner is only visible to root)",
			h.claim.describe())
	}
}

// holderEvidence returns at most two captures — one for the containers among the
// holders and one for the sockets — because they come from two different
// observations and a finding must not attribute one to the other.
func holderEvidence(in Input, holders []portHolder) []model.Evidence {
	var containers, sockets []string
	for _, h := range holders {
		if h.isSocket {
			sockets = append(sockets, fmt.Sprintf("%s %s:%d %s pid=%d process=%s",
				h.socket.Protocol, h.socket.Address, h.socket.Port, h.socket.State, h.socket.Pid, h.socket.Process))
			continue
		}
		containers = append(containers, fmt.Sprintf("container %s (project %s, service %s) state %s, publishing %s",
			h.container.Name, h.container.Project, h.container.Service, h.container.State,
			renderPorts(h.container.Ports)))
	}

	var out []model.Evidence
	if len(containers) > 0 {
		out = append(out, evidence(in, "docker ps -a --format {{json .}}", strings.Join(containers, "\n")))
	}
	if len(sockets) > 0 {
		out = append(out, evidence(in, "ss -lntupH", strings.Join(sockets, "\n")))
	}
	return out
}

func protocolOf(mapping model.PortMapping) string {
	if mapping.Protocol == "" {
		return "tcp"
	}
	return mapping.Protocol
}

func renderPorts(mappings []model.PortMapping) string {
	var parts []string
	for _, m := range mappings {
		host := fmt.Sprint(m.HostPort)
		if m.HostIP != "" {
			host = m.HostIP + ":" + host
		}
		parts = append(parts, fmt.Sprintf("%s→%d/%s", host, m.ContainerPort, protocolOf(m)))
	}
	return strings.Join(parts, ", ")
}

// 2. witness.container_name_conflict
func containerNameConflicts(in Input) []model.Finding {
	var out []model.Finding

	existing := map[string]model.Container{}
	for _, c := range in.Caps.Containers {
		existing[c.Name] = c
	}

	for _, svc := range in.Manifest.Services {
		if svc.ContainerName == "" {
			continue
		}
		found, ok := existing[svc.ContainerName]
		if !ok {
			continue
		}

		finding := model.Finding{
			Code:       "witness.container_name_conflict",
			Category:   model.CategoryConflict,
			Subject:    svc.ContainerName,
			Confidence: model.ConfidenceHigh,
			Evidence: []model.Evidence{
				manifestEvidence(in, svc.Name, "container_name: "+svc.ContainerName),
				evidence(in, "docker ps -a --format {{json .}}", fmt.Sprintf(
					"container %s exists: image %s, state %s, project %q",
					found.Name, found.Image, found.State, found.Project)),
			},
		}

		if sameProject(in, found.Project) {
			finding.Severity = model.FindingInfo
			finding.Title = fmt.Sprintf("Container %q already exists and belongs to this deployment", svc.ContainerName)
			finding.Description = fmt.Sprintf(
				"A container named %q is present and carries this deployment's own project label. Deploying replaces it.",
				svc.ContainerName)
			finding.WhyItMatters = "Nothing is blocked."
			finding.WhatToDo = "No action needed."
			out = append(out, finding)
			continue
		}

		finding.Severity = model.FindingBlocker
		finding.Title = fmt.Sprintf("Container name %q is taken", svc.ContainerName)
		finding.Description = fmt.Sprintf(
			"Service %q fixes its container name to %q with container_name, and a container of that name already "+
				"exists on this host (image %s, state %s, project %q).",
			svc.Name, svc.ContainerName, found.Image, found.State, found.Project)
		finding.WhyItMatters = "Container names are unique per engine. The deployment will fail outright, and " +
			"an explicit container_name is precisely the case Compose cannot work around by prefixing the project name."
		finding.WhatToDo = fmt.Sprintf(
			"Drop container_name from %q and let Compose name it, or rename it to something unused. "+
				"Do not remove the existing container without establishing what it belongs to.", svc.Name)
		out = append(out, finding)
	}
	return out
}

// 3. witness.volume_name_conflict
func volumeNameConflicts(in Input) []model.Finding {
	var out []model.Finding

	existing := map[string]model.ContainerVolume{}
	for _, v := range in.Caps.ContainerVolumes {
		existing[v.Name] = v
	}

	for _, vol := range in.Manifest.Volumes {
		// Compose prefixes a project's volumes with the project name, so a plain
		// declaration cannot collide with an unrelated stack. An `external: true`
		// volume is referenced by its literal name, which can.
		if !vol.External {
			continue
		}
		found, ok := existing[vol.Name]

		finding := model.Finding{
			Code:       "witness.volume_name_conflict",
			Category:   model.CategoryConflict,
			Subject:    vol.Name,
			Confidence: model.ConfidenceHigh,
			Evidence: []model.Evidence{
				manifestEvidence(in, "", fmt.Sprintf("volumes: %s declared external", vol.Name)),
			},
		}

		if !ok {
			finding.Severity = model.FindingBlocker
			finding.Title = fmt.Sprintf("External volume %q does not exist", vol.Name)
			finding.Description = fmt.Sprintf(
				"The manifest declares volume %q as external, which means Compose expects it to exist already. "+
					"It is not present on this host.", vol.Name)
			finding.WhyItMatters = "Compose refuses to start a stack whose external volume is missing. It will not " +
				"create it for you — that is what declaring it external asks for."
			finding.WhatToDo = fmt.Sprintf(
				"Create the volume before deploying, or remove `external: true` so Compose manages %q itself.", vol.Name)
			finding.Evidence = append(finding.Evidence, evidence(in, "docker volume ls --format {{json .}}",
				fmt.Sprintf("no volume named %s among the %d volumes on this host", vol.Name, len(in.Caps.ContainerVolumes))))
			out = append(out, finding)
			continue
		}

		if sameProject(in, found.Project) {
			continue
		}

		finding.Severity = model.FindingWarning
		finding.Title = fmt.Sprintf("External volume %q already holds somebody else's data", vol.Name)
		finding.Description = fmt.Sprintf(
			"Volume %q exists, mounted at %s, and carries project label %q — not this deployment's. "+
				"Deploying will attach it to the new containers.", vol.Name, found.Mountpoint, found.Project)
		finding.WhyItMatters = "This does not fail. It succeeds, and the new service starts on top of existing " +
			"data belonging to something else — which is worse, because nothing announces it."
		finding.WhatToDo = fmt.Sprintf(
			"Confirm that reusing %q is intended. If it is not, pick a different volume name.", vol.Name)
		finding.Evidence = append(finding.Evidence, evidence(in, "docker volume ls --format {{json .}}",
			fmt.Sprintf("volume %s driver=%s mountpoint=%s project=%q",
				found.Name, found.Driver, found.Mountpoint, found.Project)))
		out = append(out, finding)
	}
	return out
}

// 4. witness.bind_path_conflict
func bindPathConflicts(in Input) []model.Finding {
	var out []model.Finding

	// Bind mounts already in use by existing containers cannot be read from
	// `docker ps`, so the comparison here is against the host filesystem: does the
	// path exist, is it non-empty, and is it somewhere that should not be mounted.
	for _, svc := range in.Manifest.Services {
		for _, mount := range svc.Volumes {
			if mount.Kind != model.MountBind {
				continue
			}
			source := mount.Source
			if !strings.HasPrefix(source, "/") {
				// A relative bind is resolved against the compose file's directory;
				// it is reported as-is rather than guessed at.
				continue
			}

			if sensitive := sensitiveHostPath(source); sensitive != "" {
				out = append(out, model.Finding{
					Code:       "witness.bind_path_conflict",
					Category:   model.CategoryConflict,
					Subject:    source,
					Severity:   model.FindingWarning,
					Confidence: model.ConfidenceHigh,
					SortOrder:  1,
					Title:      fmt.Sprintf("Bind mount of %s exposes host state", source),
					Description: fmt.Sprintf(
						"Service %q bind-mounts %s into the container at %s. %s",
						svc.Name, source, mount.Target, sensitive),
					WhyItMatters: "A bind mount is not a copy. The container writes straight into the host path, " +
						"and anything that goes wrong inside it goes wrong on the host.",
					WhatToDo: fmt.Sprintf(
						"Mount a dedicated directory instead of %s, or add `:ro` if the service only needs to read it.",
						source),
					Evidence: []model.Evidence{
						manifestEvidence(in, svc.Name, fmt.Sprintf("volumes: %s:%s%s",
							source, mount.Target, readOnlySuffix(mount))),
					},
				})
			}
		}
	}
	return out
}

func readOnlySuffix(mount model.VolumeMount) string {
	if mount.ReadOnly {
		return ":ro"
	}
	return ""
}

// sensitiveHostPath explains why a bind source is a poor idea, or returns "".
//
// The list is short on purpose: each entry is a path where a container writing
// through the mount changes how the host itself behaves.
func sensitiveHostPath(path string) string {
	clean := filepath.Clean(path)
	switch {
	case clean == "/":
		return "That is the whole root filesystem."
	case clean == "/etc" || strings.HasPrefix(clean, "/etc/"):
		return "That is host configuration."
	case clean == "/var/run" || clean == "/run" || strings.HasSuffix(clean, "docker.sock") ||
		strings.HasSuffix(clean, "podman.sock"):
		return "That is the container runtime's own socket, which is equivalent to root on the host."
	case clean == "/home" || clean == "/root":
		return "That is somebody's home directory."
	case clean == "/var/lib/docker" || strings.HasPrefix(clean, "/var/lib/docker/"):
		return "That is the engine's own storage; writing into it corrupts the engine's view of its images and layers."
	case clean == "/sys" || strings.HasPrefix(clean, "/sys/") || clean == "/proc" || strings.HasPrefix(clean, "/proc/"):
		return "That is a kernel interface."
	}
	return ""
}

// 5. witness.network_name_conflict
func networkNameConflicts(in Input) []model.Finding {
	var out []model.Finding

	existing := map[string]model.ContainerNetwork{}
	for _, n := range in.Caps.ContainerNetworks {
		existing[n.Name] = n
	}

	for _, network := range in.Manifest.Networks {
		if !network.External {
			continue
		}
		found, ok := existing[network.Name]

		finding := model.Finding{
			Code:       "witness.network_name_conflict",
			Category:   model.CategoryConflict,
			Subject:    network.Name,
			Confidence: model.ConfidenceHigh,
			Evidence: []model.Evidence{
				manifestEvidence(in, "", fmt.Sprintf("networks: %s declared external", network.Name)),
			},
		}

		if !ok {
			finding.Severity = model.FindingBlocker
			finding.Title = fmt.Sprintf("External network %q does not exist", network.Name)
			finding.Description = fmt.Sprintf(
				"The manifest expects network %q to exist already. It is not present on this host.", network.Name)
			finding.WhyItMatters = "Compose will not create an external network, and refuses to start without it."
			finding.WhatToDo = fmt.Sprintf(
				"Create %q before deploying, or drop `external: true` so Compose manages it.", network.Name)
			finding.Evidence = append(finding.Evidence, evidence(in, "docker network ls --format {{json .}}",
				fmt.Sprintf("no network named %s among the %d networks on this host",
					network.Name, len(in.Caps.ContainerNetworks))))
			out = append(out, finding)
			continue
		}

		if sameProject(in, found.Project) {
			continue
		}

		finding.Severity = model.FindingInfo
		finding.Title = fmt.Sprintf("External network %q is shared with another stack", network.Name)
		finding.Description = fmt.Sprintf(
			"Network %q exists (driver %s, project %q) and this deployment will join it.",
			network.Name, found.Driver, found.Project)
		finding.WhyItMatters = "Containers on a shared network can reach each other by name. That is often the " +
			"intent; it also means a service here is reachable from whatever else is on that network."
		finding.WhatToDo = "Confirm the sharing is intended."
		finding.Evidence = append(finding.Evidence, evidence(in, "docker network ls --format {{json .}}",
			fmt.Sprintf("network %s driver=%s subnets=%s project=%q",
				found.Name, found.Driver, strings.Join(found.Subnets, ", "), found.Project)))
		out = append(out, finding)
	}
	return out
}

// 6. witness.subnet_overlap
func subnetOverlaps(in Input) []model.Finding {
	var out []model.Finding

	for _, network := range in.Manifest.Networks {
		for _, cidr := range network.Subnets {
			_, want, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			for _, existing := range in.Caps.ContainerNetworks {
				if sameProject(in, existing.Project) {
					continue
				}
				for _, existingCIDR := range existing.Subnets {
					_, have, err := net.ParseCIDR(existingCIDR)
					if err != nil {
						continue
					}
					if !networksOverlap(want, have) {
						continue
					}
					out = append(out, model.Finding{
						Code:       "witness.subnet_overlap",
						Category:   model.CategoryConflict,
						Subject:    cidr,
						Severity:   model.FindingBlocker,
						Confidence: model.ConfidenceHigh,
						Title:      fmt.Sprintf("Subnet %s overlaps an existing network", cidr),
						Description: fmt.Sprintf(
							"Network %q asks for %s, which overlaps %s already used by the existing network %q.",
							network.Name, cidr, existingCIDR, existing.Name),
						WhyItMatters: "The engine refuses to create a network whose address range overlaps one it " +
							"already has. When it does create it, routing between the two becomes ambiguous and the " +
							"symptom appears later, as traffic reaching the wrong container.",
						WhatToDo: fmt.Sprintf(
							"Choose a range outside %s for %q, or reuse the existing network instead of declaring a new one.",
							existingCIDR, network.Name),
						Evidence: []model.Evidence{
							manifestEvidence(in, "", fmt.Sprintf("networks.%s.ipam: subnet %s", network.Name, cidr)),
							evidence(in, "docker network inspect "+existing.Name+" --format {{json .IPAM}}",
								fmt.Sprintf("network %s uses %s", existing.Name, existingCIDR)),
						},
					})
				}
			}
		}
	}
	return out
}

// networksOverlap reports whether two CIDR ranges intersect at all — either one
// containing the other's base address is enough, which is the whole condition for
// two prefixes.
func networksOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

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
		if svc.NetworkMode == "host" {
			// No publish at all: the container shares the host's network stack, the
			// engine discards `ports:`, and the application binds what it binds.
			out = append(out, hostNetworkPorts(in, svc)...)
			continue
		}
		for _, mapping := range svc.Ports {
			if mapping.Dynamic() {
				if f, ok := dynamicRange(in, svc, mapping); ok {
					out = append(out, f)
				}
				continue
			}
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
	st := stackOf(in)

	for _, container := range in.Caps.Containers {
		best := portHolder{container: container}
		for _, mapping := range container.Ports {
			for _, port := range mapping.HostPorts() {
				held := claimFromMapping(mapping, port)
				result, why := collides(st, want, held)
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
		result, why := collides(st, want, held)
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
	case blocked && !ownershipKnown(in, certain):
		// Something certainly holds the binding, but the engine's container list was
		// not read, so whether that something is this deployment's own container
		// (its docker-proxy) cannot be told. A blocker here would stop every
		// redeployment audited without access to the engine.
		finding.Outcome = model.OutcomeUnknown
		finding.Severity = model.FindingWarning
		finding.Confidence = model.ConfidenceMedium
		finding.Title = fmt.Sprintf("Port %d is held, and by whom could not be established", want.port)
		_, why := engineList(in, model.SourceContainers)
		finding.Description = fmt.Sprintf(
			"Service %q publishes %s, and that binding is held on this host by %s. The engine's containers could "+
				"not be listed (%s), so whether the holder is this deployment's own container — which Compose "+
				"replaces — or something else cannot be decided.",
			svc.Name, want.describe(), describeHolders(in, certain), why)
		finding.WhyItMatters = "If the holder is not this deployment's own container, the container will fail to " +
			"start. This is reported as an open question because a blocker on the previous version of the same " +
			"deployment is the false blocker."
		finding.WhatToDo = fmt.Sprintf(
			"Re-run the audit as a user who can reach the container engine, or check by hand: `docker ps "+
				"--filter publish=%d` names the container holding it, if any.", want.port)
		finding.Evidence = append(finding.Evidence, holderEvidence(in, certain)...)

	case blocked:
		// Something unrelated holds the binding, and the tool is sure of it.
		finding.Outcome = model.OutcomeProblem
		finding.Severity = model.FindingBlocker
		finding.Title = fmt.Sprintf("Port %d is already in use", want.port)
		finding.Description = fmt.Sprintf(
			"Service %q publishes %s, and that binding is already held on this host by %s.",
			svc.Name, want.describe(), describeHolders(in, certain))
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
		finding.Outcome = model.OutcomeNoProblem
		finding.Severity = model.FindingInfo
		finding.Title = fmt.Sprintf("Port %d is held by this deployment's own container", want.port)
		finding.Description = fmt.Sprintf(
			"Host %s %s container %q, which belongs to the same Compose project (%s). The planned run "+
				"releases it before binding: %s.", want.describe(), holds, container.Name, container.Project,
			ownerOf(in, container).action)
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
		finding.Outcome = model.OutcomeUnknown
		finding.Severity = model.FindingWarning
		finding.Confidence = model.ConfidenceMedium
		finding.Title = fmt.Sprintf("Port %d may already be in use — this could not be established", want.port)
		finding.Description = fmt.Sprintf(
			"Service %q publishes %s. Something is bound to that port on this host — %s — and whether the two "+
				"bindings actually overlap could not be decided offline. %s",
			svc.Name, want.describe(), describeHolders(in, holders), unknownReasons(holders))
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

// dynamicRange checks a host range published to one container port
// ("8000-8010:80"). The engine binds one port of it, the first it finds free, so the
// range is a conflict only when every port of it is taken — and a single free port
// settles it the other way.
func dynamicRange(in Input, svc model.ManifestService, mapping model.PortMapping) (model.Finding, bool) {
	protocol := protocolOf(mapping)
	if !observableProtocol(baseProtocol(protocol)) {
		return unobservableProtocol(in, svc, mapping, claimFromMapping(mapping, mapping.HostPort)), true
	}
	var taken, maybe []string
	for _, port := range mapping.HostPorts() {
		switch state, holders := portState(in, mapping, port); state {
		case portFree:
			return model.Finding{}, false
		case portTaken:
			taken = append(taken, fmt.Sprintf("%d (%s)", port, holders))
		default:
			maybe = append(maybe, fmt.Sprintf("%d (%s)", port, orUnknown(holders)))
		}
	}
	subject := fmt.Sprintf("%d-%d/%s", mapping.HostPort, mapping.HostPortEnd, baseProtocol(protocol))
	finding := model.Finding{
		Code:       "witness.port_conflict",
		Category:   model.CategoryConflict,
		Subject:    subject,
		Confidence: model.ConfidenceHigh,
		SortOrder:  mapping.HostPort,
		Evidence: []model.Evidence{
			manifestEvidence(in, svc.Name, fmt.Sprintf("ports: publishes one port of host range %s → container port %d",
				subject, mapping.ContainerPort)),
			evidence(in, "ss -lntupH", strings.Join(append(append([]string{}, taken...), maybe...), "\n")),
		},
	}
	if len(maybe) == 0 {
		finding.Outcome, finding.Severity = model.OutcomeProblem, model.FindingBlocker
		finding.Title = fmt.Sprintf("Every port of %s is already in use", subject)
		finding.Description = fmt.Sprintf("Service %q publishes one port of %s, which the engine picks from the "+
			"ports still free. None is: %s.", svc.Name, subject, strings.Join(taken, "; "))
		finding.WhyItMatters = "The container will fail to start: there is no free port in the range for the engine to bind."
		finding.WhatToDo = fmt.Sprintf("Widen the range or free a port in it before deploying %q.", svc.Name)
		return finding, true
	}
	finding.Outcome, finding.Severity, finding.Confidence = model.OutcomeUnknown, model.FindingWarning, model.ConfidenceMedium
	finding.Title = fmt.Sprintf("Whether %s has a free port could not be established", subject)
	finding.Description = fmt.Sprintf("Service %q publishes one port of %s. No port of it is certainly free: "+
		"taken — %s; undecided — %s.", svc.Name, subject, orNone(taken), strings.Join(maybe, "; "))
	finding.WhyItMatters = "If none is free the container will not start; if one is, the engine takes it. This audit could not tell."
	finding.WhatToDo = fmt.Sprintf("Check by hand: `ss -lntup` for the ports of %s.", subject)
	return finding, true
}

func orNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, "; ")
}

// hostNetworkPorts checks a service on the host's network stack (network_mode:
// host). The engine discards `ports:` for it and publishes nothing; the
// application binds its ports directly on the host, at addresses of its own
// choosing. Its declared ports (`ports:` container side, `expose:`) are what the
// plan says it listens on; a port nothing declares cannot be checked at all.
func hostNetworkPorts(in Input, svc model.ManifestService) []model.Finding {
	type declared struct {
		port     int
		protocol string
	}
	var ports []declared
	for _, m := range svc.Ports {
		end := m.ContainerPortEnd
		if end < m.ContainerPort {
			end = m.ContainerPort
		}
		for p := m.ContainerPort; p <= end; p++ {
			ports = append(ports, declared{p, baseProtocol(m.Protocol)})
		}
	}
	for _, p := range svc.Expose {
		ports = append(ports, declared{p, "tcp"})
	}

	base := manifestEvidence(in, svc.Name, "network_mode: host")
	if len(ports) == 0 {
		return []model.Finding{{
			Code: "witness.port_conflict", Category: model.CategoryConflict, Subject: svc.Name,
			Severity: model.FindingInfo, Confidence: model.ConfidenceHigh, Outcome: model.OutcomeManualCheck,
			Title: fmt.Sprintf("Service %q binds host ports nobody declared", svc.Name),
			Description: fmt.Sprintf("Service %q runs on the host's network stack (network_mode: host) and declares "+
				"no port, so which ports it will bind is up to the application.", svc.Name),
			WhyItMatters: "A port the plan does not declare cannot be checked; it conflicts or not when the application starts.",
			WhatToDo:     fmt.Sprintf("List the ports %q listens on under `expose:` so they can be checked.", svc.Name),
			Evidence:     []model.Evidence{base},
		}}
	}

	var out []model.Finding
	for _, d := range ports {
		want := portClaim{protocol: d.protocol, port: d.port, readable: true}
		if !observableProtocol(d.protocol) {
			continue
		}
		var holders []portHolder
		st := stackOf(in)
		for _, socket := range in.Caps.Ports {
			held := claimFromSocket(socket)
			if result, why := collides(st, want, held); result != overlapNone {
				holders = append(holders, portHolder{overlap: result, why: why, claim: held, socket: socket, isSocket: true})
			}
		}
		if len(holders) == 0 {
			continue
		}
		f := model.Finding{
			Code: "witness.port_conflict", Category: model.CategoryConflict,
			Subject:   fmt.Sprintf("%d/%s (host network)", d.port, d.protocol),
			SortOrder: d.port, Confidence: model.ConfidenceMedium,
			Evidence: append([]model.Evidence{base, manifestEvidence(in, svc.Name,
				fmt.Sprintf("declares port %d/%s", d.port, d.protocol))}, holderEvidence(in, holders)...),
		}
		wildcard := false
		for _, h := range holders {
			if h.claim.anyAddr || (h.claim.ip != nil && h.claim.ip.IsUnspecified()) {
				wildcard = true
			}
		}
		previous := runningOwnContainer(in, svc.Name)
		switch {
		case wildcard && previous == "":
			f.Outcome, f.Severity, f.Confidence = model.OutcomeProblem, model.FindingBlocker, model.ConfidenceHigh
			f.Title = fmt.Sprintf("Port %d is already in use on the host network", d.port)
			f.Description = fmt.Sprintf("Service %q runs on the host's network stack and listens on %d/%s, which %s "+
				"already holds on every address — so the port is taken whatever address the application binds.",
				svc.Name, d.port, d.protocol, describeHolders(in, holders))
			f.WhyItMatters = "The application will fail to bind when it starts, which on the host network is a crash of the container."
			f.WhatToDo = fmt.Sprintf("Free %d/%s, or run %q on a bridge network with a published port.", d.port, d.protocol, svc.Name)
		default:
			f.Outcome, f.Severity = model.OutcomeUnknown, model.FindingWarning
			f.Title = fmt.Sprintf("Port %d may be in use on the host network — this could not be established", d.port)
			reason := "the application binds an address of its own choosing, which the plan does not state"
			if previous != "" {
				reason = fmt.Sprintf("the holder may be this service's own previous container %q, which Compose "+
					"stops first — a socket on the host network carries no container label", previous)
			}
			f.Description = fmt.Sprintf("Service %q runs on the host's network stack and listens on %d/%s; %s holds "+
				"that port, and whether the two collide is unknown: %s.", svc.Name, d.port, d.protocol,
				describeHolders(in, holders), reason)
			f.WhyItMatters = "If they collide the application fails to bind when the container starts."
			f.WhatToDo = fmt.Sprintf("Settle it by hand: `ss -lntup | grep ':%d '`.", d.port)
		}
		out = append(out, f)
	}
	return out
}

// runningOwnContainer names a running container of this deployment's service, if
// there is one the plan releases.
func runningOwnContainer(in Input, service string) string {
	for _, c := range in.Caps.Containers {
		if c.Service == service && c.State == "running" {
			if o := ownerOf(in, c); o.kind == ownService && o.released {
				return c.Name
			}
		}
	}
	return ""
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
		Outcome:    model.OutcomeManualCheck,
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

// ownHolder returns the holder that the planned run releases before it binds —
// this deployment's own previous container, recreated or kept, or an orphan it
// removes — if any. It is consulted before the certain holders because a published
// port's raw socket belongs to that same container's proxy and carries no label.
func ownHolder(in Input, holders []portHolder) *portHolder {
	for i, h := range holders {
		if !h.isSocket && ownerOf(in, h.container).released {
			return &holders[i]
		}
	}
	return nil
}

// ownershipKnown reports whether the holders of a binding can be told apart from
// this deployment's own containers: always when a container is among them (it
// carries its project label), and for a bare socket only when the engine's
// container list was read in full — otherwise the socket may be this deployment's
// own docker-proxy.
func ownershipKnown(in Input, holders []portHolder) bool {
	for _, h := range holders {
		if !h.isSocket {
			return true
		}
	}
	listed, _ := engineList(in, model.SourceContainers)
	return listed
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
		if !h.isSocket && !ownerOf(in, h.container).released {
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

func describeHolders(in Input, holders []portHolder) string {
	var parts []string
	for _, h := range holders {
		parts = append(parts, describeHolder(in, h))
	}
	if len(parts) == 0 {
		return "another process"
	}
	return strings.Join(parts, "; ")
}

func describeHolder(in Input, h portHolder) string {
	if !h.isSocket {
		return fmt.Sprintf("container %q (%s), publishing %s",
			h.container.Name, describeOwner(in, h.container), h.claim.describe())
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

		owner := ownerOf(in, found)
		if owner.kind == ownService && (found.Service == "" || found.Service == svc.Name) {
			finding.Outcome = model.OutcomeNoProblem
			finding.Severity = model.FindingInfo
			finding.Title = fmt.Sprintf("Container %q already exists and belongs to this deployment", svc.ContainerName)
			finding.Description = fmt.Sprintf(
				"A container named %q is present and carries this deployment's own project label and service. "+
					"The planned run: %s.", svc.ContainerName, owner.action)
			finding.WhyItMatters = "Nothing is blocked."
			finding.WhatToDo = "No action needed."
			out = append(out, finding)
			continue
		}
		if owner.kind == unlabelled {
			finding.Outcome = model.OutcomeUnknown
			finding.Severity = model.FindingWarning
			finding.Title = fmt.Sprintf("Container %q exists, and whose it is could not be established", svc.ContainerName)
			finding.Description = fmt.Sprintf("A container named %q exists, and the engine reported no labels for "+
				"it, so whether it is this deployment's previous version cannot be read.", svc.ContainerName)
			finding.WhyItMatters = "If it is not this deployment's, `docker compose up` fails on the name."
			finding.WhatToDo = fmt.Sprintf("Check by hand: `docker inspect --format '{{json .Config.Labels}}' %s`.",
				svc.ContainerName)
			out = append(out, finding)
			continue
		}

		finding.Outcome = model.OutcomeProblem
		finding.Severity = model.FindingBlocker
		finding.Title = fmt.Sprintf("Container name %q is taken", svc.ContainerName)
		finding.Description = fmt.Sprintf(
			"Service %q fixes its container name to %q with container_name, and a container of that name already "+
				"exists on this host (image %s, state %s), belonging to %s.",
			svc.Name, svc.ContainerName, found.Image, found.State, describeOwner(in, found))
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
//
// Every named volume the plan mounts, matched by its name in the engine (`name:`,
// <project>_<key>, or the key of an external one). Presence, ownership and the
// completeness of the list are three separate questions:
//
//   - external and absent from a list read in full: Compose refuses to start;
//   - external and the list was not read: unknown — never "absent";
//   - external and present with another project's label: its data is attached;
//   - not external and absent: Compose creates it — a planned change, not a conflict;
//   - not external and present without this project's label: Compose warns ("already
//     exists but was not created by Docker Compose") and reuses its data.
func volumeNameConflicts(in Input) []model.Finding {
	var out []model.Finding

	existing := map[string]model.ContainerVolume{}
	for _, v := range in.Caps.ContainerVolumes {
		existing[v.Name] = v
	}
	listed, why := engineList(in, model.SourceVolumes)
	used := mountedVolumes(in)

	for _, vol := range in.Manifest.Volumes {
		if !used[vol.Name] {
			continue
		}
		name := engineNameOf(vol.EngineName, vol.Name)
		found, ok := existing[name]
		finding := model.Finding{
			Code:       "witness.volume_name_conflict",
			Category:   model.CategoryConflict,
			Subject:    name,
			Confidence: model.ConfidenceHigh,
			Evidence:   []model.Evidence{manifestEvidence(in, "", volumeDeclaration(vol, name))},
		}

		switch {
		case vol.External && !ok && !listed:
			// Absence is proven only by a list that was read in full.
			finding.Outcome = model.OutcomeUnknown
			finding.Severity = model.FindingWarning
			finding.Title = fmt.Sprintf("Whether external volume %q exists could not be established", name)
			finding.Description = fmt.Sprintf(
				"The manifest declares volume %q as external, so Compose expects it to exist already. The engine's "+
					"volumes could not be listed (%s), so its presence is unknown — not absent.", name, why)
			finding.WhyItMatters = "If it is missing, Compose refuses to start the stack. If it exists, nothing is " +
				"wrong. This audit could not tell."
			finding.WhatToDo = fmt.Sprintf("Check by hand: `docker volume inspect %s`. Re-run the audit as a user "+
				"who can reach the engine to have it checked.", name)
			finding.Evidence = append(finding.Evidence, evidence(in, engineCommand(in, "volume ls --format {{json .}}"),
				onEngine(in, why)))

		case vol.External && !ok:
			finding.Outcome = model.OutcomeProblem
			finding.Severity = model.FindingBlocker
			finding.Title = fmt.Sprintf("External volume %q does not exist", name)
			finding.Description = fmt.Sprintf(
				"The manifest declares volume %q as external, which means Compose expects it to exist already. "+
					"It is not present in this engine's volume list.", name)
			finding.WhyItMatters = "Compose refuses to start a stack whose external volume is missing. It will not " +
				"create it for you — that is what declaring it external asks for."
			finding.WhatToDo = fmt.Sprintf(
				"Create the volume before deploying, or remove `external: true` so Compose manages %q itself.", name)
			finding.Evidence = append(finding.Evidence, evidence(in, engineCommand(in, "volume ls --format {{json .}}"),
				onEngine(in, fmt.Sprintf("no volume named %s among the %d volumes", name, len(in.Caps.ContainerVolumes)))))

		case !ok:
			// Not there yet: Compose creates it. That is the change list's business.
			continue

		case sameProject(in, found.Project):
			// This project's own volume, reused on purpose.
			continue

		case vol.External && found.Project == "":
			// An external volume created by hand (`docker volume create`) is exactly
			// what `external: true` is for.
			continue

		case vol.External:
			finding.Outcome = model.OutcomeProblem
			finding.Severity = model.FindingWarning
			finding.Title = fmt.Sprintf("External volume %q already holds somebody else's data", name)
			finding.Description = fmt.Sprintf(
				"Volume %q exists, mounted at %s, and carries project label %q — not this deployment's. "+
					"Deploying will attach it to the new containers.", name, found.Mountpoint, found.Project)
			finding.WhyItMatters = "This does not fail. It succeeds, and the new service starts on top of existing " +
				"data belonging to something else — which is worse, because nothing announces it."
			finding.WhatToDo = fmt.Sprintf(
				"Confirm that reusing %q is intended. If it is not, pick a different volume name.", name)
			finding.Evidence = append(finding.Evidence, volumeEvidence(in, found))

		default:
			owner := "was not created by Compose"
			if found.Project != "" {
				owner = fmt.Sprintf("was created for project %q", found.Project)
			}
			finding.Outcome = model.OutcomeProblem
			finding.Severity = model.FindingWarning
			finding.SortOrder = 1
			finding.Title = fmt.Sprintf("Volume %q already exists and %s", name, owner)
			finding.Description = fmt.Sprintf(
				"The plan's volume %q is not external, so Compose expects to create %q for project %q. A volume of "+
					"that name already exists and %s. Compose warns (\"already exists but was not created by Docker "+
					"Compose. Use `external: true`\") and mounts it — with whatever data it holds.",
				vol.Name, name, in.Project, owner)
			finding.WhyItMatters = "The new containers start on top of data nobody declared they would use, and " +
				"`docker compose down -v` for this project will not remove it."
			finding.WhatToDo = fmt.Sprintf("Declare it `external: true` if reusing it is intended, or give the plan's "+
				"volume another name.")
			finding.Evidence = append(finding.Evidence, volumeEvidence(in, found))
		}
		out = append(out, finding)
	}
	return out
}

// mountedVolumes is the set of declared volumes a planned service mounts — the
// only ones Compose creates or looks up.
func mountedVolumes(in Input) map[string]bool {
	used := map[string]bool{}
	for _, svc := range in.Manifest.Services {
		for _, m := range svc.Volumes {
			if m.Kind == model.MountVolume && m.Source != "" {
				used[m.Source] = true
			}
		}
	}
	return used
}

func engineNameOf(engineName, key string) string {
	if engineName != "" {
		return engineName
	}
	return key
}

func volumeDeclaration(vol model.ManifestVolume, name string) string {
	if vol.External {
		return fmt.Sprintf("volumes: %s declared external (engine name %s)", vol.Name, name)
	}
	return fmt.Sprintf("volumes: %s, created by Compose as %s", vol.Name, name)
}

func volumeEvidence(in Input, found model.ContainerVolume) model.Evidence {
	return evidence(in, engineCommand(in, "volume ls --format {{json .}}"), onEngine(in, fmt.Sprintf(
		"volume %s driver=%s mountpoint=%s project=%q", found.Name, found.Driver, found.Mountpoint, found.Project)))
}

// onEngine names the engine an observation came from. Two servers may hold
// volumes, networks and containers of the same names; the engine ID is what tells
// one's answer from the other's.
func onEngine(in Input, observation string) string {
	if in.Caps.Runtime == nil || in.Caps.Runtime.EngineID == "" {
		return observation
	}
	return fmt.Sprintf("%s (engine %s, %s)", observation, in.Caps.Runtime.EngineID, orUnknown(in.Caps.Runtime.EngineName))
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
				// Sources are resolved against the project directory when the plan is
				// read; one that is still relative could not be resolved.
				continue
			}
			out = append(out, bindSourceFindings(in, svc, mount)...)

			if sensitive := sensitiveHostPath(source); sensitive != "" {
				out = append(out, model.Finding{
					Code:       "witness.bind_path_conflict",
					Category:   model.CategoryConflict,
					Subject:    source,
					Severity:   model.FindingWarning,
					Confidence: model.ConfidenceHigh,
					SortOrder:  1,
					Outcome:    model.OutcomeProblem,
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
//
// The same three questions as for volumes — present, whose, read in full — and a
// fourth: present but unusable, a swarm-scoped network that is not attachable,
// which a standalone container cannot join.
func networkNameConflicts(in Input) []model.Finding {
	var out []model.Finding

	existing := map[string]model.ContainerNetwork{}
	for _, n := range in.Caps.ContainerNetworks {
		existing[n.Name] = n
	}
	listed, why := engineList(in, model.SourceNetworks)

	for _, network := range in.Manifest.Networks {
		name := engineNameOf(network.EngineName, network.Name)
		found, ok := existing[name]
		declaration := fmt.Sprintf("networks: %s, created by Compose as %s", network.Name, name)
		if network.External {
			declaration = fmt.Sprintf("networks: %s declared external (engine name %s)", network.Name, name)
		}
		finding := model.Finding{
			Code:       "witness.network_name_conflict",
			Category:   model.CategoryConflict,
			Subject:    name,
			Confidence: model.ConfidenceHigh,
			Evidence:   []model.Evidence{manifestEvidence(in, "", declaration)},
		}
		listing := func(text string) model.Evidence {
			return evidence(in, engineCommand(in, "network ls --format {{json .}}"), onEngine(in, text))
		}

		switch {
		case network.External && !ok && !listed:
			finding.Outcome = model.OutcomeUnknown
			finding.Severity = model.FindingWarning
			finding.Title = fmt.Sprintf("Whether external network %q exists could not be established", name)
			finding.Description = fmt.Sprintf(
				"The manifest expects network %q to exist already. The engine's networks could not be listed (%s), "+
					"so its presence is unknown — not absent.", name, why)
			finding.WhyItMatters = "If it is missing, Compose refuses to start the stack. This audit could not tell."
			finding.WhatToDo = fmt.Sprintf("Check by hand: `docker network inspect %s`. Re-run the audit as a user "+
				"who can reach the engine to have it checked.", name)
			finding.Evidence = append(finding.Evidence, listing(why))

		case network.External && !ok:
			finding.Outcome = model.OutcomeProblem
			finding.Severity = model.FindingBlocker
			finding.Title = fmt.Sprintf("External network %q does not exist", name)
			finding.Description = fmt.Sprintf(
				"The manifest expects network %q to exist already. It is not in this engine's network list.", name)
			finding.WhyItMatters = "Compose will not create an external network, and refuses to start without it."
			finding.WhatToDo = fmt.Sprintf(
				"Create %q before deploying, or drop `external: true` so Compose manages it.", name)
			finding.Evidence = append(finding.Evidence, listing(fmt.Sprintf("no network named %s among the %d networks",
				name, len(in.Caps.ContainerNetworks))))

		case !ok:
			continue

		case found.Scope == "swarm" && found.Attachable == "no":
			finding.Outcome = model.OutcomeProblem
			finding.Severity = model.FindingBlocker
			finding.Title = fmt.Sprintf("Network %q exists but cannot take a standalone container", name)
			finding.Description = fmt.Sprintf("Network %q is a swarm-scoped %s network that is not attachable, and "+
				"Compose creates standalone containers.", name, orUnknown(found.Driver))
			finding.WhyItMatters = "The containers fail to start: the engine refuses to connect them to the network."
			finding.WhatToDo = fmt.Sprintf("Recreate %q with --attachable, or deploy the stack to the swarm.", name)
			finding.Evidence = append(finding.Evidence, networkEvidence(in, found))

		case found.Scope == "swarm" && found.Attachable == "":
			finding.Outcome = model.OutcomeUnknown
			finding.Severity = model.FindingWarning
			finding.Title = fmt.Sprintf("Whether swarm network %q takes a standalone container could not be established", name)
			finding.Description = fmt.Sprintf("Network %q is swarm-scoped, and whether it is attachable was not read "+
				"(its inspect failed or was capped).", name)
			finding.WhyItMatters = "A non-attachable swarm network refuses Compose's standalone containers."
			finding.WhatToDo = fmt.Sprintf("Check by hand: `docker network inspect --format '{{.Attachable}}' %s`.", name)
			finding.Evidence = append(finding.Evidence, networkEvidence(in, found))

		case sameProject(in, found.Project):
			continue

		case network.External:
			finding.Outcome = model.OutcomeManualCheck
			finding.Severity = model.FindingInfo
			finding.Title = fmt.Sprintf("External network %q is shared with another stack", name)
			finding.Description = fmt.Sprintf(
				"Network %q exists (driver %s, project %q) and this deployment will join it.",
				name, found.Driver, found.Project)
			finding.WhyItMatters = "Containers on a shared network can reach each other by name. That is often the " +
				"intent; it also means a service here is reachable from whatever else is on that network."
			finding.WhatToDo = "Confirm the sharing is intended."
			finding.Evidence = append(finding.Evidence, networkEvidence(in, found))

		default:
			owner := "was not created by Compose"
			if found.Project != "" {
				owner = fmt.Sprintf("was created for project %q", found.Project)
			}
			finding.Outcome = model.OutcomeProblem
			finding.Severity = model.FindingWarning
			finding.SortOrder = 1
			finding.Title = fmt.Sprintf("Network %q already exists and %s", name, owner)
			finding.Description = fmt.Sprintf(
				"The plan's network %q is not external, so Compose expects to create %q for project %q. A network of "+
					"that name already exists and %s; Compose warns (\"exists but was not created by compose. Set "+
					"`external: true`\") and joins it.", network.Name, name, in.Project, owner)
			finding.WhyItMatters = "The services land on a network shared with whatever else is attached to it, " +
				"and its configuration (subnet, driver, options) is not the plan's."
			finding.WhatToDo = "Declare it `external: true` if joining it is intended, or give the plan's network another name."
			finding.Evidence = append(finding.Evidence, networkEvidence(in, found))
		}
		out = append(out, finding)
	}
	return out
}

func networkEvidence(in Input, found model.ContainerNetwork) model.Evidence {
	return evidence(in, engineCommand(in, "network ls --format {{json .}}"), onEngine(in, fmt.Sprintf(
		"network %s driver=%s scope=%s attachable=%s subnets=%s project=%q", found.Name, found.Driver,
		orUnknown(found.Scope), orUnknown(found.Attachable), strings.Join(found.Subnets, ", "), found.Project)))
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
						Outcome:    model.OutcomeProblem,
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
							evidence(in, "docker network inspect "+existing.Name+" --format {{json .}}",
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

package witness

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// The two rules about the front of the machine: the ports a web server already
// holds, and the names it already answers for. Both are the same class of problem —
// the deployment is not the only thing that thinks it owns the public face of this
// host — and both are the ones a control panel makes worse.

// 13. witness.proxy_conflict
//
// A front end's listen ports are collected as bare port numbers — model.Proxy
// and model.Panel record neither the protocol nor the address behind them. So
// the only collision this rule can *state* is against a TCP publish, which is
// what a web server listens on; a publish of 80 or 443 over another protocol
// (QUIC on 443/udp, most obviously) is a question, not a blocker. The address
// half cannot be narrowed at all from what is collected, which is a documented
// limitation of the collector rather than something the rule can fix.
func proxyPortConflict(in Input) []model.Finding {
	// Which of the manifest's published ports are web-facing, split by whether
	// the protocol is the one the front end is known to speak.
	wanted := map[int][]string{}
	other := map[int][]string{}
	for _, svc := range in.Manifest.Services {
		for _, mapping := range svc.Ports {
			for _, port := range mapping.HostPorts() {
				if port != 80 && port != 443 {
					continue
				}
				if baseProtocol(mapping.Protocol) == "tcp" {
					wanted[port] = append(wanted[port], svc.Name)
					continue
				}
				other[port] = append(other[port],
					fmt.Sprintf("%s (%s)", svc.Name, baseProtocol(mapping.Protocol)))
			}
		}
	}
	if len(wanted) == 0 && len(other) == 0 {
		return nil
	}

	var out []model.Finding

	for _, port := range []int{80, 443} {
		services, asked := wanted[port]
		otherServices, askedOther := other[port]
		if !asked && !askedOther {
			continue
		}
		// When the same port is published over TCP as well, the collision is
		// stated outright and the other protocol adds nothing to say.
		stated := asked
		if !stated {
			services = otherServices
		}

		// A control panel is the more serious case and is reported first: unlike a
		// plain nginx, a panel will regenerate its configuration and undo a manual
		// change without telling anybody.
		for _, panel := range in.Caps.Panels {
			if !holdsPort(panel.OwnsPorts, port) {
				continue
			}
			out = append(out, model.Finding{
				Code:       "witness.proxy_conflict",
				Category:   model.CategoryConflict,
				Severity:   severityFor(stated),
				Confidence: confidenceFor(stated, model.ConfidenceMedium),
				Subject:    fmt.Sprintf("%d/%s", port, panel.Name),
				Title:      fmt.Sprintf("%s owns port %d on this host", panel.Name, port),
				Description: fmt.Sprintf(
					"Service(s) %s publish host port %d, and %s%s is installed here and holds that port.%s",
					strings.Join(services, ", "), port, panel.Name, runningSuffix(panel), protocolCaveat(stated)),
				WhyItMatters: "A control panel does not merely occupy the port: it owns the web server " +
					"configuration and rewrites it on its own schedule, so a hand-made vhost placed alongside it " +
					"survives only until the panel next regenerates. The container will also simply fail to bind.",
				WhatToDo: fmt.Sprintf(
					"Publish the service on an internal port and let %s proxy to it through its own configuration, "+
						"rather than taking %d away from it.%s", panel.Name, port, protocolCheck(stated, port)),
				Evidence: []model.Evidence{
					manifestEvidence(in, strings.Join(services, ", "), fmt.Sprintf("ports: publishes %d", port)),
					evidence(in, panel.Evidence, fmt.Sprintf("%s detected%s, holds ports %s",
						panel.Name, runningSuffix(panel), renderInts(panel.OwnsPorts))),
				},
			})
		}

		if in.Caps.Proxy == nil || !holdsPort(in.Caps.Proxy.ListenPorts, port) {
			continue
		}
		proxy := in.Caps.Proxy
		out = append(out, model.Finding{
			Code:       "witness.proxy_conflict",
			Category:   model.CategoryConflict,
			Severity:   severityFor(stated),
			Confidence: confidenceFor(stated, model.ConfidenceHigh),
			Subject:    fmt.Sprintf("%d/%s", port, proxy.Kind),
			SortOrder:  1,
			Title:      fmt.Sprintf("%s already listens on port %d", proxy.Kind, port),
			Description: fmt.Sprintf(
				"Service(s) %s publish host port %d, and %s %s is configured to listen on it.%s",
				strings.Join(services, ", "), port, proxy.Kind, orUnknown(proxy.Version), protocolCaveat(stated)),
			WhyItMatters: "Two processes cannot hold the same port. The container fails to start, and on a " +
				"deployment that stops the old stack first, it fails after the site is already down.",
			WhatToDo: fmt.Sprintf(
				"Put the service behind %s with a proxy_pass to an internal port, which is what the existing "+
					"front end is for — or move %s off %d deliberately.%s",
				proxy.Kind, proxy.Kind, port, protocolCheck(stated, port)),
			Evidence: []model.Evidence{
				manifestEvidence(in, strings.Join(services, ", "), fmt.Sprintf("ports: publishes %d", port)),
				evidence(in, proxy.Kind+" -T", fmt.Sprintf("%s listens on %s (config root %s)",
					proxy.Kind, renderInts(proxy.ListenPorts), orUnknown(proxy.ConfigRoot))),
			},
		})
	}
	return out
}

// severityFor, confidenceFor, protocolCaveat and protocolCheck are the four
// places the "we did not record the front end's protocol" caveat lands. A publish
// this tool cannot match to the front end's listener is downgraded rather than
// dropped: the port may well be taken, and saying nothing would be the failure
// the second promise forbids.
func severityFor(stated bool) model.FindingSeverity {
	if stated {
		return model.FindingBlocker
	}
	return model.FindingWarning
}

func confidenceFor(stated bool, certain model.Confidence) model.Confidence {
	if stated {
		return certain
	}
	return model.ConfidenceLow
}

func protocolCaveat(stated bool) string {
	if stated {
		return ""
	}
	return " The publish is not over TCP, and the protocol the front end listens on was not recorded, so " +
		"whether the two actually collide could not be established — a QUIC publish on 443/udp, for instance, " +
		"does not take 443/tcp away from a web server."
}

func protocolCheck(stated bool, port int) string {
	if stated {
		return ""
	}
	return fmt.Sprintf(" Confirm it first: `ss -lnup | grep ':%d '` shows whether anything already holds the "+
		"UDP side of that port.", port)
}

func runningSuffix(panel model.Panel) string {
	if panel.Running {
		return " and running"
	}
	return " (not currently running)"
}

func holdsPort(ports []int, want int) bool {
	for _, port := range ports {
		if port == want {
			return true
		}
	}
	return false
}

func renderInts(values []int) string {
	if len(values) == 0 {
		return "none recorded"
	}
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, fmt.Sprint(v))
	}
	return strings.Join(parts, ", ")
}

// traefikHostRule extracts the names out of a Traefik router rule. Labels are the
// only place a Compose file says which domain a service expects, so this is the
// requirement side of the domain check.
var traefikHostRule = regexp.MustCompile(`Host\(([^)]*)\)`)

// 14. witness.domain_conflict
func domainConflict(in Input) []model.Finding {
	if in.Caps.Proxy == nil || len(in.Caps.Proxy.ServerNames) == 0 {
		return nil
	}

	served := map[string]model.ProxyServerName{}
	catchAll := model.ProxyServerName{}
	hasCatchAll := false
	for _, name := range in.Caps.Proxy.ServerNames {
		if name.Name == "_" || name.Name == "*" {
			catchAll, hasCatchAll = name, true
			continue
		}
		served[strings.ToLower(name.Name)] = name
	}

	var out []model.Finding
	for _, svc := range in.Manifest.Services {
		for _, domain := range serviceDomains(svc) {
			existing, taken := served[strings.ToLower(domain)]
			switch {
			case taken:
				out = append(out, model.Finding{
					Code:       "witness.domain_conflict",
					Category:   model.CategoryConflict,
					Severity:   model.FindingWarning,
					Confidence: model.ConfidenceMedium,
					Subject:    domain,
					Title:      fmt.Sprintf("%s is already served by %s on this host", domain, in.Caps.Proxy.Kind),
					Description: fmt.Sprintf(
						"Service %q expects to be reached at %s, and %s already has a vhost for that name at %s:%d.",
						svc.Name, domain, in.Caps.Proxy.Kind, existing.File, existing.Line),
					WhyItMatters: "Whichever configuration the web server reads first wins, and it is not " +
						"necessarily the new one. The symptom is a domain that keeps serving the old site, which " +
						"looks like a caching problem and is not.",
					WhatToDo: fmt.Sprintf(
						"Decide which vhost owns %s and remove the other. The existing one is at %s:%d.",
						domain, existing.File, existing.Line),
					Evidence: []model.Evidence{
						manifestEvidence(in, svc.Name, "labels: routes "+domain),
						evidence(in, in.Caps.Proxy.Kind+" -T",
							fmt.Sprintf("%s:%d — server_name %s", existing.File, existing.Line, existing.Name)),
					},
				})
			case hasCatchAll:
				out = append(out, model.Finding{
					Code:       "witness.domain_conflict",
					Category:   model.CategoryConflict,
					Severity:   model.FindingInfo,
					Confidence: model.ConfidenceMedium,
					Subject:    domain,
					SortOrder:  1,
					Title:      fmt.Sprintf("%s will land on the catch-all vhost until the new one is in place", domain),
					Description: fmt.Sprintf(
						"No vhost serves %s yet, and %s has a catch-all server block at %s:%d that answers for any "+
							"name it does not recognise.", domain, in.Caps.Proxy.Kind, catchAll.File, catchAll.Line),
					WhyItMatters: "Requests for the new domain will be answered by whatever the catch-all serves " +
						"rather than failing visibly, so a missing or mistyped vhost looks like a working site " +
						"showing the wrong content.",
					WhatToDo: fmt.Sprintf("Add the vhost for %s, and check the catch-all at %s:%d is what you want "+
						"unmatched names to reach.", domain, catchAll.File, catchAll.Line),
					Evidence: []model.Evidence{
						manifestEvidence(in, svc.Name, "labels: routes "+domain),
						evidence(in, in.Caps.Proxy.Kind+" -T",
							fmt.Sprintf("%s:%d — catch-all server_name %s", catchAll.File, catchAll.Line, catchAll.Name)),
					},
				})
			}
		}
	}
	return out
}

// serviceDomains reads the domains a service expects out of its labels. Traefik's
// router rules and the `VIRTUAL_HOST`-style proxy labels are the two conventions in
// use; anything else is not guessed at.
func serviceDomains(svc model.ManifestService) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		name = strings.Trim(strings.TrimSpace(name), "`\"'")
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}

	for key, value := range svc.Labels {
		lower := strings.ToLower(key)
		switch {
		case strings.HasPrefix(lower, "traefik.") && strings.HasSuffix(lower, ".rule"):
			for _, match := range traefikHostRule.FindAllStringSubmatch(value, -1) {
				for _, name := range strings.Split(match[1], ",") {
					add(name)
				}
			}
		case lower == "virtual_host" || lower == "virtual.host":
			for _, name := range strings.Split(value, ",") {
				add(name)
			}
		}
	}
	return out
}

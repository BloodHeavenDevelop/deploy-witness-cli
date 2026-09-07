package manifest

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"gopkg.in/yaml.v3"
)

// ports reads a service's `ports:`, accepting both the short string form and the
// long mapping form. An entry that cannot be understood is reported and dropped;
// the rest of the list still stands, because one nonsense mapping is not a reason
// to claim the service publishes nothing.
func (w *warner) ports(node *yaml.Node, where string) []model.PortMapping {
	if node == nil || isNull(node) {
		return nil
	}
	if node.Kind != yaml.SequenceNode {
		w.add("%s: expected a sequence, got %s", where, kindName(node))
		return nil
	}

	var out []model.PortMapping
	for i, item := range items(node) {
		at := fmt.Sprintf("%s[%d]", where, i)
		switch {
		case item == nil || isNull(item):
			w.add("%s: empty entry", at)
		case item.Kind == yaml.ScalarNode:
			mapping, err := parseShortPort(item.Value)
			if err != nil {
				w.add("%s: %v", at, err)
				continue
			}
			out = append(out, mapping)
		case item.Kind == yaml.MappingNode:
			mapping, err := w.parseLongPort(item, at)
			if err != nil {
				w.add("%s: %v", at, err)
				continue
			}
			out = append(out, mapping)
		default:
			w.add("%s: expected a scalar or a mapping, got %s", at, kindName(item))
		}
	}
	return out
}

// parseShortPort reads the string form:
//
//	"80"                       container port only, nothing published
//	"8080:80"                  host:container
//	"127.0.0.1:8080:80/udp"    host ip, host port, container port, protocol
//	"3000-3005:3000-3005"      a range of host ports
//	"[::1]:8080:80"            a bracketed IPv6 host address
//
// The container end of a range is not kept: model.PortMapping has one container
// port, and the host range is the part a port-conflict check needs.
func parseShortPort(spec string) (model.PortMapping, error) {
	mapping := model.PortMapping{Protocol: "tcp"}

	rest := strings.TrimSpace(spec)
	if rest == "" {
		return mapping, fmt.Errorf("empty port specification")
	}

	if slash := strings.LastIndex(rest, "/"); slash >= 0 {
		protocol := strings.ToLower(strings.TrimSpace(rest[slash+1:]))
		if protocol == "" {
			return mapping, fmt.Errorf("%q: no protocol after the slash", spec)
		}
		mapping.Protocol = protocol
		rest = rest[:slash]
	}

	bracketed := false
	if strings.HasPrefix(rest, "[") {
		closeAt := strings.Index(rest, "]")
		if closeAt < 0 {
			return mapping, fmt.Errorf("%q: unterminated [ipv6] host address", spec)
		}
		mapping.HostIP = rest[1:closeAt]
		rest = strings.TrimPrefix(rest[closeAt+1:], ":")
		bracketed = true
	}

	parts := strings.Split(rest, ":")
	var hostSpec, containerSpec string

	switch {
	case bracketed && len(parts) == 2:
		hostSpec, containerSpec = parts[0], parts[1]
	case bracketed:
		return mapping, fmt.Errorf("%q: a host address needs both a host and a container port", spec)
	case len(parts) == 1:
		containerSpec = parts[0]
	case len(parts) == 2:
		hostSpec, containerSpec = parts[0], parts[1]
	case len(parts) == 3:
		mapping.HostIP = strings.TrimSpace(parts[0])
		hostSpec, containerSpec = parts[1], parts[2]
	default:
		return mapping, fmt.Errorf("%q: too many colon-separated parts (an IPv6 address must be written in brackets)", spec)
	}

	containerStart, _, err := parsePortRange(containerSpec)
	if err != nil {
		return mapping, fmt.Errorf("%q: container port: %w", spec, err)
	}
	mapping.ContainerPort = containerStart

	if strings.TrimSpace(hostSpec) != "" {
		start, end, err := parsePortRange(hostSpec)
		if err != nil {
			return mapping, fmt.Errorf("%q: host port: %w", spec, err)
		}
		mapping.HostPort, mapping.HostPortEnd = start, end
	}

	return mapping, nil
}

// parseLongPort reads the mapping form: target, published, protocol, host_ip and
// mode. `mode` is understood and deliberately dropped — the manifest types have
// nowhere to keep it and no rule asks about it.
func (w *warner) parseLongPort(node *yaml.Node, at string) (model.PortMapping, error) {
	mapping := model.PortMapping{Protocol: "tcp"}

	target := field(node, "target")
	if target == nil || isNull(target) {
		return mapping, fmt.Errorf("no target port")
	}
	text, ok := str(target)
	if !ok {
		return mapping, fmt.Errorf("target: expected a port number, got %s", kindName(target))
	}
	start, _, err := parsePortRange(text)
	if err != nil {
		return mapping, fmt.Errorf("target: %w", err)
	}
	mapping.ContainerPort = start

	if published := field(node, "published"); published != nil && !isNull(published) {
		text, ok := str(published)
		if !ok {
			w.add("%s.published: expected a port number, got %s", at, kindName(published))
		} else if strings.TrimSpace(text) != "" {
			start, end, err := parsePortRange(text)
			if err != nil {
				w.add("%s.published: %v", at, err)
			} else {
				mapping.HostPort, mapping.HostPortEnd = start, end
			}
		}
	}

	if protocol, ok := str(field(node, "protocol")); ok && strings.TrimSpace(protocol) != "" {
		mapping.Protocol = strings.ToLower(strings.TrimSpace(protocol))
	}
	if hostIP, ok := str(field(node, "host_ip")); ok {
		mapping.HostIP = strings.TrimSpace(hostIP)
	}

	return mapping, nil
}

// parsePortRange reads "8080" or "3000-3005". The end equals the start for a
// single port, which is what model.PortMapping.HostPorts expects.
func parsePortRange(spec string) (int, int, error) {
	text := strings.TrimSpace(spec)
	if text == "" {
		return 0, 0, fmt.Errorf("empty port")
	}

	low, high, isRange := strings.Cut(text, "-")
	start, err := parsePort(low)
	if err != nil {
		return 0, 0, err
	}
	if !isRange {
		return start, start, nil
	}

	end, err := parsePort(high)
	if err != nil {
		return 0, 0, err
	}
	if end < start {
		return 0, 0, fmt.Errorf("%q: the range ends below where it starts", text)
	}
	return start, end, nil
}

func parsePort(spec string) (int, error) {
	text := strings.TrimSpace(spec)
	port, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("%q is not a port number", text)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("%d is outside the port range 1-65535", port)
	}
	return port, nil
}

// expose reads `expose:`, which declares container-internal ports. A protocol
// suffix is accepted and dropped: model.ManifestService.Expose is a port list.
func (w *warner) expose(node *yaml.Node, where string) []int {
	if node == nil || isNull(node) {
		return nil
	}
	if node.Kind != yaml.SequenceNode {
		w.add("%s: expected a sequence, got %s", where, kindName(node))
		return nil
	}

	var out []int
	for i, item := range items(node) {
		at := fmt.Sprintf("%s[%d]", where, i)
		text, ok := str(item)
		if !ok {
			w.add("%s: expected a port number, got %s", at, kindName(item))
			continue
		}
		if slash := strings.LastIndex(text, "/"); slash >= 0 {
			text = text[:slash]
		}
		port, err := parsePort(text)
		if err != nil {
			w.add("%s: %v", at, err)
			continue
		}
		out = append(out, port)
	}
	return out
}

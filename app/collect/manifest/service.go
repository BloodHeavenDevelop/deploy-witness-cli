package manifest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"gopkg.in/yaml.v3"
)

// parseService reads one service block. Every field is optional and every field is
// read defensively: a service that declares one thing in a shape this parser does
// not expect still contributes everything else it declared.
func (w *warner) parseService(name string, node *yaml.Node, dir string) model.ManifestService {
	service := model.ManifestService{Name: name}
	where := "services." + name

	node = resolve(node)
	switch {
	case node == nil || isNull(node):
		w.add("%s: the service block is empty", where)
		return service
	case node.Kind != yaml.MappingNode:
		w.add("%s: expected a mapping, got %s", where, kindName(node))
		return service
	}

	if image := field(node, "image"); image != nil && !isNull(image) {
		if text, ok := str(image); ok {
			service.Image = parseImage(text)
		} else {
			w.add("%s.image: expected a string, got %s", where, kindName(image))
		}
	}

	service.Build = w.build(field(node, "build"), where+".build")
	service.ContainerName = w.scalar(node, where, "container_name")
	service.Platform = w.scalar(node, where, "platform")
	service.Restart = w.scalar(node, where, "restart")
	service.NetworkMode = w.scalar(node, where, "network_mode")

	service.Ports = w.ports(field(node, "ports"), where+".ports")
	service.Expose = w.expose(field(node, "expose"), where+".expose")

	service.Volumes = w.volumeMounts(field(node, "volumes"), where+".volumes")
	for _, mount := range service.Volumes {
		if mountsContainerSocket(mount) {
			service.MountsContainerSocket = true
			break
		}
	}

	service.Networks = w.names(field(node, "networks"), where+".networks")
	service.DependsOn = w.names(field(node, "depends_on"), where+".depends_on")

	service.HasHealthcheck = w.healthcheck(field(node, "healthcheck"), where+".healthcheck")
	service.EnvNames = w.envNames(field(node, "environment"), where+".environment")
	service.EnvFiles = w.envFiles(field(node, "env_file"), where+".env_file", dir)

	w.resources(node, where, &service)

	if privileged := field(node, "privileged"); privileged != nil && !isNull(privileged) {
		if value, ok := parseBool(privileged); ok {
			service.Privileged = value
		} else {
			w.add("%s.privileged: expected true or false", where)
		}
	}

	// `extends:` pulls the rest of this service out of another file. Nothing here
	// opens that file, so the service is knowingly incomplete and has to say so —
	// an image or a port list that lives in the extended file would otherwise be
	// reported as absent.
	if extends := field(node, "extends"); extends != nil && !isNull(extends) {
		w.add("%s.extends: the extended definition was not followed, so this service's requirements are incomplete", where)
	}

	service.CapAdd = w.stringList(field(node, "cap_add"), where+".cap_add")
	service.Devices = w.stringList(field(node, "devices"), where+".devices")
	service.DNS = w.stringList(field(node, "dns"), where+".dns")
	service.ExtraHosts = w.extraHosts(field(node, "extra_hosts"), where+".extra_hosts")
	service.Labels = w.labels(field(node, "labels"), where+".labels")

	return service
}

// build reads `build:` in both forms and returns the build context.
//
// The long form without a context is invalid compose, but the fact that the
// service is built rather than pulled changes what several rules mean, so the
// context is assumed to be the compose file's own directory and the assumption is
// reported instead of the whole key being dropped.
func (w *warner) build(node *yaml.Node, where string) string {
	if node == nil || isNull(node) {
		return ""
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Value
	case yaml.MappingNode:
		if context, ok := str(field(node, "context")); ok && strings.TrimSpace(context) != "" {
			return context
		}
		w.add("%s: no context; the service is built, and the context was taken to be \".\"", where)
		return "."
	}
	w.add("%s: expected a path or a mapping, got %s", where, kindName(node))
	return ""
}

// scalar reads an optional scalar field.
func (w *warner) scalar(node *yaml.Node, where, key string) string {
	value := field(node, key)
	if value == nil || isNull(value) {
		return ""
	}
	text, ok := str(value)
	if !ok {
		w.add("%s.%s: expected a scalar, got %s", where, key, kindName(value))
		return ""
	}
	return text
}

// stringList reads a field that is either one scalar or a sequence of them —
// `dns`, `cap_add`, `devices`.
func (w *warner) stringList(node *yaml.Node, where string) []string {
	if node == nil || isNull(node) {
		return nil
	}
	if text, ok := str(node); ok {
		return []string{text}
	}
	if node.Kind != yaml.SequenceNode {
		w.add("%s: expected a scalar or a sequence, got %s", where, kindName(node))
		return nil
	}

	var out []string
	for i, item := range items(node) {
		text, ok := str(item)
		if !ok {
			w.add("%s[%d]: expected a scalar, got %s", where, i, kindName(item))
			continue
		}
		out = append(out, text)
	}
	return out
}

// names reads a field that is either a sequence of names or a mapping keyed by
// them: `networks` (whose values hold aliases) and `depends_on` (whose values hold
// start-up conditions). Only the names are kept — the manifest types have nowhere
// to put a condition, and the dependency itself is the requirement.
func (w *warner) names(node *yaml.Node, where string) []string {
	if node == nil || isNull(node) {
		return nil
	}
	if node.Kind == yaml.MappingNode {
		entries := mapEntries(node)
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			out = append(out, e.key)
		}
		return out
	}
	return w.stringList(node, where)
}

// healthcheck reports whether the service actually has one.
//
// `healthcheck: {disable: true}` and a test of ["NONE"] both switch the image's
// own healthcheck off, so the presence of the key is not the answer — an audit
// that read it that way would report a health check on a container that has none.
func (w *warner) healthcheck(node *yaml.Node, where string) bool {
	if node == nil || isNull(node) {
		return false
	}
	if node.Kind != yaml.MappingNode {
		w.add("%s: expected a mapping, got %s", where, kindName(node))
		return false
	}

	if disable := field(node, "disable"); disable != nil && !isNull(disable) {
		value, ok := parseBool(disable)
		if !ok {
			w.add("%s.disable: expected true or false", where)
		} else if value {
			return false
		}
	}

	if test := field(node, "test"); test != nil && !isNull(test) {
		if text, ok := str(test); ok {
			if strings.EqualFold(strings.TrimSpace(text), "none") {
				return false
			}
		} else if entries := items(test); len(entries) > 0 {
			if first, ok := str(entries[0]); ok && strings.EqualFold(strings.TrimSpace(first), "none") {
				return false
			}
		}
	}

	return true
}

// envNames reads `environment:` and keeps the variable names only.
//
// Values are not stored, not returned and not reported — not the literal ones and
// not the substituted ones. This is the one place in the parser where reading less
// than the file says is the point.
func (w *warner) envNames(node *yaml.Node, where string) []string {
	if node == nil || isNull(node) {
		return nil
	}

	switch node.Kind {
	case yaml.MappingNode:
		entries := mapEntries(node)
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			out = append(out, e.key)
		}
		return out

	case yaml.SequenceNode:
		var out []string
		for i, item := range items(node) {
			text, ok := str(item)
			if !ok {
				w.add("%s[%d]: expected KEY=value or KEY, got %s", where, i, kindName(item))
				continue
			}
			name, _, _ := strings.Cut(text, "=")
			name = strings.TrimSpace(name)
			if name == "" {
				w.add("%s[%d]: an entry with no variable name", where, i)
				continue
			}
			out = append(out, name)
		}
		return out
	}

	w.add("%s: expected a mapping or a sequence, got %s", where, kindName(node))
	return nil
}

// labels reads `labels:` in both the mapping and the `KEY=value` sequence form.
//
// Unlike `environment`, the values are kept. Labels are configuration rather than
// credentials, and they are the only place a compose file states which domain a
// service expects to be reached at — a Traefik router rule, a VIRTUAL_HOST label.
// Without them the domain-collision check has nothing to compare against.
func (w *warner) labels(node *yaml.Node, where string) map[string]string {
	if node == nil || isNull(node) {
		return nil
	}

	out := map[string]string{}
	switch node.Kind {
	case yaml.MappingNode:
		for _, e := range mapEntries(node) {
			value, ok := str(e.value)
			if !ok {
				w.add("%s.%s: expected a scalar label value, got %s", where, e.key, kindName(e.value))
				continue
			}
			out[e.key] = value
		}

	case yaml.SequenceNode:
		for i, item := range items(node) {
			text, ok := str(item)
			if !ok {
				w.add("%s[%d]: expected KEY=value, got %s", where, i, kindName(item))
				continue
			}
			key, value, found := strings.Cut(text, "=")
			key = strings.TrimSpace(key)
			if key == "" {
				w.add("%s[%d]: a label with no name", where, i)
				continue
			}
			if !found {
				// `labels: [com.example.flag]` is a label with an empty value, which
				// is legal and is not the same as the label being absent.
				out[key] = ""
				continue
			}
			out[key] = strings.TrimSpace(value)
		}

	default:
		w.add("%s: expected a mapping or a sequence, got %s", where, kindName(node))
		return nil
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// envFiles reads `env_file:` in all three shapes: one path, a list of paths, and a
// list of {path, required} mappings. Existence is checked by stat'ing the path
// relative to the compose file's directory; the contents are never opened.
func (w *warner) envFiles(node *yaml.Node, where, dir string) []model.EnvFileRef {
	if node == nil || isNull(node) {
		return nil
	}

	if text, ok := str(node); ok {
		return []model.EnvFileRef{w.envFile(text, dir)}
	}
	if node.Kind != yaml.SequenceNode {
		w.add("%s: expected a path, a sequence or a sequence of mappings, got %s", where, kindName(node))
		return nil
	}

	var out []model.EnvFileRef
	for i, item := range items(node) {
		at := fmt.Sprintf("%s[%d]", where, i)
		switch {
		case item == nil || isNull(item):
			w.add("%s: empty entry", at)
		case item.Kind == yaml.ScalarNode:
			out = append(out, w.envFile(item.Value, dir))
		case item.Kind == yaml.MappingNode:
			text, ok := str(field(item, "path"))
			if !ok || strings.TrimSpace(text) == "" {
				w.add("%s: no path", at)
				continue
			}
			// `required: false` says the deployment tolerates the file being absent.
			// It changes what a missing file means, not whether it is there, so it is
			// not recorded: EnvFileRef has Path and Exists and nothing else.
			out = append(out, w.envFile(text, dir))
		default:
			w.add("%s: expected a path or a mapping, got %s", at, kindName(item))
		}
	}
	return out
}

// envFile stats one referenced env file. Path keeps what the manifest wrote, so a
// finding quotes the file rather than a path the reader never typed; the stat is
// done against the compose file's directory, which is how compose resolves it.
//
// The file is stat'ed and nothing more. Its contents are the values this tool has
// promised not to read.
func (w *warner) envFile(declared, dir string) model.EnvFileRef {
	ref := model.EnvFileRef{Path: declared}

	resolved := declared
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(dir, resolved)
	}

	switch _, err := os.Stat(resolved); {
	case err == nil:
		ref.Exists = true
	case errors.Is(err, fs.ErrNotExist):
		// Absent is an ordinary answer, and Exists already says it.
	default:
		w.add("env_file %q: %v", declared, err)
	}
	return ref
}

// resources reads deploy.resources, and falls back to the pre-`deploy` keys
// (`mem_limit`, `mem_reservation`, `cpus`) when they are what the file uses. A
// limit written the old way is still a limit; reporting zero for it would tell the
// reader the manifest asked for nothing.
func (w *warner) resources(node *yaml.Node, where string, service *model.ManifestService) {
	resources := field(field(node, "deploy"), "resources")
	limits := field(resources, "limits")
	reservations := field(resources, "reservations")

	service.MemLimitBytes = w.memory(limits, where+".deploy.resources.limits", "memory")
	service.MemReservationBytes = w.memory(reservations, where+".deploy.resources.reservations", "memory")
	service.CPULimit = w.scalar(limits, where+".deploy.resources.limits", "cpus")
	service.CPUReservation = w.scalar(reservations, where+".deploy.resources.reservations", "cpus")

	if service.MemLimitBytes == 0 {
		service.MemLimitBytes = w.memory(node, where, "mem_limit")
	}
	if service.MemReservationBytes == 0 {
		service.MemReservationBytes = w.memory(node, where, "mem_reservation")
	}
	if service.CPULimit == "" {
		service.CPULimit = w.scalar(node, where, "cpus")
	}
}

// memory reads one memory field as a byte count.
func (w *warner) memory(node *yaml.Node, where, key string) int64 {
	value := field(node, key)
	if value == nil || isNull(value) {
		return 0
	}
	text, ok := str(value)
	if !ok {
		w.add("%s.%s: expected a memory size, got %s", where, key, kindName(value))
		return 0
	}
	bytes, err := parseMemory(text)
	if err != nil {
		w.add("%s.%s: %v", where, key, err)
		return 0
	}
	return bytes
}

// extraHosts reads `extra_hosts:` in both the "host:address" sequence form and the
// mapping form, normalising both to "host:address".
func (w *warner) extraHosts(node *yaml.Node, where string) []string {
	if node == nil || isNull(node) {
		return nil
	}
	if node.Kind == yaml.MappingNode {
		entries := mapEntries(node)
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			address, ok := str(e.value)
			if !ok {
				w.add("%s.%s: expected an address, got %s", where, e.key, kindName(e.value))
				continue
			}
			out = append(out, e.key+":"+address)
		}
		return out
	}
	return w.stringList(node, where)
}

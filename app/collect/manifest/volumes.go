package manifest

import (
	"fmt"
	"path"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"gopkg.in/yaml.v3"
)

// volumeMounts reads a service's `volumes:` in both the short string form and the
// long mapping form.
func (w *warner) volumeMounts(node *yaml.Node, where string) []model.VolumeMount {
	if node == nil || isNull(node) {
		return nil
	}
	if node.Kind != yaml.SequenceNode {
		w.add("%s: expected a sequence, got %s", where, kindName(node))
		return nil
	}

	var out []model.VolumeMount
	for i, item := range items(node) {
		at := fmt.Sprintf("%s[%d]", where, i)
		switch {
		case item == nil || isNull(item):
			w.add("%s: empty entry", at)
		case item.Kind == yaml.ScalarNode:
			mount, err := parseShortVolume(item.Value)
			if err != nil {
				w.add("%s: %v", at, err)
				continue
			}
			out = append(out, mount)
		case item.Kind == yaml.MappingNode:
			mount, err := w.parseLongVolume(item, at)
			if err != nil {
				w.add("%s: %v", at, err)
				continue
			}
			out = append(out, mount)
		default:
			w.add("%s: expected a scalar or a mapping, got %s", at, kindName(item))
		}
	}
	return out
}

// parseShortVolume reads the string form:
//
//	"/container"                    an anonymous volume
//	"named:/container"              a named volume
//	"/host:/container:ro"           a read-only bind mount
//	"./relative:/container"         a bind mount relative to the compose file
func parseShortVolume(spec string) (model.VolumeMount, error) {
	var mount model.VolumeMount

	text := strings.TrimSpace(spec)
	if text == "" {
		return mount, fmt.Errorf("empty volume specification")
	}

	parts := strings.Split(text, ":")
	var options string

	switch len(parts) {
	case 1:
		// No source at all: docker creates an anonymous volume for the path.
		mount.Target = parts[0]
	case 2:
		mount.Source, mount.Target = parts[0], parts[1]
	case 3:
		mount.Source, mount.Target, options = parts[0], parts[1], parts[2]
	default:
		return mount, fmt.Errorf("%q: too many colon-separated parts", text)
	}

	if strings.TrimSpace(mount.Target) == "" {
		return mount, fmt.Errorf("%q: no container path", text)
	}

	mount.Kind = classifyMount(mount.Source)
	for _, option := range strings.Split(options, ",") {
		switch strings.ToLower(strings.TrimSpace(option)) {
		case "ro", "readonly":
			mount.ReadOnly = true
		}
	}
	return mount, nil
}

// parseLongVolume reads the mapping form: type, source, target and read_only.
// The per-type sub-blocks (`bind:`, `volume:`, `tmpfs:`) carry tuning options the
// manifest types have nowhere to keep, so they are read past rather than reported.
func (w *warner) parseLongVolume(node *yaml.Node, at string) (model.VolumeMount, error) {
	var mount model.VolumeMount

	target, ok := str(field(node, "target"))
	if !ok || strings.TrimSpace(target) == "" {
		return mount, fmt.Errorf("no target path")
	}
	mount.Target = target

	if source, ok := str(field(node, "source")); ok {
		mount.Source = source
	}

	declared, hasType := str(field(node, "type"))
	switch strings.ToLower(strings.TrimSpace(declared)) {
	case model.MountBind, model.MountVolume, model.MountTmpfs:
		mount.Kind = strings.ToLower(strings.TrimSpace(declared))
	case "":
		mount.Kind = classifyMount(mount.Source)
		if hasType {
			w.add("%s.type: empty; the kind was inferred from the source instead", at)
		}
	default:
		mount.Kind = classifyMount(mount.Source)
		w.add("%s.type: %q is not a mount type this parser knows; the kind was inferred from the source instead",
			at, declared)
	}

	readOnly := field(node, "read_only")
	if readOnly == nil {
		readOnly = field(node, "readonly")
	}
	if readOnly != nil && !isNull(readOnly) {
		if value, ok := parseBool(readOnly); ok {
			mount.ReadOnly = value
		} else {
			w.add("%s.read_only: expected true or false", at)
		}
	}

	return mount, nil
}

// classifyMount decides whether a source is a host path or a volume name. An
// absolute path, a relative one and a `~` path are binds; a bare name is a volume;
// nothing at all is an anonymous volume.
func classifyMount(source string) string {
	text := strings.TrimSpace(source)
	switch {
	case text == "":
		return model.MountVolume
	case strings.HasPrefix(text, "/"),
		strings.HasPrefix(text, "./"),
		strings.HasPrefix(text, "../"),
		strings.HasPrefix(text, "~"),
		text == ".", text == "..":
		return model.MountBind
	}
	return model.MountVolume
}

// containerSocketDirs are the runtime directories that contain the API socket.
// Mounting one of them whole hands over the socket just as directly as mounting
// the socket itself does.
var containerSocketDirs = map[string]bool{
	"/var/run/docker": true,
	"/run/docker":     true,
	"/var/run/podman": true,
	"/run/podman":     true,
}

// mountsContainerSocket reports whether a mount gives the container the host's
// container-runtime API — /var/run/docker.sock, /run/docker.sock,
// /run/podman/podman.sock and the like. Write access to that socket is root on
// the host, whatever the container's own user is.
func mountsContainerSocket(mount model.VolumeMount) bool {
	if mount.Kind != model.MountBind || mount.Source == "" {
		return false
	}
	cleaned := path.Clean(mount.Source)
	if containerSocketDirs[cleaned] {
		return true
	}
	switch path.Base(cleaned) {
	case "docker.sock", "podman.sock":
		return true
	}
	return false
}

package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"gopkg.in/yaml.v3"
)

// FromComposeConfig reads the model `docker compose config --format json` printed
// for the planned run: the files merged in order, the env files and profiles
// applied, every variable interpolated and every relative path resolved by Compose
// itself. It is the requirements side of a preflight whenever Compose is available,
// because it is the model Compose will actually run — not this package's reading of
// the files.
//
// The output carries interpolated values, environment values among them. They are
// decoded into types that have nowhere to keep them: `environment:` contributes its
// variable names, and nothing else of the document survives this function. raw is
// never stored, logged or written, by this package or its caller.
//
// first is the first Compose file of the plan; it becomes Manifest.Path, which is
// what evidence quotes.
//
// composeVersion is the version of the Compose that printed the model ("2.33.0",
// "5.5.0"): the model's encoding of create_host_path changed between them — 2.x
// prints only `true`, 5.x only `false` — so an absent key means the opposite thing
// in each, and only the version tells which.
func FromComposeConfig(raw []byte, first, composeVersion string, result *model.SectionResult) (*model.Manifest, error) {
	var doc composeDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("docker compose config printed something that is not its JSON model: %w", err)
	}
	if doc.Services == nil {
		return nil, fmt.Errorf("docker compose config printed a model with no services")
	}

	w := &warner{path: first, result: result, seen: make(map[string]bool), composeMajor: majorOf(composeVersion)}
	manifest := &model.Manifest{Path: first, Name: doc.Name}

	names := make([]string, 0, len(doc.Services))
	for name := range doc.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		manifest.Services = append(manifest.Services, w.resolvedService(name, doc.Services[name]))
	}

	for _, key := range sortedKeys(doc.Networks) {
		n := doc.Networks[key]
		network := model.ManifestNetwork{Name: key, EngineName: n.Name, Driver: n.Driver, External: bool(n.External)}
		for _, c := range n.IPAM.Config {
			if strings.TrimSpace(c.Subnet) != "" {
				network.Subnets = append(network.Subnets, c.Subnet)
			}
		}
		manifest.Networks = append(manifest.Networks, network)
	}
	for _, key := range sortedKeys(doc.Volumes) {
		v := doc.Volumes[key]
		manifest.Volumes = append(manifest.Volumes, model.ManifestVolume{Name: key, EngineName: v.Name, Driver: v.Driver,
			External: bool(v.External)})
	}

	manifest.Warnings = w.warnings
	return manifest, nil
}

// The JSON model, as far as this audit reads it. Everything else in the document —
// commands, entrypoints, secrets, configs, environment values — has no field here
// and is dropped by the decoder.
type composeDoc struct {
	Name     string                     `json:"name"`
	Services map[string]composeService  `json:"services"`
	Networks map[string]composeNetwork  `json:"networks"`
	Volumes  map[string]composeResource `json:"volumes"`
}

type composeService struct {
	Image         string                     `json:"image"`
	Build         *composeBuild              `json:"build"`
	ContainerName string                     `json:"container_name"`
	Platform      string                     `json:"platform"`
	Restart       string                     `json:"restart"`
	NetworkMode   string                     `json:"network_mode"`
	Ports         []composePort              `json:"ports"`
	Expose        []json.RawMessage          `json:"expose"`
	Volumes       []composeMount             `json:"volumes"`
	Networks      map[string]json.RawMessage `json:"networks"`
	DependsOn     map[string]json.RawMessage `json:"depends_on"`
	Healthcheck   *composeHealthcheck        `json:"healthcheck"`
	// Environment is decoded into names only: the values are read into nothing.
	Environment map[string]json.RawMessage `json:"environment"`
	EnvFile     []composeEnvFile           `json:"env_file"`
	Deploy      *composeDeploy             `json:"deploy"`
	MemLimit    json.RawMessage            `json:"mem_limit"`
	MemReserve  json.RawMessage            `json:"mem_reservation"`
	Privileged  bool                       `json:"privileged"`
	CapAdd      []string                   `json:"cap_add"`
	Devices     []json.RawMessage          `json:"devices"`
	DNS         []string                   `json:"dns"`
	ExtraHosts  []string                   `json:"extra_hosts"`
	Labels      map[string]string          `json:"labels"`
	User        string                     `json:"user"`
	Profiles    []string                   `json:"profiles"`
}

type composeBuild struct {
	Context string `json:"context"`
}

type composePort struct {
	Target    int    `json:"target"`
	Published string `json:"published"`
	HostIP    string `json:"host_ip"`
	Protocol  string `json:"protocol"`
	Mode      string `json:"mode"`
}

type composeMount struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
	Bind     *struct {
		CreateHostPath *bool  `json:"create_host_path"`
		SELinux        string `json:"selinux"`
		Propagation    string `json:"propagation"`
	} `json:"bind"`
	Consistency string `json:"consistency"`
}

type composeHealthcheck struct {
	Test    json.RawMessage `json:"test"`
	Disable bool            `json:"disable"`
}

type composeEnvFile struct {
	Path     string `json:"path"`
	Required *bool  `json:"required"`
}

func (e *composeEnvFile) UnmarshalJSON(raw []byte) error {
	// Older Compose prints env_file as a list of paths.
	var path string
	if err := json.Unmarshal(raw, &path); err == nil {
		e.Path = path
		return nil
	}
	type plain composeEnvFile
	return json.Unmarshal(raw, (*plain)(e))
}

type composeDeploy struct {
	Resources struct {
		Limits       composeLimits `json:"limits"`
		Reservations composeLimits `json:"reservations"`
	} `json:"resources"`
}

type composeLimits struct {
	Memory json.RawMessage `json:"memory"`
	CPUs   json.RawMessage `json:"cpus"`
}

type composeNetwork struct {
	Name     string          `json:"name"`
	Driver   string          `json:"driver"`
	External flexBool        `json:"external"`
	IPAM     composeIPAM     `json:"ipam"`
	Labels   json.RawMessage `json:"labels"`
}

type composeIPAM struct {
	Config []struct {
		Subnet string `json:"subnet"`
	} `json:"config"`
}

type composeResource struct {
	Name     string   `json:"name"`
	Driver   string   `json:"driver"`
	External flexBool `json:"external"`
}

// flexBool accepts `true` and the legacy `{name: …}` form of `external`.
type flexBool bool

func (b *flexBool) UnmarshalJSON(raw []byte) error {
	text := strings.TrimSpace(string(raw))
	switch {
	case text == "true":
		*b = true
	case strings.HasPrefix(text, "{"):
		*b = true
	default:
		*b = false
	}
	return nil
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (w *warner) resolvedService(name string, s composeService) model.ManifestService {
	where := "services." + name
	svc := model.ManifestService{
		Name:          name,
		ContainerName: s.ContainerName,
		Platform:      s.Platform,
		Restart:       s.Restart,
		NetworkMode:   s.NetworkMode,
		Privileged:    s.Privileged,
		CapAdd:        s.CapAdd,
		DNS:           s.DNS,
		ExtraHosts:    s.ExtraHosts,
		Labels:        s.Labels,
		User:          s.User,
	}
	if s.Image != "" {
		svc.Image = parseImage(s.Image)
	}
	if s.Build != nil {
		svc.Build = s.Build.Context
		if svc.Build == "" {
			svc.Build = "."
		}
	}

	for i, p := range s.Ports {
		mapping, err := resolvedPort(p)
		if err != nil {
			w.add("%s.ports[%d]: %v", where, i, err)
			continue
		}
		svc.Ports = append(svc.Ports, mapping)
	}
	for i, raw := range s.Expose {
		text := strings.Trim(strings.TrimSpace(string(raw)), `"`)
		start, end, err := parsePortRange(strings.SplitN(text, "/", 2)[0])
		if err != nil {
			w.add("%s.expose[%d]: %v", where, i, err)
			continue
		}
		for port := start; port <= end; port++ {
			svc.Expose = append(svc.Expose, port)
		}
	}

	for _, m := range s.Volumes {
		mount := model.VolumeMount{Kind: strings.ToLower(m.Type), Source: m.Source, Target: m.Target, ReadOnly: m.ReadOnly}
		if mount.Kind == model.MountBind {
			// An explicit create_host_path is the answer. An absent one is the
			// version's default: Compose 5.x omits true (and prints false), Compose
			// 2.x omits false (and prints true). Verified on 2.33.0 and 5.5.0; with
			// no version it stays unknown.
			mount.CreateHostPath = w.defaultCreateHostPath()
			if m.Bind != nil {
				if m.Bind.CreateHostPath != nil {
					value := *m.Bind.CreateHostPath
					mount.CreateHostPath = &value
				}
				if m.Bind.SELinux != "" {
					mount.Options = append(mount.Options, "selinux="+m.Bind.SELinux)
				}
				if m.Bind.Propagation != "" {
					mount.Options = append(mount.Options, "propagation="+m.Bind.Propagation)
				}
			}
			if m.Consistency != "" {
				mount.Options = append(mount.Options, "consistency="+m.Consistency)
			}
		}
		switch mount.Kind {
		case model.MountBind, model.MountVolume, model.MountTmpfs:
		case "":
			mount.Kind = classifyMount(mount.Source)
		default:
			w.add("%s.volumes: mount type %q is not one this audit checks; %s is not compared", where, m.Type, m.Target)
		}
		svc.Volumes = append(svc.Volumes, mount)
		if mountsContainerSocket(mount) {
			svc.MountsContainerSocket = true
		}
	}

	svc.Networks = sortedKeys(s.Networks)
	svc.DependsOn = sortedKeys(s.DependsOn)
	svc.HasHealthcheck = s.Healthcheck != nil && !s.Healthcheck.Disable && len(s.Healthcheck.Test) > 0 &&
		string(s.Healthcheck.Test) != "null"
	svc.EnvNames = sortedKeys(s.Environment)

	for _, ref := range s.EnvFile {
		if strings.TrimSpace(ref.Path) == "" {
			continue
		}
		file := w.envFile(ref.Path, "")
		file.Optional = ref.Required != nil && !*ref.Required
		svc.EnvFiles = append(svc.EnvFiles, file)
	}

	if s.Deploy != nil {
		svc.MemReservationBytes = w.resolvedBytes(s.Deploy.Resources.Reservations.Memory, where+".deploy.resources.reservations.memory")
		svc.MemLimitBytes = w.resolvedBytes(s.Deploy.Resources.Limits.Memory, where+".deploy.resources.limits.memory")
		svc.CPUReservation = rawScalar(s.Deploy.Resources.Reservations.CPUs)
		svc.CPULimit = rawScalar(s.Deploy.Resources.Limits.CPUs)
	}
	if svc.MemLimitBytes == 0 {
		svc.MemLimitBytes = w.resolvedBytes(s.MemLimit, where+".mem_limit")
	}
	if svc.MemReservationBytes == 0 {
		svc.MemReservationBytes = w.resolvedBytes(s.MemReserve, where+".mem_reservation")
	}

	for _, raw := range s.Devices {
		var device struct {
			Source string `json:"source"`
			Target string `json:"target"`
		}
		var text string
		switch {
		case json.Unmarshal(raw, &text) == nil:
			svc.Devices = append(svc.Devices, text)
		case json.Unmarshal(raw, &device) == nil && device.Source != "":
			target := device.Target
			if target == "" {
				target = device.Source
			}
			svc.Devices = append(svc.Devices, device.Source+":"+target)
		}
	}
	return svc
}

// resolvedPort converts one port of the resolved model. Compose prints `published`
// as a string — a port, a range, or nothing for an ephemeral host port.
func resolvedPort(p composePort) (model.PortMapping, error) {
	mapping := model.PortMapping{
		HostIP:        strings.Trim(p.HostIP, "[]"),
		ContainerPort: p.Target,
		Protocol:      strings.ToLower(p.Protocol),
	}
	if mapping.Protocol == "" {
		mapping.Protocol = "tcp"
	}
	if strings.TrimSpace(p.Published) == "" {
		return mapping, nil
	}
	start, end, err := parsePortRange(p.Published)
	if err != nil {
		return mapping, err
	}
	mapping.HostPort = start
	if end != start {
		mapping.HostPortEnd = end
	}
	return mapping, nil
}

func (w *warner) resolvedBytes(raw json.RawMessage, where string) int64 {
	text := rawScalar(raw)
	if text == "" || text == "0" {
		return 0
	}
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		return n
	}
	n, err := parseMemory(text)
	if err != nil {
		w.add("%s: %v", where, err)
		return 0
	}
	return n
}

func (w *warner) defaultCreateHostPath() *bool {
	switch {
	case w.composeMajor >= 5:
		v := true
		return &v
	case w.composeMajor >= 2:
		v := false
		return &v
	}
	return nil
}

// majorOf is the major number of a version string, 0 when there is none.
func majorOf(version string) int {
	head, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(version), "v"), ".")
	n, err := strconv.Atoi(head)
	if err != nil {
		return 0
	}
	return n
}

func rawScalar(raw json.RawMessage) string {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return ""
	}
	return strings.Trim(text, `"`)
}

// maxComposeRefs bounds the walk over local includes, so a file tree that keeps
// referring to new files cannot keep the check busy.
const maxComposeRefs = 256

// composeDefaultNames are the files Compose looks for when an include names a
// directory.
var composeDefaultNames = []string{"compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"}

// RemoteIncludes returns the sources a Compose file pulls in that this audit cannot
// keep local: an `include:` or `extends.file` naming a remote source (a git URL, an
// OCI artifact, anything with a scheme), or one whose path depends on a variable and
// so cannot be known before Compose interpolates it. Resolving the plan with one of
// them could fetch it, which an offline audit must not do.
//
// Local includes and extends are followed, since a file they name can carry the same
// references. A relative reference is tried against the directory of the file holding
// it and against each of bases (the project directory). A local file that does not
// exist is left for Compose to reject. Only these references are looked at.
func RemoteIncludes(path string, bases ...string) ([]string, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	walk := &composeRefWalk{bases: bases, seen: make(map[string]bool)}
	if err := walk.file(path); err != nil {
		return nil, err
	}
	return walk.remote, nil
}

type composeRefWalk struct {
	bases  []string
	seen   map[string]bool
	remote []string
}

func (w *composeRefWalk) file(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if w.seen[abs] {
		return nil
	}
	if len(w.seen) >= maxComposeRefs {
		return fmt.Errorf("%s: more than %d files are included", path, maxComposeRefs)
	}
	w.seen[abs] = true

	info, err := os.Stat(abs)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		for _, name := range composeDefaultNames {
			if err := w.file(filepath.Join(abs, name)); err != nil {
				return err
			}
		}
		return nil
	}

	raw, err := os.ReadFile(abs)
	if err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	for {
		var doc map[string]any
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := w.document(doc, filepath.Dir(abs)); err != nil {
			return err
		}
	}

	// Compose applies <name>.override.<ext> beside an included file.
	ext := filepath.Ext(abs)
	return w.file(strings.TrimSuffix(abs, ext) + ".override" + ext)
}

func (w *composeRefWalk) document(doc map[string]any, dir string) error {
	includes, ok := doc["include"].([]any)
	if !ok && doc["include"] != nil {
		includes = []any{doc["include"]}
	}
	for _, item := range includes {
		switch entry := item.(type) {
		case string:
			if err := w.reference(entry, dir); err != nil {
				return err
			}
		case map[string]any:
			switch paths := entry["path"].(type) {
			case string:
				if err := w.reference(paths, dir); err != nil {
					return err
				}
			case []any:
				for _, p := range paths {
					if text, ok := p.(string); ok {
						if err := w.reference(text, dir); err != nil {
							return err
						}
					}
				}
			}
		}
	}

	services, _ := doc["services"].(map[string]any)
	for _, name := range sortedKeys(services) {
		service, _ := services[name].(map[string]any)
		extends, _ := service["extends"].(map[string]any)
		if file, ok := extends["file"].(string); ok {
			if err := w.reference(file, dir); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *composeRefWalk) reference(text, dir string) error {
	text = strings.TrimSpace(text)
	switch {
	case text == "":
		return nil
	case isRemoteSource(text), strings.Contains(text, "$"):
		w.remote = append(w.remote, text)
		return nil
	case filepath.IsAbs(text):
		return w.file(text)
	}
	for _, base := range append([]string{dir}, w.bases...) {
		if err := w.file(filepath.Join(base, text)); err != nil {
			return err
		}
	}
	return nil
}

func isRemoteSource(text string) bool {
	text = strings.TrimSpace(text)
	return strings.Contains(text, "://") || strings.HasPrefix(text, "git@") || strings.HasPrefix(text, "oci:")
}

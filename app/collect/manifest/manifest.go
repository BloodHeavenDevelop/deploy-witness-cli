// Package manifest reads a docker-compose file and reports the requirements it
// declares: the requirements half of the witness section.
//
// It observes nothing about the host and judges nothing. Everything here comes out
// of one file on disk — no command is run, no socket is opened and no registry is
// contacted, so the package is as offline as the rest of the tool. Deciding that a
// requirement collides with the machine is somebody else's job, and keeping the two
// apart is what makes a finding explainable to the person who has to act on it.
//
// Two habits run through the whole package:
//
//   - Environment variable values are never stored. `environment:` contributes
//     names, `env_file:` contributes a path and whether it exists, and the `.env`
//     file beside the compose file is read for ${VARIABLE} substitution only.
//   - A field the parser could not make sense of is reported twice: once in
//     Manifest.Warnings, which travels with the report, and once through
//     SectionResult.Degrade, which stops the section being labelled complete. A
//     requirement that was not understood is not a requirement that was met, and
//     the honest answer to a malformed port list is "this could not be read" rather
//     than an empty list of published ports.
package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"gopkg.in/yaml.v3"
)

// Parse reads a compose file and returns the requirements it declares.
//
// The error result is reserved for the file as a whole: unreadable, not YAML, or a
// top level that is not a mapping. Everything smaller degrades — one unparsable
// port entry costs that entry and a warning, not the file. result may be nil, which
// is only useful in tests; the caller normally passes the witness section's result
// so that warnings reach summary.csv.
func Parse(path string, result *model.SectionResult) (*model.Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var document yaml.Node
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	root := documentRoot(&document)
	if root == nil {
		return nil, fmt.Errorf("%s: the file declares nothing", path)
	}
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: expected a compose file at the top level, got %s", path, kindName(root))
	}

	manifest := &model.Manifest{Path: path}
	w := &warner{path: path, result: result, seen: make(map[string]bool)}

	// The compose file's own directory is the project directory: it is where `.env`
	// is looked for and what every relative path is resolved against.
	dir := filepath.Dir(path)
	dotenv, err := loadDotEnv(filepath.Join(dir, ".env"))
	if err != nil {
		w.add(".env: %v; ${VARIABLE} references may be left unresolved as a result", err)
	}
	interpolate(root, environment{dotenv: dotenv}, w)

	if version := field(root, "version"); version != nil && !isNull(version) {
		if text, ok := str(version); ok {
			manifest.Version = text
		} else {
			w.add("version: expected a string, got %s", kindName(version))
		}
	}

	// `include:` merges other compose files into this one. They are not read — this
	// package parses the one file it was given — so the manifest is short of
	// whatever they declare, and that is reported rather than left to be mistaken
	// for a complete picture.
	if include := field(root, "include"); include != nil && !isNull(include) {
		w.add("include: the included compose files were not read, so this manifest is missing whatever they declare")
	}

	services := field(root, "services")
	switch {
	case services == nil || isNull(services):
		w.add("services: the file declares no services")
	case services.Kind != yaml.MappingNode:
		w.add("services: expected a mapping, got %s", kindName(services))
	default:
		for _, e := range mapEntries(services) {
			manifest.Services = append(manifest.Services, w.parseService(e.key, e.value, dir))
		}
	}

	manifest.Networks = w.networks(field(root, "networks"))
	manifest.Volumes = w.volumes(field(root, "volumes"))
	manifest.Warnings = w.warnings

	return manifest, nil
}

// networks reads the top-level `networks:` block.
func (w *warner) networks(node *yaml.Node) []model.ManifestNetwork {
	if node == nil || isNull(node) {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		w.add("networks: expected a mapping, got %s", kindName(node))
		return nil
	}

	var out []model.ManifestNetwork
	for _, e := range mapEntries(node) {
		// The key is the name services reference, which is the name a collision is
		// reported against. A `name:` override inside the block renames the network in
		// the engine and is not what the rest of the file talks about.
		network := model.ManifestNetwork{Name: e.key}
		where := "networks." + e.key

		body := resolve(e.value)
		switch {
		case body == nil || isNull(body):
			// `mynet:` with nothing under it — the default bridge, and a complete
			// declaration.
		case body.Kind != yaml.MappingNode:
			w.add("%s: expected a mapping, got %s", where, kindName(body))
		default:
			network.Driver = w.scalar(body, where, "driver")
			network.External = w.external(body, where)
			network.Subnets = w.subnets(field(body, "ipam"), where+".ipam")
		}
		out = append(out, network)
	}
	return out
}

// volumes reads the top-level `volumes:` block.
func (w *warner) volumes(node *yaml.Node) []model.ManifestVolume {
	if node == nil || isNull(node) {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		w.add("volumes: expected a mapping, got %s", kindName(node))
		return nil
	}

	var out []model.ManifestVolume
	for _, e := range mapEntries(node) {
		volume := model.ManifestVolume{Name: e.key}
		where := "volumes." + e.key

		body := resolve(e.value)
		switch {
		case body == nil || isNull(body):
			// `data:` with nothing under it — the default local driver.
		case body.Kind != yaml.MappingNode:
			w.add("%s: expected a mapping, got %s", where, kindName(body))
		default:
			volume.Driver = w.scalar(body, where, "driver")
			volume.External = w.external(body, where)
		}
		out = append(out, volume)
	}
	return out
}

// external reads `external:`, which has a boolean form and a legacy mapping form
// (`external: {name: shared}`) that means the same thing.
func (w *warner) external(node *yaml.Node, where string) bool {
	value := field(node, "external")
	if value == nil || isNull(value) {
		return false
	}
	if value.Kind == yaml.MappingNode {
		return true
	}
	external, ok := parseBool(value)
	if !ok {
		w.add("%s.external: expected true or false, got %s", where, kindName(value))
		return false
	}
	return external
}

// subnets reads the explicit IPAM subnets, which are what a subnet-overlap check
// needs. An address pool without a subnet contributes nothing and says so.
func (w *warner) subnets(node *yaml.Node, where string) []string {
	if node == nil || isNull(node) {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		w.add("%s: expected a mapping, got %s", where, kindName(node))
		return nil
	}

	config := field(node, "config")
	if config == nil || isNull(config) {
		return nil
	}
	if config.Kind != yaml.SequenceNode {
		w.add("%s.config: expected a sequence, got %s", where, kindName(config))
		return nil
	}

	var out []string
	for i, item := range items(config) {
		at := fmt.Sprintf("%s.config[%d]", where, i)
		if item == nil || item.Kind != yaml.MappingNode {
			w.add("%s: expected a mapping, got %s", at, kindName(item))
			continue
		}
		subnet := field(item, "subnet")
		if subnet == nil || isNull(subnet) {
			continue
		}
		text, ok := str(subnet)
		if !ok {
			w.add("%s.subnet: expected a CIDR string, got %s", at, kindName(subnet))
			continue
		}
		if strings.TrimSpace(text) == "" {
			w.add("%s.subnet: empty", at)
			continue
		}
		out = append(out, text)
	}
	return out
}

// warner collects everything the parser could not make sense of, and forwards each
// remark to the section result as it happens so that a caller reading only
// summary.csv still learns the manifest was not fully understood.
//
// Duplicates are dropped: one unresolved variable used in ten services is one fact,
// and repeating it ten times buries the other nine warnings.
type warner struct {
	path     string
	result   *model.SectionResult
	warnings []string
	seen     map[string]bool
}

func (w *warner) add(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if w.seen[message] {
		return
	}
	w.seen[message] = true
	w.warnings = append(w.warnings, message)

	if w.result != nil {
		w.result.Degrade(w.path + ": " + message)
	}
}

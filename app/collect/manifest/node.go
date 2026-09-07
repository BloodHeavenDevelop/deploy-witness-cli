package manifest

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Compose allows two shapes for most of its fields, so the file is read through
// yaml.Node rather than decoded into structs: a node keeps the declared order of
// mapping keys (services come out in file order, not map order), keeps the line
// number a warning needs, and lets a field in an unexpected shape be reported and
// skipped instead of failing the whole document.

// resolve follows a YAML alias to the node it points at. The bound is there only
// so that a hand-written cycle cannot hang the audit.
func resolve(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 64; i++ {
		n = n.Alias
	}
	return n
}

// entry is one key/value pair of a mapping, in declared order.
type entry struct {
	key   string
	value *yaml.Node
}

// mapEntries lists a mapping's pairs, expanding YAML merge keys (`<<: *base`,
// which compose files use heavily for shared service blocks). Keys written
// directly on the mapping win over merged ones, as YAML requires.
func mapEntries(n *yaml.Node) []entry {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}

	var direct, merged []entry
	seen := make(map[string]bool, len(n.Content)/2)

	for i := 0; i+1 < len(n.Content); i += 2 {
		key := resolve(n.Content[i])
		if key == nil || key.Kind != yaml.ScalarNode {
			continue
		}
		if key.Tag == "!!merge" || key.Value == "<<" {
			for _, source := range mergeSources(n.Content[i+1]) {
				merged = append(merged, mapEntries(source)...)
			}
			continue
		}
		direct = append(direct, entry{key: key.Value, value: n.Content[i+1]})
		seen[key.Value] = true
	}

	for _, e := range merged {
		if !seen[e.key] {
			seen[e.key] = true
			direct = append(direct, e)
		}
	}
	return direct
}

// mergeSources is the one or many mappings a `<<` key refers to.
func mergeSources(n *yaml.Node) []*yaml.Node {
	n = resolve(n)
	if n == nil {
		return nil
	}
	if n.Kind == yaml.SequenceNode {
		return n.Content
	}
	return []*yaml.Node{n}
}

// field returns a mapping's value for one key, already alias-resolved, or nil.
func field(n *yaml.Node, key string) *yaml.Node {
	for _, e := range mapEntries(n) {
		if e.key == key {
			return resolve(e.value)
		}
	}
	return nil
}

// items lists a sequence's elements, alias-resolved. A nil or non-sequence node
// has no elements; callers that need to complain check the kind themselves.
func items(n *yaml.Node) []*yaml.Node {
	n = resolve(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]*yaml.Node, 0, len(n.Content))
	for _, c := range n.Content {
		out = append(out, resolve(c))
	}
	return out
}

// isNull reports an explicitly or implicitly empty value (`healthcheck:` with
// nothing after it). It is not the same as a missing key, and not the same as an
// empty string.
func isNull(n *yaml.Node) bool {
	n = resolve(n)
	return n == nil || (n.Kind == yaml.ScalarNode && n.Tag == "!!null")
}

// str returns a scalar's text. The second result is false for a missing key, a
// null, a mapping or a sequence — anything the caller must not read as a string.
func str(n *yaml.Node) (string, bool) {
	n = resolve(n)
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return "", false
	}
	return n.Value, true
}

// parseBool accepts the spellings YAML and compose between them allow. yaml.v3
// follows YAML 1.2, where `yes` is a plain string, so the check is on the text
// rather than on the node's tag.
func parseBool(n *yaml.Node) (bool, bool) {
	s, ok := str(n)
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	}
	if v, err := strconv.ParseBool(s); err == nil {
		return v, true
	}
	return false, false
}

// kindName names a node's shape the way the compose reference does, so a warning
// reads "expected a sequence, got a mapping".
func kindName(n *yaml.Node) string {
	n = resolve(n)
	if n == nil {
		return "nothing"
	}
	switch n.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a sequence"
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			return "an empty value"
		}
		return "a scalar"
	case yaml.AliasNode:
		return "an unresolvable alias"
	case yaml.DocumentNode:
		return "a document"
	}
	return "an unknown node"
}

// documentRoot unwraps the document node yaml.Unmarshal produces when decoding
// into a yaml.Node. It returns nil for an empty file.
func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc == nil || doc.Kind == 0 {
		return nil
	}
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return nil
		}
		return resolve(doc.Content[0])
	}
	return resolve(doc)
}

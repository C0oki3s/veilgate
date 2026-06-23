package admin

// yaml_patch.go — surgical YAML document patcher.
//
// ApplyYAMLPatches walks the yaml.v3 node tree and replaces only the specified
// key-paths, preserving every comment, style, and key order from the original
// document. Keys that don't yet exist are appended at the end of their parent
// mapping — already-commented-out sections are left untouched.
//
// Only scalar, sequence ([]string), and map (map[string]string) patches are
// supported — sufficient for every veilgate.yaml field exposed in the UI.
// Complex list-of-maps fields (upload_policies, capture.scrub, verifiers.cookies,
// verifiers.headers) are intentionally left to the Raw-YAML editor.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ── Patch descriptors ──────────────────────────────────────────────────────

type patchKind int

const (
	pkString  patchKind = iota
	pkInt               // int64 written as decimal
	pkOctal             // int64 written as 0o600 style
	pkBool              // "true" / "false"
	pkFloat             // float64
	pkStrings           // sequence of strings (one-per-line in forms)
	pkKVMap             // mapping of string → string (key: value lines in forms)
)

type patchValue struct {
	kind  patchKind
	str   string
	num   int64
	flt   float64
	flag  bool
	strs  []string
	kvmap map[string]string
}

// YAMLPatch binds a dot-path to a value.
type YAMLPatch struct {
	Path  []string
	Value patchValue
}

func PatchString(path []string, v string) YAMLPatch {
	return YAMLPatch{Path: path, Value: patchValue{kind: pkString, str: v}}
}
func PatchInt(path []string, v int) YAMLPatch {
	return YAMLPatch{Path: path, Value: patchValue{kind: pkInt, num: int64(v)}}
}
func PatchInt64(path []string, v int64) YAMLPatch {
	return YAMLPatch{Path: path, Value: patchValue{kind: pkInt, num: v}}
}
func PatchOctal(path []string, v int) YAMLPatch {
	return YAMLPatch{Path: path, Value: patchValue{kind: pkOctal, num: int64(v)}}
}
func PatchBool(path []string, v bool) YAMLPatch {
	return YAMLPatch{Path: path, Value: patchValue{kind: pkBool, flag: v}}
}
func PatchFloat(path []string, v float64) YAMLPatch {
	return YAMLPatch{Path: path, Value: patchValue{kind: pkFloat, flt: v}}
}
func PatchStrings(path []string, v []string) YAMLPatch {
	return YAMLPatch{Path: path, Value: patchValue{kind: pkStrings, strs: v}}
}
func PatchKVMap(path []string, v map[string]string) YAMLPatch {
	return YAMLPatch{Path: path, Value: patchValue{kind: pkKVMap, kvmap: v}}
}

// ── Core patcher ───────────────────────────────────────────────────────────

// ApplyYAMLPatches applies all patches to raw YAML, returning the updated
// document. Comments, key order, and unpatched sections are preserved.
func ApplyYAMLPatches(raw string, patches []YAMLPatch) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return "", fmt.Errorf("yaml parse: %w", err)
	}
	// Empty document → start with an empty mapping.
	if doc.Kind == 0 || (doc.Kind == yaml.DocumentNode && len(doc.Content) == 0) {
		doc = yaml.Node{
			Kind: yaml.DocumentNode,
			Content: []*yaml.Node{
				{Kind: yaml.MappingNode, Tag: "!!map"},
			},
		}
	}

	root := &doc
	if doc.Kind == yaml.DocumentNode {
		root = doc.Content[0]
	}

	for _, p := range patches {
		if err := yamlSetPath(root, p.Path, p.Value); err != nil {
			return "", fmt.Errorf("patch %s: %w", strings.Join(p.Path, "."), err)
		}
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return "", fmt.Errorf("yaml marshal: %w", err)
	}
	return string(out), nil
}

// yamlSetPath walks the node tree, creating intermediate mapping nodes as
// needed, and sets the leaf value.
func yamlSetPath(n *yaml.Node, path []string, val patchValue) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("node at path root is kind=%d, want MappingNode", n.Kind)
	}

	key, rest := path[0], path[1:]

	if len(rest) == 0 {
		// Leaf: set or append the value.
		return yamlSetKey(n, key, patchValueToNode(val))
	}

	// Intermediate: find or create a child MappingNode.
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			child := n.Content[i+1]
			if child.Kind != yaml.MappingNode {
				newMap := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
				n.Content[i+1] = newMap
				child = newMap
			}
			return yamlSetPath(child, rest, val)
		}
	}
	// Key missing: append a new sub-mapping.
	child := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	n.Content = append(n.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		child,
	)
	return yamlSetPath(child, rest, val)
}

// yamlSetKey sets (or appends) a key→value pair inside a mapping node.
// Any line-comment that was on the old value node is transferred to the new one.
func yamlSetKey(n *yaml.Node, key string, newVal *yaml.Node) error {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			newVal.LineComment = n.Content[i+1].LineComment
			newVal.HeadComment = n.Content[i+1].HeadComment
			n.Content[i+1] = newVal
			return nil
		}
	}
	n.Content = append(n.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		newVal,
	)
	return nil
}

// patchValueToNode converts a patchValue to a yaml.Node.
func patchValueToNode(v patchValue) *yaml.Node {
	switch v.kind {
	case pkString:
		// Use double-quoted style so empty strings, special chars, and
		// ${VAR} references all round-trip without ambiguity.
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: v.str,
			Style: yaml.DoubleQuotedStyle,
		}
	case pkInt:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int",
			Value: strconv.FormatInt(v.num, 10)}
	case pkOctal:
		// Write as 0o600 so the YAML is human-readable.
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int",
			Value: fmt.Sprintf("0o%o", v.num)}
	case pkBool:
		s := "false"
		if v.flag {
			s = "true"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: s}
	case pkFloat:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!float",
			Value: strconv.FormatFloat(v.flt, 'f', -1, 64)}
	case pkStrings:
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, s := range v.strs {
			if s = strings.TrimSpace(s); s != "" {
				seq.Content = append(seq.Content, &yaml.Node{
					Kind:  yaml.ScalarNode,
					Tag:   "!!str",
					Value: s,
					Style: yaml.DoubleQuotedStyle,
				})
			}
		}
		return seq
	case pkKVMap:
		m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		// Sort keys for deterministic output.
		keys := make([]string, 0, len(v.kvmap))
		for k := range v.kvmap {
			if k = strings.TrimSpace(k); k != "" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			vv := strings.TrimSpace(v.kvmap[k])
			m.Content = append(m.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: vv,
					Style: yaml.DoubleQuotedStyle},
			)
		}
		return m
	default:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
	}
}

// ── Form-parsing helpers ───────────────────────────────────────────────────

// parseLines splits a textarea value (newline-separated) into trimmed non-empty strings.
func parseLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// parseKVLines parses "key: value" lines into a map.
// Lines without ": " separator are silently skipped.
func parseKVLines(s string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, ": "); i >= 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+2:])
			if k != "" {
				m[k] = v
			}
		}
	}
	return m
}

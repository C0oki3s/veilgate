package blueprint

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// candidateFiles are searched in order; the first match wins.
var candidateFiles = []string{
	"api_blueprint.yaml",
	"api_blueprint.json",
	"openapi.yaml",
	"openapi.json",
}

// Load searches dir for a blueprint file and returns a compiled Matcher.
// Returns (nil, nil) when no blueprint file is found — the caller should treat
// nil as "blueprint feature disabled" and skip the api_blueprint_miss signal.
func Load(dir string) (*Matcher, error) {
	for _, name := range candidateFiles {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		return parse(data)
	}
	return nil, nil
}

// rawDoc is the union type covering OpenAPI 3.x, Swagger 2.0, and the custom
// simple-routes format. Unknown keys are silently ignored by yaml.Unmarshal.
type rawDoc struct {
	// OpenAPI 3.x / Swagger 2.0: map of path template → method object
	Paths map[string]interface{} `yaml:"paths"`
	// Swagger 2.0: base path to prepend to every route
	BasePath string `yaml:"basePath"`
	// Custom simple format: flat list of path strings
	Routes []string `yaml:"routes"`
}

func parse(data []byte) (*Matcher, error) {
	var doc rawDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var paths []string

	switch {
	case len(doc.Routes) > 0:
		// Custom simple format wins when present.
		paths = doc.Routes

	case len(doc.Paths) > 0:
		// OpenAPI 3.x or Swagger 2.0 — extract path templates.
		prefix := ""
		if doc.BasePath != "" && doc.BasePath != "/" {
			prefix = strings.TrimRight(doc.BasePath, "/")
		}
		for p := range doc.Paths {
			paths = append(paths, prefix+p)
		}
	}

	if len(paths) == 0 {
		return nil, nil
	}
	return buildMatcher(paths), nil
}

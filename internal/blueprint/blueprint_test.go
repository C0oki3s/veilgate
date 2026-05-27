package blueprint

import (
	"os"
	"path/filepath"
	"testing"
)

// ── Matcher unit tests ────────────────────────────────────────────────────────

func TestMatcherExactRoute(t *testing.T) {
	m := buildMatcher([]string{"/api/users", "/api/posts"})
	if !m.Matches("/api/users") {
		t.Error("exact route /api/users should match")
	}
	if !m.Matches("/api/posts") {
		t.Error("exact route /api/posts should match")
	}
}

func TestMatcherPathParam(t *testing.T) {
	m := buildMatcher([]string{"/api/users/{id}", "/api/posts/{id}/comments"})
	if !m.Matches("/api/users/42") {
		t.Error("{id} segment should match numeric ID")
	}
	if !m.Matches("/api/users/abc-def-123") {
		t.Error("{id} segment should match string ID")
	}
	if !m.Matches("/api/posts/99/comments") {
		t.Error("nested path param should match")
	}
	if m.Matches("/api/users/42/extra") {
		t.Error("extra segment must not match")
	}
}

func TestMatcherCaseInsensitive(t *testing.T) {
	m := buildMatcher([]string{"/API/Users"})
	if !m.Matches("/api/users") {
		t.Error("matching should be case-insensitive")
	}
	if !m.Matches("/API/USERS") {
		t.Error("matching should be case-insensitive")
	}
}

func TestMatcherNoMatch(t *testing.T) {
	m := buildMatcher([]string{"/api/users"})
	if m.Matches("/api/unknown") {
		t.Error("/api/unknown must not match when not in blueprint")
	}
	if m.Matches("/other/path") {
		t.Error("/other/path must not match")
	}
}

func TestMatcherInNamespace(t *testing.T) {
	m := buildMatcher([]string{"/api/users", "/api/posts/{id}", "/v1/status"})
	if !m.InNamespace("/api/anything") {
		t.Error("/api/* should be in namespace")
	}
	if !m.InNamespace("/v1/anything") {
		t.Error("/v1/* should be in namespace")
	}
	if m.InNamespace("/other/path") {
		t.Error("/other is not a blueprint namespace")
	}
	if m.InNamespace("/") {
		t.Error("root path has no first segment")
	}
}

func TestMatcherIsEmpty(t *testing.T) {
	m := buildMatcher(nil)
	if !m.IsEmpty() {
		t.Error("empty routes should be IsEmpty")
	}
	m2 := buildMatcher([]string{"/api/users"})
	if m2.IsEmpty() {
		t.Error("non-empty routes should not be IsEmpty")
	}
}

func TestMatcherRouteCount(t *testing.T) {
	m := buildMatcher([]string{"/a", "/b", "/c"})
	if m.RouteCount() != 3 {
		t.Errorf("expected 3 routes, got %d", m.RouteCount())
	}
}

// ── Loader tests ──────────────────────────────────────────────────────────────

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	dir := t.TempDir()
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Error("expected nil Matcher when no file present")
	}
}

func TestLoadCustomRoutesYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "api_blueprint.yaml", `
routes:
  - /api/users
  - /api/users/{id}
  - /api/posts
`)
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil Matcher")
	}
	if m.RouteCount() != 3 {
		t.Errorf("expected 3 routes, got %d", m.RouteCount())
	}
	if !m.Matches("/api/users") {
		t.Error("should match /api/users")
	}
	if !m.Matches("/api/users/123") {
		t.Error("should match /api/users/123 via path param")
	}
}

func TestLoadOpenAPI3YAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "openapi.yaml", `
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /api/health: {}
  /api/users: {}
  /api/users/{id}: {}
`)
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil Matcher")
	}
	if m.RouteCount() != 3 {
		t.Errorf("expected 3 routes, got %d", m.RouteCount())
	}
	if !m.Matches("/api/health") {
		t.Error("should match /api/health")
	}
}

func TestLoadSwagger2WithBasePath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "openapi.yaml", `
swagger: "2.0"
basePath: /v1
paths:
  /users: {}
  /users/{id}: {}
  /status: {}
`)
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil Matcher")
	}
	// basePath /v1 is prepended, so effective routes are /v1/users etc.
	if !m.Matches("/v1/users") {
		t.Error("should match /v1/users with basePath prepended")
	}
	if !m.Matches("/v1/users/42") {
		t.Error("should match /v1/users/42 via path param")
	}
	if !m.InNamespace("/v1/anything") {
		t.Error("/v1 should be in namespace")
	}
}

func TestLoadCandidateFileOrder(t *testing.T) {
	// When api_blueprint.yaml and openapi.yaml both exist, api_blueprint.yaml wins.
	dir := t.TempDir()
	writeFile(t, dir, "api_blueprint.yaml", `routes: [/priority/route]`)
	writeFile(t, dir, "openapi.yaml", `paths: { /other/route: {} }`)

	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil Matcher")
	}
	if !m.Matches("/priority/route") {
		t.Error("api_blueprint.yaml should take priority over openapi.yaml")
	}
	if m.Matches("/other/route") {
		t.Error("openapi.yaml routes should be ignored when api_blueprint.yaml is present")
	}
}

func TestLoadEmptyDocReturnsNil(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "api_blueprint.yaml", `routes: []`)
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Error("empty routes list should return nil Matcher")
	}
}

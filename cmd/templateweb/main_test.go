package main

import (
	"strings"
	"testing"
)

func TestRewritePreviewURLs(t *testing.T) {
	body := rewritePreviewURLs(`
		<a href="/#!/overview">Overview</a>
		<a href='/admin'>Admin</a>
		<form action="/api/auth/login"></form>
		<script>
		fetch('/api/auth/me')
		location.href = '/'
		</script>
	`)
	for _, want := range []string{
		`href="/_preview/#!/overview"`,
		`href='/_preview/admin'`,
		`action="/_preview/api/auth/login"`,
		`fetch('/_preview/api/auth/me')`,
		`location.href = '/_preview/'`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("rewritten body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "/_preview/_preview/") {
		t.Fatalf("double preview prefix in body:\n%s", body)
	}
}

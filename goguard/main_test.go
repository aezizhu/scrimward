package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDecideRoutedAllowsSilently(t *testing.T) {
	out, err := decide(true, "Bash", "echo hi")
	if err != nil || out != nil {
		t.Fatalf("routed must allow with no output; got out=%q err=%v", out, err)
	}
}

func TestDecideBootstrapEscapeAllowsScrimwardBash(t *testing.T) {
	for _, tool := range []string{"Bash", "Shell"} {
		if out, _ := decide(false, tool, "scrimward setup --port 8788"); out != nil {
			t.Fatalf("%s scrimward command must be allowed; got %q", tool, out)
		}
	}
}

func TestDecideBootstrapEscapeIsInvocationNotSubstring(t *testing.T) {
	for _, c := range []string{"scrimward setup", "bin/scrimward-py status", "ENV=1 scrimward setup"} {
		if out, _ := decide(false, "Bash", c); out != nil {
			t.Fatalf("%q should be allowed; got %q", c, out)
		}
	}
	// The audit's bypass: a command that merely CONTAINS scrimward must be DENIED.
	for _, c := range []string{"cat ~/Desktop/scrimward/.env", "printenv  # scrimward", "rm -rf /tmp/x"} {
		if out, _ := decide(false, "Bash", c); out == nil {
			t.Fatalf("%q must be DENIED — substring-only must not escape the guard", c)
		}
	}
}

func TestDecideDeniesUnroutedToolUse(t *testing.T) {
	out, err := decide(false, "Edit", "")
	if err != nil {
		t.Fatal(err)
	}
	var o hookOutput
	if json.Unmarshal(out, &o) != nil {
		t.Fatalf("deny output must be valid JSON; got %q", out)
	}
	h := o.HookSpecificOutput
	if h.HookEventName != "PreToolUse" || h.PermissionDecision != "deny" {
		t.Fatalf("expected PreToolUse/deny; got %+v", h)
	}
	if !strings.Contains(h.PermissionDecisionReason, "fail-closed") {
		t.Fatalf("reason missing fail-closed wording: %q", h.PermissionDecisionReason)
	}
}

func TestDecideDeniesNonScrimwardBash(t *testing.T) {
	if out, _ := decide(false, "Bash", "rm -rf /tmp/x"); out == nil {
		t.Fatal("a non-scrimward bash command must be denied when unrouted")
	}
}

func TestHealthz(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer ok.Close()
	if !healthz(ok.URL) {
		t.Fatal("a 200 /healthz should be healthy")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	if healthz(bad.URL) {
		t.Fatal("a 500 /healthz should be unhealthy")
	}
	if healthz("http://127.0.0.1:1") {
		t.Fatal("an unreachable proxy should be unhealthy")
	}
}

func writeSettings(t *testing.T, dir, baseURL string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"env":{"ANTHROPIC_BASE_URL":"` + baseURL + `"}}`
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.local.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredBaseURL(t *testing.T) {
	dir := t.TempDir()
	writeSettings(t, dir, "http://127.0.0.1:8788")
	t.Chdir(dir)
	if got := configuredBaseURL(); got != "http://127.0.0.1:8788" {
		t.Fatalf("got %q", got)
	}
	t.Chdir(t.TempDir()) // no settings file
	if got := configuredBaseURL(); got != "" {
		t.Fatalf("missing file should yield empty, got %q", got)
	}
}

func TestIsRoutedTrueWhenConfiguredAndHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	t.Setenv("ANTHROPIC_BASE_URL", "")
	dir := t.TempDir()
	writeSettings(t, dir, srv.URL) // configured == http://127.0.0.1:<port>
	t.Chdir(dir)

	if !isRouted(port) {
		t.Fatal("expected routed=true when configured base URL matches and /healthz is 200")
	}
	// Wrong port (proxy not there) → not routed.
	if isRouted(port + 1) {
		t.Fatal("expected routed=false when the configured URL does not match the port")
	}
}

func TestIsRoutedFalseWhenUnconfigured(t *testing.T) {
	t.Setenv("ANTHROPIC_BASE_URL", "")
	t.Chdir(t.TempDir()) // no settings, no env
	if isRouted(8788) {
		t.Fatal("expected routed=false with nothing configured")
	}
}

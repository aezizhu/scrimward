// Command scrimward-guard is a fast, dependency-free Go port of the
// PreToolUse hook ("scrimward hook guard"). It runs on EVERY tool use, so the
// per-call Python interpreter + click cold-start is the thing worth removing —
// and a single static binary sidesteps "is a working Python installed?".
//
// It is byte-faithful to scrimward/cli.py's `hook_guard`/`_is_routed`:
//   - routed  := configured ANTHROPIC_BASE_URL == http://127.0.0.1:<port>
//                AND the proxy answers GET /healthz with 200 (1.5s timeout)
//   - configured := .claude/settings.local.json env.ANTHROPIC_BASE_URL, else $ANTHROPIC_BASE_URL
//   - routed                       -> allow (exit 0, no output)
//   - a `scrimward ...` Bash/Shell  -> allow (bootstrap escape, so setup is runnable)
//   - otherwise                    -> deny (fail-closed PreToolUse JSON)
//
// It NEVER errors out in a way that bricks the session: any failure → allow-silent
// is avoided; on a genuinely un-decodable state it still emits the fail-closed deny.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// A bootstrap command is one whose EXECUTABLE is scrimward / scrimward-py (after
// optional env-assignments and a path prefix) — NOT any command that merely
// CONTAINS "scrimward" (the repo lives at ~/Desktop/scrimward/, so a substring
// check would disable the guard across its own tree). Kept in sync with cli.py.
var scrimwardInvocation = regexp.MustCompile(`^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:\S*/)?scrimward(?:-py)?(?:\s|$)`)

const defaultPort = 8788

// Exact reason string from scrimward/cli.py hook_guard (kept in sync for parity).
const denyReason = "Scrimward fail-closed guard: this session is NOT routed through the local " +
	"redaction proxy, so anything sent to the cloud could leak secrets/PII. Run /scrimward:setup " +
	"and restart your AI tool to activate redaction, then retry."

type hookOutput struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// decide returns the JSON to print (nil = allow with no output). Pure: no IO, so
// it is exhaustively unit-testable and is the single source of the allow/deny rule.
func decide(routed bool, toolName, command string) ([]byte, error) {
	if routed {
		return nil, nil // allow
	}
	// Bootstrap escape: never block scrimward's OWN setup/status invocation, or
	// the user could not run /scrimward:setup to turn routing on. Match the
	// invocation, not contains-anywhere (see scrimwardInvocation).
	if (toolName == "Bash" || toolName == "Shell") && scrimwardInvocation.MatchString(command) {
		return nil, nil
	}
	var out hookOutput
	out.HookSpecificOutput.HookEventName = "PreToolUse"
	out.HookSpecificOutput.PermissionDecision = "deny"
	out.HookSpecificOutput.PermissionDecisionReason = denyReason
	return json.Marshal(out)
}

func proxyURL(port int) string { return fmt.Sprintf("http://127.0.0.1:%d", port) }

// configuredBaseURL reads .claude/settings.local.json -> env.ANTHROPIC_BASE_URL.
func configuredBaseURL() string {
	data, err := os.ReadFile(filepath.Join(".claude", "settings.local.json"))
	if err != nil {
		return ""
	}
	var s struct {
		Env map[string]string `json:"env"`
	}
	if json.Unmarshal(data, &s) != nil {
		return ""
	}
	return s.Env["ANTHROPIC_BASE_URL"]
}

func healthz(base string) bool {
	client := http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(base + "/healthz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func isRouted(port int) bool {
	configured := configuredBaseURL()
	if configured == "" {
		configured = os.Getenv("ANTHROPIC_BASE_URL")
	}
	if configured != proxyURL(port) {
		return false
	}
	return healthz(proxyURL(port))
}

func readHookInput() map[string]any {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice != 0 {
		return map[string]any{} // a tty (no piped input)
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return map[string]any{}
	}
	return m
}

func main() {
	port := flag.Int("port", defaultPort, "redaction proxy port")
	flag.Parse()

	payload := readHookInput()
	toolName, _ := payload["tool_name"].(string)
	command := ""
	if ti, ok := payload["tool_input"].(map[string]any); ok {
		command, _ = ti["command"].(string)
	}

	out, err := decide(isRouted(*port), toolName, command)
	if err == nil && out != nil {
		fmt.Println(string(out))
	}
	os.Exit(0) // a hook must never crash the session
}

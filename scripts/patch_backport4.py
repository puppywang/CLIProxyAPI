"""Backport: learnedUnsupported registry mechanism + cooldown mgmt methods onto remerge2 (a904b626)."""
import re, subprocess, sys

def git_show(ref, path):
    out = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True)
    if out.returncode != 0:
        raise RuntimeError(f"git show {ref}:{path} failed")
    return out.stdout.decode("utf-8", errors="replace").replace("\r\n", "\n")

def patch_file(path, marker, insert, append=False):
    with open(path, "r", encoding="utf-8", newline="") as f:
        text = f.read()
    crlf = "\r\n" in text
    text = text.replace("\r\n", "\n")
    if append:
        text = text.rstrip("\n") + "\n\n" + insert.rstrip("\n") + "\n"
    else:
        idx = text.rindex(marker) + len(marker)
        text = text[:idx] + "\n" + insert.rstrip("\n") + text[idx:]
    out = text.replace("\n", "\r\n") if crlf else text
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(out)
    print(f"patched {path}")

# ---------- 1. registry: learnedUnsupported mechanism ----------
reg = git_show("monitor-feature", "internal/registry/model_registry.go")

def extract_between(src, start_marker, end_marker):
    s = src.index(start_marker)
    e = src.index(end_marker, s)
    return src[s:e]

field_snippet = """	// hook is an optional callback sink for model registration changes
	hook ModelRegistryHook
	// learnedUnsupported records, per model ID, the clients that have LEARNED
	// they cannot serve that model (upstream model_not_supported), each with an
	// expiry. DELIBERATELY separate from SuspendedClients: a downgraded request
	// looks like a success for the original model to the conductor, so its
	// ResumeClientModel would wipe a SuspendedClients marker but must not wipe
	// this durable, self-healing flag. Guarded by mutex; lazily allocated.
	learnedUnsupported map[string]map[string]time.Time
}"""

old_tail = """	// hook is an optional callback sink for model registration changes
	hook ModelRegistryHook
}"""

patch_file("internal/registry/model_registry.go", old_tail, field_snippet)

# methods: extract from monitor reg (from ModelNotSupportedReason const through IsClientModelSuspended)
start = reg.index("const ModelNotSupportedReason")
end = reg.index("// IsClientModelSuspended reports")
methods_block = reg[start:end]
methods_block = re.sub(r"// Expired \uFFFD.*\n", "// Expired - drop it lazily under the write lock.\n", methods_block)
patch_file("internal/registry/model_registry.go", "func (r *ModelRegistry) IsClientModelUnsupported", "", append=True) if False else None

# append the whole methods block (minus trailing) at EOF
patch_file("internal/registry/model_registry.go", "", methods_block.rstrip("\n"), append=True)

# ---------- 2. SessionCache methods ----------
cache_methods = '''
// InvalidateAuthCount removes every cache row bound to authID and returns the
// count of removed rows. A single logical conversation usually has two entries
// (the codex-thread key and its codex-window mirror), so the count can exceed
// the number of distinct conversations.
func (c *SessionCache) InvalidateAuthCount(authID string) int {
	if authID == "" {
		return 0
	}
	removed := 0
	c.mu.Lock()
	for sid, entry := range c.entries {
		if entry.authID == authID {
			delete(c.entries, sid)
			removed++
		}
	}
	c.mu.Unlock()
	return removed
}

// splitCacheKeyID returns the trailing conversation id of a session cache
// key. Keys have the shape "<provider>::<kind>:<id>". ok=false for malformed.
func splitCacheKeyID(key string) (id string, ok bool) {
	if idx := strings.Index(key, "::"); idx >= 0 {
		key = key[idx+2:]
	}
	colon := strings.Index(key, ":")
	if colon <= 0 {
		return "", false
	}
	id = key[colon+1:]
	return id, id != ""
}

// InvalidateWindowForAuth removes every cache row for the given conversation
// uuid that is currently bound to authID. The authID filter makes the call
// safe against stale UI data. Returns the number of rows removed.
func (c *SessionCache) InvalidateWindowForAuth(authID, uuid string) int {
	if authID == "" || uuid == "" {
		return 0
	}
	removed := 0
	c.mu.Lock()
	for key, entry := range c.entries {
		if entry.authID != authID {
			continue
		}
		if id, ok := splitCacheKeyID(key); ok && id == uuid {
			delete(c.entries, key)
			removed++
		}
	}
	c.mu.Unlock()
	return removed
}
'''
patch_file("sdk/cliproxy/auth/session_cache.go", "func (c *SessionCache) InvalidateAuth(authID string) {", cache_methods)

# ---------- 3. Selector methods ----------
selector_methods = '''
// InvalidateAuthBindings removes every session-affinity binding for authID.
// Used by the management cooldown panel's "release" action. Returns 0 when no
// cache is configured.
func (s *SessionAffinitySelector) InvalidateAuthBindings(authID string) int {
	if s == nil || s.cache == nil {
		return 0
	}
	return s.cache.InvalidateAuthCount(authID)
}

// InvalidateWindowBinding removes the cache rows for ONE conversation (uuid)
// but only while it is still bound to authID. Returns the number of rows
// removed; 0 when the uuid isn't bound to that auth or no cache is configured.
func (s *SessionAffinitySelector) InvalidateWindowBinding(authID, uuid string) int {
	if s == nil || s.cache == nil {
		return 0
	}
	return s.cache.InvalidateWindowForAuth(authID, uuid)
}
'''
patch_file("sdk/cliproxy/auth/selector.go", "func (s *SessionAffinitySelector) InvalidateAuth(authID string) {", selector_methods)

# ---------- 4. Conductor: cooldown methods + autoReleaseOn429 ----------
mon_con = git_show("monitor-feature", "sdk/cliproxy/auth/conductor.go")

def extract_func(src, fname):
    pat = re.compile(r"(//.*?\n)*func \(m \*Manager\) " + fname + r"\(.*?\n}", re.S)
    m = pat.search(src)
    if not m:
        raise RuntimeError(f"{fname} not found")
    return m.group(0)

clear_cd = extract_func(mon_con, "ClearCooldown")
force_cd = extract_func(mon_con, "ForceCooldown")
force_cd = re.sub(r".*GetModelQuotaExceeded.*\n", "", force_cd)

conductor_add = f'''
// ManualCooldownReason marks a cooldown that was set by an operator,
// not by the conductor in response to an upstream signal.
const ManualCooldownReason = "manual"

// autoReleaseOn429 gates whether a 429 response releases the session-affinity
// binding for that auth automatically (management panel control).
var autoReleaseOn429 atomic.Bool

// SetAutoReleaseOn429 toggles whether 429 responses release session-affinity
// bindings automatically (management panel control).
func SetAutoReleaseOn429(enable bool) {{
	autoReleaseOn429.Store(enable)
}}

// AutoReleaseOn429Enabled reports whether 429 auto-release is currently on.
func AutoReleaseOn429Enabled() bool {{
	return autoReleaseOn429.Load()
}}

{clear_cd}

{force_cd}
'''
patch_file("sdk/cliproxy/auth/conductor.go", "", conductor_add, append=True)
print("DONE")

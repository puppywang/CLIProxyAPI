import re, subprocess, sys

def git_show(ref, path):
    out = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True, text=True)
    return out.stdout.replace("\r\n", "\n") if out.returncode == 0 else None

def extract_func(src, fname):
    pat = re.compile(r"(//.*?\n)*func \(m \*Manager\) " + fname + r"\(.*?\n}", re.S)
    m = pat.search(src)
    if not m:
        raise RuntimeError(f"{fname} not found")
    return m.group(0)

def append_to_file(path, insert):
    with open(path, "r", encoding="utf-8", newline="") as f:
        text = f.read()
    crlf = "\r\n" in text
    text = text.replace("\r\n", "\n")
    text = text.rstrip("\n") + "\n\n" + insert.rstrip("\n") + "\n"
    out = text.replace("\n", "\r\n") if crlf else text
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(out)
    print(f"appended {path}")

mon = git_show("monitor-feature", "sdk/cliproxy/auth/conductor.go")
clear_cd = extract_func(mon, "ClearCooldown")
force_cd = extract_func(mon, "ForceCooldown")
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
append_to_file("sdk/cliproxy/auth/conductor.go", conductor_add)

selector_add = '''
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
append_to_file("sdk/cliproxy/auth/selector.go", selector_add)
print("DONE")

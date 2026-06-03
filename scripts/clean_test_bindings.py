#!/usr/bin/env python3
"""Remove specific test bindings from the session-affinity cache file.

Usage: clean_test_bindings.py <cache.json> <session_id> [<session_id> ...]
"""

import json
import os
import sys
import tempfile


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: clean_test_bindings.py <cache.json> <session_id>...", file=sys.stderr)
        return 2

    path = sys.argv[1]
    session_ids = sys.argv[2:]

    with open(path, "r", encoding="utf-8") as fh:
        snap = json.load(fh)

    entries = snap.get("entries", {}) or {}
    removed = []
    for sid in session_ids:
        for prefix in ("mixed::codex-thread:", "mixed::codex-window:"):
            key = prefix + sid
            if key in entries:
                removed.append((key, entries[key].get("auth_id", "")))
                del entries[key]

    snap["entries"] = entries

    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=os.path.dirname(os.path.abspath(path)) or ".",
        prefix=".cache-clean-",
        suffix=".tmp",
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(snap, fh, indent=2)
            fh.write("\n")
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    print(f"removed {len(removed)} entries from {path}")
    for k, auth in removed:
        print(f"  {k} -> {auth}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

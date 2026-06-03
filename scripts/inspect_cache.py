#!/usr/bin/env python3
"""Print cache binding distribution and check for a set of session IDs."""

import json
import sys


def main():
    path = sys.argv[1]
    targets = sys.argv[2:]
    with open(path, "r", encoding="utf-8") as fh:
        d = json.load(fh)
    entries = d.get("entries", {})
    print(f"total entries: {len(entries)}")
    counts = {}
    for v in entries.values():
        a = v.get("auth_id", "")
        counts[a] = counts.get(a, 0) + 1
    for k in sorted(counts, key=lambda x: (-counts[x], x)):
        print(f"  {counts[k]:3d}  {k}")
    if targets:
        print("--- targets ---")
        for sid in targets:
            for prefix in ("mixed::codex-thread:", "mixed::codex-window:"):
                key = prefix + sid
                if key in entries:
                    auth = entries[key].get("auth_id", "")
                    print(f"  HIT  {key} -> {auth}")


if __name__ == "__main__":
    main()

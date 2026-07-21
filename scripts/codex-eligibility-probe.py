#!/usr/bin/env python3
"""Codex referral eligibility probe — single GET via curl_cffi.

CPA's main Go HTTP path uses Go's stdlib TLS, whose JA3 fingerprint is
nothing like any real browser. Cloudflare protects the
/backend-api/referrals/invite/eligibility path with UA-Client-Hints
enforcement (cf-mitigated: challenge), so Go's request gets a 403 + HTML
page instead of the JSON eligibility blob. curl_cffi with the chrome116
impersonation profile passes the challenge — newer profiles (chrome120+)
get blocked because real Chrome 120+ ships Sec-CH-UA-Bitness/Arch/
Full-Version-List headers that those impersonation profiles don't fully
replicate, so CF spots the mismatch. chrome116 predates that enforcement
era and slips through.

This script is intentionally tiny — one read-only GET, JSON in, JSON
out — so the Go process can shell out without inheriting any state.

Input (stdin, JSON):
    {
      "access_token": "...",     # required
      "account_id":   "...",     # optional, sent as ChatGPT-Account-Id
      "proxy_url":    "socks5://host:port/",  # optional
      "referral_key": "codex_referral_persistent_invite",  # optional
      "base_url":     "https://chatgpt.com"   # optional
    }

Output (stdout, JSON):
    On success: {"ok": true, "status": 200, "data": {...eligibility...}}
    On failure: {"ok": false, "status": <int|null>, "error": "<short>"}

Exit codes:
    0  always (the failure mode is in the JSON body, not the exit code,
       so callers can rely on the body without checking $?)
"""

from __future__ import annotations

import json
import sys

try:
    from curl_cffi import requests
except ImportError as exc:
    print(json.dumps({
        "ok": False,
        "status": None,
        "error": "curl_cffi not installed: " + str(exc),
    }))
    sys.exit(0)


def emit(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False))


def main() -> int:
    try:
        req = json.load(sys.stdin)
    except Exception as exc:
        emit({"ok": False, "status": None, "error": "stdin: " + str(exc)})
        return 0

    token = (req.get("access_token") or "").strip()
    if not token:
        emit({"ok": False, "status": None, "error": "missing access_token"})
        return 0

    account_id = (req.get("account_id") or "").strip()
    proxy_url = (req.get("proxy_url") or "").strip()
    referral_key = (req.get("referral_key") or "codex_referral_persistent_invite").strip()
    base_url = (req.get("base_url") or "https://chatgpt.com").strip().rstrip("/")

    headers = {
        # Codex Desktop -specific bits the userscript also sends. These
        # do NOT bypass CF on their own — the TLS fingerprint via
        # impersonate=chrome116 is what passes the challenge. We include
        # them anyway because they match what a real Desktop client sends.
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "OAI-Language": "zh-CN",
        "originator": "Codex Desktop",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "referer": base_url + "/codex",
        "priority": "u=1, i",
    }
    if account_id:
        headers["ChatGPT-Account-Id"] = account_id

    proxies = None
    if proxy_url:
        # socks5h:// resolves DNS at the proxy, matching how CPA's Go
        # http.ProxyURL handles socks5:// URLs. Keeps egress IP and DNS
        # behaviour consistent with the account's normal traffic.
        norm = proxy_url.replace("socks5://", "socks5h://").rstrip("/")
        proxies = {"http": norm, "https": norm}

    try:
        resp = requests.get(
            base_url + "/backend-api/referrals/invite/eligibility",
            params={"referral_key": referral_key},
            headers=headers,
            impersonate="chrome116",
            proxies=proxies,
            timeout=20,
        )
    except Exception as exc:
        emit({
            "ok": False,
            "status": None,
            "error": "request: " + type(exc).__name__ + ": " + str(exc),
        })
        return 0

    body = resp.text or ""

    if 200 <= resp.status_code < 300:
        try:
            data = resp.json()
        except Exception as exc:
            emit({
                "ok": False,
                "status": resp.status_code,
                "error": "non-JSON 2xx: " + str(exc) + ": " + body[:160],
            })
            return 0
        emit({"ok": True, "status": resp.status_code, "data": data})
        return 0

    snippet = body[:200].replace("\n", " ")
    emit({
        "ok": False,
        "status": resp.status_code,
        "error": "upstream " + str(resp.status_code) + ": " + snippet,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())

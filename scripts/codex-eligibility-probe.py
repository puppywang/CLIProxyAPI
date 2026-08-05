#!/usr/bin/env python3
"""Codex referral probe — Cloudflare-bypass helper via curl_cffi.

CPA's main Go HTTP path uses Go's stdlib TLS. Cloudflare protects the
/backend-api/referrals/invite/* family with UA-Client-Hints enforcement
(cf-mitigated: challenge), so Go gets 403 HTML instead of JSON.
curl_cffi with impersonate=chrome116 passes the challenge.

This script is intentionally small — JSON in on stdin, JSON out on
stdout — so the Go process can shell out without inheriting state.

Input (stdin, JSON):
    {
      "action":       "eligibility" | "tracking" | "invite",  # default eligibility
      "access_token": "...",                                  # required
      "account_id":   "...",                                  # optional
      "proxy_url":    "socks5://host:port/",                  # optional
      "base_url":     "https://chatgpt.com",                  # optional
      "program_id":   "codex_referral_consumer",              # optional
      "entrypoint":   "persistent",                           # optional
      "emails":       ["a@b.com"],                            # invite only
      "period":       "past_90_days",                         # tracking only
      "limit":        100                                     # tracking only
    }

Output (stdout, JSON):
    success: {"ok": true, "status": 200, "data": {...}}
    failure: {"ok": false, "status": <int|null>, "error": "<short>"}

Exit code is always 0 — callers read the body, not $?.
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


DEFAULT_PROGRAM_ID = "codex_referral_consumer"
DEFAULT_ENTRYPOINT = "persistent"
DEFAULT_BASE_URL = "https://chatgpt.com"


def emit(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False))


def build_session(req: dict):
    token = (req.get("access_token") or "").strip()
    if not token:
        raise ValueError("missing access_token")

    account_id = (req.get("account_id") or "").strip()
    proxy_url = (req.get("proxy_url") or "").strip()
    base_url = (req.get("base_url") or DEFAULT_BASE_URL).strip().rstrip("/")

    headers = {
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
        # socks5h:// resolves DNS at the proxy, matching CPA's Go socks5
        # behaviour so egress IP and DNS stay consistent with the account.
        norm = proxy_url.replace("socks5://", "socks5h://").rstrip("/")
        proxies = {"http": norm, "https": norm}

    return base_url, headers, proxies


def do_request(method: str, url: str, headers: dict, proxies, *, params=None, json_body=None):
    kwargs = {
        "headers": headers,
        "impersonate": "chrome116",
        "proxies": proxies,
        "timeout": 25,
    }
    if params is not None:
        kwargs["params"] = params
    if json_body is not None:
        kwargs["json"] = json_body
        headers = dict(headers)
        headers["Content-Type"] = "application/json"
        kwargs["headers"] = headers

    if method == "GET":
        return requests.get(url, **kwargs)
    if method == "POST":
        return requests.post(url, **kwargs)
    raise ValueError("unsupported method " + method)


def handle_response(resp) -> int:
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


def main() -> int:
    try:
        req = json.load(sys.stdin)
    except Exception as exc:
        emit({"ok": False, "status": None, "error": "stdin: " + str(exc)})
        return 0

    action = (req.get("action") or "eligibility").strip().lower()
    program_id = (req.get("program_id") or DEFAULT_PROGRAM_ID).strip()
    entrypoint = (req.get("entrypoint") or DEFAULT_ENTRYPOINT).strip()

    try:
        base_url, headers, proxies = build_session(req)
    except Exception as exc:
        emit({"ok": False, "status": None, "error": str(exc)})
        return 0

    try:
        if action in ("eligibility", "elig", ""):
            resp = do_request(
                "GET",
                base_url + "/backend-api/referrals/invite/eligibility",
                headers,
                proxies,
                params={"program_id": program_id, "entrypoint": entrypoint},
            )
            return handle_response(resp)

        if action in ("tracking", "history", "referrals"):
            period = (req.get("period") or "past_90_days").strip()
            limit = req.get("limit") or 100
            try:
                limit = int(limit)
            except Exception:
                limit = 100
            resp = do_request(
                "GET",
                base_url + "/backend-api/referrals/invite/tracking",
                headers,
                proxies,
                params={
                    "program_id": program_id,
                    "period": period,
                    "limit": limit,
                },
            )
            return handle_response(resp)

        if action in ("invite", "send"):
            emails = req.get("emails") or []
            if not isinstance(emails, list) or not emails:
                emit({"ok": False, "status": None, "error": "invite requires emails[]"})
                return 0
            resp = do_request(
                "POST",
                base_url + "/backend-api/referrals/invite",
                headers,
                proxies,
                json_body={
                    "program_id": program_id,
                    "entrypoint": entrypoint,
                    "emails": emails,
                },
            )
            return handle_response(resp)

        emit({"ok": False, "status": None, "error": "unknown action " + action})
        return 0
    except Exception as exc:
        emit({
            "ok": False,
            "status": None,
            "error": "request: " + type(exc).__name__ + ": " + str(exc),
        })
        return 0


if __name__ == "__main__":
    sys.exit(main())

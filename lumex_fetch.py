#!/usr/bin/env python3
"""
LUMEX VPN — fetch servers without the app

Flow:
  1. GET /api/remote-config  from backend IP
  2. Read driveSubFileId
  3. Download Google Drive file (API key from libnexuscrypto.so)
  4. base64-decode → extract trojan:// vless:// … URIs
  5. Save to files

Usage:
  python3 lumex_fetch.py
  python3 lumex_fetch.py --out /path/to/dir
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ── recovered from libnexuscrypto.so ──────────────────────────────────────────
GOOGLE_API_KEY = "AIzaSyA7GpkRna8_l-mfGF5PMQZvcxSF5rFAvaw"

# backend.txt on Drive (file id 1x8UAg4bH9Pzv7lj55PAoePI6QT7QeFcW)
BACKEND_URLS = [
    "https://193.23.201.236",
    "http://193.23.201.236",
]

# fallback driveSubFileId if remote-config is unreachable
FALLBACK_DRIVE_ID = "1p3zomBe8rmJwtX2sJD2c7Jm5hetfTWFm"

URI_RE = re.compile(
    r"(?:trojan|vless|vmess|ss|ssr|hysteria2|hy2|tuic|wireguard|sn)://[^\s\r\n]+",
    re.IGNORECASE,
)

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def http_get(url: str, timeout: int = 15) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "okhttp/4.12.0",
            "Accept": "application/json, text/plain, */*",
        },
    )
    with urllib.request.urlopen(req, context=CTX, timeout=timeout) as resp:
        return resp.read()


def fetch_remote_config() -> dict:
    last_err = None
    for base in BACKEND_URLS:
        url = f"{base}/api/remote-config"
        try:
            raw = http_get(url)
            data = json.loads(raw)
            print(f"[remote-config] OK  {url}")
            return data
        except Exception as e:
            last_err = e
            print(f"[remote-config] fail {url}: {e}")
    raise RuntimeError(f"remote-config unreachable: {last_err}")


def download_drive(file_id: str, api_key: str = GOOGLE_API_KEY) -> bytes:
    urls = [
        f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media&key={api_key}",
        f"https://drive.usercontent.google.com/download?id={file_id}&export=download",
    ]
    last_err = None
    for url in urls:
        try:
            data = http_get(url, timeout=30)
            print(f"[drive] OK  {file_id}  ({len(data)} bytes)")
            return data
        except Exception as e:
            last_err = e
            print(f"[drive] fail {url[:70]}…: {e}")
    raise RuntimeError(f"Drive download failed: {last_err}")


def decode_subscription(raw: bytes) -> str:
    """Drive file is base64(plain subscription text)."""
    text = raw.decode("utf-8", errors="replace").strip()
    # already plain?
    if URI_RE.search(text) or text.startswith("#"):
        return text
    # base64 wrapper
    try:
        pad = "=" * ((4 - len(text) % 4) % 4)
        decoded = base64.b64decode(text + pad)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return text


def extract_uris(sub_text: str) -> list[str]:
    return URI_RE.findall(sub_text)


def uri_host(uri: str) -> str:
    m = re.search(r"@([^:/]+):(\d+)", uri)
    if m:
        return f"{m.group(1)}:{m.group(2)}"
    m = re.search(r"://([^:/]+):(\d+)", uri)
    if m:
        return f"{m.group(1)}:{m.group(2)}"
    return "?"


def main() -> int:
    ap = argparse.ArgumentParser(description="LUMEX VPN config fetcher")
    ap.add_argument("--out", default=".", help="output directory")
    ap.add_argument(
        "--drive-id",
        default=None,
        help="override driveSubFileId (skip remote-config)",
    )
    ap.add_argument(
        "--backend",
        default=None,
        help="override backend base URL",
    )
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.backend:
        BACKEND_URLS.insert(0, args.backend.rstrip("/"))

    # ── 1. remote-config ──────────────────────────────────────────────────────
    drive_id = args.drive_id
    remote = {}
    if not drive_id:
        try:
            remote = fetch_remote_config()
            (out / "remote_config.json").write_text(
                json.dumps(remote, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            print(f"[save] remote_config.json")
            drive_id = remote.get("driveSubFileId") or FALLBACK_DRIVE_ID
            print(f"[remote-config] driveSubFileId = {drive_id}")
            print(f"[remote-config] driveEnabled   = {remote.get('driveEnabled')}")
            print(f"[remote-config] marzbanEnabled = {remote.get('marzbanEnabled')}")
            print(f"[remote-config] configVersion  = {remote.get('configVersion')}")
        except Exception as e:
            print(f"[remote-config] using fallback drive id: {e}")
            drive_id = FALLBACK_DRIVE_ID

    # ── 2. Google Drive ───────────────────────────────────────────────────────
    raw = download_drive(drive_id)
    (out / "drive_raw.bin").write_bytes(raw)

    # ── 3. decode subscription ────────────────────────────────────────────────
    sub_text = decode_subscription(raw)
    (out / "subscription.txt").write_text(sub_text, encoding="utf-8")
    print(f"[save] subscription.txt  ({len(sub_text)} chars)")

    # ── 4. extract URIs ───────────────────────────────────────────────────────
    uris = extract_uris(sub_text)
    all_path = out / "lumex_uris_all.txt"
    all_path.write_text("\n".join(uris) + ("\n" if uris else ""), encoding="utf-8")
    print(f"[save] lumex_uris_all.txt  ({len(uris)} URIs)")

    # group by protocol
    by_proto: dict[str, list[str]] = {}
    for u in uris:
        proto = u.split("://", 1)[0].lower()
        by_proto.setdefault(proto, []).append(u)

    servers = []
    for u in uris:
        proto = u.split("://", 1)[0].lower()
        host = uri_host(u)
        servers.append({"protocol": proto, "host": host, "uri": u})

    (out / "lumex_uris.json").write_text(
        json.dumps(
            {
                "driveSubFileId": drive_id,
                "count": len(uris),
                "by_protocol": {k: len(v) for k, v in by_proto.items()},
                "servers": servers,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(f"[save] lumex_uris.json")

    # ── summary ───────────────────────────────────────────────────────────────
    print()
    print(f"=== {len(uris)} URIs ===")
    for proto, items in sorted(by_proto.items()):
        print(f"  {proto}: {len(items)}")
    print()
    for s in servers:
        print(f"  [{s['protocol']:10}] {s['host']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
    

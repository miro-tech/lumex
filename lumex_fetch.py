#!/usr/bin/env python3
"""
LUMEX VPN — fetch servers without the app

Flow:
  1. GET /api/remote-config from backend IP
  2. Read driveSubFileId
  3. Download Google Drive file
  4. base64-decode → extract trojan:// vless:// … URIs
  5. Normalize server names:
       - preserve the original server name completely
       - extract serverDescription from fragment
       - decode serverDescription from Base64
       - remove invisible Unicode characters
       - append serverDescription to the original name
       - remove technical serverDescription parameter
  6. Save to files

IMPORTANT:
  Connection parameters are NOT modified.

Example:

  Original:

    trojan://USER@IP:443?...#🇳🇱Login:LUMEXVPN2?serverDescription=BASE64

  Result:

    trojan://USER@IP:443?...#🇳🇱Login:LUMEXVPN2 • decoded description

The part before '#' is preserved exactly.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path


# ── Google API key ────────────────────────────────────────────────────────────

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")

if not GOOGLE_API_KEY:
    raise RuntimeError(
        "GOOGLE_API_KEY is not set. "
        "Set the environment variable GOOGLE_API_KEY."
    )


# ── Backend ──────────────────────────────────────────────────────────────────

BACKEND_URLS = [
    "https://193.23.201.236",
    "http://193.23.201.236",
]


# Fallback driveSubFileId if remote-config is unreachable
FALLBACK_DRIVE_ID = "1p3zomBe8rmJwtX2sJD2c7Jm5hetfTWFm"


# ── URI extractor ────────────────────────────────────────────────────────────

URI_RE = re.compile(
    r"(?:trojan|vless|vmess|ss|ssr|hysteria2|hy2|tuic|wireguard|sn)://[^\s\r\n]+",
    re.IGNORECASE,
)


# ── TLS ──────────────────────────────────────────────────────────────────────

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


# ── HTTP ─────────────────────────────────────────────────────────────────────

def http_get(url: str, timeout: int = 15) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "okhttp/4.12.0",
            "Accept": "application/json, text/plain, */*",
        },
    )

    with urllib.request.urlopen(
        req,
        context=CTX,
        timeout=timeout,
    ) as resp:
        return resp.read()


# ── Remote config ────────────────────────────────────────────────────────────

def fetch_remote_config() -> dict:
    last_err = None

    for base in BACKEND_URLS:
        url = f"{base}/api/remote-config"

        try:
            raw = http_get(url)
            data = json.loads(raw)

            print(
                f"[remote-config] OK  {url}"
            )

            return data

        except Exception as e:
            last_err = e

            print(
                f"[remote-config] fail "
                f"{url}: {e}"
            )

    raise RuntimeError(
        f"remote-config unreachable: "
        f"{last_err}"
    )


# ── Google Drive ─────────────────────────────────────────────────────────────

def download_drive(
    file_id: str,
    api_key: str = GOOGLE_API_KEY,
) -> bytes:

    urls = [
        (
            "https://www.googleapis.com/drive/v3/files/"
            f"{file_id}?alt=media&key={api_key}"
        ),
        (
            "https://drive.usercontent.google.com/"
            f"download?id={file_id}&export=download"
        ),
    ]

    last_err = None

    for url in urls:

        try:
            data = http_get(
                url,
                timeout=30,
            )

            print(
                f"[drive] OK  {file_id}  "
                f"({len(data)} bytes)"
            )

            return data

        except Exception as e:
            last_err = e

            print(
                f"[drive] fail "
                f"{url[:70]}…: {e}"
            )

    raise RuntimeError(
        f"Drive download failed: "
        f"{last_err}"
    )


# ── Subscription decoder ─────────────────────────────────────────────────────

def decode_subscription(raw: bytes) -> str:
    """
    Drive file is normally base64(plain subscription text).
    """

    text = raw.decode(
        "utf-8",
        errors="replace",
    ).strip()

    # Already plain?
    if URI_RE.search(text) or text.startswith("#"):
        return text

    # Base64 wrapper
    try:

        pad = "=" * (
            (4 - len(text) % 4) % 4
        )

        decoded = base64.b64decode(
            text + pad,
        )

        return decoded.decode(
            "utf-8",
            errors="replace",
        )

    except Exception:
        return text


# ── Unicode cleanup ──────────────────────────────────────────────────────────

def remove_invisible_unicode(text: str) -> str:
    """
    Removes invisible/formatting Unicode characters.

    Removed:

      U+200B ... U+200F
      U+202A ... U+202E
      U+2060 ... U+206F
      U+FEFF

    Also removes ASCII control characters.

    Normal letters, numbers, emoji,
    spaces and punctuation are preserved.
    """

    result = []

    for ch in text:

        code = ord(ch)

        # Zero-width / formatting characters
        if (
            0x200B <= code <= 0x200F
            or 0x202A <= code <= 0x202E
            or 0x2060 <= code <= 0x206F
            or code == 0xFEFF
        ):
            continue

        # ASCII control characters
        if code < 32 and ch not in (
            "\t",
            "\n",
            "\r",
        ):
            continue

        result.append(ch)

    return "".join(result)


# ── Base64 description decoder ───────────────────────────────────────────────

def decode_server_description(
    value: str,
) -> str:
    """
    Decode LUMEX serverDescription.

    Example:

        8J+foiDQmtCw0L3QsNC7IOKAoiBU

    Supports:
      - URL encoding
      - '+' / spaces
      - missing Base64 padding
    """

    if not value:
        return ""

    # URL decode.
    value = urllib.parse.unquote(
        value
    ).strip()

    # '+' may have become spaces.
    value = value.replace(
        " ",
        "+",
    )

    try:

        padding = "=" * (
            (4 - len(value) % 4) % 4
        )

        raw = base64.b64decode(
            value + padding,
            validate=False,
        )

        text = raw.decode(
            "utf-8",
            errors="replace",
        )

        text = remove_invisible_unicode(
            text
        )

        text = re.sub(
            r"\s+",
            " ",
            text,
        ).strip()

        return text

    except (
        ValueError,
        binascii.Error,
        UnicodeDecodeError,
    ):
        return ""


# ── Server name cleanup ──────────────────────────────────────────────────────

def clean_server_name(
    name: str,
) -> str:
    """
    Cleans a server name without removing
    meaningful text.

    IMPORTANT:

      Login:LUMEXVPN2
      Швеция
      Россия
      🇳🇱
      🇸🇪
      🇷🇺

    are preserved.
    """

    if not name:
        return ""

    name = urllib.parse.unquote(
        name
    )

    name = remove_invisible_unicode(
        name
    )

    name = re.sub(
        r"\s+",
        " ",
        name,
    )

    return name.strip()


# ── URI normalizer ───────────────────────────────────────────────────────────

def normalize_uri(uri: str) -> str:
    """
    Normalize LUMEX URI.

    IMPORTANT:

    The original server name is preserved.

    Example input:

      #🇳🇱Login:LUMEXVPN2?serverDescription=BASE64

    Result:

      #🇳🇱Login:LUMEXVPN2 • decoded description

    We do NOT delete:

      Login:LUMEXVPN2
      Швеция
      Россия
      country flag
      any other original name text

    Only serverDescription itself is removed from
    the fragment after being decoded.

    The connection parameters before '#' are preserved.
    """

    try:
        parts = urllib.parse.urlsplit(
            uri
        )

    except Exception:
        return uri

    # ==========================================================
    # IMPORTANT:
    #
    # Preserve everything before '#'.
    #
    # Do NOT rebuild the query using urlencode().
    # This avoids changing existing URL encoding.
    # ==========================================================

    if parts.fragment:
        base = uri.split(
            "#",
            1,
        )[0]

    else:
        base = uri

    fragment = parts.fragment

    # ==========================================================
    # 1. Find serverDescription inside fragment
    #
    # Example:
    #
    # #🇳🇱Login:LUMEXVPN2?serverDescription=BASE64
    #
    # ==========================================================

    server_description = ""

    match = re.search(
        r"\?serverDescription=([^&#]*)",
        fragment,
        flags=re.IGNORECASE,
    )

    if match:

        desc_value = match.group(1)

        server_description = (
            decode_server_description(
                desc_value
            )
        )

        # Remove ONLY:
        #
        # ?serverDescription=BASE64
        #
        # from the name.
        #
        # Everything before it is preserved.
        fragment = (
            fragment[:match.start()]
            + fragment[match.end():]
        )

        print(
            "[name-description] "
            f"{server_description!r}"
        )

    # ==========================================================
    # 2. Clean original server name
    #
    # Nothing meaningful is removed.
    # ==========================================================

    old_name = clean_server_name(
        fragment
    )

    # ==========================================================
    # 3. Clean decoded description
    # ==========================================================

    server_description = clean_server_name(
        server_description
    )

    # ==========================================================
    # 4. Combine names
    #
    # Original name ALWAYS has priority.
    #
    # Example:
    #
    # old:
    #   🇳🇱Login:LUMEXVPN2
    #
    # description:
    #   🟢 Канал • T
    #
    # result:
    #   🇳🇱Login:LUMEXVPN2 • 🟢 Канал • T
    # ==========================================================

    if old_name and server_description:

        readable_name = (
            old_name
            + " • "
            + server_description
        )

    elif old_name:

        readable_name = old_name

    elif server_description:

        readable_name = server_description

    else:

        readable_name = ""

    # ==========================================================
    # 5. Final cleanup
    # ==========================================================

    readable_name = clean_server_name(
        readable_name
    )

    # ==========================================================
    # 6. Build final URI
    #
    # Everything before '#' comes from the original URI.
    # ==========================================================

    if readable_name:

        return (
            base
            + "#"
            + urllib.parse.quote(
                readable_name,
                safe="",
            )
        )

    return base


# ── Extract URIs ─────────────────────────────────────────────────────────────

def extract_uris(
    sub_text: str,
) -> list[str]:

    raw_uris = URI_RE.findall(
        sub_text
    )

    result = []

    for uri in raw_uris:

        normalized = normalize_uri(
            uri
        )

        if normalized:
            result.append(
                normalized
            )

    return result


# ── Host extractor ───────────────────────────────────────────────────────────

def uri_host(
    uri: str,
) -> str:

    m = re.search(
        r"@([^:/]+):(\d+)",
        uri,
    )

    if m:
        return (
            f"{m.group(1)}:"
            f"{m.group(2)}"
        )

    m = re.search(
        r"://([^:/]+):(\d+)",
        uri,
    )

    if m:
        return (
            f"{m.group(1)}:"
            f"{m.group(2)}"
        )

    return "?"


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:

    ap = argparse.ArgumentParser(
        description=(
            "LUMEX VPN config fetcher"
        )
    )

    ap.add_argument(
        "--out",
        default=".",
        help="output directory",
    )

    ap.add_argument(
        "--drive-id",
        default=None,
        help=(
            "override driveSubFileId "
            "(skip remote-config)"
        ),
    )

    ap.add_argument(
        "--backend",
        default=None,
        help="override backend base URL",
    )

    args = ap.parse_args()

    out = Path(
        args.out
    )

    out.mkdir(
        parents=True,
        exist_ok=True,
    )

    if args.backend:

        BACKEND_URLS.insert(
            0,
            args.backend.rstrip("/"),
        )

    # ── 1. remote-config ─────────────────────────────────────────────────────

    drive_id = args.drive_id
    remote = {}

    if not drive_id:

        try:

            remote = fetch_remote_config()

            (
                out
                / "remote_config.json"
            ).write_text(
                json.dumps(
                    remote,
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            print(
                "[save] "
                "remote_config.json"
            )

            drive_id = (
                remote.get(
                    "driveSubFileId"
                )
                or FALLBACK_DRIVE_ID
            )

            print(
                "[remote-config] "
                f"driveSubFileId = "
                f"{drive_id}"
            )

            print(
                "[remote-config] "
                f"driveEnabled   = "
                f"{remote.get('driveEnabled')}"
            )

            print(
                "[remote-config] "
                f"marzbanEnabled = "
                f"{remote.get('marzbanEnabled')}"
            )

            print(
                "[remote-config] "
                f"configVersion  = "
                f"{remote.get('configVersion')}"
            )

        except Exception as e:

            print(
                "[remote-config] "
                f"using fallback drive id: "
                f"{e}"
            )

            drive_id = (
                FALLBACK_DRIVE_ID
            )

    # ── 2. Google Drive ──────────────────────────────────────────────────────

    raw = download_drive(
        drive_id
    )

    (
        out / "drive_raw.bin"
    ).write_bytes(
        raw
    )

    # ── 3. Decode subscription ───────────────────────────────────────────────

    sub_text = decode_subscription(
        raw
    )

    (
        out / "subscription.txt"
    ).write_text(
        sub_text,
        encoding="utf-8",
    )

    print(
        "[save] subscription.txt  "
        f"({len(sub_text)} chars)"
    )

    # ── 4. Extract + normalize URIs ──────────────────────────────────────────

    uris = extract_uris(
        sub_text
    )

    all_path = (
        out / "lumex_uris_all.txt"
    )

    all_path.write_text(
        "\n".join(uris)
        + (
            "\n"
            if uris
            else ""
        ),
        encoding="utf-8",
    )

    print(
        "[save] lumex_uris_all.txt  "
        f"({len(uris)} URIs)"
    )

    # ── Group by protocol ────────────────────────────────────────────────────

    by_proto: dict[
        str,
        list[str],
    ] = {}

    for u in uris:

        proto = (
            u.split(
                "://",
                1,
            )[0]
            .lower()
        )

        by_proto.setdefault(
            proto,
            [],
        ).append(u)

    # ── Server JSON ──────────────────────────────────────────────────────────

    servers = []

    for u in uris:

        proto = (
            u.split(
                "://",
                1,
            )[0]
            .lower()
        )

        host = uri_host(
            u
        )

        servers.append(
            {
                "protocol": proto,
                "host": host,
                "uri": u,
            }
        )

    (
        out / "lumex_uris.json"
    ).write_text(
        json.dumps(
            {
                "driveSubFileId": drive_id,
                "count": len(uris),
                "by_protocol": {
                    k: len(v)
                    for k, v in by_proto.items()
                },
                "servers": servers,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        "[save] lumex_uris.json"
    )

    # ── Summary ───────────────────────────────────────────────────────────────

    print()

    print(
        f"=== {len(uris)} URIs ==="
    )

    for proto, items in sorted(
        by_proto.items()
    ):

        print(
            f"  {proto}: "
            f"{len(items)}"
        )

    print()

    for s in servers:

        print(
            f"  [{s['protocol']:10}] "
            f"{s['host']}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())

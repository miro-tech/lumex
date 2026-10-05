#!/usr/bin/env python3
"""
LUMEX VPN — fetch servers without the app

Flow:
  1. GET /api/remote-config from backend IP
  2. Read driveSubFileId
  3. Download Google Drive file
  4. base64-decode → extract trojan:// vless:// … URIs
  5. Normalize server names:
       - URL-decode URI fragment
       - decode serverDescription from Base64
       - remove invisible Unicode characters
       - use readable serverDescription as server name
  6. Save to files

Usage:
  python3 lumex_fetch.py
  python3 lumex_fetch.py --out /path/to/dir
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
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


# ── Google API key ───────────────────────────────────────────────────────────
# Локально:
#   export GOOGLE_API_KEY="AIza..."
#
# GitHub Actions:
#   secrets.GOOGLE_API_KEY
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


# fallback driveSubFileId if remote-config is unreachable
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


# ── HTTP ──────────────────────────────────────────────────────────────────────

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

            print(f"[remote-config] OK  {url}")

            return data

        except Exception as e:
            last_err = e
            print(f"[remote-config] fail {url}: {e}")

    raise RuntimeError(
        f"remote-config unreachable: {last_err}"
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
                f"[drive] fail {url[:70]}…: {e}"
            )

    raise RuntimeError(
        f"Drive download failed: {last_err}"
    )


# ── Subscription decoder ─────────────────────────────────────────────────────

def decode_subscription(raw: bytes) -> str:
    """
    Drive file is base64(plain subscription text).
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
        pad = "=" * ((4 - len(text) % 4) % 4)

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
    Удаляет невидимые/служебные Unicode-символы,
    которые LUMEX добавляет в названия серверов.

    Сохраняет обычные буквы, цифры, emoji,
    пробелы и знаки пунктуации.
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
        if code < 32 and ch not in ("\t", "\n", "\r"):
            continue

        result.append(ch)

    return "".join(result)


# ── Base64 description decoder ───────────────────────────────────────────────

def decode_server_description(value: str) -> str:
    """
    Decode:

        ?serverDescription=8J+foiDQmtCw0L3QsNC7IOKAoiBU

    LUMEX использует URL query + Base64.
    """

    if not value:
        return ""

    # Иногда '+' приходит как пробел после parse_qs().
    value = value.replace(" ", "+")

    # URL decode
    value = urllib.parse.unquote(value).strip()

    try:
        # Добавляем padding.
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

        text = remove_invisible_unicode(text)

        return text.strip()

    except (
        ValueError,
        binascii.Error,
        UnicodeDecodeError,
    ):
        return ""


# ── URI normalizer ───────────────────────────────────────────────────────────

def normalize_uri(uri: str) -> str:
    """
    Преобразует LUMEX URI в более читаемый вид для NekoBox.

    Что делаем:

      1. Извлекаем ?serverDescription=...
      2. Декодируем Base64 description.
      3. Удаляем мусорные invisible Unicode.
      4. Если description есть — используем его как имя.
      5. Убираем сам serverDescription из URI.
      6. URL-decode старый fragment.
      7. Удаляем invisible Unicode из старого fragment.
      8. Сохраняем реальные параметры подключения.
    """

    # --------------------------------------------------
    # 1. Разделяем URI на base/query/fragment
    # --------------------------------------------------

    try:
        parts = urllib.parse.urlsplit(uri)

    except Exception:
        return uri

    base = parts.scheme + "://" + parts.netloc

    query = parts.query
    fragment = parts.fragment

    # --------------------------------------------------
    # 2. Читаем query
    # --------------------------------------------------

    query_items = urllib.parse.parse_qsl(
        query,
        keep_blank_values=True,
    )

    server_description = ""

    clean_query = []

    for key, value in query_items:

        if key.lower() == "serverdescription":

            server_description = (
                decode_server_description(value)
            )

            continue

        clean_query.append(
            (key, value)
        )

    # --------------------------------------------------
    # 3. Обрабатываем старый fragment
    # --------------------------------------------------

    readable_fragment = ""

    if fragment:

        readable_fragment = urllib.parse.unquote(
            fragment
        )

        readable_fragment = remove_invisible_unicode(
            readable_fragment
        ).strip()

    # --------------------------------------------------
    # 4. Выбираем имя
    # --------------------------------------------------

    if server_description:

        readable_name = server_description

    else:

        readable_name = readable_fragment

    # --------------------------------------------------
    # 5. Удаляем лишние пробелы
    # --------------------------------------------------

    readable_name = re.sub(
        r"\s+",
        " ",
        readable_name,
    ).strip()

    # --------------------------------------------------
    # 6. Собираем query обратно
    # --------------------------------------------------

    clean_query_string = urllib.parse.urlencode(
        clean_query,
        doseq=True,
    )

    # --------------------------------------------------
    # 7. Собираем URI
    # --------------------------------------------------

    result = base

    if clean_query_string:
        result += "?" + clean_query_string

    if readable_name:
        result += "#" + urllib.parse.quote(
            readable_name,
            safe="",
        )

    return result


# ── Extract URIs ─────────────────────────────────────────────────────────────

def extract_uris(sub_text: str) -> list[str]:

    raw_uris = URI_RE.findall(sub_text)

    result = []

    for uri in raw_uris:

        normalized = normalize_uri(uri)

        if normalized:
            result.append(normalized)

    return result


# ── Host extractor ───────────────────────────────────────────────────────────

def uri_host(uri: str) -> str:

    m = re.search(
        r"@([^:/]+):(\d+)",
        uri,
    )

    if m:
        return f"{m.group(1)}:{m.group(2)}"

    m = re.search(
        r"://([^:/]+):(\d+)",
        uri,
    )

    if m:
        return f"{m.group(1)}:{m.group(2)}"

    return "?"


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:

    ap = argparse.ArgumentParser(
        description="LUMEX VPN config fetcher"
    )

    ap.add_argument(
        "--out",
        default=".",
        help="output directory",
    )

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

    out.mkdir(
        parents=True,
        exist_ok=True,
    )

    if args.backend:

        BACKEND_URLS.insert(
            0,
            args.backend.rstrip("/"),
        )

    # ── 1. remote-config ──────────────────────────────────────────────────────

    drive_id = args.drive_id
    remote = {}

    if not drive_id:

        try:

            remote = fetch_remote_config()

            (out / "remote_config.json").write_text(
                json.dumps(
                    remote,
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            print(
                "[save] remote_config.json"
            )

            drive_id = (
                remote.get("driveSubFileId")
                or FALLBACK_DRIVE_ID
            )

            print(
                "[remote-config] "
                f"driveSubFileId = {drive_id}"
            )

            print(
                "[remote-config] "
                f"driveEnabled   = {remote.get('driveEnabled')}"
            )

            print(
                "[remote-config] "
                f"marzbanEnabled = {remote.get('marzbanEnabled')}"
            )

            print(
                "[remote-config] "
                f"configVersion  = {remote.get('configVersion')}"
            )

        except Exception as e:

            print(
                "[remote-config] "
                f"using fallback drive id: {e}"
            )

            drive_id = FALLBACK_DRIVE_ID

    # ── 2. Google Drive ───────────────────────────────────────────────────────

    raw = download_drive(
        drive_id
    )

    (out / "drive_raw.bin").write_bytes(
        raw
    )

    # ── 3. decode subscription ────────────────────────────────────────────────

    sub_text = decode_subscription(
        raw
    )

    (out / "subscription.txt").write_text(
        sub_text,
        encoding="utf-8",
    )

    print(
        "[save] subscription.txt  "
        f"({len(sub_text)} chars)"
    )

    # ── 4. extract + normalize URIs ───────────────────────────────────────────

    uris = extract_uris(
        sub_text
    )

    all_path = (
        out / "lumex_uris_all.txt"
    )

    all_path.write_text(
        "\n".join(uris)
        + ("\n" if uris else ""),
        encoding="utf-8",
    )

    print(
        "[save] lumex_uris_all.txt  "
        f"({len(uris)} URIs)"
    )

    # ── group by protocol ────────────────────────────────────────────────────

    by_proto: dict[str, list[str]] = {}

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

    # ── server JSON ──────────────────────────────────────────────────────────

    servers = []

    for u in uris:

        proto = (
            u.split(
                "://",
                1,
            )[0]
            .lower()
        )

        host = uri_host(u)

        servers.append(
            {
                "protocol": proto,
                "host": host,
                "uri": u,
            }
        )

    (out / "lumex_uris.json").write_text(
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

    # ── summary ───────────────────────────────────────────────────────────────

    print()
    print(
        f"=== {len(uris)} URIs ==="
    )

    for proto, items in sorted(
        by_proto.items()
    ):

        print(
            f"  {proto}: {len(items)}"
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

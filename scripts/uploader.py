#!/usr/bin/env python3
"""
MoviesNow • Simple Uploader
==========================

CLI helper to upload files to a presigned PUT URL. Optionally requests a
bundle upload slot first, then uploads, and prints the computed SHA-256.

Examples
--------
1) Upload to an existing presigned URL:
    python scripts/uploader.py --put-url "<URL>" ./Season01.zip

2) Create a bundle slot and upload (admin key required):
    python scripts/uploader.py \
      --api http://localhost:8000/api/v1 \
      --admin-key dev-secret \
      --title-id 11111111-1111-1111-1111-111111111111 \
      --season 1 \
      ./Season01.zip
"""

import argparse
import hashlib
import mimetypes
import os
import sys
from typing import Optional

import requests


def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("file", help="Path to file to upload")
    ap.add_argument("--put-url", help="Existing presigned PUT URL")
    ap.add_argument("--api", help="API base (e.g., http://localhost:8000/api/v1)")
    ap.add_argument("--admin-key", help="Admin API key (X-Admin-Key)")
    ap.add_argument("--title-id", help="Title UUID for bundles")
    ap.add_argument("--season", type=int, help="Season number for bundles")
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        print(f"Not a file: {args.file}", file=sys.stderr)
        sys.exit(2)

    put_url = args.put_url
    if not put_url and args.api and args.title_id:
        # Create bundle slot
        url = args.api.rstrip("/") + f"/admin/titles/{args.title_id}/bundles"
        body = {"season_number": args.season}
        headers = {"Content-Type": "application/json"}
        if args.admin_key:
            headers["X-Admin-Key"] = args.admin_key
        r = requests.post(url, json=body, headers=headers, timeout=30)
        r.raise_for_status()
        put_url = r.json()["upload_url"]
        print(f"Bundle id={r.json().get('bundle_id')} key={r.json().get('storage_key')}")

    if not put_url:
        print("Provide --put-url or --api + --title-id", file=sys.stderr)
        sys.exit(2)

    ctype = mimetypes.guess_type(args.file)[0] or "application/octet-stream"
    data = open(args.file, "rb").read()
    sha = compute_sha256(args.file)
    print(f"Uploading {args.file} ({len(data)} bytes, sha256={sha})...")
    resp = requests.put(put_url, data=data, headers={"Content-Type": ctype}, timeout=120)
    if resp.status_code not in (200, 201):
        print(f"Upload failed: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)
    print("Upload complete.")
    print(sha)


if __name__ == "__main__":
    main()


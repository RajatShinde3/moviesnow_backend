#!/usr/bin/env python3
"""
Register curated downloadable variants from a JSON manifest.

Manifest format (list of items):
[
  {
    "title_id": "<uuid>",
    "storage_key": "downloads/<title_id>/video/1080p/h264/file.mp4",
    "width": 1920,
    "height": 1080,
    "bandwidth_bps": 6000000,
    "video_codec": "H264",
    "audio_codec": "AAC",
    "label": "1080p H.264",
  },
  {
    "title_id": "<uuid>",
    "episode_id": "<uuid>",
    "storage_key": "downloads/<title_id>/<episode_id>/video/720p/h264/file.mp4",
    "width": 1280,
    "height": 720,
    "bandwidth_bps": 3000000
  }
]

Env vars:
  API_BASE         (default http://localhost:8000/api/v1)
  ADMIN_API_KEY    (optional, sent as X-Admin-Key)
  BEARER_TOKEN     (optional, sent as Authorization: Bearer ...)

Usage:
  python scripts/register_downloads.py path/to/manifest.json
"""

import json
import os
import sys
from typing import Dict, Any

import urllib.request


def _request(url: str, data: Dict[str, Any]) -> Dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if os.environ.get("ADMIN_API_KEY"):
        headers["X-Admin-Key"] = os.environ["ADMIN_API_KEY"]
    if os.environ.get("BEARER_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['BEARER_TOKEN']}"
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req) as resp:  # nosec B310 (tooling script)
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: register_downloads.py path/to/manifest.json", file=sys.stderr)
        return 2
    path = sys.argv[1]
    with open(path, "r", encoding="utf-8") as f:
        items = json.load(f)
    base = os.environ.get("API_BASE", "http://localhost:8000/api/v1")
    ok = 0
    for it in items:
        if "episode_id" in it and it["episode_id"]:
            url = f"{base}/admin/titles/{it['title_id']}/episodes/{it['episode_id']}/downloads/register"
        else:
            url = f"{base}/admin/titles/{it['title_id']}/downloads/register"
        payload = {k: v for k, v in it.items() if k in {
            "storage_key", "width", "height", "bandwidth_bps", "container", "video_codec", "audio_codec", "audio_language", "label", "sha256"
        }}
        try:
            res = _request(url, payload)
            print("OK:", res)
            ok += 1
        except Exception as e:
            print("ERROR:", url, e, file=sys.stderr)
    print(f"Registered {ok}/{len(items)} items")
    return 0 if ok == len(items) else 1


if __name__ == "__main__":
    raise SystemExit(main())

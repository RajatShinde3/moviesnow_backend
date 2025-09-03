#!/usr/bin/env python3
"""
MoviesNow • Backfill Asset Metadata
==================================

Iterates over MediaAsset rows missing size/checksum and calls admin endpoints to
HEAD and optionally compute/store SHA-256.

Usage
-----
    python scripts/backfill_asset_meta.py \
      --api http://localhost:8000/api/v1 \
      --admin-key dev-secret \
      --compute-sha-small
"""

import argparse
import requests


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True, help="API base, e.g., http://localhost:8000/api/v1")
    ap.add_argument("--admin-key", required=True, help="Admin API key for privileged endpoints")
    ap.add_argument("--ids", help="Comma-separated asset IDs to target; default: all candidates")
    ap.add_argument("--compute-sha-small", action="store_true", help="Compute SHA-256 server-side when <= 10MB")
    args = ap.parse_args()

    headers = {"X-Admin-Key": args.admin_key}

    target_ids = []
    if args.ids:
        target_ids = [s.strip() for s in args.ids.split(",") if s.strip()]
    else:
        print("Note: provide --ids to control which assets to backfill.")

    for aid in target_ids:
        r = requests.get(f"{args.api}/admin/assets/{aid}/head", headers=headers, timeout=30)
        if r.status_code // 100 != 2:
            print(f"HEAD failed for {aid}: {r.status_code} {r.text}")
            continue
        if args.compute_sha_small:
            r2 = requests.post(f"{args.api}/admin/assets/{aid}/checksum", json={}, headers=headers, timeout=120)
            if r2.status_code // 100 != 2:
                print(f"Checksum failed for {aid}: {r2.status_code} {r2.text}")
                continue
            print(f"Updated checksum for {aid}: {r2.json().get('sha256')}")


if __name__ == "__main__":
    main()


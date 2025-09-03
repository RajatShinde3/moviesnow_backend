#!/usr/bin/env python3
"""
MoviesNow • Build Season Bundle
===============================

Create a ZIP file from a list of episode files and print its path.

Example
-------
    python scripts/build_bundle.py --out ./Season01.zip ./E01.mkv ./E02.mkv
"""

import argparse
import os
import sys
import zipfile
from typing import List


def build_zip(out_path: str, files: List[str]) -> None:
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in files:
            arcname = os.path.basename(p)
            z.write(p, arcname)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="Output ZIP path")
    ap.add_argument("files", nargs="+", help="Episode files to include")
    args = ap.parse_args()

    for f in args.files:
        if not os.path.isfile(f):
            print(f"Not a file: {f}", file=sys.stderr)
            sys.exit(2)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    build_zip(args.out, args.files)
    print(args.out)


if __name__ == "__main__":
    main()


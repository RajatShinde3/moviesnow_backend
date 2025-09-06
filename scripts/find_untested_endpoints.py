import os
import re
import sys
from pathlib import Path


def build_app():
    # Ensure project root is on sys.path
    from pathlib import Path as _P  # local import to avoid top-level Path reliance
    root = _P(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    # Tame optional background tasks to avoid side effects while importing.
    os.environ.setdefault("TOKEN_CLEANUP_SCHEDULER", "false")
    os.environ.setdefault("JWKS_SCHEDULER", "false")
    # Ensure we default to a local/dev environment if app checks it.
    os.environ.setdefault("ENV", "test")
    try:
        from app.main import create_app  # type: ignore
        return create_app()
    except Exception:
        # Fallback: try module-level app
        from app import main  # type: ignore
        return getattr(main, "app", None)


def iter_routes_static(root: Path):
    """Yield routes by statically scanning router files.

    This avoids importing FastAPI or the app and should be robust in bare envs.
    """
    api_root = root / "app" / "api" / "v1" / "routers"
    extra_files = [
        root / "app" / "api" / "well_known.py",
        root / "app" / "main.py",
    ]

    files: list[Path] = []
    if api_root.exists():
        files += [p for p in api_root.rglob("*.py") if "__pycache__" not in p.parts]
    files += [p for p in extra_files if p.exists()]

    route_items: list[dict] = []

    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Determine global prefix bucket
        file_norm = str(p.as_posix())
        if "/app/api/v1/routers/admin/" in file_norm:
            global_prefix = "/api/v1/admin"
        elif file_norm.endswith("/app/api/v1/routers/user/me.py"):
            # Tests mount `me` directly under /api/v1
            global_prefix = "/api/v1"
        elif "/app/api/v1/routers/user/" in file_norm:
            global_prefix = "/api/v1/user"
        elif "/app/api/v1/routers/auth/" in file_norm:
            global_prefix = "/api/v1/auth"
        elif file_norm.endswith("/app/api/v1/routers/orgs/admin.py"):
            global_prefix = "/api/v1/orgs/admin"
        elif file_norm.endswith("/app/api/v1/routers/orgs/management.py"):
            global_prefix = "/api/v1/orgs/management"
        elif file_norm.endswith("/app/api/v1/routers/player/sessions.py"):
            global_prefix = "/api/v1/player/sessions"
        elif "/app/api/v1/routers/" in file_norm:
            global_prefix = "/api/v1"
        elif file_norm.endswith("/app/api/well_known.py"):
            global_prefix = ""
        elif file_norm.endswith("/app/main.py"):
            global_prefix = ""
        else:
            global_prefix = ""

        # Local APIRouter(prefix=...) if declared
        local_prefix = ""
        m_pref = re.search(r"APIRouter\([^\)]*?prefix\s*=\s*([\'\"])(.+?)\1", text)
        if m_pref:
            local_prefix = m_pref.group(2)

        # Handle decorator-based routes
        for m2 in re.finditer(r"@router\.(get|post|put|patch|delete)\(\s*([\'\"])(.+?)\2", text, re.DOTALL):
            method = m2.group(1).upper()
            path = m2.group(3)
            full_path = path
            if path.startswith("/api/"):
                full_path = path  # absolute
            elif (file_norm.endswith("/app/main.py") or file_norm.endswith("/app/api/well_known.py")):
                full_path = path
            else:
                base_prefix = local_prefix if local_prefix.startswith("/api/") else f"{global_prefix}{local_prefix}"
                full_path = f"{base_prefix}{path}"
            # Normalize duplicate slashes
            full_path = re.sub(r"//+", "/", full_path)
            route_items.append({"path": full_path, "methods": [method], "file": file_norm})

        # Handle add_api_route(..., methods=[..])
        for m3 in re.finditer(r"router\.add_api_route\(\s*([\'\"])(.+?)\1\s*,[^\)]*?methods\s*=\s*\[([^\]]+)\]", text, re.DOTALL):
            path = m3.group(2)
            methods_raw = m3.group(3)
            methods = [s.strip().strip("'\"").upper() for s in methods_raw.split(',') if s.strip()]
            full_path = path
            if path.startswith("/api/"):
                full_path = path
            else:
                base_prefix = local_prefix if local_prefix.startswith("/api/") else f"{global_prefix}{local_prefix}"
                full_path = f"{base_prefix}{path}"
            full_path = re.sub(r"//+", "/", full_path)
            route_items.append({"path": full_path, "methods": methods, "file": file_norm})

    # Merge duplicate paths to union methods
    merged: dict[str, dict] = {}
    for item in route_items:
        key = item["path"]
        if key not in merged:
            merged[key] = {"path": item["path"], "methods": set(item["methods"]), "file": item["file"]}
        else:
            merged[key]["methods"].update(item["methods"])  # type: ignore
    for k in list(merged.keys()):
        merged[k]["methods"] = sorted(merged[k]["methods"])  # type: ignore
    return list(merged.values())


def route_to_test_pattern(path: str) -> str:
    # Replace FastAPI params like {item_id} or {slug:str} with a single path segment matcher.
    # We avoid matching slashes inside params to keep it simple.
    esc = re.escape(path)
    pattern = re.sub(r"\\\{[^}]+\\\}", r"[^/]+", esc)
    # Allow optional trailing slash in tests
    if not pattern.endswith("/"):
        pattern += "/?"
    return pattern


def collect_tests(root: Path) -> list[Path]:
    tests_dir = root / "tests"
    if not tests_dir.exists():
        return []
    files: list[Path] = []
    for p in tests_dir.rglob("*.py"):
        # Skip pycache or compiled files just in case
        if "__pycache__" in p.parts:
            continue
        files.append(p)
    return files


def file_contains_pattern(p: Path, regex: re.Pattern) -> bool:
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    return bool(regex.search(text))


def extract_base_vars(text: str) -> dict[str, str]:
    """Extract simple URL base variables like `BASE = "/api/v1/admin"`.

    Returns a map from var name to its literal string value.
    """
    bases: dict[str, str] = {}
    for m in re.finditer(r"^\s*([A-Z_][A-Z0-9_]*)\s*=\s*['\"](/api/[^'\"]+)['\"]\s*$", text, re.MULTILINE):
        bases[m.group(1)] = m.group(2)
    return bases


def covered_in_file_by_base(text: str, full_path: str) -> bool:
    bases = extract_base_vars(text)
    if not bases:
        return False
    for var, base in bases.items():
        if not full_path.startswith(base):
            continue
        suffix = full_path[len(base):]
        # Build flexible regex for f-strings: f"{VAR}/path/{id}"
        # Convert suffix replacing {param} with a generic placeholder pattern
        parts = re.split(r"(\{[^}]+\})", suffix)
        rx_parts: list[str] = []
        for token in parts:
            if not token:
                continue
            if re.fullmatch(r"\{[^}]+\}", token):
                rx_parts.append(r"{[^}]+}")
            else:
                rx_parts.append(re.escape(token))
        suffix_rx = "".join(rx_parts)
        # match either f"{VAR}..." or f'{VAR}...'
        pat = rf"f[\'\"]\{{{var}\}}{suffix_rx}"
        if re.search(pat, text):
            return True
        # Also match concatenation: VAR + "/path/{id}"
        pat2 = rf"\b{var}\b\s*\+\s*[rR]?[fF]?[\'\"]{suffix_rx}"
        if re.search(pat2, text):
            return True
    return False


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    # Prefer static scan (no framework import dependency)
    routes = list(iter_routes_static(root))
    test_files = collect_tests(root)
    untested = []

    for r in routes:
        path = r["path"]
        pattern = route_to_test_pattern(path)
        try:
            rx = re.compile(pattern)
        except re.error:
            # Fallback to literal search if regex fails
            rx = re.compile(re.escape(path))

        covered = False
        for tf in test_files:
            try:
                text = tf.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            base_hit = covered_in_file_by_base(text, path)
            if (os.getenv("FIND_EP_DEBUG") == "1") and ("cdn/invalidation" in path):
                print(f"DBG {tf}: direct={bool(rx.search(text))} base={base_hit}")
            if rx.search(text) or base_hit:
                covered = True
                break

        if not covered:
            untested.append({
                "path": path,
                "methods": r.get("methods", []),
                "file": r.get("file", ""),
            })

    # Sort for stable output
    untested.sort(key=lambda x: x["path"]) 

    # Human-friendly report
    if not untested:
        print("All discovered endpoints appear in tests (string match heuristic).")
        return 0

    print("Untested endpoints (heuristic check):")
    for item in untested:
        methods = ",".join(item.get("methods", []))
        file = item.get("file") or ""
        print(f"  [{methods}] {item['path']}  ({file})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

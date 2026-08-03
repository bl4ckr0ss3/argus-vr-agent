"""ARGUS run cleanup — auto-purge old detonation artifacts.

Production mode: regularly cleans runs/ older than retention days to save disk.
Dry-run by default, pass --apply to actually delete.

Usage:
    python -m argus.cleanup                    # dry-run
    python -m argus.cleanup --days 14          # 14 day retention
    python -m argus.cleanup --apply            # actual delete
    python run.py cleanup                       # run.py CLI alias
"""
from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import config

_TARGET_DIRS = (
    config.RUNS_DIR,           # hunt / collab / workflow transcripts
    config.ROOT / "quarantine",  # sample extracts
)

# Keep the N most recent run dirs even if older than retention window
_KEEP_LAST = 5


def _age_days(path: Path) -> float:
    """Age of a file or directory in days (based on mtime)."""
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return (datetime.now(timezone.utc) - mtime).total_seconds() / 86400


def clean(days: int | None = None, dry: bool = True) -> dict[str, int]:
    """Delete run artifacts older than `days`. Defaults to config.RUNTIME_RETENTION_DAYS."""
    if days is None:
        days = config.RUNTIME_RETENTION_DAYS
    if days <= 0:
        return {"result": "skipped", "reason": "retention disabled", "freed_bytes": 0, "deleted": 0}

    totals = {"deleted": 0, "freed_bytes": 0, "errors": 0}
    for base_dir in _TARGET_DIRS:
        if not base_dir.exists():
            continue

        # Collect subdirectories sorted by mtime (most recent first)
        items = sorted(
            [p for p in base_dir.iterdir() if p.is_dir()],
            key=lambda p: p.stat().st_mtime, reverse=True,
        )
        # Keep the most recent K_LAST regardless of age
        candidates = items[_KEEP_LAST:]

        for item in candidates:
            age = _age_days(item)
            if age < days:
                continue
            size = sum(f.stat().st_size for f in item.rglob("*") if f.is_file()) if item.exists() else 0

            if dry:
                print(f"  [DRY] would delete {item.name} ({age:.0f}d, {size//1024}KB)")
                totals["deleted"] += 1
                totals["freed_bytes"] += size
            else:
                try:
                    import shutil
                    shutil.rmtree(item, ignore_errors=True)
                    print(f"  [DEL] {item.name} ({age:.0f}d, {size//1024}KB)")
                    totals["deleted"] += 1
                    totals["freed_bytes"] += size
                except Exception as e:
                    print(f"  [ERR] {item.name}: {e}")
                    totals["errors"] += 1

    return totals


def main() -> None:
    p = argparse.ArgumentParser(prog="cleanup", description="Purge old run artifacts")
    p.add_argument("--days", type=int, default=config.RUNTIME_RETENTION_DAYS,
                   help=f"Max age in days (default: {config.RUNTIME_RETENTION_DAYS})")
    p.add_argument("--apply", action="store_true", help="Actually delete (default: dry-run)")
    p.add_argument("--watch", type=int, default=0,
                   help="Run as daemon, checking every N seconds")
    args = p.parse_args()

    if args.apply:
        print(f"Cleanup — deleting artifacts older than {args.days} days")
        result = clean(days=args.days, dry=False)
        print(f"Done: {result['deleted']} items, {result['freed_bytes'] // 1024}KB freed ({result['errors']} errors)")
    else:
        print(f"Dry-run — would delete artifacts older than {args.days} days")
        result = clean(days=args.days, dry=True)
        print(f"\nWould free: {result['freed_bytes'] // 1024}KB across {result['deleted']} items")

    if args.watch:
        print(f"\nWatching every {args.watch}s...")
        while True:
            time.sleep(args.watch)
            clean(days=args.days, dry=not args.apply)


if __name__ == "__main__":
    main()

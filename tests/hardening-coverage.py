#!/usr/bin/env python3
"""Which hardening defects have a regression test, and which do not.

The tables in docs/hardening.md number every confirmed defect. A unit
test that guards one carries the number in its doc comment
(`/// Hardening 35.`; several numbers separated by commas), and the
local battle test maps numbers to case names in its HARDENING table.
Both are read here, so the report never goes stale by hand:

    python3 tests/hardening-coverage.py          # the table
    python3 tests/hardening-coverage.py --check  # exit 1 on an unguarded row

Rows from the first two passes were fixed in the pipeline (kernel
builds, guest boots) and mostly have no unit-testable shape; the check
reports them but only counts rows from the pass given by --since.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROW = re.compile(r"^\| (\d+)\s+\| (.+?)\s+\| \S+\s+\|$")
TAG = re.compile(r"///\s*Hardening ([0-9, ]+)\.")


def defects() -> dict[int, str]:
    rows = {}
    for line in (ROOT / "docs/hardening.md").read_text(encoding="utf-8").splitlines():
        match = ROW.match(line)
        if match:
            rows[int(match.group(1))] = match.group(2)
    return rows


def unit_tests() -> dict[int, list[str]]:
    guards: dict[int, list[str]] = {}
    for path in sorted((ROOT / "src").rglob("*.rs")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            match = TAG.search(line)
            if not match:
                continue
            name = next(
                (
                    re.search(r"fn (\w+)", later).group(1)
                    for later in lines[index : index + 6]
                    if re.search(r"^\s*fn \w+", later)
                ),
                "?",
            )
            for number in match.group(1).replace(" ", "").split(","):
                guards.setdefault(int(number), []).append(name)
    return guards


def battle_cases() -> dict[int, list[str]]:
    sys.path.insert(0, str(ROOT / "tests"))
    try:
        import battletest
    except ImportError:
        return {}
    names = [name for name, _ in battletest.cases()]
    return {
        number: sorted(
            {name for name in names if any(re.search(p, name) for p in patterns)}
        )
        for number, patterns in battletest.HARDENING.items()
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true", help="exit 1 if a counted row is unguarded"
    )
    parser.add_argument(
        "--since", type=int, default=26, help="first row the check counts (default 26)"
    )
    args = parser.parse_args()
    rows, units, battles = defects(), unit_tests(), battle_cases()
    unguarded = []
    for number, title in sorted(rows.items()):
        unit, battle = units.get(number, []), battles.get(number, [])
        marks = (
            ("unit" if unit else "    ")
            + " "
            + (f"battle:{len(battle)}" if battle else "        ")
        )
        print(f"{number:>3}  {marks}  {title[:70]}")
        if not unit and not battle and number >= args.since:
            unguarded.append(number)
    counted = [n for n in rows if n >= args.since]
    print(
        f"\n{len(counted) - len(unguarded)}/{len(counted)} rows from {args.since} on are guarded",
        end="",
    )
    if unguarded:
        print(f"; unguarded: {', '.join(map(str, unguarded))}")
    else:
        print()
    stray = sorted(set(units) - set(rows))
    if stray:
        print(f"tags without a table row: {', '.join(map(str, stray))}")
    return 1 if args.check and (unguarded or stray) else 0


if __name__ == "__main__":
    raise SystemExit(main())

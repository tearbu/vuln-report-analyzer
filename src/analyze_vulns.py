#!/usr/bin/env python3
"""
analyze_vulns.py - turn a Nessus-style vulnerability export into a
prioritized remediation plan.

What it does:
  * Reads a scanner CSV export (one row per host finding).
  * De-duplicates repeated findings for the same host + CVE, keeping the
    earliest "First Found" date (repeat scans re-report the same issue).
  * Applies a simple remediation SLA policy based on CVSS v3 severity:
        Critical (CVSS >= 9.0)  -> 15 days
        High     (7.0 - 8.9)    -> 30 days
        Medium   (4.0 - 6.9)    -> 90 days
        Low      (< 4.0)        -> 180 days
  * Scores every finding for fix-first priority:
        priority = CVSS x asset-criticality weight
        (Critical asset x1.5, High x1.25, Medium x1.0, Low x0.75)
  * Writes a prioritized remediation plan (CSV) and a Markdown summary
    with severity counts, the overdue count, and the top 10 fixes.

Usage:
    python3 src/analyze_vulns.py
    python3 src/analyze_vulns.py --input data/sample-scan.csv --as-of 2026-11-12

Standard library only. No network access. Demo data is fictional.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

# --- Policy -----------------------------------------------------------------

SLA_DAYS = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}
CRITICALITY_WEIGHT = {"Critical": 1.5, "High": 1.25, "Medium": 1.0, "Low": 0.75}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
DEFAULT_AS_OF = "2026-11-12"


def severity_from_cvss(score: float) -> str:
    """Map a CVSS v3 base score to a severity band."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


# --- Input ------------------------------------------------------------------

def load_findings(path: Path) -> list[dict]:
    """Read the scanner export. Expects the columns used by the sample file."""
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    findings = []
    for i, row in enumerate(rows, start=2):  # line 1 is the header
        try:
            findings.append(
                {
                    "host": row["Host"].strip(),
                    "fqdn": row["FQDN/IP"].strip(),
                    "cve": row["CVE"].strip(),
                    "cvss": float(row["CVSS v3 Base Score"]),
                    "name": row["Name"].strip(),
                    "solution": row["Solution"].strip(),
                    "first_found": date.fromisoformat(row["First Found"].strip()),
                    "asset_criticality": row["Asset Criticality"].strip(),
                }
            )
        except (KeyError, ValueError, AttributeError) as exc:
            sys.exit(f"error: could not parse row {i} of {path}: {exc}")
    return findings


def dedupe(findings: list[dict]) -> list[dict]:
    """Collapse repeated host+CVE rows, keeping the earliest First Found."""
    best: dict[tuple[str, str], dict] = {}
    for f in findings:
        key = (f["host"], f["cve"])
        if key not in best or f["first_found"] < best[key]["first_found"]:
            best[key] = f
    return list(best.values())


# --- Analysis ---------------------------------------------------------------

def enrich(f: dict, as_of: date) -> dict:
    """Add severity, SLA due date, overdue status, and priority score."""
    severity = severity_from_cvss(f["cvss"])
    due = f["first_found"] + timedelta(days=SLA_DAYS[severity])
    delta = (as_of - due).days  # >0 means the SLA deadline has passed
    weight = CRITICALITY_WEIGHT.get(f["asset_criticality"], 1.0)
    out = dict(f)
    out.update(
        severity=severity,
        due_date=due,
        overdue=delta > 0,
        days_overdue=max(delta, 0),
        days_remaining=max(-delta, 0),
        priority=round(f["cvss"] * weight, 2),
    )
    return out


def status_text(f: dict) -> str:
    if f["overdue"]:
        return "Overdue"
    if f["days_remaining"] == 0:
        return "Due today"
    return "Within SLA"


def reason(f: dict) -> str:
    """One-line explanation of why this finding ranks where it does."""
    bits = [
        f"{f['severity']} severity (CVSS {f['cvss']:.1f}) on a "
        f"{f['asset_criticality']}-criticality asset"
    ]
    if f["overdue"]:
        bits.append(f"SLA breached {f['days_overdue']} days ago (due {f['due_date']})")
    elif f["days_remaining"] == 0:
        bits.append(f"SLA deadline is today ({f['due_date']})")
    else:
        bits.append(f"{f['days_remaining']} days left in SLA (due {f['due_date']})")
    return "; ".join(bits)


# --- Output -----------------------------------------------------------------

PLAN_FIELDS = [
    "Rank", "Host", "FQDN/IP", "CVE", "Vulnerability", "CVSS", "Severity",
    "Asset Criticality", "Priority Score", "First Found", "SLA Due",
    "Status", "Days Overdue", "Solution",
]


def write_plan(findings: list[dict], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=PLAN_FIELDS)
        writer.writeheader()
        for rank, f in enumerate(findings, start=1):
            writer.writerow(
                {
                    "Rank": rank,
                    "Host": f["host"],
                    "FQDN/IP": f["fqdn"],
                    "CVE": f["cve"],
                    "Vulnerability": f["name"],
                    "CVSS": f"{f['cvss']:.1f}",
                    "Severity": f["severity"],
                    "Asset Criticality": f["asset_criticality"],
                    "Priority Score": f"{f['priority']:.2f}",
                    "First Found": f["first_found"],
                    "SLA Due": f["due_date"],
                    "Status": status_text(f),
                    "Days Overdue": f["days_overdue"],
                    "Solution": f["solution"],
                }
            )


def build_summary(findings: list[dict], total_rows: int, as_of: date) -> str:
    sev_counts = Counter(f["severity"] for f in findings)
    overdue = [f for f in findings if f["overdue"]]
    lines = [
        "# Vulnerability Remediation Summary",
        "",
        f"- As-of date: {as_of}",
        f"- Findings in scanner export: {total_rows}",
        f"- Duplicates removed: {total_rows - len(findings)}",
        f"- Unique findings analyzed: {len(findings)}",
        f"- Overdue against SLA: {len(overdue)}",
        "",
        "## Findings by severity",
        "",
        "| Severity | Count | SLA (days) |",
        "| --- | --- | --- |",
    ]
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev} | {sev_counts.get(sev, 0)} | {SLA_DAYS[sev]} |")
    lines += [
        "",
        "## Top 10 - fix these first",
        "",
        "| Rank | Host | CVE | CVSS | Asset | Priority | Status | Why |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for rank, f in enumerate(findings[:10], start=1):
        lines.append(
            f"| {rank} | {f['host']} | {f['cve']} | {f['cvss']:.1f} | "
            f"{f['asset_criticality']} | {f['priority']:.2f} | {status_text(f)} | "
            f"{f['name']} - {reason(f)} |"
        )
    lines.append("")
    return "\n".join(lines)


# --- Main -------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description="Build a prioritized remediation plan from a scanner CSV export."
    )
    parser.add_argument(
        "--input", type=Path, default=root / "data" / "sample-scan.csv",
        help="Scanner CSV export to analyze (default: bundled sample data).",
    )
    parser.add_argument(
        "--as-of", default=DEFAULT_AS_OF, metavar="YYYY-MM-DD",
        help=f"'Today' for SLA math (default: {DEFAULT_AS_OF}, keeps demos deterministic).",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=root / "output",
        help="Where to write remediation-plan.csv and summary.md.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    as_of = date.fromisoformat(args.as_of)

    raw = load_findings(args.input)
    findings = [enrich(f, as_of) for f in dedupe(raw)]
    findings.sort(key=lambda f: (-f["priority"], -f["days_overdue"], f["host"]))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    plan_path = args.output_dir / "remediation-plan.csv"
    summary_path = args.output_dir / "summary.md"
    write_plan(findings, plan_path)
    summary = build_summary(findings, len(raw), as_of)
    summary_path.write_text(summary, encoding="utf-8")

    print(summary)
    print(f"Wrote {plan_path}")
    print(f"Wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

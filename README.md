# Vulnerability Report Analyzer

Turns a raw vulnerability scanner export into a **prioritized remediation plan**, which is the thing a spreadsheet of scanner output never gives you. It de-duplicates repeat findings, applies a remediation SLA policy, weights each finding by asset criticality, and produces a ranked fix-first list with a plain-language reason for every ranking.

## Why it matters

Vulnerability management programs rarely fail because scanning doesn't happen. They fail in the hand-off. A scanner export with hundreds of rows, duplicates from repeat scans, and no business context gets ignored. Security and GRC teams are expected to answer three questions from that export: *What is overdue? What do we fix first? Why that order?* This tool answers all three, in a format (CSV plan + Markdown summary) that can go straight into a ticket queue or a management report.

Skills it demonstrates: vulnerability management lifecycle, risk-based prioritization (CVSS + asset context), SLA tracking and exception reporting, Python automation with the standard library only.

## How it works

1. **Load** a Nessus-style CSV export (`Host, FQDN/IP, CVE, CVSS v3 Base Score, Risk, Name, Solution, First Found, Asset Criticality`).
2. **De-duplicate** repeated host + CVE findings, keeping the earliest *First Found* date. Aging should be measured from first discovery, not the latest rescan.
3. **Apply SLA policy** from the CVSS v3 score:

   | Severity | CVSS | SLA |
   | --- | --- | --- |
   | Critical | ≥ 9.0 | 15 days |
   | High | 7.0 to 8.9 | 30 days |
   | Medium | 4.0 to 6.9 | 90 days |
   | Low | < 4.0 | 180 days |

4. **Score priority** = `CVSS × asset-criticality weight` (Critical asset ×1.5, High ×1.25, Medium ×1.0, Low ×0.75), so a serious flaw on a domain controller outranks the same flaw on a test workstation.
5. **Output** a ranked remediation plan (CSV) and a Markdown summary with severity counts, the overdue count, and the top 10 fixes with reasons.

## Run it

```bash
python3 src/analyze_vulns.py                      # bundled sample data, as-of 2026-11-12
python3 src/analyze_vulns.py --as-of 2026-12-01   # different "today" for SLA math
python3 src/analyze_vulns.py --input path/to/your-export.csv
```

Outputs land in `output/`: `remediation-plan.csv` and `summary.md`. The `--as-of` flag defaults to `2026-11-12` so demo output is deterministic; pass today's date for real data. No dependencies. Python 3 standard library only.

## Sample output (actual run on the bundled data)

The sample export has 30 findings across 8 hosts, including two findings that repeat scans reported twice:

```text
# Vulnerability Remediation Summary

- As-of date: 2026-11-12
- Findings in scanner export: 30
- Duplicates removed: 2
- Unique findings analyzed: 28
- Overdue against SLA: 17

## Findings by severity

| Severity | Count | SLA (days) |
| --- | --- | --- |
| Critical | 11 | 15 |
| High | 10 | 30 |
| Medium | 6 | 90 |
| Low | 1 | 180 |

## Top 10 - fix these first

| Rank | Host | CVE | CVSS | Asset | Priority | Status | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | web-01 | CVE-2021-44228 | 10.0 | Critical | 15.00 | Overdue | Apache Log4j2 Remote Code Execution - Critical severity (CVSS 10.0) on a Critical-criticality asset; SLA breached 55 days ago (due 2026-09-18) |
| 2 | db-01 | CVE-2020-1472 | 10.0 | Critical | 15.00 | Overdue | Netlogon Elevation of Privilege (Zerologon) - ... SLA breached 26 days ago (due 2026-10-17) |
| 3 | dc-01 | CVE-2020-1472 | 10.0 | Critical | 15.00 | Within SLA | ... 8 days left in SLA (due 2026-11-20) |
| 4 | dc-01 | CVE-2024-38063 | 9.8 | Critical | 14.70 | Overdue | Windows TCP/IP Remote Code Execution - ... SLA breached 87 days ago (due 2026-08-17) |
| 5 | db-01 | CVE-2019-0708 | 9.8 | Critical | 14.70 | Overdue | Microsoft RDP Remote Code Execution (BlueKeep) - ... SLA breached 74 days ago |
```

Note the same CVE (Zerologon) ranking #2 on one host and #3 on another: identical CVSS and asset weight, separated only by SLA state. That is exactly the judgment call this tool automates. 17 of 28 unique findings are already past SLA, which is the number a program manager needs on one line.

## Repository layout

```text
src/analyze_vulns.py     the analyzer (single file, stdlib only)
data/sample-scan.csv     fictional scanner export: 30 findings, 8 hosts
output/                  generated plan + summary (created on run)
```

## Limitations (honest ones)

- **One input format.** It expects the exact column layout of the bundled sample. Real Nessus/Tenable/Qualys exports vary; a production version would add a column-mapping layer.
- **CVSS is the only severity input.** It doesn't ingest exploit intelligence (KEV/EPSS), exposure (internet-facing or not), or compensating controls, all of which change real-world priority. The asset-criticality weight is a deliberate, simple stand-in.
- **SLA policy is fixed in code.** Real programs negotiate SLAs per environment and grant exceptions; here the policy is a constant so the demo is transparent and reproducible.
- **It reports; it doesn't remediate or track state.** No ticketing integration, no re-scan verification, no memory of previous runs.

## Sample data

All hosts, CVEs-in-context, and dates in `data/sample-scan.csv` are fictional demo data assembled for this project (real CVE IDs are used so the output reads realistically; the environment described does not exist).

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Araf Abubakar.

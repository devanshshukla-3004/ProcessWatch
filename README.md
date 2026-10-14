# ProcessWatch — Local Process Security Triage

**Day 11/100 · 100 Days • 100 Cybersecurity Projects**

ProcessWatch is a read-only Python utility that inventories local process metadata or analyzes a supplied JSON snapshot, then applies transparent heuristics to flag process names, executable paths, and command-line patterns that deserve review. It is for learning and defensive triage, not a replacement for endpoint detection products.

## Features
- Read-only local process metadata collection through psutil.
- Offline analysis of JSON process snapshots.
- Heuristics for dual-use tool names, temporary/shared-memory executable paths, encoded PowerShell indicators, risky interpreter arguments, and self-parent PID data.
- Severity labels, rule IDs, plain-language reasons, and summary counts.
- JSON and CSV report export.
- Unit tests and synthetic sample data.

## Requirements
- Python 3.10+
- psutil for live process collection. Snapshot analysis uses the standard library.

## Setup — Windows PowerShell
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```
If activation is blocked, run `\.venv\Scripts\python.exe processwatch.py --input samples/process_snapshot.json --pretty`.

## Setup — Linux / Kali / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Demo
```bash
python processwatch.py --input samples/process_snapshot.json
python processwatch.py --input samples/process_snapshot.json --json reports/demo-report.json --csv reports/demo-findings.csv
python processwatch.py --input samples/process_snapshot.json --pretty
```
The included snapshot is synthetic lab data, not a record of a real machine.

## Inspect this machine (read-only)
```bash
python processwatch.py
python processwatch.py --json reports/local-report.json --csv reports/local-findings.csv
```
Run only on devices you own or are authorized to administer. The tool does not terminate processes, change settings, connect to remote hosts, or perform remediation.

## Tests
```bash
python -m unittest discover -s tests -v
```

## Limitations
A process name can be spoofed, legitimate administrators may use dual-use tools, and temporary paths or encoded command lines can be benign. Findings are leads to investigate, not proof of compromise. This is a small heuristic project, not a replacement for EDR or antivirus.

## Stack
Python · psutil · JSON · CSV · unittest

Author: Devansh Shukla · https://github.com/devanshshukla-3004

#!/usr/bin/env python3
"""ProcessWatch: read-only local process inventory and heuristic risk triage."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from processwatch.core import analyze_processes, collect_processes, write_report

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only local process inventory and suspicious-pattern triage")
    parser.add_argument("--input", type=Path, help="JSON process snapshot to analyze instead of inspecting this machine")
    parser.add_argument("--json", dest="json_path", type=Path, help="Write full JSON report")
    parser.add_argument("--csv", dest="csv_path", type=Path, help="Write findings CSV")
    parser.add_argument("--pretty", action="store_true", help="Print full JSON report")
    args = parser.parse_args(argv)
    try:
        records = json.loads(args.input.read_text(encoding="utf-8")) if args.input else collect_processes()
        if isinstance(records, dict):
            records = records.get("processes", [])
        if not isinstance(records, list):
            raise ValueError("Input must be a JSON array or an object with a 'processes' array")
        report = analyze_processes(records)
        if args.json_path or args.csv_path:
            write_report(report, args.json_path, args.csv_path)
        if args.pretty:
            print(json.dumps(report, indent=2))
        else:
            print("ProcessWatch | Local Process Security Triage")
            print(f"Processes analyzed : {report['summary']['process_count']}")
            print(f"Findings            : {report['summary']['finding_count']}")
            print("Severity            : " + ", ".join(f"{k}={v}" for k, v in report["summary"]["severity_counts"].items()))
            for item in report["findings"]:
                print(f"[{item['severity']}] PID {item.get('pid', '?')} {item.get('name', '<unknown>')}: {item['rule']} — {item['reason']}")
            if not report["findings"]:
                print("No heuristic findings. This does not prove the system is clean.")
            if args.json_path:
                print(f"JSON report saved: {args.json_path}")
            if args.csv_path:
                print(f"CSV report saved : {args.csv_path}")
        return 0
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ProcessWatch error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())

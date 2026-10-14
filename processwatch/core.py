"""Process collection, transparent heuristic rules, and report export."""
from __future__ import annotations
import csv, json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SUSPICIOUS_NAMES = {"mimikatz.exe", "psexec.exe", "nc.exe", "ncat.exe", "netcat", "xmrig", "keylogger.exe", "procdump.exe"}
RISKY_PATH_PARTS = ("\\temp\\", "/tmp/", "\\appdata\\local\\temp\\", "/dev/shm/")

def _norm(s: Any) -> str:
    return str(s or "").strip().lower().replace("/", "\\")

def collect_processes() -> list[dict[str, Any]]:
    """Collect basic process metadata using psutil; does not terminate or modify processes."""
    try:
        import psutil
    except ImportError as exc:
        raise ValueError("psutil is required for live collection. Install requirements.txt or use --input samples/process_snapshot.json") from exc
    records = []
    for p in psutil.process_iter(attrs=["pid", "ppid", "name", "exe", "username", "cmdline", "create_time"]):
        try:
            info = p.info
            records.append({"pid": info.get("pid"), "ppid": info.get("ppid"), "name": info.get("name") or "", "exe": info.get("exe") or "", "username": info.get("username") or "", "cmdline": " ".join(info.get("cmdline") or []), "create_time": info.get("create_time")})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return records

def analyze_processes(records: list[dict[str, Any]]) -> dict[str, Any]:
    findings, normalized = [], []
    for raw in records:
        if not isinstance(raw, dict):
            continue
        proc = {"pid": raw.get("pid"), "ppid": raw.get("ppid"), "name": str(raw.get("name") or ""), "exe": str(raw.get("exe") or ""), "username": str(raw.get("username") or ""), "cmdline": str(raw.get("cmdline") or ""), "create_time": raw.get("create_time")}
        normalized.append(proc)
        name, path, cmd = _norm(proc["name"]), _norm(proc["exe"]), _norm(proc["cmdline"])
        rules = []
        if name in SUSPICIOUS_NAMES:
            rules.append(("KNOWN_TOOL_NAME", "HIGH", 35, f"Process name matches a dual-use or commonly abused tool name: {proc['name']}"))
        if path and any(part in path for part in RISKY_PATH_PARTS):
            rules.append(("EXECUTABLE_FROM_TEMP_PATH", "MEDIUM", 22, "Executable path contains a temporary or shared-memory directory"))
        if ("-enc " in cmd or "-encodedcommand" in cmd) and ("powershell" in name or "powershell" in cmd):
            rules.append(("ENCODED_POWERSHELL_ARGUMENT", "MEDIUM", 20, "PowerShell command line includes an encoded-command indicator"))
        if name in {"python", "python.exe", "bash", "sh", "pwsh", "powershell.exe"} and any(token in cmd for token in ("/dev/tcp/", "downloadstring", "frombase64string", "invoke-expression", " iwr ", " curl ")):
            rules.append(("SCRIPT_INTERPRETER_RISKY_ARGUMENT", "MEDIUM", 18, "Script interpreter command line contains a review-worthy execution or retrieval pattern"))
        if proc["pid"] == proc["ppid"] and proc["pid"] not in (None, 0):
            rules.append(("SELF_PARENT_PID", "LOW", 8, "PID and parent PID are equal; validate source data or platform-specific semantics"))
        for rule, severity, score, reason in rules:
            findings.append({"pid": proc["pid"], "name": proc["name"], "exe": proc["exe"], "severity": severity, "score": score, "rule": rule, "reason": reason})
    counts = {k: sum(1 for f in findings if f["severity"] == k) for k in ("HIGH", "MEDIUM", "LOW")}
    return {"tool": "ProcessWatch", "version": "1.0.0", "generated_at": datetime.now(timezone.utc).isoformat(), "mode": "offline_snapshot_analysis", "summary": {"process_count": len(normalized), "finding_count": len(findings), "severity_counts": counts}, "findings": findings, "processes": normalized, "disclaimer": "Heuristic findings are review leads, not proof of malicious activity. Process names and command lines can be benign or spoofed."}

def write_report(report: dict[str, Any], json_path: Path | None = None, csv_path: Path | None = None) -> None:
    if json_path:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if csv_path:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        fields = ["pid", "name", "exe", "severity", "score", "rule", "reason"]
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows({key: item.get(key, "") for key in fields} for item in report["findings"])

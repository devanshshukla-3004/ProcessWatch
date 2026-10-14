import json
import tempfile
import unittest
from pathlib import Path
from processwatch.core import analyze_processes, write_report

class ProcessWatchTests(unittest.TestCase):
    def test_detects_known_tool_name(self):
        r = analyze_processes([{"pid": 4, "name": "mimikatz.exe"}])
        self.assertEqual(r["summary"]["finding_count"], 1)
        self.assertEqual(r["findings"][0]["rule"], "KNOWN_TOOL_NAME")
        self.assertEqual(r["findings"][0]["severity"], "HIGH")
    def test_detects_temp_executable(self):
        r = analyze_processes([{"pid": 2, "name": "worker.exe", "exe": "C:\\Users\\a\\AppData\\Local\\Temp\\worker.exe"}])
        self.assertIn("EXECUTABLE_FROM_TEMP_PATH", [x["rule"] for x in r["findings"]])
    def test_detects_encoded_powershell(self):
        r = analyze_processes([{"pid": 3, "name": "powershell.exe", "cmdline": "powershell.exe -EncodedCommand abc"}])
        self.assertIn("ENCODED_POWERSHELL_ARGUMENT", [x["rule"] for x in r["findings"]])
    def test_clean_process_has_no_findings(self):
        r = analyze_processes([{"pid": 9, "name": "explorer.exe", "exe": "C:\\Windows\\explorer.exe"}])
        self.assertEqual(r["summary"]["finding_count"], 0)
    def test_summary_counts_processes_and_severity(self):
        r = analyze_processes([{"pid": 1, "name": "mimikatz.exe"}, {"pid": 2, "name": "powershell.exe", "cmdline": "powershell -enc abc"}])
        self.assertEqual(r["summary"]["process_count"], 2)
        self.assertEqual(r["summary"]["severity_counts"]["HIGH"], 1)
        self.assertEqual(r["summary"]["severity_counts"]["MEDIUM"], 1)
    def test_json_and_csv_export(self):
        r = analyze_processes([{"pid": 1, "name": "mimikatz.exe"}])
        with tempfile.TemporaryDirectory() as d:
            jp, cp = Path(d)/"nested"/"report.json", Path(d)/"nested"/"report.csv"
            write_report(r, jp, cp)
            self.assertEqual(json.loads(jp.read_text())["summary"]["finding_count"], 1)
            self.assertIn("KNOWN_TOOL_NAME", cp.read_text())
    def test_ignores_non_dict_entries(self):
        r = analyze_processes(["bad", None, {"pid": 1, "name": "explorer.exe"}])
        self.assertEqual(r["summary"]["process_count"], 1)
    def test_self_parent_rule(self):
        r = analyze_processes([{"pid": 77, "ppid": 77, "name": "odd.exe"}])
        self.assertIn("SELF_PARENT_PID", [x["rule"] for x in r["findings"]])

if __name__ == "__main__":
    unittest.main()

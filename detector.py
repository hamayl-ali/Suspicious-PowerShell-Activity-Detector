"""
Suspicious PowerShell Activity Detector
=========================================
Scans PowerShell Script Block Logging events (Event ID 4104) for patterns
commonly associated with malicious activity, scores each script block,
and produces a triaged report.

MITRE ATT&CK mapping: T1059.001 (Command and Scripting Interpreter:
PowerShell), with sub-techniques touched including T1027 (Obfuscated
Files or Information), T1140 (Deobfuscate/Decode), T1562.001 (Impair
Defenses), T1003 (OS Credential Dumping).

Usage:
    python3 detector.py --input sample_powershell_logs.json
    python3 detector.py --input real_logs.evtx          # requires python-evtx
    python3 detector.py --input sample_powershell_logs.json --min-severity MEDIUM
"""

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------
# Each rule: (name, regex pattern, weight, MITRE technique, description)
# Weight roughly reflects how strong a standalone signal the pattern is.

RULES = [
    (
        "Encoded Command",
        r"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}",
        40,
        "T1027",
        "Base64-encoded command, commonly used to evade signature detection "
        "and logging of the literal command text.",
    ),
    (
        "Download Cradle",
        r"(New-Object\s+Net\.WebClient|Invoke-WebRequest|Invoke-RestMethod|iwr\s|curl\s)\s*.{0,80}(DownloadString|DownloadFile|-OutFile)",
        35,
        "T1105",
        "Script downloads and/or executes remote content — classic stager "
        "or payload-fetch behavior.",
    ),
    (
        "In-Memory Execution (IEX)",
        r"\b(IEX|Invoke-Expression)\b",
        25,
        "T1059.001",
        "Invoke-Expression executes a dynamically built string as code, a "
        "primary technique for fileless / in-memory PowerShell attacks.",
    ),
    (
        "AMSI Bypass",
        r"(amsiInitFailed|AmsiUtils|AmsiScanBuffer)",
        50,
        "T1562.001",
        "Attempts to disable or blind the Antimalware Scan Interface so "
        "subsequent malicious code is not inspected.",
    ),
    (
        "Reverse / Bind Shell Indicators",
        r"(Net\.Sockets\.TCPClient|Net\.Sockets\.TCPListener|System\.Net\.Sockets\.Socket)",
        45,
        "T1059.001",
        "Raw socket usage consistent with a reverse or bind shell.",
    ),
    (
        "Credential Dumping Tooling",
        r"(Mimikatz|sekurlsa|lsadump|Invoke-Mimikatz|DumpCreds|Invoke-Kerberoast)",
        50,
        "T1003",
        "References known credential-dumping tools or techniques.",
    ),
    (
        "Defense Impairment",
        r"(Add-MpPreference\s+-Exclusion|Set-MpPreference\s+-DisableRealtimeMonitoring|Disable-WindowsOptionalFeature.{0,40}Defender)",
        45,
        "T1562.001",
        "Modifies Windows Defender configuration to exclude paths or "
        "disable real-time protection — typically precedes payload drop.",
    ),
    (
        "Hidden / No-Profile Execution Flags",
        r"-(w(indowstyle)?\s+hidden|nop(rofile)?\b|noni(nteractive)?\b)",
        15,
        "T1059.001",
        "Execution flags used to suppress visible windows and skip "
        "profile loading — common in automated/attacker-launched scripts.",
    ),
    (
        "Execution Policy Bypass",
        r"-ep\s+bypass|-ExecutionPolicy\s+Bypass",
        20,
        "T1059.001",
        "Explicitly bypasses PowerShell's script execution policy "
        "safeguard.",
    ),
    (
        "BITS Job Abuse",
        r"Start-BitsTransfer",
        20,
        "T1197",
        "Background Intelligent Transfer Service used to download files, "
        "a technique that can blend into normal Windows update traffic.",
    ),
    (
        "Reflective Assembly Load",
        r"\[Reflection\.Assembly\]::Load\(|System\.Reflection\.Assembly",
        30,
        "T1620",
        "Loads a .NET assembly directly from memory (e.g. from a decoded "
        "byte array), avoiding writing an executable to disk.",
    ),
    (
        "Base64 Decode Routine",
        r"\[Convert\]::FromBase64String",
        15,
        "T1140",
        "Decodes base64 data at runtime — frequently paired with "
        "in-memory execution of the decoded payload.",
    ),
    (
        "String Concatenation Obfuscation",
        r"(\$\w+\s*=\s*['\"][^'\"]{1,15}['\"]\s*;\s*){2,}.*\+",
        20,
        "T1027",
        "Command built from multiple short concatenated string variables, "
        "a common technique to break up keywords and evade string-based "
        "signature detection.",
    ),
    (
        "Suspicious WMI Persistence",
        r"Set-WmiInstance|Win32_Process.{0,40}CommandLine|Register-WmiEvent",
        25,
        "T1546.003",
        "WMI used to create processes or persistent event subscriptions, "
        "a known living-off-the-land persistence mechanism.",
    ),
]

COMPILED_RULES = [
    (name, re.compile(pattern, re.IGNORECASE), weight, technique, desc)
    for name, pattern, weight, technique, desc in RULES
]

SEVERITY_THRESHOLDS = [
    (70, "CRITICAL"),
    (45, "HIGH"),
    (20, "MEDIUM"),
    (0, "LOW"),
]


def severity_for_score(score: int) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


@dataclass
class Finding:
    event_id: int
    time_created: str
    computer: str
    user: str
    script_block_id: str
    score: int
    severity: str
    matched_rules: list = field(default_factory=list)
    script_excerpt: str = ""


# ---------------------------------------------------------------------------
# Log loading
# ---------------------------------------------------------------------------

def load_json_logs(path: str):
    with open(path, "r") as f:
        data = json.load(f)
    return data if isinstance(data, list) else data.get("events", [])


def load_evtx_logs(path: str):
    """Load real Windows .evtx PowerShell Operational logs.
    Requires: pip install python-evtx --break-system-packages
    """
    try:
        import Evtx.Evtx as evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        sys.exit(
            "python-evtx is not installed. Run:\n"
            "  pip install python-evtx --break-system-packages\n"
            "to parse real .evtx files, or supply --input as JSON instead."
        )

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    records = []
    with evtx.Evtx(path) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            system = root.find("e:System", ns)
            event_id = int(system.find("e:EventID", ns).text)
            if event_id != 4104:
                continue
            time_created = system.find("e:TimeCreated", ns).attrib.get(
                "SystemTime", ""
            )
            computer = system.find("e:Computer", ns).text or ""

            event_data = root.find("e:EventData", ns)
            data_map = {
                d.attrib.get("Name", ""): (d.text or "")
                for d in event_data.findall("e:Data", ns)
            }
            records.append({
                "EventID": event_id,
                "TimeCreated": time_created,
                "Computer": computer,
                "UserID": data_map.get("UserId", "unknown"),
                "ScriptBlockId": data_map.get("ScriptBlockId", ""),
                "ScriptBlockText": data_map.get("ScriptBlockText", ""),
            })
    return records


def load_logs(path: str):
    p = Path(path)
    if p.suffix.lower() == ".evtx":
        return load_evtx_logs(path)
    return load_json_logs(path)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def analyze_entry(entry: dict) -> Finding:
    script_text = entry.get("ScriptBlockText", "") or ""
    score = 0
    matched = []

    for name, pattern, weight, technique, desc in COMPILED_RULES:
        if pattern.search(script_text):
            score += weight
            matched.append({
                "rule": name,
                "weight": weight,
                "mitre": technique,
                "description": desc,
            })

    excerpt = script_text.strip().replace("\n", " ")
    if len(excerpt) > 160:
        excerpt = excerpt[:160] + "..."

    return Finding(
        event_id=entry.get("EventID", 4104),
        time_created=entry.get("TimeCreated", ""),
        computer=entry.get("Computer", "unknown"),
        user=entry.get("UserID", "unknown"),
        script_block_id=entry.get("ScriptBlockId", ""),
        score=score,
        severity=severity_for_score(score),
        matched_rules=matched,
        script_excerpt=excerpt,
    )


def analyze_logs(entries):
    return [analyze_entry(e) for e in entries]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def print_report(findings, min_severity="LOW"):
    min_rank = SEVERITY_ORDER[min_severity]
    relevant = [f for f in findings if SEVERITY_ORDER[f.severity] <= min_rank]
    relevant.sort(key=lambda f: (-f.score, f.time_created))

    total = len(findings)
    flagged = sum(1 for f in findings if f.score > 0)
    by_sev = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    print("=" * 78)
    print("SUSPICIOUS POWERSHELL ACTIVITY REPORT")
    print("=" * 78)
    print(f"Total script blocks analyzed: {total}")
    print(f"Script blocks with at least one rule match: {flagged}")
    print(
        "Severity breakdown: "
        + ", ".join(f"{k}={v}" for k, v in sorted(
            by_sev.items(), key=lambda kv: SEVERITY_ORDER[kv[0]]
        ))
    )
    print(f"Showing severity >= {min_severity}")
    print("-" * 78)

    if not relevant or all(f.score == 0 for f in relevant):
        print("No findings at or above the selected severity threshold.")
    else:
        for f in relevant:
            if f.score == 0:
                continue
            print(f"\n[{f.severity}] score={f.score}  {f.time_created}")
            print(f"  Host: {f.computer}    User: {f.user}")
            print(f"  ScriptBlockId: {f.script_block_id}")
            print(f"  Excerpt: {f.script_excerpt}")
            print("  Matched rules:")
            for m in f.matched_rules:
                print(f"    - [{m['mitre']}] {m['rule']}: {m['description']}")
    print("\n" + "=" * 78)


def write_csv_report(findings, out_path):
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "TimeCreated", "Computer", "User", "ScriptBlockId",
            "Severity", "Score", "MatchedRules", "MitreTechniques",
            "ScriptExcerpt",
        ])
        for finding in sorted(findings, key=lambda x: -x.score):
            rule_names = "; ".join(m["rule"] for m in finding.matched_rules)
            techniques = "; ".join(
                sorted(set(m["mitre"] for m in finding.matched_rules))
            )
            writer.writerow([
                finding.time_created,
                finding.computer,
                finding.user,
                finding.script_block_id,
                finding.severity,
                finding.score,
                rule_names,
                techniques,
                finding.script_excerpt,
            ])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Detect suspicious PowerShell activity in Event ID 4104 logs."
    )
    parser.add_argument(
        "--input", required=True,
        help="Path to log file (.json sample format, or real .evtx)",
    )
    parser.add_argument(
        "--min-severity", default="LOW",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity to display in the console report (default: LOW = show all)",
    )
    parser.add_argument(
        "--csv-out", default=None,
        help="Optional path to write a CSV report of all findings",
    )
    args = parser.parse_args()

    entries = load_logs(args.input)
    if not entries:
        print(f"No Event ID 4104 records found in {args.input}", file=sys.stderr)
        sys.exit(1)

    findings = analyze_logs(entries)
    print_report(findings, min_severity=args.min_severity)

    if args.csv_out:
        write_csv_report(findings, args.csv_out)
        print(f"\nCSV report written to: {args.csv_out}")


if __name__ == "__main__":
    main()

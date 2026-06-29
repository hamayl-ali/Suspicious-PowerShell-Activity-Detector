# Suspicious PowerShell Activity Detector

A Python-based detection tool that analyzes **Windows PowerShell Script Block Logging (Event ID 4104)** and identifies potentially malicious PowerShell activity using rule-based detection.

The detector scores each PowerShell script according to suspicious indicators, maps detections to the MITRE ATT&CK framework, assigns a severity level, and generates both console and CSV reports.

---

## Features

* Detects suspicious PowerShell activity from:

  * JSON log files
  * Windows EVTX Event Logs
* Rule-based detection using Regular Expressions
* Risk scoring system
* Severity classification:

  * LOW
  * MEDIUM
  * HIGH
  * CRITICAL
* MITRE ATT&CK technique mapping
* Console report generation
* Optional CSV report export

---

## Detection Rules

Current rules include detection for:

* Encoded PowerShell commands
* Invoke-Expression (IEX)
* Download Cradles
* AMSI Bypass
* Reverse Shell indicators
* Credential Dumping (Mimikatz)
* Windows Defender tampering
* Hidden / NoProfile execution
* Execution Policy Bypass
* BITS transfer abuse
* Reflective Assembly Loading
* Base64 decoding routines
* String concatenation obfuscation
* Suspicious WMI persistence

---

## Installation

Clone the repository.

```bash
git clone https://github.com/hamayl-ali/Suspicious-PowerShell-Activity-Detector.git

cd Suspicious-PowerShell-Activity-Detector
```

Install dependencies.

```bash
pip install python-evtx
```

---

## Usage

Analyze JSON logs

```bash
python detector.py --input sample_powershell_logs.json
```

Analyze EVTX logs

```bash
python detector.py --input Microsoft-Windows-PowerShell%4Operational.evtx
```

Show only HIGH severity findings

```bash
python detector.py --input sample_powershell_logs.json --min-severity HIGH
```

Export CSV report

```bash
python detector.py --input sample_powershell_logs.json --csv-out report.csv
```

---

## Sample Output

```
========================================================================
SUSPICIOUS POWERSHELL ACTIVITY REPORT
========================================================================

Total script blocks analyzed: 30

Script blocks with rule matches: 6

Severity Breakdown

CRITICAL : 2
HIGH     : 2
MEDIUM   : 1
LOW      : 1
```

---

## Sample Dataset

The repository includes:

* `sample_log_generator.py`
* `sample_powershell_logs.json`

The generator creates synthetic Event ID 4104 PowerShell logs containing a mixture of benign administrative commands and malicious PowerShell techniques for testing purposes.

Approximately 20% of generated events are malicious.

---

## MITRE ATT&CK Coverage

| Technique | Description                     |
| --------- | ------------------------------- |
| T1059.001 | PowerShell                      |
| T1027     | Obfuscated Files or Information |
| T1140     | Deobfuscate / Decode            |
| T1003     | Credential Dumping              |
| T1105     | Ingress Tool Transfer           |
| T1197     | BITS Jobs                       |
| T1546.003 | WMI Event Subscription          |
| T1562.001 | Impair Defenses                 |
| T1620     | Reflective Code Loading         |

---

## Future Improvements

* YARA integration
* Sigma rule export
* HTML dashboard
* Real-time Windows event monitoring
* Machine Learning anomaly detection
* SIEM integration (Splunk / Microsoft Sentinel / Elastic)

---

## Disclaimer

This project is intended for educational, research, and defensive cybersecurity purposes only.

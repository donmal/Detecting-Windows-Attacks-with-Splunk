# 01 - Credential Abuse Attacks Detection 

## Executive Summary

This repository documents the investigation and detection of three common credential abuse techniques frequently used by adversaries in Active Directory environments.

The project focuses on understanding how attackers abuse Windows authentication mechanisms, how these attacks appear in Windows logs, and how they can be detected using Sysmon and Splunk.

The techniques covered in this repository are commonly observed during lateral movement, privilege escalation, and post-exploitation phases of an intrusion.

The repository was developed as part of hands-on SOC Analyst and Detection Engineering training and demonstrates practical investigation workflows using real attack telemetry.

## Project Objectives

The primary goals of this project are:

•	Understand NTLM and Kerberos authentication internals.
•	Identify artifacts left by credential abuse attacks.
•	Investigate Windows Security and Sysmon logs.
•	Develop Splunk detections for common credential abuse techniques.
•	Correlate authentication events with process activity.
•	Build practical detection engineering skills.

## Attack Techniques Covered

1. Pass-the-Hash (PtH)

Pass-the-Hash allows an attacker to authenticate using a stolen NTLM password hash instead of a plaintext password.

Topics covered:

•	LSASS credential dumping
•	NTLM hash extraction
•	Logon Type 9 analysis
•	NewCredentials authentication
•	Mimikatz Pass-the-Hash
•	Sysmon Event ID 10 correlation
•	Splunk detection development

2. Pass-the-Ticket (PtT)

Pass-the-Ticket abuses legitimate Kerberos tickets to authenticate without requiring user passwords.

Topics covered:

•	Ticket Granting Tickets (TGT)
•	Service Tickets (TGS)
•	Ticket injection
•	Rubeus ticket manipulation
•	Kerberos event correlation
•	Transaction-based Splunk detections

3. Overpass-the-Hash (Pass-the-Key)

Overpass-the-Hash combines NTLM credential theft with Kerberos authentication by requesting Kerberos tickets using stolen password material.

Topics covered:

•	AS-REQ requests
•	Kerberos TGT generation
•	Rubeus asktgt
•	Kerberos traffic analysis
•	Detection through Sysmon network telemetry
•	Port 88 monitoring

## Investigation Methodology

Each chapter follows a consistent investigation methodology:

1.	Understand the attack workflow.
2.	Review authentication mechanics.
3.	Identify relevant Windows events.
4.	Examine Sysmon telemetry.
5.	Develop Splunk detections.
6.	Investigate a practical lab scenario.
7.	Identify indicators of compromise.
8.	Document lessons learned.

## Data Sources

| Source | Event IDs / Data | Purpose |
|---------|------------------|----------|
| Windows Security Logs | 4624, 4648, 4672, 4768, 4769, 4770, 4771 | Authentication events, privilege assignments, and Kerberos activity |
| Sysmon | Event ID 1 (Process Creation), Event ID 3 (Network Connection), Event ID 10 (Process Access) | Process execution, network telemetry, and LSASS access monitoring |
| Splunk Index (main) | Centralized Windows Security and Sysmon telemetry | Threat hunting, event correlation, behavioral analysis, and detection engineering using Splunk SPL |

## MITRE ATT&CK Coverage

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Credential Access | Credential Dumping | T1003 | Extraction of authentication material from compromised systems |
| Credential Access | Pass-the-Hash | T1550.002 | Reuse of stolen NTLM hashes for authentication |
| Credential Access | Pass-the-Ticket | T1550.003 | Reuse of stolen Kerberos service tickets |
| Credential Access | Kerberos Attacks | T1558 | Abuse of Kerberos authentication and ticket-based attacks |
| Lateral Movement | Lateral Movement | TA0008 | Authentication to remote systems using compromised credentials or Kerberos tickets |
| Defense Evasion | Defense Evasion | TA0005 | Blending malicious authentication activity with legitimate Windows behavior |

## Skills Demonstrated

•	Windows Event Log Analysis
•	Sysmon Analysis
•	Splunk Search Language (SPL)
•	Detection Engineering
•	Threat Hunting
•	Incident Investigation
•	Active Directory Security
•	Authentication Analysis
•	Credential Abuse Detection

## References

•	MITRE ATT&CK
•	Microsoft Security Documentation
•	Sysinternals Sysmon
•	Splunk Documentation
•	Active Directory Security Research

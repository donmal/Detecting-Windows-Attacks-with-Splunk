# 01 - Credential Abuse Attacks Detection 
Write-up of Hack The Box Academy labs. Practice work. 

## Executive Summary

This project documents hands-on security investigations and detection workflows involving three credential abuse techniques in Active Directory environments: Pass-the-Hash, Pass-the-Ticket, and Overpass-the-Hash.

The project focuses on understanding how attackers abuse Windows authentication mechanisms, how these attacks appear in Windows logs, and how they can be detected using Sysmon and Splunk.

The techniques covered in this repository are commonly observed during lateral movement, privilege escalation, and post-exploitation phases of an intrusion.

The investigations use lab-generated Windows authentication and endpoint telemetry to examine suspicious activity, correlate security events, and explore detection opportunities relevant to SOC operations.

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

Investigation Focus:

•	LSASS credential dumping

•	NTLM hash extraction

•	Logon Type 9 analysis

•	NewCredentials authentication

•	Mimikatz Pass-the-Hash

•	Sysmon Event ID 10 correlation

•	Splunk detection development

2. Pass-the-Ticket (PtT)

Pass-the-Ticket abuses legitimate Kerberos tickets to authenticate without requiring user passwords.

Investigation Focus:

•	Ticket Granting Tickets (TGT)

•	Service Tickets (TGS)

•	Ticket injection

•	Rubeus ticket manipulation

•	Kerberos event correlation

•	Transaction-based Splunk detections

3. Overpass-the-Hash (Pass-the-Key)

Overpass-the-Hash (Pass-the-Key) involves using stolen Kerberos-compatible key material, such as an NT hash, to request Kerberos authentication tickets without knowing the plaintext password.

Investigation Focus:

•	AS-REQ requests

•	Kerberos TGT generation

•	Rubeus asktgt

•	Kerberos traffic analysis

•	Detection through Sysmon network telemetry

•	Port 88 monitoring

## Investigation Methodology

The investigations are organized around the following analytical workflow:

1.	Examine the credential abuse technique and its authentication behaviour.
   
2.	Identify relevant NTLM or Kerberos authentication artifacts.
   
3.	Identify relevant Windows events.
   
4.	Examine Sysmon telemetry.
   
5.	Develop Splunk detections.
   
6.	Analyze authentication and process activity wtihin the lab environment.
   
7.	Document suspicious indicators and investigation findings.
   
8.	Document lessons learned.

## Data Sources

| Source | Event IDs / Data | Purpose |
|---------|------------------|----------|
| Windows Security Logs | 4624, 4648, 4672, 4768, 4769, 4770, 4771 | Authentication events, privilege assignments, and Kerberos activity |
| Sysmon | Event ID 1 (Process Creation), Event ID 3 (Network Connection), Event ID 10 (Process Access) | Process execution, network telemetry, and LSASS access monitoring |
| Splunk Index (main) | Centralized Windows Security and Sysmon telemetry | Threat hunting, event correlation, behavioral analysis, and detection engineering using Splunk SPL |

These data sources represent the telemetry relevant to the investigations. The individual technical sections document which event IDs and data fields were actually queried and analyzed.

## MITRE ATT&CK Coverage

The following mapping identifies techniques relevant to the project's credential abuse investigations. Individual investigation sections should distinguish observed activity from theoretical attack scenarios and proposed detections.

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Credential Access | Credential Dumping | T1003 | Extraction of authentication material from compromised systems |
| Defense Evasion / Lateral Movement | Pass-the-Hash | T1550.002 | Reuse of stolen NTLM hashes for authentication |
| Defense Evasion / Lateral Movement | Pass-the-Ticket | T1550.003 | Reuse of stolen Kerberos service tickets |
| Credential Access | Kerberos Attacks | T1558 | Abuse of Kerberos authentication and ticket-based attacks |
| Defense Evasion / Lateral Movement| Use Alternate Authentication Material: Pass the Hash | T1550.002 | Overpass-the-Hash / Pass-the-Key using stolen NT hash material to obtain Kerberos tickets |

Mapping note: Pass-the-Hash and Pass-the-Ticket are sub-techniques of T1550 (Use Alternate Authentication Material). Overpass-the-Hash is also associated with T1550.002 when an NT hash is used to obtain Kerberos tickets. T1003 and T1558 provide broader credential access context and should be retained as observed techniques only where the individual investigations contain supporting evidence.

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

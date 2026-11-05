# Detecting Windows Attacks with Splunk - Active Directory Threat Hunting & Detection Portfolio

## Overview

This repository contains a practical threat hunting and detection engineering portfolio focused on Active Directory attack detection using Splunk, Windows Security Events, Sysmon telemetry, and MITRE ATT&CK.

The project documents complete investigation workflows for some of the most common Active Directory attack techniques used by adversaries during post-exploitation, credential abuse, privilege escalation, persistence, and lateral movement.
Rather than presenting isolated detection rules, each investigation follows a structured SOC investigation methodology that includes:

- Attack background
- Investigation objectives
- Data sources
- Threat hunting methodology
- Splunk detection queries
- Investigation findings
- Detection logic
- Indicators of Compromise (IOCs)
- MITRE ATT&CK mapping
- Lessons learned
- Investigation conclusions

The goal is to demonstrate practical blue team skills by reconstructing attacker activity through log correlation, behavioral analysis, and Active Directory security monitoring.

---

# Technologies Used

- Splunk
- Windows Security Logs
- Sysmon
- Active Directory
- PowerShell Logging
- LDAP
- Kerberos
- Windows Event Forwarding
- MITRE ATT&CK Framework

---

# Investigation Topics

## 01. Kerberoasting & AS-REP Roasting

Credential access techniques targeting Kerberos authentication.
Topics include:

- Service Principal Name (SPN) enumeration
- LDAP reconnaissance
- Kerberos TGS requests
- AS-REP roasting
- Event ID 4768
- Event ID 4769
- LDAP SearchFilter analysis
- PID correlation
- Sysmon Process Creation
- Offline password cracking detection

---
## 02. Pass-the-Hash, Pass-the-Ticket & Overpass-the-Hash

Credential abuse and lateral movement investigations.

Topics include:

### Pass-the-Hash

- NTLM authentication abuse
- Logon Type 9 detection
- LSASS access monitoring
- Event ID 4624
- Sysmon Event ID 10
- Security/Sysmon correlation

### Pass-the-Ticket

- Kerberos ticket reuse
- Missing TGT detection
- Transaction analysis
- Kerberos authentication flow reconstruction
- Event IDs 4768, 4769, 4770

### Overpass-the-Hash (Pass-the-Key)

- Kerberos TGT requests
- Rubeus detection
- Kerberos traffic monitoring
- Process-to-network correlation
- Sysmon Event IDs 1 and 3
- Port 88 monitoring

---

## 03. Kerberos Ticket Forgery

Detection of forged Kerberos tickets.
Topics include:

- Golden Ticket
- Silver Ticket
- Forged TGT detection
- Forged TGS detection
- KRBTGT abuse
- Service account abuse
- Baseline user validation
- Service Principal Name (SPN) analysis
- Authentication artifact correlation

---
## 04. Kerberos Delegation Abuse

Threat hunting for Active Directory delegation attacks.
Topics include:

### Unconstrained Delegation

- TrustedForDelegation enumeration
- userAccountControl analysis
- PowerShell Script Block Logging
- Kerberos ticket harvesting

### Constrained Delegation

- msDS-AllowedToDelegateTo enumeration
- S4U2Self
- S4U2Proxy
- Rubeus delegation abuse
- Kerberos delegation monitoring

---

## 05. Active Directory Replication Abuse

Detection of replication-based attacks.
Topics include:

### DCSync

- DRSGetNCChanges abuse
- Replication permissions
- Event ID 4662
- KRBTGT hash extraction
- Directory replication monitoring

### DCShadow

- Rogue Domain Controller registration
- Global Catalog SPN analysis
- Event ID 4742
- Service Principal Name monitoring
- Active Directory object modification

---

# Investigation Methodology

Each investigation follows a consistent workflow:

1. Executive Summary
2. Investigation Objectives
3. Technical Background
4. MITRE ATT&CK Mapping (Background)
5. Data Sources
6. Investigation Scope
7. Investigation Methodology
8. Challenge Context
9. Investigation Overview
10. Investigation Queries
11. Investigation Findings
12. Investigation Workflow
13. Detection Logic
14. IOC Summary
15. MITRE ATT&CK Mapping
16. Lessons Learned
17. Conclusion

This standardized structure reflects a real-world Security Operations Center (SOC) investigation process rather than isolated lab exercises.
---
# Detection Engineering Focus

Throughout the repository, investigations emphasize:

- Behavioral detection
- Event correlation
- Active Directory threat hunting
- Kerberos security monitoring
- Windows Security Event analysis
- Sysmon telemetry
- Process attribution
- Authentication analysis
- Privilege escalation detection
- Credential abuse detection
- Lateral movement detection

---
# MITRE ATT&CK Coverage

The repository covers techniques including (but not limited to):

| ATT&CK ID | Technique |
|-----------|-----------|
| T1003.001 | LSASS Memory |
| T1003.006 | DCSync |
| T1087.002 | Domain Account Discovery |
| T1098 | Account Manipulation |
| T1207 | DCShadow |
| T1482 | Domain Trust Discovery |
| T1550 | Use Alternate Authentication Material |
| T1550.002 | Pass-the-Hash |
| T1550.003 | Pass-the-Ticket |
| T1558 | Steal or Forge Kerberos Tickets |
| T1558.001 | Golden Ticket |
| T1558.002 | Silver Ticket |
| T1558.003 | Kerberoasting |
| T1558.004 | AS-REP Roasting |

---
# Skills Demonstrated

This project demonstrates practical experience with:

- Threat Hunting
- Detection Engineering
- Active Directory Security
- Splunk SPL
- Windows Event Analysis
- Sysmon Analysis
- Kerberos Authentication
- Active Directory Replication
- Behavioral Detection
- Log Correlation
- Incident Investigation
- MITRE ATT&CK Mapping
- IOC Identification
- Security Operations (SOC)
- Blue Team Methodology

---

# Purpose

This repository was created to consolidate practical Active Directory threat hunting knowledge into a structured investigation portfolio.

The objective is to document not only how specific attacks work, but also how defenders can detect, investigate, and attribute malicious activity through log analysis, event correlation, and behavioral detection techniques commonly used within modern Security Operations Centers.








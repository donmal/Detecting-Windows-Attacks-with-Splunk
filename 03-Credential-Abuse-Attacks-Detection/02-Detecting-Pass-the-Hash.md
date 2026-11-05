# 02 - Detecting Pass-the-Hash 

## Executive Summary 

This investigation focused on detecting Pass-the-Hash (PtH) activity in Splunk by analyzing Windows Security Events, Sysmon telemetry, and authentication artifacts. The investigation correlated NewCredentials logon sessions with LSASS memory access to identify behavioral patterns commonly associated with NTLM hash abuse and credential-based lateral movement.

## Investigation Objectives 

- Detect Pass-the-Hash authentication artifacts.
- Identify NewCredentials logon sessions.
- Analyze the relationship between Logon Type 9 and the Secondary Logon service.
- Correlate LSASS access with authentication activity.
- Reduce false positives through event correlation.
- Map observed behavior to MITRE ATT&CK. 

## Background 

### What is Pass-the-Hash? 

Pass-the-Hash (PtH) is a credential abuse technique in which an attacker authenticates using an NTLM hash instead of the user's plaintext password. By leveraging stolen authentication material, attackers can access remote systems without ever knowing the original credentials.

Pass-the-Hash is commonly associated with:

-	Lateral Movement
-	Privilege Escalation
-	Active Directory compromise
-	Post-exploitation operations

One of the most widely used tools for performing Pass-the-Hash attacks is **Mimikatz**.

### Access Tokens

When a user successfully authenticates to Windows, the operating system creates an Access Token representing that security context.

An Access Token contains:

-	User SID
-	Group memberships
-	Assigned privileges
-	Security context

Every child process created by the authenticated user inherits a copy of this token. 

### Logon Sessions

Each Access Token is associated with a Logon Session containing the authentication material required by Windows.

A Logon Session typically includes:

-	Username
-	Domain
-	Authentication material
-	NTLM hash
-	LM hash

During Pass-the-Hash attacks, adversaries manipulate the authentication material associated with the Logon Session rather than using the user's plaintext password.

### runas dhe /netonly

Windows provides the `runas` utility to execute processes under alternate credentials.

Example:

```cmd
runas /user:CORP\Administrator cmd.exe
```

## Key Detection Artifact 

One of the strongest authentication artifacts associated with Pass-the-Hash is:
-	Security Event ID 4624 
-	Logon Type = 9 
-	Logon Process = seclogo 
This combination indicates a **NewCredentials** authentication session and is frequently observed during Pass-the-Hash attacks, credential injection, and legitimate `runas /netonly` executions.

## MITRE ATT&CK Mapping (Background) 

| Technique | ATT&CK ID |
|-----------|-----------|
| Pass-the-Hash | T1550.002 |
| OS Credential Dumping: LSASS Memory | T1003.001 |
| Lateral Movement | TA0008 |
| Defense Evasion | TA0005 |

## Data Sources

| Source | Purpose |
|---------|----------|
| Windows Security Logs | Authentication telemetry |
| Sysmon | Process telemetry |
| Splunk Index (main) | Centralized log analysis |
| Security Event ID 4624 | Successful logon events |
| Sysmon Event ID 10 | LSASS process access |

## Investigation Scope 

The investigation focused on identifying hosts exhibiting NewCredentials authentication sessions during the specified time window and correlating those events with Sysmon telemetry to determine whether the observed behavior was consistent with Pass-the-Hash activity.

## Investigation Methodology 

The investigation followed a structured four-stage correlation process:

1. Identify successful NewCredentials logon sessions.
2. Filter authentication events using Logon Type 9.
3. Validate the Secondary Logon process (seclogo).
4. Attribute the activity to the originating host. 

## Investigation Query #1

### Purpose:

Identify NewCredentials logon sessions associated with Security Event ID 4624, Logon Type 9, and the Secondary Logon process.

### SPL:

```spl
index=main earliest=1690543380 latest=1690545180
source="WinEventLog:Security"
EventCode=4624
Logon_Type=9
Logon_Process=seclogo
| table _time, ComputerName, EventCode, user,
Network_Account_Domain,
Network_Account_Name,
Logon_Type,
Logon_Process
```

### Results:

| Field | Value |
|-------|-------|
| Computer Name | `BLUE.corp.local` |

### Query Analysis

The search followed a four-stage filtering process:
1. Identify successful authentication events using Security Event ID 4624.
2. Filter for Logon Type 9 to isolate NewCredentials sessions.
3. Restrict results to the `seclogo` logon process.
4. Identify the host on which the authentication activity occurred.

## Detection Logic 

### NewCredentials Authentication

Security Event ID 4624 with `Logon_Type = 9` indicates the creation of a NewCredentials authentication session. This behavior is associated with alternate credential usage and may appear during legitimate administration, `runas /netonly` execution, or Pass-the-Hash activity.

### Secondary Logon Process 

The `seclogo` logon process is associated with the Windows Secondary Logon service and is commonly observed during:

- `runas`
- `runas /netonly`
- Credential injection
- Pass-the-Hash scenarios

### LSASS Access 

Sysmon Event ID 10 should be monitored for access to `lsass.exe`. Classical Pass-the-Hash implementations frequently require access to LSASS memory to extract or manipulate authentication material.

### Event Correlation 

The highest-confidence detection pattern combines:

- Sysmon Event ID 10 targeting `lsass.exe`
- Credential extraction or manipulation
- Security Event ID 4624
- Logon Type 9
- `seclogo`
- Subsequent remote authentication activity

This correlation is significantly more reliable than analyzing NewCredentials logons in isolation.

## Investigation Query #2

### Purpose:

Correlate LSASS access with NewCredentials authentication events to identify behavior more closely aligned with Pass-the-Hash activity.

### SPL: 

```spl
index=main earliest=1690450689 latest=1690451116
(source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=10
TargetImage="C:\Windows\system32\lsass.exe"
SourceImage!="C:\ProgramData\Microsoft\Windows Defender\platform\*\MsMpEng.exe")
OR
(source="WinEventLog:Security"
EventCode=4624
Logon_Type=9
Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m
endswith=(EventCode=4624)
startswith=(EventCode=10)
| stats count by
_time,
Computer,
SourceImage,
SourceProcessId,
Network_Account_Domain,
Network_Account_Name,
Logon_Type,
Logon_Process
| fields - count
```

### Query Analysis

The second query extends the initial investigation by correlating Security Event ID 4624 with Sysmon Event ID 10. This approach combines authentication activity with LSASS memory access, producing a behavioral pattern that more closely resembles Pass-the-Hash activity while significantly reducing false positives.

### Why the Correlation Query is Stronger

The first query detects Security Event ID 4624 events with Logon Type 9 and the `seclogo` logon process. Although this is a useful indicator, legitimate `runas /netonly` activity may generate the same authentication pattern.

The second query adds Sysmon Event ID 10 telemetry showing access to `lsass.exe`. Correlating LSASS access with a subsequent NewCredentials logon significantly reduces false positives and produces a behavioral pattern more consistent with Pass-the-Hash activity.

## IOC Summary

| IOC Type | Value |
|-----------|-------|
| Security Events | 4624, 4648, 4672 |
| Sysmon Events | 1, 10 |
| Authentication Indicators | Logon Type 9, Logon Process = seclogo |
| Processes | mimikatz.exe, runas.exe |
| Commands | sekurlsa::pth |
| Host | BLUE.corp.local |

## Figures

### **Figure 1.** Mimikatz credential dumping demonstration. 
Mimikatz Credential Dumping

### **Figure 2.** NTLM hash extraction.
NTLM Hash Extraction

### **Figure 3.** runas /netonly execution.
runas /netonly Demonstration

### **Figure 4.** Security Event ID 4624 (Logon Type 9).
Event ID 4624
(Logon Type 9)

### **Figure 5.** Sysmon Event ID 10 (LSASS access). 
Sysmon Event ID 10
(LSASS Access)

### **Figure 6.** Splunk Pass-the-Hash detection query. 
Splunk Detection Query

### **Figure 7.** Investigation results identifying BLUE.corp.local. 

Results

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Credential extraction from LSASS |
| Credential Access | Pass-the-Hash | T1550.002 | NTLM hash authentication abuse |
| Lateral Movement | Lateral Movement | TA0008 | Authentication to remote systems |
| Defense Evasion | Defense Evasion | TA0005 | Credential abuse using legitimate authentication mechanisms |

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| NTLM Authentication | Pass-the-Hash abuses NTLM hashes instead of plaintext passwords. |
| Authentication Artifacts | Logon Type 9 is a valuable indicator but should not be treated as conclusive evidence. |
| Administrative Activity | `runas /netonly` produces artifacts similar to Pass-the-Hash and requires contextual analysis. |
| LSASS Monitoring | Monitoring LSASS access significantly improves detection capability. |
| Event Correlation | Correlating Security and Sysmon events greatly reduces false positives. |
| Behavioral Detection | Behavioral correlation is more reliable than monitoring isolated events. |
| Lateral Movement | Pass-the-Hash remains one of the most common techniques used for Active Directory lateral movement. |

## Conclusion

This investigation demonstrated how Pass-the-Hash activity can be detected by correlating Windows Security events, Sysmon telemetry, and authentication artifacts within Splunk. Combining NewCredentials logons, LSASS memory access, and process telemetry provides defenders with high-confidence visibility into credential abuse while significantly improving detection accuracy and reducing false positives.

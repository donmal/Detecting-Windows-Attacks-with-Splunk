# 04 - Detection Logic and IOCs

## Executive Summary 

This document consolidates the detection logic, Indicators of Compromise (IOCs), and threat hunting methodologies identified throughout the Pass-the-Hash, Pass-the-Ticket, and Overpass-the-Hash investigations.

The objective is to transform investigation findings into reusable detection logic suitable for SOC operations, threat hunting, and SIEM detection engineering.

## Covered Techniques 

The investigation covered three common Active Directory credential abuse techniques:
- **Pass-the-Hash (PtH)** – Authentication using stolen NTLM hashes.
- **Pass-the-Ticket (PtT)** – Authentication using stolen Kerberos tickets.
- **Overpass-the-Hash (Pass-the-Key)** – Requesting Kerberos tickets using stolen NTLM hashes or AES keys.

## Technique Comparison 

| Technique | Authentication Protocol | Primary Detection Artifact | Primary Event IDs |
|-----------|-------------------------|----------------------------|-------------------|
| Pass-the-Hash | NTLM | Logon Type 9 (`seclogo`) | 4624, 10 |
| Pass-the-Ticket | Kerberos | Event ID 4769 without Event ID 4768 | 4768, 4769, 4770 |
| Overpass-the-Hash | Kerberos | Non-standard process communicating with Domain Controller over port 88 | 1, 3, 4768 |

## IOC Summary

| IOC | Detection Opportunity | Investigation Relevance |
|-----|------------------------|--------------------------|
| NewCredentials Logon | Security Event ID 4624 (Logon Type 9) | Possible Pass-the-Hash activity |
| LSASS Memory Access | Sysmon Event ID 10 | Credential dumping or hash extraction |
| Service Ticket without TGT | Event ID 4769 without Event ID 4768 | Pass-the-Ticket |
| Kerberos Communication | Sysmon Event ID 3 targeting port 88 | Overpass-the-Hash |
| LOLBin Abuse | rundll32.exe, Rubeus.exe | Credential abuse using legitimate binaries |

RR Detection Logic 

### Pass-the-Hash

Investigate Security Event ID 4624 with:
- Logon Type = 9
- Logon Process = seclogo

Correlate these events with Sysmon Event ID 10 targeting `lsass.exe`.

### Pass-the-Ticket

Investigate Kerberos authentication sequences containing:

- Event ID 4769
- Event ID 4770
without a preceding:
- Event ID 4768

### Overpass-the-Hash

Monitor Sysmon Event ID 3 for:

- Destination Port = 88
- Domain Controller communication
- Non-standard client processes

Correlate with Sysmon Event ID 1 for process attribution.

## Splunk Hunting Queries

The investigation developed reusable hunting queries covering:

- Pass-the-Hash authentication artifacts
- LSASS memory access
- Pass-the-Ticket transaction analysis
- Overpass-the-Hash process-to-network correlation

## Attack Correlation

Credential abuse techniques rarely occur in isolation.

A common attack progression consists of:

Credential Dumping → Pass-the-Hash → Overpass-the-Hash → Pass-the-Ticket → Lateral Movement

Correlating events across each phase provides significantly greater detection confidence than analyzing isolated events.

## MITRE ATT&CK Mapping

| Technique | ATT&CK ID |
|-----------|-----------|
| OS Credential Dumping: LSASS Memory | T1003.001 |
| Pass-the-Hash | T1550.002 |
| Pass-the-Ticket | T1550.003 |
| Steal or Forge Kerberos Tickets | T1558 |
| Lateral Movement | TA0008 |
| Defense Evasion | TA0005 |

## Figures 

### **Figure 1.** Pass-the-Hash detection query results.

### **Figure 2.** Sysmon Event ID 10 identifying LSASS memory access.

### **Figure 3.** Pass-the-Ticket transaction analysis.

### **Figure 4.** Kerberos communication over port 88.

### **Figure 5.** Correlation between Sysmon Event IDs 1 and 3 identifying Rubeus activity.

### **Figure 6.** IOC summary and detection engineering overview.

## Detection Engineering Considerations 

Effective detection of credential abuse relies on behavioral correlation rather than isolated events.

Detection engineering should emphasize:

- Multi-event correlation
- Process attribution
- Authentication flow reconstruction
- Network-to-process relationships
- Organizational baselining to reduce false positives

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Event Correlation | No individual event conclusively identifies credential abuse. Correlation is essential. |
| Security + Sysmon | Combining Windows Security Logs with Sysmon telemetry provides significantly greater visibility. |
| LOLBins | Legitimate Windows binaries such as `rundll32.exe` are frequently abused during credential attacks. |
| Kerberos Monitoring | Unexpected communication with Domain Controllers over port 88 is a valuable hunting indicator. |
| Authentication Baselines | Legitimate Kerberos authentication follows a predictable sequence that can be monitored for deviations. |
| Attack Progression | Credential abuse techniques frequently occur as part of a larger attack chain rather than isolated events. |

## Conclusion

The investigations demonstrated that effective detection of Active Directory credential abuse depends on correlating authentication events, process telemetry, and network activity. By combining Windows Security Logs, Sysmon, and Splunk correlation searches, defenders can reliably identify Pass-the-Hash, Pass-the-Ticket, and Overpass-the-Hash activity while minimizing false positives through behavioral analysis.

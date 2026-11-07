# 04 - Detection Logic and IOCs

## Executive Summary 

This section consolidates the detection logic, investigation artifacts, and threat hunting methodologies developed across the Pass-the-Hash, Pass-the-Ticket, and Overpass-the-Hash lab investigations.

The objective is to transform investigation findings into reusable detection logic suitable for SOC operations, threat hunting, and SIEM detection engineering.

The detection approaches focus on correlating Windows authentication events, Sysmon process telemetry, and network activity while distinguishing suspicious behavioral indicators from confirmed credential abuse.

## Covered Techniques 

The investigation covered three common Active Directory credential abuse techniques:

- **Pass-the-Hash (PtH)** – Authentication using stolen NTLM hashes.
  
- **Pass-the-Ticket (PtT)** – Authentication using stolen Kerberos tickets.
  
- **Overpass-the-Hash (Pass-the-Key)** – Requesting Kerberos tickets using stolen NTLM hashes or AES keys.

## Technique Comparison 

| Technique | Authentication Protocol | Primary Detection Artifact | Primary Event IDs |
|-----------|-------------------------|----------------------------|-------------------|
| Pass-the-Hash | NTLM | Logon Type 9 (`seclogo`) with LSASS access correlation | 4624, 10 |
| Pass-the-Ticket | Kerberos | Event ID 4769 without Event ID 4768 within the observation window | 4768, 4769, 4770 |
| Overpass-the-Hash | Kerberos | Non-standard process communicating with Domain Controller over port 88 | 1, 3, 4768 |

**Detection limitation**: These artifacts represent potential hunting indicators rather than definitive evidence of the corresponding attacks. Logon Type 9 can occur during legitimate **runas /netonly** activity, missing TGT events may result from Kerberos ticket caching, and communication with port 88 can be legitimate.

Event ID 4768 is relevant to Overpass-the-Hash validation but was not included in the documented process-to-network correlation query.

## Investigation Artifacts and Detection Indicators

| IOC | Detection Opportunity | Investigation Relevance |
|-----|------------------------|--------------------------|
| NewCredentials Logon | Security Event ID 4624 (Logon Type 9) | Possible Pass-the-Hash activity |
| LSASS Access | Sysmon Event ID 10 | Potential credential access requiring contextual validation |
| Service Ticket without observed TGT | Event ID 4769 without an associated Event ID 4768 | Potential ticket reuse requiring further investigation |
| Kerberos Communication | Sysmon Event ID 3 targeting port 88 | Potential Overpass-the-Hash when associated with unexpected processes |
| Unusual Process Activity | rundll32.exe, Rubeus.exe | Observed process images requiring investigation of execution context and network behaviour |

**Important distinction**: The items above are investigation artifacts and behavioral detection indicators, not confirmed Indicators of Compromise. **rundll32.exe** is a legitimate Windows binary, whereas **Rubeus.exe** is a Kerberos interaction and security testing tool; they should not be classified identically as LOLBins.

## Detection Logic 

### Pass-the-Hash

Investigate Security Event ID 4624 with:

- Logon Type = 9
  
- Logon Process = seclogo

Correlate these events with Sysmon Event ID 10 targeting `lsass.exe`.

**Additional validation**: Review the source process, process lineage, user account, and subsequent remote authentication activity. Logon Type 9 and LSASS access do not independently establish NTLM hash injection.

### Pass-the-Ticket

Investigate Kerberos authentication sequences involving:

- Event ID 4769 - Service Ticket requests.
  
- Event ID 4770 - Ticket renewal activity.
  
- Event ID 4768 - Ticket Granting Ticket requests.

Identify service ticket activity without an associated TGT request within the available observation window. Correlate usernames, source IP addresses, and service names while accounting for legitimate ticket caching and incomplete event coverage.

### Overpass-the-Hash

Monitor Sysmon Event ID 3 for:

- Destination Port = 88
  
- Domain Controller communication
  
- Non-standard client processes

Correlate with Sysmon Event ID 1 for process attribution.

**Additional validation**: Investigate unexpected process images, particularly the observed **Rubeus.exe** and **rundll32.exe** activity. Where available, correlate with Domain Controller Kerberos events and process command-line telemetry to determine whether ticket requests involved suspicious authentication material.

## Splunk Hunting Queries

The investigation developed reusable hunting queries covering:

- Pass-the-Hash authentication artifacts
  
- LSASS memory access
  
- Pass-the-Ticket transaction analysis
  
- Overpass-the-Hash process-to-network correlation

The detailed SPL searches, investigation methodology, and available results are documented in the corresponding technique-specific sections.

These queries provide a foundation for threat hunting and detection development; further testing, field normalization, and false-positive evaluation would be necessary before operational deployment.

## Attack Correlation

Credential abuse techniques may occur independently or as part of a broader post-exploitation sequence. For example, stolen authentication material can enable Pass-the-Hash or Overpass-the-Hash activity, while compromised Kerberos tickets may subsequently be reused through Pass-the-Ticket.

These techniques do not necessarily occur in a fixed order. Correlating credential access indicators, authentication anomalies, process activity, and remote connections can help reconstruct an attack sequence when supporting telemetry is available.

## MITRE ATT&CK Mapping

| Technique | ATT&CK ID |
|-----------|-----------|
| OS Credential Dumping: LSASS Memory | T1003.001 |
| Pass-the-Hash | T1550.002 |
| Pass-the-Ticket | T1550.003 |

**Mapping note**: T1550.002 and T1550.003 represent the primary credential abuse techniques investigated. Overpass-the-Hash using stolen NT hash material is also associated with T1550.002.

T1003.001 provides relevant context for LSASS credential access, but Sysmon Event ID 10 alone does not confirm credential dumping. The mapping describes the investigated techniques and should not be interpreted as confirmation that each attack occurred successfully.

## Detection Engineering Considerations 

Effective detection of credential abuse relies on behavioral correlation rather than isolated events.

Detection engineering should emphasize:

- Multi-event correlation
  
- Process attribution
  
- Authentication flow reconstruction
  
- Network-to-process relationships
  
- Organizational baselining to reduce false positives

Detection rules should also account for legitimate administrative activity, Kerberos ticket caching, process identifier reuse, and incomplete telemetry. These factors can generate patterns resembling credential abuse without indicating malicious activity.

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Event Correlation | No individual event conclusively identifies credential abuse. Correlation is essential. |
| Security + Sysmon | Combining Windows Security Logs with Sysmon telemetry provides significantly greater visibility. |
| LOLBins | Legitimate Windows binaries such as `rundll32.exe` are frequently abused during credential attacks. |
| Kerberos Monitoring | Unexpected communication with Domain Controllers over port 88 is a valuable hunting indicator. |
| Authentication Baselines | Kerberos authentication patterns should be evaluated against ticket caching, session duration, and expected organizational behaviour. |
| Attack Progression | Credential abuse techniques may occur as part of a larger attack chain rather than isolated events. |

## Conclusion

These investigations demonstrated how Windows Security Logs, Sysmon telemetry, and Splunk correlation searches can support threat hunting for credential abuse in Active Directory environments.

The combined detection approaches examined NewCredentials authentication, Kerberos ticket activity, LSASS process access, and unexpected process-to-network relationships. Although these indicators do not independently confirm Pass-the-Hash, Pass-the-Ticket, or Overpass-the-Hash, they provide useful investigative leads and a foundation for developing more reliable behavioral detections.

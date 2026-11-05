# 02 - Detecting Pass-the-Ticket 

## Executive Summary

This investigation focused on detecting Pass-the-Ticket (PtT) activity in Splunk by analyzing Kerberos authentication events and transaction-based event correlation. The investigation identified incomplete Kerberos authentication sequences that may indicate stolen Kerberos ticket reuse and credential abuse.

## Investigation Objectives

- Detect Pass-the-Ticket authentication artifacts.
- Identify incomplete Kerberos authentication sequences.
- Correlate Kerberos ticket activity across multiple event types.
- Detect missing Ticket Granting Ticket (TGT) requests.
- Reduce false positives through transaction-based correlation.
- Map observed behavior to MITRE ATT&CK.

## Background 

### What is Pass-the-Ticket?

Pass-the-Ticket (PtT) is a credential abuse technique in which an attacker steals and reuses Kerberos tickets instead of authenticating with a plaintext password or NTLM hash.

Rather than possessing valid credentials, the attacker authenticates using a previously obtained:

- Ticket Granting Ticket (TGT)
- Ticket Granting Service Ticket (TGS)

This technique enables unauthorized authentication to remote services while bypassing normal credential validation.

### Attack Objectives

Pass-the-Ticket is commonly used to achieve:

- Lateral Movement
- Privilege Escalation
- Domain Persistence
- Access to internal services
- Active Directory abuse

## Common Tools

### Mimikatz

Typical commands:

``` text
kerberos::list
kerberos::ptt ticket.kirbi
``` 

### Rubeus

Typical command:

```text
Rubeus.exe ptt /ticket:ticket.kirbi
``` 

## Kerberos Authentication Flow

| Step | Activity | Related Event |
|------|----------|---------------|
| 1 | Client requests a Ticket Granting Ticket (TGT) | Event ID 4768 |
| 2 | Domain Controller issues the TGT | — |
| 3 | Client requests a Service Ticket (TGS) | Event ID 4769 |
| 4 | Domain Controller issues the TGS | — |
| 5 | Client authenticates to the target service | Event ID 4624 |

## How Pass-the-Ticket Differs 

Under normal Kerberos authentication, a client first requests a Ticket Granting Ticket (TGT), generating Security Event ID 4768. The TGT is then used to request a Service Ticket (Event ID 4769), followed by successful authentication to the target service (Event ID 4624).

During a Pass-the-Ticket attack, the attacker imports an existing Kerberos ticket instead of requesting a new TGT. As a result, Event ID 4769 and subsequent authentication events may occur without a corresponding Event ID 4768. This missing TGT request represents one of the primary behavioral indicators used to detect Pass-the-Ticket activity.

## Detection Artifact 

One of the strongest indicators of Pass-the-Ticket activity is a Kerberos Service Ticket request (Event ID 4769) occurring without a preceding Ticket Granting Ticket request (Event ID 4768) from the same host. Missing TGT requests often indicate imported Kerberos tickets rather than legitimate authentication.

## MITRE ATT&CK Mapping (Background) 

| Technique | ATT&CK ID |
|-----------|-----------|
| Pass-the-Ticket | T1550.003 |
| Steal or Forge Kerberos Tickets | T1558 |
| Lateral Movement | TA0008 |
| Defense Evasion | TA0005 |

## Data Sources 

| Source | Purpose |
|---------|----------|
| Windows Security Logs | Kerberos authentication events |
| Splunk Index (main) | Centralized log analysis |
| Event ID 4768 | Ticket Granting Ticket requests |
| Event ID 4769 | Service Ticket requests |
| Event ID 4770 | Ticket renewals |
| Event ID 4624 | Successful logons |

## Investigation Scope

The investigation focused on identifying user accounts exhibiting incomplete Kerberos authentication sequences by correlating Ticket Granting Ticket requests, Service Ticket requests, and ticket renewal events using Splunk transaction analysis.

## Investigation Methodology 

The investigation followed a structured seven-stage correlation process:

1. Collect Kerberos authentication events.
2. Exclude machine accounts.
3. Normalize usernames.
4. Normalize source IPv4 addresses.
5. Build Kerberos authentication transactions.
6. Identify incomplete authentication sequences.
7. Attribute suspicious activity to individual user accounts.

## Investigation Query 

### Purpose: 

Identify user accounts potentially performing Pass-the-Ticket activity by reconstructing Kerberos authentication transactions and detecting Service Ticket requests that occur without an associated Ticket Granting Ticket request.

### SPL:

```spl
index=main earliest=1690392405 latest=1690451745
source="WinEventLog:Security"
user!=*$
EventCode IN (4768,4769,4770)
| rex field=user "(?[^@]+)"
| rex field=src_ip "(::ffff:)?(?<src_ip_4>[0-9.]+)"
| transaction username, src_ip_4
maxspan=10h
keepevicted=true
startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="$@"
| table _time,
ComputerName,
username,
src_ip_4,
service_name,
category
```

### Results

| Field | Value |
|-------|-------|
| Identified Users | Administrator, YOUNG_WILKINSON |
| Missing Username | YOUNG_WILKINSON |

### Query Analysis 

The query reconstructs Kerberos authentication activity by collecting Event IDs 4768, 4769 and 4770 while excluding machine accounts. Usernames and IPv4 addresses are normalized before transaction analysis groups related Kerberos events into complete authentication sequences. Transactions missing an initial Ticket Granting Ticket request (`closed_txn=0`) are retained, allowing analysts to identify users whose authentication activity may be consistent with Pass-the-Ticket.

## Detection Logic

### Missing Ticket Granting Ticket

A Service Ticket request (Event ID 4769) occurring without a preceding Ticket Granting Ticket request (Event ID 4768) is one of the strongest behavioral indicators of Pass-the-Ticket activity.

### Ticket Renewal Analysis

Event ID 4770 occurring without a corresponding Ticket Granting Ticket request may indicate continued use of an imported Kerberos ticket rather than a newly issued authentication session.

### Unexpected Kerberos Activity 

Investigate unusual combinations of:

- Computer Name
- Source IP Address
- Service Name

Unexpected relationships between these fields may indicate suspicious Kerberos authentication activity.

### Authentication Flow Correlation

Legitimate Kerberos authentication normally follows the sequence:

- Event ID 4768
- Event ID 4769
- Event ID 4624

Pass-the-Ticket activity frequently deviates from this pattern by generating Event ID 4769 or Event ID 4770 without an associated Event ID 4768, creating an observable gap in the authentication sequence.

## Transaction Analysis

Splunk transactions reconstruct complete Kerberos authentication flows by grouping related events across a configurable time window. This approach enables analysts to identify incomplete authentication sequences, particularly missing Ticket Granting Ticket requests, which represent one of the strongest behavioral indicators of Pass-the-Ticket activity.

## Transaction-Based Detection

Transaction analysis reconstructs complete Kerberos authentication flows by grouping related authentication events over time. This approach enables analysts to identify incomplete authentication sequences that would be difficult to detect by examining individual events in isolation.

By retaining open transactions (`closed_txn=0`), investigators can efficiently identify missing Ticket Granting Ticket requests, one of the strongest behavioral indicators of Pass-the-Ticket activity.

## IOC Summary

| IOC Type | Value |
|-----------|-------|
| Event IDs | 4768, 4769, 4770, 4624, 4672 |
| Authentication Indicators | Missing TGT, Open Transactions, Unexpected Service Tickets |
| Kerberos Artifacts | TGT, TGS, KRB-CRED, KIRBI |
| Tools | Mimikatz, Rubeus |
| Users | Administrator, YOUNG_WILKINSON |

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Credential Access | Steal or Forge Kerberos Tickets | T1558 | Theft or reuse of Kerberos authentication material |
| Credential Access | Pass-the-Ticket | T1550.003 | Authentication using stolen Kerberos tickets |
| Lateral Movement | Lateral Movement | TA0008 | Movement between systems using valid Kerberos tickets |
| Defense Evasion | Defense Evasion | TA0005 | Bypassing normal authentication mechanisms |

## Figures

### **Figure 1.** Mimikatz ticket extraction.
Mimikatz Ticket Extraction

### **Figure 2.** Pass-the-Ticket injection using Mimikatz or Rubeus.
Ticket Injection (PTT)

### **Figure 3.** Kerberos authentication workflow.
Kerberos Authentication Flow

### **Figure 4.** Security Event ID 4768.
4768 Event Example

### **Figure 5.** Security Event ID 4769.
4769 Event Example

### **Figure 6.** Security Event ID 4770.
4770 Event Example

### **Figure 7.** Splunk transaction query.
Splunk Detection Query

### **Figure 8.** Transaction analysis results.
Transaction Results

### **Figure 9.** Investigation output identifying suspicious users.
Output

## Detection Engineering Notes

| Consideration | Description |
|--------------|-------------|
| Long-lived Kerberos Sessions | Long-lived sessions may legitimately generate Event ID 4769 without a corresponding Event ID 4768 within the available retention period. |
| Domain Controllers | Domain Controllers generate large volumes of Kerberos authentication events and should be baselined before alerting. |
| Service Accounts | Service accounts often exhibit authentication patterns that differ from interactive user accounts and require contextual validation. |

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Kerberos Authentication | Pass-the-Ticket abuses Kerberos tickets rather than passwords or NTLM hashes. |
| Missing TGT Detection | Event ID 4769 without a preceding Event ID 4768 is a strong detection opportunity. |
| Transaction Analysis | Correlating multiple Kerberos events is significantly more effective than analyzing isolated events. |
| Tooling | Mimikatz and Rubeus generate similar Kerberos authentication artifacts. |
| Event Correlation | Correlating usernames, source IP addresses and service names reduces false positives. |
| Authentication Gaps | Imported Kerberos tickets create observable gaps in the normal authentication sequence. |
| Threat Hunting | Pass-the-Ticket frequently follows credential dumping or privilege escalation activities. |

## Conclusion

This investigation demonstrated how transaction-based correlation of Kerberos authentication events can be used to identify Pass-the-Ticket activity in Splunk. Detecting missing Ticket Granting Ticket requests, combined with user and network attribution, enables defenders to identify stolen Kerberos ticket reuse while reducing false positives through behavioral analysis.

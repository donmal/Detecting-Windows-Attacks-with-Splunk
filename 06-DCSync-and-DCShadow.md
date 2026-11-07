# 06 - DCSync and DCShadow 

## Executive Summary 

This investigation examined potential Active Directory replication abuse using Splunk by analyzing Windows Security Events associated with directory service access and computer account modifications.

The analysis focused on two techniques: DCSync, which abuses directory replication capabilities to obtain credential material, and DCShadow, which can use rogue Domain Controller registration to introduce unauthorized directory changes.

Event ID 4662 analysis identified the account **RAUL_LYNN** associated with replication-related permissions on **DC=corp,DC=local**. Event ID 4742 analysis identified a Global Catalog Service Principal Name (SPN), **GC/YELLOW.evil.local/evil.local**, relevant to the investigation of potential rogue Domain Controller registration.

These findings provide indicators for further investigation but do not independently confirm successful credential extraction or unauthorized directory replication.

## Investigation Objectives 

- Understand the differences between DCSync and DCShadow attacks.
  
- Investigate indicators of potentially unauthorized Active Directory replication activity.
  
- Identify accounts performing replication requests.
  
- Detect rogue Domain Controller registration attempts.
  
- Analyze replication-related Windows Security Events.
  
- Correlate replication artifacts with Active Directory object modifications.
  
- Map observed behavior to MITRE ATT&CK.

## Background 

### What is DCSync? 

DCSync is a credential access technique in which an attacker abuses the Active Directory Directory Replication Service (DRS) to request password data directly from a Domain Controller. 

Rather than directly copying the **NTDS.dit** database, an attacker with sufficient replication permissions can request directory data through legitimate Active Directory replication interfaces.

Successful DCSync attacks commonly result in the extraction of privileged account hashes, including the KRBTGT account, enabling subsequent attacks such as Golden Ticket forgery.

### What is DCShadow?

DCShadow is a defense evasion and persistence technique in which an attacker registers a rogue Domain Controller within Active Directory and pushes unauthorized directory changes through the normal replication process. By temporarily emulating a legitimate Domain Controller, attackers can modify Active Directory objects while bypassing many traditional administrative controls and auditing mechanisms.

## Key Differences 

| Feature | DCSync | DCShadow |
|---------|---------|----------|
| Primary Objective | Extract Active Directory credentials | Modify Active Directory objects |
| Abuse Mechanism | Directory Replication Service (DRS) | Rogue Domain Controller registration |
| Primary Events | Event ID 4662 | Event ID 4742 |
| Key Artifact | Replicating Directory Changes | Global Catalog SPN (GC/) |
| Required Privilege | Replication permissions | Domain Controller registration privileges |
| Typical Outcome | KRBTGT hash extraction | Unauthorized directory replication |
| ATT&CK Technique | T1003.006 | T1207 |

**Detection note**: Event ID 4662 is useful for identifying directory service access involving replication rights, while Event ID 4742 records computer account changes. Neither event alone proves that DCSync or DCShadow succeeded.

## MITRE ATT&CK Mapping (Background) 

| Technique | ATT&CK ID |
|-----------|-----------|
| DCSync | T1003.006 |
| DCShadow | T1207 |
| Account Manipulation | T1098 |

## Data Sources

| Source | Purpose |
|---------|----------|
| Windows Security Logs | Active Directory replication events |
| Splunk Index (main) | Centralized event analysis |
| Event ID 4662 | Directory service object access, including replication-related rights |
| Event ID 4742 | Computer account modifications |
| Active Directory Objects | Replication targets |
| Service Principal Names (SPNs) | Rogue Domain Controller detection |

## Investigation Scope 

The investigation focused on identifying Windows Security events associated with potential Active Directory replication abuse. Analysis included Event ID 4662 records referencing replication-related permissions and Event ID 4742 records containing Global Catalog SPN information.

The objective was to identify relevant accounts, directory objects, and computer account changes that could support further investigation of DCSync or DCShadow activity.

## Investigation Methodology 

The investigation followed a structured correlation process:

1. Review Active Directory replication events.
   
2. Identify replication permissions associated with Event ID 4662.
   
3. Review computer account modifications.
   
4. Identify suspicious Service Principal Name registrations.
   
5. Correlate replication-related artifacts.
   
6. Determine whether the observed behavior is consistent with DCSync or DCShadow activity.

## Global Catalog SPN Investigation Artifact

| Artifact | Value | Investigation Relevance |
|----------|-------|-------------------------|
| Global Catalog SPN | `GC/<hostname>/<domain>` | Unexpected Global Catalog SPN changes can indicate potentially unauthorized Domain Controller registration activity. |
| Observed SPN | `GC/YELLOW.evil.local/evil.local` | Global Catalog SPN identified in the recorded Event ID 4742 investigaiton results. |

## DCSync - Replication Permission Analysis

### Purpose:

Identify directory service access events involving replication-related permissions that may warrant investigation for potential DCSync activity.

### Detecting DCSync:

```spl
index=main earliest=1690544278 latest=1690544280 EventCode=4662 Message="*Replicating Directory Changes*"
| rex field=Message "(?P<property>Replicating Directory Changes.*)"
| table _time, user, object_file_name, Object_Server, property
```
**Technical note**: The query filters Event ID 4662 records for replication-related text and extracts a **property** field. This provides evidence of directory service access involving replication permissions, but the query does not independently demonstrate that a DRS replication request retrieved credential material.

The **rex** expression uses the named capture syntax **(?P<property>...)**, which is supported by PCRE-style regular expressions. The query should be tested against the original event format to ensure the extracted value is populated as intended.

### Results 

| Field | Value |
|-------|-------|
| User | `RAUL_LYNN` |
| Property | `Replicating Directory Changes` |
| Additional Permission | `Replicating Directory Changes All` |
| Object | `DC=corp,DC=local` |

### Figure 13 - DCShadow Global Catalog SPN Investigation 

![DCShadow Global Catalog SPN Investigation](../images/dcsync-and-dcshadow/dcshadow-global-catalog-spn.jpeg)

### Query Analysis: 

The query searches Windows Security Event ID 4662 for directory service access involving the **Replicating Directory Changes** permission.

The recorded results identified account **RAUL_LYNN** in connection with replication-related permissions, including **Replicating Directory Changes All**, on the directory object **DC=corp,DC=local**.

These findings are relevant to DCSync threat hunting because the technique relies on Active Directory replication rights. However, legitimate replication activity and authorized administrative operations may produce related events, so the account's permissions and activity should be validated before attributing the behavior to DCSync.

## DCShadow - Global Catalog SPN Investigation

### Purpose: 

Identify suspicious computer account modifications that may indicate rogue Domain Controller registration associated with DCShadow activity.

### Detecting DCShadow:

```spl
index=main earliest=1690623888 latest=1690623890 EventCode=4742
| rex field=Message "(?P<gcspn>GC\/[a-zA-Z0-9\.\-\/]+)"
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn
| search gcspn=*
```

### Results:

| Field | Value |
|-------|-------|
| Global Catalog SPN | `GC/YELLOW.evil.local/evil.local` |
| Indicator | `GC/` |

The query analyzes Windows Security Event ID 4742 for computer account modification events containing a Global Catalog SPN matching the **GC/** prefix.

The recorded results identified **GC/YELLOW.evil.local/evil.local**, which is relevant to investigations of potential rogue Domain Controller registration. Unexpected SPN modifications can be associated with DCShadow preparation, although the event alone does not establish that a rogue Domain Controller successfully replicated directory changes.

## Detection Logic

### Replication Permission Monitoring 

Monitor Windows Security Event ID 4662 for directory service access involving replication-related rights, particularly when the requesting account is not an expected Domain Controller or authorized replication principal.

Relevant replication permissions include **Replicating Directory Changes** and **Replicating Directory Changes All**. Their presence should be evaluated alongside the account identity, directory object, and surrounding activity.

### Replication GUID Monitoring 

The Active Directory replication GUID:

`{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}`

corresponds to the **DS-Replication-Get-Changes** permission. 

Monitoring this GUID can help identify directory service access involving replication rights. However, the GUID alone does not distinguish authorized replication from DCSync abuse.

### Computer Account Modification Monitoring 

Windows Security Event ID 4742 records modifications to computer accounts. Unexpected changes involving Domain Controller-related attributes or Service Principal Names may indicate DCShadow activity or rogue Domain Controller registration.

### Global Catalog SPN Monitoring 

Unexpected registration of the `GC/` Service Principal Name prefix should be investigated immediately.

Global Catalog SPNs are associated with Domain Controller services. Unexpected changes involving these SPNs, particularly on unauthorized computer accounts, can provide a useful indicator of potential DCShadow activity.

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Credential Access | DCSync | T1003.006 | Active Directory replication abuse for credential extraction |
| Defense Evasion | DCShadow | T1207 | Rogue Domain Controller registration and unauthorized replication |

**Mapping note**: T1003.006 and T1207 represent the primary techniques investigated. The documented telemetry supports replication-related access and suspicious SPN analysis but does not independently confirm successful DCSync credential extraction or DCShadow directory replication.

T1098 (Account Manipulation) should not be presented as an observed technique without evidence of an account modification performed for persistence or privilege escalation.

## Investigation Artifacts and Detection References

| IOC Type | Value |
|-----------|-------|
| Event IDs | 4662, 4742 |
| Replication Property | `Replicating Directory Changes` |
| Replication GUID | `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` |
| SPN Prefix | `GC/` |
| User | `RAUL_LYNN` |
| Active Directory Object | `DC=corp,DC=local` |
| Observed Global Catalog SPN | `GC/YELLOW.evil.local/evil.local` |

The event IDs, permission names, account, directory object, and SPN are investigation artifacts rather than confirmed Indicators of Compromise. Their significance depends on the surrounding Active Directory configuration and authentication context.

## Lessons Learned 

| Lesson | Description |
|---------|-------------|
| Active Directory Replication | DCSync abuses legitimate Active Directory replication rather than accessing NTDS.dit directly. |
| Event ID 4662 | Replication-related permissions provide useful investigation indicators when correlated with account identity and expected replication behaviour. |
| Replication GUIDs | Monitoring replication GUIDs provides additional investigative context beyond Event IDs alone. |
| Computer Account Monitoring | Event ID 4742 helps identify suspicious computer account modifications associated with DCShadow. |
| Service Principal Names | Unexpected registration of the `GC/` SPN prefix is a valuable indicator of rogue Domain Controller activity. |
| Attack Progression | Successful DCSync activity can enable subsequent credential abuse, including Golden Ticket forgery if the KRBTGT secret is compromised. |
| Event Correlation | Correlating replication events, SPN modifications, and Kerberos activity can improve investigative context and detection confidence. |
| Active Directory Visibility | Combining Windows Security Events with replication telemetry provides additional visibility into potential Active Directory replication abuse. |


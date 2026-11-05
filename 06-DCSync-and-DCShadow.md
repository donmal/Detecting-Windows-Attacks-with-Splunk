# 06 - DCSync and DCShadow 

## Executive Summary 

This investigation focused on detecting Active Directory replication abuse using Splunk by analyzing Windows Security Events associated with directory replication operations and computer account modifications. The investigation examined both DCSync and DCShadow techniques by correlating replication permissions, directory replication requests, and Service Principal Name (SPN) modifications to identify behavior consistent with unauthorized Active Directory replication.

## Investigation Objectives 

- Understand the differences between DCSync and DCShadow attacks.
- Detect unauthorized Active Directory replication activity.
- Identify accounts performing replication requests.
- Detect rogue Domain Controller registration attempts.
- Analyze replication-related Windows Security Events.
- Correlate replication artifacts with Active Directory object modifications.
- Map observed behavior to MITRE ATT&CK.

## Background 

### What is DCSync? 

DCSync is a credential access technique in which an attacker abuses the Active Directory Directory Replication Service (DRS) to request password data directly from a Domain Controller. Instead of accessing the NTDS.dit database, the attacker impersonates a legitimate replication partner and requests credential information through the normal replication protocol. Successful DCSync attacks commonly result in the extraction of privileged account hashes, including the KRBTGT account, enabling subsequent attacks such as Golden Ticket forgery.

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

## Attack Flow 

### DCSync Attack Flow 

1. Obtain Active Directory replication privileges.
2. Send DRSGetNCChanges replication requests.
3. Request password attributes from the Domain Controller.
4. Extract privileged account hashes (e.g., KRBTGT).
5. Use stolen credentials for persistence or Kerberos ticket forgery.

### DCShadow Attack Flow 

1. Register a rogue Domain Controller.
2. Create or modify the nTDSDSA object.
3. Register Global Catalog Service Principal Names (SPNs).
4. Push unauthorized Active Directory changes through replication.
5. Remove traces of the rogue Domain Controller.

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
| Event ID 4662 | Directory replication permissions |
| Event ID 4742 | Computer account modifications |
| Active Directory Objects | Replication targets |
| Service Principal Names (SPNs) | Rogue Domain Controller detection |

## Investigation Scope 

The investigation focused on identifying unauthorized Active Directory replication activity by correlating replication permissions, directory replication requests, computer account modifications, and Service Principal Name (SPN) registrations. While both DCSync and DCShadow techniques were examined, the practical investigation primarily focused on identifying artifacts associated with rogue Domain Controller registration.

## Investigation Methodology 

The investigation followed a structured correlation process:

1. Review Active Directory replication events.
2. Identify replication permissions associated with Event ID 4662.
3. Review computer account modifications.
4. Identify suspicious Service Principal Name registrations.
5. Correlate replication-related artifacts.
6. Determine whether the observed behavior is consistent with DCSync or DCShadow activity.

## Challenge Context

The investigation was initiated after the security team identified suspicious Active Directory replication activity potentially associated with credential theft or unauthorized directory replication. Analysts were tasked with determining whether an attacker had abused replication permissions to extract credentials or had attempted to register a rogue Domain Controller to replicate unauthorized changes throughout the domain.

Using Splunk, the investigation focused on correlating Windows Security Events, replication permissions, Service Principal Name modifications, and Active Directory object changes to identify indicators of DCSync and DCShadow abuse.

## Investigation Exercise 

### Objective

During an investigation into suspicious Active Directory replication activity, analysts identified modifications to computer objects potentially associated with rogue Domain Controller registration.

Using the provided Splunk data, determine the Service Principal Name (SPN) prefix associated with the suspicious activity.

### Question

Modify the final Splunk search by replacing the missing characters (XX) so that the returned results match the expected output.

### Solution

`GC`

## Investigation Overview 

Before examining individual events, the investigation followed a hypothesis-driven approach. Rather than relying on isolated Windows Security Events, replication permissions, directory replication activity, and Service Principal Name modifications were correlated to reconstruct the complete attack sequence.

The overall investigation focused on determining:

- whether unauthorized replication requests occurred,
- whether replication permissions were abused,
- whether computer account modifications indicated rogue Domain Controller registration,
- whether the observed behavior was consistent with DCSync or DCShadow.

## Key Detection Artifact

| Artifact | Value | Investigation Relevance |
|----------|-------|-------------------------|
| Global Catalog SPN | `GC/<hostname>/<domain>` | Registration of unauthorized Global Catalog SPNs is a strong indicator of DCShadow activity. |
| Example | `GC/YELLOW.evil.local/evil.local` | Example extracted during the investigation. |

## Investigation Query #1

### Purpose:

Identify Active Directory replication requests indicative of DCSync activity by searching for Event ID 4662 records containing replication-related permissions.

### Detecting DCSync:

```spl
index=main earliest=1690544278 latest=1690544280 EventCode=4662 Message="*Replicating Directory Changes*"
| rex field=Message "(?P<property>Replicating Directory Changes.*)"
| table _time, user, object_file_name, Object_Server, property
```

### Results 

| Field | Value |
|-------|-------|
| User | `RAUL_LYNN` |
| Property | `Replicating Directory Changes` |
| Additional Permission | `Replicating Directory Changes All` |
| Object | `DC=corp,DC=local` |

### Query Analysis: 

The query searches Windows Security Event ID 4662 for replication permissions associated with the Directory Replication Service. Requests containing the "Replicating Directory Changes" property frequently indicate DCSync activity because attackers must possess replication privileges to request password data from Domain Controllers.

## Investigation Query #2

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

GC/YELLOW.evil.local/evil.local

### Query Analysis:

The query analyzes Event ID 4742 to identify modifications to computer accounts containing Global Catalog Service Principal Names (SPNs). Unexpected registration of the GC/ prefix is a strong indicator of DCShadow because attackers commonly register rogue Domain Controllers before replicating unauthorized directory changes.

## Investigation Workflow

### DCSync Investigation Workflow 

1. Review Windows Security Event ID 4662.
2. Identify entries containing the replication permission:
   `Replicating Directory Changes`
3. Verify the account requesting replication privileges.
   **User:** `RAUL_LYNN`
4. Confirm the replicated directory object.
   **Object:** `DC=corp,DC=local`
5. Assess whether the observed replication activity is consistent with DCSync.

### DCSync Investigation Workflow 

1. Review Windows Security Event ID 4742 for computer account modifications.
2. Analyze Service Principal Name (SPN) changes.
3. Identify Global Catalog SPN registrations containing the `GC/` prefix.
4. Verify the modified computer account.
5. Determine whether the observed behavior is consistent with rogue Domain Controller registration.

## Detection Logic

### Replication Permission Monitoring 

Windows Security Event ID 4662 should be monitored for replication-related permissions such as **Replicating Directory Changes**. These permissions are commonly requested during DCSync attacks because they allow an account to perform directory replication operations normally reserved for Domain Controllers.

### Replication GUID Monitoring 

The Active Directory replication GUID:

`{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}`

corresponds to the **DS-Replication-Get-Changes** permission. Monitoring this GUID provides additional context when investigating replication-related activity and helps distinguish legitimate replication from potential DCSync abuse.

### Computer Account Modification Monitoring 

Windows Security Event ID 4742 records modifications to computer accounts. Unexpected changes involving Domain Controller-related attributes or Service Principal Names may indicate DCShadow activity or rogue Domain Controller registration.

### Global Catalog SPN Monitoring 

Unexpected registration of the `GC/` Service Principal Name prefix should be investigated immediately. Global Catalog SPNs are normally assigned only to legitimate Domain Controllers and may indicate DCShadow attempts when observed on unauthorized systems.

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Credential Access | DCSync | T1003.006 | Active Directory replication abuse for credential extraction |
| Defense Evasion | DCShadow | T1207 | Rogue Domain Controller registration and unauthorized replication |
| Persistence | Account Manipulation | T1098 | Modification of Active Directory objects for long-term persistence |

## IOC Summary 

| IOC Type | Value |
|-----------|-------|
| Event IDs | 4662, 4742 |
| Replication Property | `Replicating Directory Changes` |
| Replication GUID | `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` |
| SPN Prefix | `GC/` |
| User | `RAUL_LYNN` |
| Active Directory Object | `DC=corp,DC=local` |

## Placeholder Screenshots

### Screenshot-01-DCSync-Mimikatz.png

### Screenshot-02-Event4662-ReplicationChanges.png

### Screenshot-03-Splunk-DCSync-Detection.png

### Screenshot-04-DCShadow-Registration.png

### Screenshot-05-DCShadow-Push.png

### Screenshot-06-Splunk-DCShadow-Detection.png

## Lessons Learned 

| Lesson | Description |
|---------|-------------|
| Active Directory Replication | DCSync abuses legitimate Active Directory replication rather than accessing NTDS.dit directly. |
| Event ID 4662 | Replication-related permissions provide one of the strongest indicators of DCSync activity. |
| Replication GUIDs | Monitoring replication GUIDs provides additional investigative context beyond Event IDs alone. |
| Computer Account Monitoring | Event ID 4742 helps identify suspicious computer account modifications associated with DCShadow. |
| Service Principal Names | Unexpected registration of the `GC/` SPN prefix is a valuable indicator of rogue Domain Controller activity. |
| Attack Progression | DCSync frequently precedes Golden Ticket attacks through KRBTGT hash extraction. |
| Event Correlation | Correlating replication events, SPN modifications, and Kerberos activity significantly improves detection accuracy. |
| Active Directory Visibility | Combining Windows Security Events with replication telemetry provides a comprehensive view of Active Directory compromise. |


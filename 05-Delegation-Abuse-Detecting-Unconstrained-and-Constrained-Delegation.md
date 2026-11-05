# 05 - Delegation Abuse: Detecting Unconstrained and Constrained Delegation 

## Executive Summary 

This investigation focused on detecting Kerberos delegation reconnaissance and abuse within an Active Directory environment using Splunk. The investigation examined both Unconstrained Delegation and Constrained Delegation by analyzing PowerShell Script Block Logging, LDAP enumeration activity, Kerberos network traffic, and Rubeus execution to identify systems targeted during delegation discovery.

## Investigation Objectives

- Understand the differences between Unconstrained and Constrained Delegation.
- Detect PowerShell-based delegation reconnaissance.
- Identify hosts targeted during delegation enumeration.
- Detect Kerberos delegation abuse using Splunk.
- Identify Rubeus activity related to S4U abuse.
- Correlate PowerShell, Sysmon and Kerberos telemetry.
- Map observed behavior to MITRE ATT&CK.

## Challenge Context 

The investigation was initiated after the security team identified potential reconnaissance activity targeting Kerberos delegation configurations within the Active Directory environment. Because both Unconstrained and Constrained Delegation can be abused for credential theft, user impersonation, and privilege escalation, analysts were tasked with determining whether delegation settings had been enumerated and identifying the systems involved.

Using Splunk, the investigation focused on PowerShell Script Block Logging, delegation-related Active Directory attributes, Kerberos activity, and process telemetry. The primary objective was to identify all hosts involved in Unconstrained Delegation reconnaissance and determine the additional affected system beyond the previously known host.

## Background 

### What is Unconstrained Delegation? 

Unconstrained Delegation is a Kerberos delegation mechanism that allows a service to impersonate users to any service within the Active Directory domain. When users authenticate to a system configured for Unconstrained Delegation, their Ticket Granting Ticket (TGT) is cached in memory, enabling the delegated service to request additional Kerberos service tickets on the user's behalf. If an attacker compromises such a system, cached TGTs may be stolen and reused for credential theft, privilege escalation, and subsequent Pass-the-Ticket attacks. Consequently, monitoring TrustedForDelegation configurations, PowerShell enumeration activity, and Kerberos ticket usage provides valuable detection opportunities.

### What is Constrained Delegation? 

Constrained Delegation restricts Kerberos delegation to a predefined list of services specified through the msDS-AllowedToDelegateTo attribute. Rather than allowing unrestricted impersonation, delegated accounts may request service tickets only for explicitly authorized Service Principal Names (SPNs) using the S4U2Self and S4U2Proxy Kerberos extensions. Although significantly more secure than Unconstrained Delegation, misconfigured or compromised delegated accounts may still enable user impersonation and unauthorized access. Detection therefore focuses on delegation enumeration, S4U-related activity, Rubeus execution, and Kerberos communication over TCP/UDP port 88.

### Key Differences

| Feature | Unconstrained Delegation | Constrained Delegation |
|---------|--------------------------|------------------------|
| Delegation Scope | Any service within the domain | Only explicitly authorized services |
| Active Directory Attribute | `TrustedForDelegation` | `msDS-AllowedToDelegateTo` |
| Ticket Handling | User TGT is cached | Service tickets requested through S4U |
| Kerberos Extensions | Standard Kerberos | `S4U2Self`, `S4U2Proxy` |
| Primary Abuse | TGT theft and reuse | User impersonation to specific services |
| Typical Attack Goal | Credential theft and domain compromise | Service impersonation and privilege escalation |
| Primary Detection Focus | TGT harvesting and delegation enumeration | S4U abuse and delegated service access |

## Attack Flow

### Unconstrained Delegation Attack Flow

•  Identify systems configured with TrustedForDelegation. 
•  A privileged user authenticates to the delegated system. 
•  The user's Ticket Granting Ticket (TGT) is cached. 
•  An attacker compromises the delegated host. 
•  Cached TGTs are extracted and reused. 
•  Stolen tickets enable Pass-the-Ticket, privilege escalation, or lateral movement.

### Constrained Delegation Attack Flow 

 •  Enumerate accounts configured with msDS-AllowedToDelegateTo. 
•  Obtain control of a delegated account. 
•  Request a Ticket Granting Ticket (TGT). 
•  Perform S4U2Self to impersonate a user. 
•  Perform S4U2Proxy to request a delegated service ticket. 
•  Access the authorized service as the impersonated user.

## Key Artifacts

| Artifact | Description |
|----------|-------------|
| `TrustedForDelegation` | Active Directory attribute indicating Unconstrained Delegation |
| `userAccountControl = 524288` | Flag identifying TrustedForDelegation accounts |
| `userAccountControl:1.2.840.113556.1.4.803:=524288` | LDAP matching rule used during delegation enumeration |
| `msDS-AllowedToDelegateTo` | Active Directory attribute identifying Constrained Delegation targets |
| `S4U2Self` | Kerberos extension used to obtain a service ticket on behalf of another user |
| `S4U2Proxy` | Kerberos extension used to request delegated service tickets |

## MITRE ATT&CK Mapping (Background)

| Technique | ATT&CK ID |
|-----------|-----------|
| Unconstrained Delegation | T1558 |
| Constrained Delegation Abuse | T1558 |
| Pass-the-Ticket | T1550.003 |
| Domain Account Discovery | T1087.002 |
| Domain Trust Discovery | T1482 |

## Data Sources

| Source | Purpose |
|---------|----------|
| Windows PowerShell Operational Log | PowerShell Script Block Logging |
| Sysmon | Process and network telemetry |
| Splunk Index (main) | Centralized event analysis |
| Event ID 4104 | PowerShell Script Block Logging |
| Sysmon Event ID 3 | Kerberos network connections |
| Active Directory Attributes | Delegation configuration analysis |

## Investigation Scope

The investigation focused on identifying PowerShell-based reconnaissance targeting Kerberos delegation settings within Active Directory. Analysis included enumeration of Unconstrained and Constrained Delegation configurations, identification of affected hosts, and correlation of PowerShell activity with Kerberos-related telemetry to determine whether delegation abuse was being prepared.

## Investigation Methodology 

•  Review PowerShell Script Block Logging. 
•  Identify delegation-related LDAP attributes. 
•  Determine which hosts performed delegation enumeration. 
•  Investigate Constrained Delegation configurations. 
•  Correlate PowerShell activity with Kerberos network traffic. 
•  Identify potential Rubeus activity. 
•  Assess whether the observed behavior is consistent with Kerberos delegation abuse.

## Investigation Overview 

The investigation began after PowerShell Script Block Logging revealed commands associated with Active Directory delegation enumeration. Analysts examined both Unconstrained Delegation and Constrained Delegation artifacts, identified the hosts involved in reconnaissance, and correlated delegation discovery with Kerberos activity to evaluate whether attackers were preparing for credential theft or user impersonation.

## Investigation Query #1

### Detecting Unconstrained Delegation Discovery

### Purpose:

Identify PowerShell Script Block events associated with Unconstrained Delegation enumeration.

### SPL:

```spl
index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104
Message="*TrustedForDelegation*"
OR
Message="*userAccountControl:1.2.840.113556.1.4.803:=524288*"
| table _time, ComputerName, EventCode, Message
```

### Result:

| Field | Value |
|-------|-------|
| Hosts Identified | `BLUE.corp.local`, `DC01.corp.local` |
| Additional Host | `DC01.corp.local` |

### Query Analysis: 

The query searches PowerShell Script Block Logging (Event ID 4104) for commands referencing TrustedForDelegation or the corresponding userAccountControl LDAP matching rule. The resulting ComputerName values identify the hosts where delegation reconnaissance occurred.

## Investigation Query #2

### Detecting Constrained Delegation Discovery

### Purpose: 

Detect PowerShell-based enumeration of accounts configured for Constrained Delegation by identifying references to the `msDS-AllowedToDelegateTo` Active Directory attribute.

### SPL:

```spl

index=main
source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104
Message="*msDS-AllowedToDelegateTo*"
| table _time, ComputerName, EventCode, Message
```

### Relevant PowerShell Command:

```powershell
Get-ADObject -Filter {(msDS-AllowedToDelegateTo -like "*")}
``` 

This command enumerates Active Directory objects configured for **Constrained Delegation**.

### Results: 

| Field | Value |
|-------|-------|
| Delegation Attribute | `msDS-AllowedToDelegateTo` |
| Enumeration Method | PowerShell (`Get-ADObject`) |
| Activity | Constrained Delegation discovery |

### Query Analysis: 

The query searches PowerShell Script Block Logging (Event ID 4104) for references to the `msDS-AllowedToDelegateTo` Active Directory attribute. This attribute specifies the services to which an account is permitted to delegate Kerberos authentication. Enumeration of this attribute is commonly performed during reconnaissance to identify accounts that may later be abused through the Kerberos Service-for-User (S4U) extensions, including **S4U2Self** and **S4U2Proxy**, enabling user impersonation and delegated service access.

## Investigation Query #3

### Detecting Kerberos Activity Related to S4U Abuse

### Purpose:

Detect Kerberos network activity potentially associated with S4U abuse and Rubeus execution.

### SPL:

```spl
index=main
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| eventstats values(process) as process by process_id
| where EventCode=3 AND dest_port=88
| table _time, Computer, dest_ip, dest_port, Image, process
```
### Results: 

| Field | Value |
|-------|-------|
| Process | `Rubeus.exe` |
| Destination Port | `88` |
| Activity | Kerberos communication |

### Query Analysis: 

The query correlates Sysmon Event ID 3 with process information to identify non-standard processes communicating over Kerberos (TCP/UDP port 88). This activity may indicate Rubeus-based delegation abuse involving S4U2Self or S4U2Proxy.

## Investigation Findings

PowerShell Script Block Logging revealed reconnaissance activity targeting both Unconstrained and Constrained Delegation configurations. Event ID 4104 records contained references to the `TrustedForDelegation` attribute and the equivalent `userAccountControl` LDAP matching rule, indicating enumeration of systems configured for Unconstrained Delegation.

Analysis of the `ComputerName` field identified delegation reconnaissance activity on both `BLUE.corp.local` and `DC01.corp.local`. Comparison of the returned hosts confirmed `DC01.corp.local` as the additional system involved in the activity.

The investigation also identified PowerShell enumeration of the `msDS-AllowedToDelegateTo` attribute, which is used to locate accounts configured for Constrained Delegation. Such reconnaissance can precede abuse of the Kerberos Service-for-User extensions, where an attacker obtains a TGT, uses `S4U2Self` to impersonate a user, and then uses `S4U2Proxy` to request a delegated service ticket for an authorized service.

Subsequent analysis demonstrated how Rubeus activity and Kerberos communication over TCP/UDP port 88 could be correlated with process telemetry to detect potential delegation abuse following the discovery phase.

## Investigation Workflow

### Unconstrained Delegation Investigation Workflow 

1. Review PowerShell Script Block Logging (Event ID 4104) for commands referencing either:

-	`TrustedForDelegation`
-	`userAccountControl:1.2.840.113556.1.4.803:=524288` 

2. Identify the systems where the delegation enumeration occurred by examining the `ComputerName` field. 

3. Review all returned hosts involved in the reconnaissance activity. 

-	`BLUE.corp.local` 
-	`DC01.corp.local` 

4. Compare the identified hosts to determine the additional system involved in the investigation.    

**Identified Host:** `DC01.corp.local` ---


### Constrained Delegation Investigation Workflow 

1. Enumerate Active Directory accounts configured for Constrained Delegation using: 

```powershell
Get-ADObject -Filter {(msDS-AllowedToDelegateTo -like "*")} 
``` 

2. Identify accounts permitted to impersonate users through Kerberos delegation. 

3. Obtain a Ticket Granting Ticket (TGT), for example using:

```text 
Rubeus asktgt 
``` 

4. Abuse the Kerberos Service-for-User (S4U) extension by requesting a service ticket on behalf of another user using **S4U2Self**.

5. Use **S4U2Proxy** to obtain a delegated service ticket for the authorized target service. 

6. Access the target service while impersonating the delegated user account.

## Detection Logic

### Indicator #1:

### TrustedForDelegation Enumeration

PowerShell commands querying the `TrustedForDelegation` attribute frequently indicate reconnaissance targeting systems configured for Unconstrained Delegation. A commonly observed command is:

```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
```

### Indicator #2:

### userAccountControl Search

Searches using the LDAP matching rule 1.2.840.113556.1.4.803:=524288 identify accounts configured for Unconstrained Delegation. Detection of this filter within PowerShell or LDAP queries is a strong indicator of delegation reconnaissance.

### Indicator #3:

### msDS-AllowedToDelegateTo Enumeration

Enumeration of the msDS-AllowedToDelegateTo attribute reveals accounts authorized for Constrained Delegation. Attackers commonly identify these accounts before abusing S4U2Self and S4U2Proxy to impersonate users.

### Indicator #4:

### Rubeus S4U Activity

Execution of Rubeus commands such as asktgt and s4u, particularly when accompanied by arguments including /impersonateuser, /msdsspn, or /altservice, represents a strong indicator of Kerberos delegation abuse.

### Indicator #5:

### Kerberos Traffic From Unusual Processes

Kerberos communication over TCP/UDP port 88 initiated by non-standard processes such as Rubeus.exe should be investigated. Correlating this activity with process creation and PowerShell telemetry significantly improves confidence when detecting delegation abuse.

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Discovery | Domain Account Discovery | T1087.002 | Enumeration of domain accounts and delegation-enabled objects |
| Discovery | Domain Trust Discovery | T1482 | Discovery of Active Directory trust and domain relationships |
| Credential Access | Steal or Forge Kerberos Tickets | T1558 | Abuse or acquisition of Kerberos authentication tickets |
| Privilege Escalation | Pass-the-Ticket | T1550.003 | Reuse of Kerberos tickets to impersonate users and access delegated services |
| Lateral Movement | Pass-the-Ticket | T1550.003 | Authentication to remote services using stolen or delegated Kerberos tickets |

## IOC Summary

| IOC Type | Value |
|-----------|-------|
| PowerShell Keywords | `TrustedForDelegation`, `userAccountControl:1.2.840.113556.1.4.803:=524288`, `msDS-AllowedToDelegateTo` |
| Event IDs | `4104`, `3` |
| Network Ports | `88/TCP`, `88/UDP` |
| Tool | `Rubeus.exe` |
| Kerberos Extensions | `S4U2Self`, `S4U2Proxy` |
| Hosts | `BLUE.corp.local`, `DC01.corp.local` |
| Exercise Answer | `DC01.corp.local` |

## Placeholder Screenshots

### Figure 1. Unconstrained Delegation Configuration in Active Directory.

### Figure 2. PowerShell Enumeration of TrustedForDelegation. 

### Figure 3. Rubeus Ticket Granting Ticket (TGT) Request.

### Figure 4. Kerberos Authentication Flow With Unconstrained Delegation. 

### Figure 5. Splunk Detection of TrustedForDelegation Enumeration.

### Figure 6. Constrained Delegation Configuration in Active Directory.

### Figure 7. PowerShell Enumeration of msDS-AllowedToDelegateTo.

### Figure 8. Rubeus asktgt Execution.

### Figure 9. Rubeus S4U Delegation Abuse.

### Figure 10. Delegated Access to the Target Service.

### Figure 11. Kerberos S4U2Self and S4U2Proxy Workflow.

### Figure 12. Splunk Detection of Constrained Delegation Discovery.

### Figure 13. Splunk Detection of Kerberos Port 88 Activity.

### Figure 14. Investigation Results Identifying DC01.corp.local.

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Unconstrained Delegation | Systems configured for Unconstrained Delegation cache user TGTs, increasing the risk of credential theft and privilege escalation. |
| PowerShell Monitoring | PowerShell Script Block Logging (Event ID 4104) provides valuable visibility into delegation reconnaissance activity. |
| TrustedForDelegation | The `TrustedForDelegation` attribute is a primary indicator of Unconstrained Delegation enumeration. |
| Constrained Delegation | The `msDS-AllowedToDelegateTo` attribute identifies accounts configured for Constrained Delegation and should be monitored. |
| Kerberos Extensions | S4U2Self and S4U2Proxy enable delegated user impersonation without requiring the user's password. |
| Rubeus Detection | Rubeus frequently abuses delegation mechanisms through `asktgt` and `s4u` functionality. |
| Kerberos Network Monitoring | Monitoring Kerberos traffic over port 88 originating from non-standard processes improves detection of delegation abuse. |
| Attack Progression | Delegation reconnaissance frequently precedes Pass-the-Ticket, privilege escalation, and lateral movement within Active Directory environments. |

## Conclusion

This investigation demonstrated how Kerberos delegation reconnaissance and abuse can be detected by correlating PowerShell Script Block Logging, Active Directory delegation attributes, Sysmon telemetry, and Kerberos network activity within Splunk. Monitoring delegation-related attributes such as TrustedForDelegation and msDS-AllowedToDelegateTo, together with Rubeus execution and Kerberos communication over port 88, provides defenders with an effective methodology for identifying delegation abuse while improving investigative confidence and reducing false positives.


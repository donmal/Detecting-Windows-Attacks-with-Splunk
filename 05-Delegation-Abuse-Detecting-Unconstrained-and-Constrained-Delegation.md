# 05 - Delegation Abuse: Detecting Unconstrained and Constrained Delegation 

## Executive Summary 

This investigation examined Kerberos delegation reconnaissance and potential abuse within an Active Directory lab environment using Splunk. The analysis focused on PowerShell Script Block Logging (Event ID 4104), delegation-related Active Directory attributes, and Sysmon network telemetry.

PowerShell searches identified delegation-related activity on **BLUE.corp.local** and **DC01.corp.local**, with **DC01.corp.local** identified as the additional host of interest. A separate Sysmon search identified **Rubeus.exe** associated with network activity targeting Kerberos port 88.

These findings support investigation of delegation reconnaissance and potential post-enumeration activity, although the supplied evidence does not independently confirm successful Kerberos delegation abuse.

## Investigation Objectives

- Understand the differences between Unconstrained and Constrained Delegation.
  
- Detect PowerShell-based delegation reconnaissance.
  
- Identify hosts targeted during delegation enumeration.
  
- Investigate potential Kerberos delegation abuse using Splunk.
  
- Identify Rubeus activity related to S4U abuse.
  
- Correlate PowerShell, Sysmon and Kerberos telemetry.
  
- Map observed behavior to MITRE ATT&CK.

## Background 

### What is Unconstrained Delegation? 

Unconstrained Delegation is a Kerberos delegation mechanism that allows a service to impersonate users to any service within the Active Directory domain. 

When a user authenticates to an unconstrained delegation-enabled service under conditions that permit credential delegation, the service may receive access to a forwarded TGT, enabling it to request additional service tickets on the user's behalf.

If an attacker compromises such a system, cached TGTs may be stolen and reused for credential theft, privilege escalation, and subsequent Pass-the-Ticket attacks. 

### What is Constrained Delegation? 

Constrained Delegation restricts Kerberos delegation to a predefined list of services specified through the msDS-AllowedToDelegateTo attribute. 

In traditional constrained delegation configurations, delegated accounts are authorized to obtain service tickets for specified Service Principal Names (SPNs). Kerberos Service-for-User extensions, including S4U2Self and S4U2Proxy, can support delegated authentication depending on the account configuration.

Although significantly more secure than Unconstrained Delegation, misconfigured or compromised delegated accounts may still enable user impersonation and unauthorized access. 

### Key Differences

| Feature | Unconstrained Delegation | Constrained Delegation |
|---------|--------------------------|------------------------|
| Delegation Scope | Any service within the domain | Only explicitly authorized services |
| Active Directory Attribute | `TrustedForDelegation` | `msDS-AllowedToDelegateTo` |
| Ticket Handling | User TGT is cached | Service tickets requested through S4U |
| Kerberos Extensions | Forwarded user TGT may be available to the delegated service | `S4U2Self`, `S4U2Proxy` |
| Primary Abuse | TGT theft and reuse | User impersonation to specific services |
| Typical Attack Goal | Credential theft and domain compromise | Service impersonation and privilege escalation |
| Primary Detection Focus | TGT harvesting and delegation enumeration | S4U abuse and delegated service access |

## Delegation Attributes and Detection References

| Artifact | Description |
|----------|-------------|
| `TrustedForDelegation` | Active Directory property indicating Unconstrained Delegation |
| `userAccountControl = 524288` | The TrustedForDelegation bit value in the userAccountControl bitmask |
| `userAccountControl:1.2.840.113556.1.4.803:=524288` | LDAP matching rule used during delegation enumeration |
| `msDS-AllowedToDelegateTo` | Active Directory attribute identifying Constrained Delegation targets |
| `S4U2Self` | Kerberos extension used to obtain a service ticket on behalf of another user |
| `S4U2Proxy` | Kerberos extension used to request delegated service tickets |

**Technical note**: **524288** is a bit flag, not necessarily the complete **userAccountControl** value of an account. The LDAP matching rule checks whether the specified bit is set.

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

The investigation focused on PowerShell-based reconnaissance targeting Active Directory Kerberos delegation configurations. The analysis examined references to Unconstrained and Constrained Delegation attributes, identified hosts associated with enumeration activity, and reviewed Sysmon telemetry for potentially related Kerberos network connections.

## Investigation Methodology 

•  Review PowerShell Script Block Logging. 

•  Identify delegation-related LDAP attributes. 

•  Determine which hosts performed delegation enumeration. 

•  Investigate Constrained Delegation configurations. 

•  Correlate PowerShell activity with Kerberos network traffic. 

•  Identify potential Rubeus activity. 

•  Assess whether the observed behavior is consistent with Kerberos delegation abuse.

## Unconstrained Delegation Discovery

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

### Figure 11 - Unconstrained Delegation Discovery 

![Unconstrained Delegation PowerShell Analysis](../images/delegation-abuse-detecting-unconstrained-and-constrained-delegation/unconstrained-delegation-powershell.jpeg)

### Query Analysis: 

The search examines PowerShell Script Block Logging (Event ID 4104) for references to **TrustedForDelegation** or the corresponding **userAccountControl** LDAP matching rule.

The recorded results identified **BLUE.corp.local** and **DC01.corp.local** as hosts associated with these script block events. **DC01.corp.local** was identified as the additional host of interest.

These results indicate delegation-related PowerShell activity on the listed hosts, although the event content should be reviewed to distinguish actual LDAP queries from scripts that merely reference the relevant attributes.

## Constrained Delegation Discovery

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

The query searches PowerShell Script Block Logging (Event ID 4104) for references to **msDS-AllowedToDelegateTo**, an Active Directory attribute used in traditional Constrained Delegation configurations.

The recorded findings identify the attribute and the **Get-ADObject** enumeration method. Such activity may represent legitimate administration or reconnaissance intended to identify delegation-enabled accounts. The supplied results do not establish that the discovered configurations were subsequently abused.

## Kerberos Network Activity and Rubeus Investigation

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

### Figure 12 - Kerberos Network Activity and Rubeus Investigation

![Kerberos Network Activity](../images/credentials-abuse-attack-detection/overpass-the-hash-kerberos-process-correlation.png)

### Query Analysis: 

The search identifies Sysmon network connections targeting destination port 88 and attempts to associate those connections with process information.

The recorded results identified **Rubeus.exe** in Kerberos-related network activity. While this is relevant to further investigation, a network connection to port 88 does not independently establish that S4U2Self or S4U2Proxy operations occurred.

## Investigation Findings

PowerShell Script Block Logging identified activity referencing both Unconstrained and Constrained Delegation configurations. Event ID 4104 searches returned references to **TrustedForDelegation**, the corresponding **userAccountControl** LDAP matching rule, and **msDS-AllowedToDelegateTo**.

The recorded results identified **BLUE.corp.local** and **DC01.corp.local** as hosts associated with delegation-related PowerShell activity, with DC01.corp.local identified as the additional host.

The Constrained Delegation search identified references to **msDS-AllowedToDelegateTo**, an attribute used to define permitted delegation targets. Such enumeration can be relevant to reconnaissance, although no successful S4U impersonation was established by the supplied findings.

A separate Sysmon investigation identified **Rubeus.exe** associated with network connections targeting Kerberos port 88. The available results provide an additional investigative lead but do not establish that this activity was causally connected to the earlier delegation enumeration.

## Detection Logic

### TrustedForDelegation Enumeration

PowerShell commands querying the `TrustedForDelegation` attribute frequently indicate reconnaissance targeting systems configured for Unconstrained Delegation. A commonly observed command is:

```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
```
References to this command or attribute in Event ID 4104 can identify delegation discovery activity, but legitimate administrative scripts may produce similar telemetry.

### userAccountControl LDAP Search

Searches using the LDAP matching rule 1.2.840.113556.1.4.803:=524288 identify accounts configured for Unconstrained Delegation. 

Detection of this filter within PowerShell or LDAP query content provides a useful indication of delegation-related enumeration and should be evaluated against the executing account and process context.

### msDS-AllowedToDelegateTo Enumeration

Enumeration of the msDS-AllowedToDelegateTo attribute reveals accounts authorized for Constrained Delegation. 

This activity can be relevant to attacker reconnaissance but may also occur during legitimate Active Directory administration and security assessments.

### Potential Rubeus S4U Activity

Rubeus execution involving **asktgt** or **s4u** functionality can provide useful evidence during investigations of Kerberos delegation abuse. Command-line arguments such as **/impersonateuser**, **/msdsspn**, or **/altservice** may provide additional context if they are observed in process creation telemetry.

The documented investigation identified **Rubeus.exe** in network-related results but did not provide command-line evidence confirming that these S4U arguments were executed.

### Kerberos Traffic From Unusual Processes

Kerberos communication over TCP/UDP port 88 initiated by non-standard processes such as Rubeus.exe should be investigated. 

Correlating this activity with process creation and PowerShell telemetry can improve investigative context, although additional evidence is required to establish actual delegation abuse.

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Discovery | Domain Account Discovery | T1087.002 | Enumeration of domain accounts and delegation-enabled objects |

**Mapping note**: T1087.002 is relevant to the documented Active Directory account and delegation discovery activity. T1482 (Domain Trust Discovery) is not supported by the supplied queries, which focus on delegation attributes rather than domain trust relationships.

The supplied results also do not establish ticket theft, forged ticket creation, or Pass-the-Ticket execution. Therefore, T1558 and T1550.003 should not be presented as confirmed observed techniques in this investigation.

## Investigation Artifacts and Detection References

| IOC Type | Value |
|-----------|-------|
| PowerShell Keywords | `TrustedForDelegation`, `userAccountControl:1.2.840.113556.1.4.803:=524288`, `msDS-AllowedToDelegateTo` |
| Event IDs | `4104`, `3` |
| Network Ports | `88/TCP`, `88/UDP` |
| Tool | `Rubeus.exe` |
| Hosts | `BLUE.corp.local`, `DC01.corp.local` |

**Investigation finding**: **DC01.corp.local** was identified as the additional host associated with delegation-related PowerShell activity.

These values are investigation artifacts and detection references, not confirmed IOCs. S4U2Self and S4U2Proxy were discussed as relevant techniques but were not directly demonstrated in the supplied event results.

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Unconstrained Delegation | Systems configured for Unconstrained Delegation may receive forwarded user TGTs, increasing the risk of credential theft and privilege escalation. |
| PowerShell Monitoring | PowerShell Script Block Logging (Event ID 4104) provides valuable visibility into delegation reconnaissance activity. |
| TrustedForDelegation | The `TrustedForDelegation` attribute is a primary indicator of Unconstrained Delegation enumeration. |
| Constrained Delegation | The `msDS-AllowedToDelegateTo` attribute identifies accounts configured for Constrained Delegation and should be monitored. |
| Kerberos Extensions | S4U2Self and S4U2Proxy enable delegated user impersonation without requiring the user's password. |
| Rubeus Detection | Rubeus can interact with delegation mechanisms through `asktgt` and `s4u` functionality. |
| Kerberos Network Monitoring | Monitoring Kerberos traffic over port 88 originating from non-standard processes provides additional context for investigating potential delegation abuse. |
| Attack Progression | Delegation reconnaissance can precede credential abuse or unauthorized service access, although no such progression was confirmed in the documented results. |

## Conclusion

This investigation demonstrated how Splunk can be used to identify PowerShell activity associated with Active Directory Kerberos delegation reconnaissance. Analysis of Event ID 4104 identified references to **TrustedForDelegation**, the corresponding **userAccountControl** LDAP matching rule, and **msDS-AllowedToDelegateTo**.

The investigation identified **BLUE.corp.local** and **DC01.corp.local** in the delegation-related results, with **DC01.corp.local** highlighted as the additional host. Separate Sysmon analysis identified **Rubeus.exe** associated with Kerberos port 88 activity.

These findings illustrate a structured approach to investigating delegation discovery and potentially related Kerberos activity. Although successful delegation abuse was not confirmed by the supplied telemetry, the documented searches provide useful detection opportunities for SOC threat hunting and further investigation.

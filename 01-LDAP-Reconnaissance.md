# 01 - LDAP Reconnaissance - Detecting LDAP Reconnaissance with Splunk

## Executive Summary

This investigation focuses on detecting Active Directory reconnaissance activity through LDAP query monitoring in Splunk.

Active Directory reconnaissance is one of the earliest and most important stages of an enterprise intrusion. Before attackers can escalate privileges, move laterally, perform Kerberoasting, abuse delegation, or attempt domain compromise, they usually need to understand the domain structure.

During this phase, adversaries commonly enumerate:

•	Domain users
•	Domain groups
•	Domain administrators
•	Computers
•	Service accounts
•	Organizational Units
•	Group Policy Objects
•	Trust relationships
•	Privileged accounts
•	Attack paths

This investigation examined LDAP query activity captured through SilkService logs and identified processes that performed LDAP searches containing the filter:

*(samAccountType=805306368)*

This filter is commonly associated with domain user enumeration.

The investigation identified multiple processes issuing LDAP queries containing the user enumeration filter *(samAccountType=805306368)*. Among the observed processes, **rundll32.exe** was identified as an unusual source of LDAP reconnaissance activity.

## Investigation Objectives

The objectives of this investigation were:
•	Understand how Active Directory reconnaissance is performed.
•	Identify LDAP-based reconnaissance activity.
•	Detect processes issuing suspicious LDAP queries.
•	Use Splunk to analyze SilkService LDAP telemetry.
•	Identify all process names associated with user enumeration LDAP filters.
•	Identify processes issuing LDAP user enumeration queries.
•	Map the observed activity to MITRE ATT&CK.
•	Document detection opportunities for SOC use.

## Background

### What Is Active Directory Reconnaissance?

Active Directory reconnaissance is the process of collecting information about a Windows domain environment.

Attackers perform reconnaissance to answer questions such as:
Who are the Domain Admins?

Which users exist in the domain?

Which machines are joined to the domain?

Which accounts have elevated privileges?

Which systems can be used for lateral movement?

Which paths lead to domain compromise?
This information helps attackers plan the next stages of an intrusion.

### Native Windows Reconnaissance

Attackers do not always need malware or offensive tools to perform reconnaissance.

Many useful commands already exist on Windows systems.

Examples include:

whoami /all
wmic computersystem get domain
net user /domain
net group "Domain Admins" /domain
arp -a
nltest /domain_trusts

Native Windows utilities are frequently used for reconnaissance because they are trusted, Microsoft-signed, and readily available on domain-joined systems.

### Example: Domain Admin Enumeration

A commonly observed reconnaissance command is:

net group "Domain Admins" /domain

This command queries Active Directory for members of the Domain Admins group, providing attackers with a list of high-value privileged accounts.

### Screenshot Placeholder

Insert Screenshot Here

Caption:

Figure 1 – Native Windows command used to enumerate Domain Admins.

## BloodHound and SharpHound Reconnaissance

### What Is BloodHound?

BloodHound is an Active Directory attack path analysis tool.
It uses graph theory to visualize relationships between:

•	Users
•	Groups
•	Computers
•	Sessions
•	Permissions
•	ACLs
•	Trusts
•	Delegation paths

Attackers use BloodHound to identify privilege escalation and lateral movement paths.

### What Is SharpHound?

SharpHound is the data collector used by BloodHound.

It collects Active Directory data and exports it for BloodHound analysis.

Example execution:

.\SharpHound.exe -c all

This collects a broad set of domain information, including:

•	Group memberships
•	Sessions
•	Logged-on users
•	ACLs
•	Trusts
•	Object properties
•	Local administrators

### Screenshot Placeholder

Insert Screenshot Here

Caption:

Figure 2 – BloodHound graph showing Active Directory relationships and attack paths.

### Screenshot Placeholder

Insert Screenshot Here

Caption:

Figure 3 – SharpHound executed with all collection methods.

## Why LDAP Matters

Under the hood, many AD reconnaissance tools perform LDAP queries.

LDAP stands for:

Lightweight Directory Access Protocol

It is used to query directory services such as Active Directory.

LDAP provides direct access to Active Directory objects, allowing users, groups, computers, service accounts and other directory objects to be enumerated through structured search queries.

## LDAP Search Filters

LDAP queries rely on search filters that define which directory objects should be returned. One of the most common filters used during user enumeration is:

`(samAccountType=805306368)`

This value corresponds to standard domain user accounts. Consequently, LDAP queries containing the filter `*(samAccountType=805306368)*` may indicate Active Directory user enumeration activity.

## Why This Filter Is Important

The filter:

samAccountType=805306368

is commonly used to search for user objects in Active Directory.

Tools such as:

•	SharpHound
•	PowerView
•	Empire
•	Custom LDAP recon tools
•	LOLBIN-based tradecraft

may generate LDAP queries containing this filter

## Detection Challenge

By default, Windows does not reliably log all LDAP queries.

Some visibility can come from:

Event ID 1644
LDAP Diagnostic Logging

Although Event ID 1644 can provide LDAP visibility, comprehensive telemetry is more reliably obtained through the Microsoft-Windows-LDAP-Client ETW Provider. In this investigation, LDAP events were collected using SilkService and analyzed in Splunk.

## Data Source

| Source | Value |
|---------|-------|
| Splunk Index | main |
| Event Source | WinEventLog:SilkService-Log |
| Telemetry | Microsoft-Windows-LDAP-Client ETW |

### Relevant Fields

| Field |
|-------|
| ComputerName |
| ProcessName |
| ProcessId |
| DistinguishedName |
| SearchFilter |

## Investigation Scope

The investigation focused on identifying processes issuing LDAP queries containing the user enumeration filter *(samAccountType=805306368)* and determining whether unexpected processes were performing Active Directory reconnaissance.

## Investigation Methodology

The investigation involved executing a Splunk search across the complete dataset, filtering LDAP queries containing the target SearchFilter value, and grouping the results by ProcessName to identify all processes performing user enumeration.

## Splunk Search Used

```spl
index=main source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| sort 0 _time
| search SearchFilter="*(samAccountType=805306368)*"
| stats count by ProcessName
``` 

### Query Breakdown

#### Index and Source

index=main source="WinEventLog:SilkService-Log"

This searches LDAP telemetry collected by SilkService.

#### Extract Structured Fields 

| spath input=Message

This extracts structured data from the Message field.

#### Rename XML Fields 

| rename XmlEventData.* as *

This removes the XmlEventData. prefix from fields to make them easier to use.

#### Select Relevant Fields 

| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter

This displays the fields needed for investigation.

#### Sort Events 

| sort 0 _time

This sorts all matching events by time.

#### Search for User Enumeration LDAP Filter 

| search SearchFilter="*(samAccountType=805306368)*"

This filters LDAP searches containing the user enumeration filter.

#### Group by Process Name 

| stats count by ProcessName

This summarizes which processes issued the LDAP queries.

## Investigation Findings 

The Splunk results returned the following process names:

N/A
Rubeus
SharpHound
mmc
powershell
rundll32

The investigation identified the following processes performing LDAP user enumeration:

- N/A
- Rubeus
- SharpHound
- mmc
- powershell
- rundll32

Among these, **rundll32.exe** represented the most unusual process and warranted further investigation.

## Why rundll32 Is Interesting

rundll32.exe is a legitimate Windows binary used to execute functions exported from DLL files.

Attackers frequently abuse it because it is:

•	Native to Windows
•	Microsoft-signed
•	Common in enterprise environments
•	Often trusted by security controls
•	Useful for proxy execution

Seeing rundll32 associated with LDAP reconnaissance is suspicious because it suggests LDAP enumeration may have been performed through a proxy execution technique rather than a normal administrative tool.

## Forensic Interpretation

The observed activity indicates that rundll32.exe issued LDAP queries containing the domain user enumeration filter *(samAccountType=805306368)*. Although this behaviour alone does not confirm malicious activity, it represents a high-value threat hunting lead because rundll32.exe is frequently abused as a Living-off-the-Land Binary (LOLBIN).

## Attack Chain Context

This activity belongs to the reconnaissance phase.

In an AD attack lifecycle, it may precede:

LDAP Reconnaissance
        ↓
SPN Enumeration
        ↓
Kerberoasting
        ↓
Credential Theft
        ↓
Pass-the-Hash / Pass-the-Ticket
        ↓
Delegation Abuse
        ↓
DCSync / Domain Compromise

## Screenshot Placeholders

### Figure 1. Native Windows command used to enumerate Domain Admins.

Native command used to enumerate Domain Admins.

[INSERT SCREENSHOT]

### Figure 2. BloodHound graph illustrating Active Directory attack paths.

BloodHound graph showing AD attack paths.

[INSERT SCREENSHOT]

### Figure 3. SharpHound executed using the ‘-c all’ collection method.

SharpHound execution with -c all.

[INSERT SCREENSHOT]

### Figure 4. SharpHound source code showing LDAP search filters.

SharpHound LDAP filters visible in code.

[INSERT SCREENSHOT]

### Figure 5. LDAP Event ID 1644 displaying the LDAP search filter. 

LDAP Event 1644 showing LDAP search filter.

[INSERT SCREENSHOT]

### Figure 6. SilkService capturing LDAP client telemetry through ETW.

SilkETW / SilkService capturing LDAP telemetry.

[INSERT SCREENSHOT]

### Figure 7. Reference table of common LDAP reconnaissance filters. 

Reference table of LDAP reconnaissance filters.

[INSERT SCREENSHOT]

### Figure 8. Splunk search detecting native Active Directory reconnaissance commands. 

Splunk query detecting native reconnaissance commands.

[INSERT SCREENSHOT]

### Figure 9. Splunk search identifying LDAP reconnaissance activity.

Splunk query detecting BloodHound-style LDAP activity.

[INSERT SCREENSHOT]

### Figure 10. Splunk Search & Reporting interface used during the investigation.

Splunk Search & Reporting interface.

[INSERT SCREENSHOT]

### Figure 11. Final Splunk search results identifying ‘rundll32.exe’.

Final Splunk result showing rundll32.

[INSERT SCREENSHOT]

## Detection Opportunities

### Detect LDAP User Enumeration

Search for:

samAccountType=805306368

in LDAP SearchFilter fields.

### Detect Suspicious Processes Performing LDAP Queries

Prioritize unusual process names such as:

rundll32
regsvr32
powershell
cmd
wscript
cscript
mshta

### Detect High-Volume LDAP Queries

A single query may be normal.

Repeated LDAP queries from the same process should be investigated.

Example logic:

| stats count by ComputerName, ProcessName, ProcessId
| where count > 10

### Detect SharpHound Behavior

Look for multiple LDAP filters associated with:

•	Users
•	Groups
•	Computers
•	ACLs
•	Trusts
•	Sessions
•	SPNs

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Discovery | Account Discovery | T1087 | Enumerating user accounts through LDAP queries |
| Discovery | Domain Account Discovery | T1087.002 | Identifying domain user accounts |
| Discovery | Permission Groups Discovery | T1069 | Discovering security and permission groups |
| Discovery | Domain Groups | T1069.002 | Enumerating Active Directory group memberships |
| Discovery | Remote System Discovery | T1018 | Discovering systems within the domain environment |
| Discovery | Domain Trust Discovery | T1482 | Identifying trust relationships between Active Directory domains |

## Key Findings

| Finding | Summary |
|---------|---------|
| LDAP Telemetry | SilkService provided visibility into LDAP client activity. |
| Search Filter Analysis | LDAP `SearchFilter` values were used to identify domain user enumeration. |
| Splunk Investigation | Splunk grouped LDAP activity by `ProcessName` to identify participating processes. |
| Reconnaissance Activity | Multiple legitimate administrative tools performed LDAP queries. |
| Suspicious Process | `rundll32.exe` represented the most unusual process observed during the investigation. |
| Detection Value | LDAP search filters provide valuable behavioral indicators for detecting Active Directory reconnaissance. |

## Conclusion

This investigation demonstrated how LDAP telemetry can be used to detect Active Directory reconnaissance activity.

By focusing on LDAP search filters rather than only process creation events, analysts can identify domain enumeration activity generated by tools such as SharpHound, Rubeus, PowerShell, MMC, and suspicious LOLBINs such as rundll32.

The key lesson is that Active Directory reconnaissance often leaves clear LDAP search patterns. When those patterns are associated with unusual processes, they become valuable detection leads for SOC analysts and threat hunters.

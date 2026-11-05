# 02 - 02-Kerberoasting and AS-REP Roasting

## Executive Summary 

This investigation focused on detecting Kerberoasting and AS-REP Roasting activity using Splunk by analyzing LDAP reconnaissance, Kerberos authentication events, and Sysmon process telemetry. The investigation reconstructed the attack sequence by correlating LDAP queries, process creation events, and user attribution to identify the account responsible for initiating Kerberoasting reconnaissance.

## Investigation Objectives 

- Detect LDAP reconnaissance targeting Service Principal Names (SPNs).
- Identify the process responsible for issuing LDAP queries.
- Correlate LDAP activity with Sysmon Process Creation events.
- Attribute reconnaissance activity to the originating user.
- Identify detection opportunities for Kerberoasting and AS-REP Roasting.
- Map observed behavior to MITRE ATT&CK.

## Background

### Kerberoasting

Kerberoasting is a credential access technique in which attackers enumerate Service Principal Names (SPNs), request Kerberos service tickets (TGS), and perform offline password cracking against the encrypted ticket material.

### AS-REP Roasting

AS-REP Roasting targets user accounts that do not require Kerberos pre-authentication. Attackers request AS-REP responses directly from the Key Distribution Center (KDC) and attempt offline password cracking without authenticating first.

### MITRE ATT&CK Mapping

| Technique | ATT&CK ID |
|-----------|-----------|
| Kerberoasting | T1558.003 |
| AS-REP Roasting | T1558.004 |
| Domain Account Discovery | T1087.002 |

## Data Sources

| Source | Purpose |
|---------|----------|
| Splunk Index (main) | LDAP and Sysmon telemetry |
| SilkService | LDAP client telemetry |
| Sysmon Event ID 1 | Process Creation |
| Security Event ID 4768 | Kerberos Authentication |
| Security Event ID 4769 | Kerberos Service Ticket Requests |

## Investigation Scope 

The investigation focused on identifying LDAP queries containing the Service Principal Name (SPN) enumeration filter and correlating the resulting Process Identifier (PID) with Sysmon Process Creation events to determine the originating user.
 
## Investigation Methodology

The investigation followed a structured correlation process:

1. Identify LDAP queries containing the SPN enumeration filter.
2. Extract the associated Process Identifier (PID).
3. Correlate the PID with Sysmon Process Creation (Event ID 1).
4. Attribute the activity to the originating user account. 

## Investigation Artifact

The primary artifact examined during this investigation was the LDAP search filter:

`(&(samAccountType=805306368)(servicePrincipalName=*))`

This filter is commonly associated with Service Principal Name (SPN) enumeration, a reconnaissance technique frequently observed prior to Kerberoasting attacks. Successful enumeration enables attackers to identify Kerberos-enabled service accounts that can subsequently be targeted through TGS requests and offline password cracking.

## Investigation Query #1

### Purpose: 

Identify the Process Identifier (PID) responsible for issuing the LDAP query containing the SPN enumeration filter. 

### SPL: 

```spl
index=main source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time ComputerName ProcessName DistinguishedName SearchFilter PID
| search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
```

### Results:

| Field | Value |
|--------|-------|
| Timestamp | 2023-07-26 16:42:44 |
| Process Identifier (PID) | 7136 |

## Investigation Query #2

### Purpose: 

Correlate the identified Process Identifier (PID) with Sysmon Process Creation events.

### SPL: 

```spl
index=main 7136 EventCode=1
| table User
```

### Results:

| Field | Value |
|--------|-------|
| Originating User | CORP\LANDON_HINES |

## Investigation Findings

The investigation identified an LDAP query containing the Service Principal Name (SPN) enumeration filter.

Correlation between LDAP telemetry and Sysmon Process Creation events revealed:

| Artifact | Value |
|----------|-------|
| LDAP Filter | (&(samAccountType=805306368)(servicePrincipalName=*)) |
| Process Identifier (PID) | 7136 |
| Originating User | CORP\LANDON_HINES |

## Detection Logic

### Indicator #1: LDAP SPN Enumeration

LDAP queries containing the filter:

`servicePrincipalName=*`

should be monitored because they frequently indicate SPN enumeration performed prior to Kerberoasting attacks.

Common tools include:

-	Rubeus
-	PowerView
-	SharpView
-	BloodHound

### Indicator #2: Kerberos Service Ticket Monitoring 

Investigate Event ID 4769 occurring without corresponding Event ID 4624 or Event ID 4648 authentication activity, as this may indicate Kerberoasting.

### Indicator #3: TGS Request Bursts 

Monitor excessive Event ID 4769 activity targeting service accounts such as:

-	MSSQLSvc/*
-	HTTP/*
-	CIFS/*
-	HOST/*

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Discovery | Domain Account Discovery | T1087.002 | Enumerating Kerberos-enabled accounts |
| Credential Access | Kerberoasting | T1558.003 | Kerberos service ticket abuse |
| Credential Access | AS-REP Roasting | T1558.004 | Offline password cracking without pre-authentication |

## IOC Summary

| IOC Type | Value |
|-----------|-------|
| LDAP Filter | (&(samAccountType=805306368)(servicePrincipalName=*)) |
| Event IDs | 4768, 4769, 4624, 4648 |
| Process | Rubeus.exe |
| Originating User | CORP\LANDON_HINES |
| Process Identifier (PID) | 7136 |

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| LDAP SearchFilter Analysis | LDAP search filters frequently reveal reconnaissance activity before Kerberoasting begins. |
| PID Correlation | Process identifiers provide the bridge between LDAP telemetry and Sysmon Process Creation events. |
| Kerberos Monitoring | Event ID 4769 without corresponding logon events is a strong Kerberoasting indicator. |
| AS-REP Detection | Event ID 4768 with `Pre_Authentication_Type = 0` provides a reliable indicator of AS-REP Roasting. |
| Event Correlation | Combining LDAP, Security and Sysmon telemetry significantly improves attribution accuracy. |

## Conclusion

This investigation demonstrated how Splunk can be used to detect Kerberoasting and AS-REP Roasting by correlating LDAP reconnaissance, Kerberos authentication events, and Sysmon process telemetry. Combining LDAP search filters, process identifiers, and user attribution provides defenders with high-confidence visibility into credential access attacks while improving threat hunting and detection engineering capabilities.

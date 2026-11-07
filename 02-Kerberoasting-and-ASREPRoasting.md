# 02 - 02-Kerberoasting and AS-REP Roasting

## Executive Summary 

This investigation focused on identifying LDAP reconnaissance activity associated with potential Kerberoasting attacks using Splunk. By analyzing SilkService LDAP telemetry and correlating process identifiers with Sysmon Process Creation events, the investigation identified the user account associated with Service Principal Name (SPN) enumeration.

The analysis identified an LDAP query containing an SPN enumeration filter, associated with Process Identifier (PID) 7136 and user account **CORP\LANDON_HINES**. These findings provide evidence of reconnaissance activity relevant to Kerberoasting, although subsequent service ticket requests, offline password cracking, and AS-REP Roasting were not confirmed by the documented results.

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

Although both techniques target Kerberos authentication, this investigation's documented evidence primarily concerns SPN enumeration, which can precede Kerberoasting.

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

Security Event IDs 4768 and 4769 are relevant to Kerberos attack detection; however, the documented investigation queries directly demonstrate the use of SilkService and Sysmon telemetry rather than analysis of these Kerberos Security events.

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

## LDAP SPN Enumeration Analysis

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

The search identified LDAP activity containing the SPN enumeration filter and associated it with PID 7136. This process identifier was subsequently used to investigate the originating execution context.

## Sysmon Process Correlation and User Attribution

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

The Sysmon search returned **CORP\LANDON_HINES** as the user associated with the matching process creation telemetry. This provided an attribution lead connecting the LDAP reconnaissance activity to a domain user account.

**Correlation limitation**: The documented Sysmon query searches for the value 7136 across Event ID 1 records but does not explicitly match the ProcessId field or correlate the process creation timestamp with the LDAP event. Additional validation would strengthen confidence in the attribution.

## Investigation Findings

The investigation identified an LDAP query containing the Service Principal Name (SPN) enumeration filter.

Correlation between LDAP telemetry and Sysmon Process Creation events revealed:

| Artifact | Value |
|----------|-------|
| LDAP Filter | (&(samAccountType=805306368)(servicePrincipalName=*)) |
| Process Identifier (PID) | 7136 |
| Originating User | CORP\LANDON_HINES |

The findings establish an SPN enumeration lead and identify a potentially associated user account. The available results do not independently establish that a Kerberos service ticket was requested, that password cracking occurred, or that AS-REP Roasting was performed.

## Detection Logic

### Indicator #1: LDAP SPN Enumeration

LDAP queries containing the filter:

`servicePrincipalName=*`

should be monitored because they frequently indicate SPN enumeration performed prior to Kerberoasting attacks.

The filter should be evaluated alongside process identity, execution context, query frequency, and subsequent Kerberos authentication activity to distinguish legitimate directory searches from suspicious reconnaissance.

### Indicator #2: Kerberos Service Ticket Monitoring 

Monitor Windows Security Event ID 4769 for unusual Kerberos service ticket requests, including abnormal request volumes, unexpected service accounts, and suspicious ticket encryption types. The absence of nearby Event ID 4624 or 4648 records is not sufficient by itself to establish Kerberoasting.

This represents a proposed detection opportunity rather than a finding validated by the documented Splunk queries.

### Indicator #3: TGS Request Bursts 

Monitor excessive Event ID 4769 activity targeting service accounts such as:

-	MSSQLSvc/*
-	HTTP/*
-	CIFS/*
-	HOST/*

Repeated TGS requests across multiple SPNs within a short time window may warrant investigation, particularly when correlated with earlier SPN enumeration. Legitimate applications can also generate frequent service ticket requests, so detection thresholds should be established against normal activity.

## Indicator #4: AS-REP Roasting Detection 

Monitor Security Event ID 4768 for Kerberos authentication requests involving accounts that do not require pre-authentication. Relevant indicators include **PreAuthType = 0**, the account's pre-authentication configuration, and unusual request patterns.

A pre-authentication value of zero alone does not confirm AS-REP Roasting. Additional account and authentication context is required. No AS-REP Roasting events were documented in the investigation results.

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Discovery | Domain Account Discovery | T1087.002 | Enumerating Kerberos-enabled accounts |

The observed LDAP SPN enumeration activity supports mapping to T1087.002 (Domain Account Discovery). Kerberoasting (T1558.003) and AS-REP Roasting (T1558.004) remain relevant detection scenarios but are not confirmed by the documented investigation evidence.

## Investigation Artifacts and Detection References

| IOC Type | Value |
|-----------|-------|
| LDAP Filter | (&(samAccountType=805306368)(servicePrincipalName=*)) |
| Originating User | CORP\LANDON_HINES |
| Process Identifier (PID) | 7136 |

**Detection Reference Events**: Security Event IDs 4768 and 4769 can support further investigation of AS-REP Roasting and Kerberoasting respectively. Events 4624 and 4648 provide additional authentication context but were not demonstrated as findings in the documented searches.

The LDAP filter, user account, and PID are investigation artifacts rather than standalone Indicators of Compromise (IOCs). Their significance depends on the surrounding activity and execution context.

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| LDAP SearchFilter Analysis | LDAP search filters frequently reveal reconnaissance activity before Kerberoasting begins. |
| PID Correlation | Process identifiers provide the bridge between LDAP telemetry and Sysmon Process Creation events. |
| Event Correlation | Combining LDAP, Security and Sysmon telemetry significantly improves attribution accuracy. |

**Kerberos Monitoring**: Event ID 4769 can help detect suspicious service ticket request patterns when correlated with LDAP reconnaissance and appropriate authentication context.

**AS-REP Detection**: Event ID 4768, combined with pre-authentication configuration and request context, can help identify potential AS-REP Roasting attempts.

**Attribution Accuracy**: PID-based correlation should be validated using process identity, host information, and timestamps to avoid incorrect attribution caused by PID reuse or unrelated search matches.

## Conclusion

This investigation demonstrated how Splunk can be used to identify LDAP SPN enumeration activity associated with potential Kerberoasting reconnaissance. Analysis of SilkService telemetry identified an SPN enumeration filter and PID 7136, while a subsequent Sysmon search returned the associated user account **CORP\LANDON_HINES**.

The investigation highlighted the value of correlating LDAP search filters with endpoint process telemetry to support user attribution and identify suspicious Active Directory reconnaissance. Further analysis of Kerberos Security events, including Event IDs 4768 and 4769, would be required to investigate potential AS-REP Roasting and Kerberoasting activity beyond the observed enumeration stage.

# 04 - Kerberos Ticket Forgery Investigation 

## Executive Summary 

This investigation examined authentication anomalies potentially associated with Kerberos ticket forgery in an Active Directory lab environment using Splunk. The analysis focused on user baseline validation, Windows Security events, explicit credential usage, privilege assignments, and service-specific authentication activity.

The investigation introduces the two primary Kerberos ticket forgery techniques—Golden Ticket and Silver Ticket—and demonstrates how multiple Windows Security events can be correlated to identify authentication behavior consistent with forged Kerberos tickets.

The practical investigation focused on a suspected Silver Ticket scenario. A baseline comparison identified the account Barbi on **SQLSERVER.corp.local**, and subsequent analysis examined Event IDs 4624, 4634, 4648, and 4672, including a recorded reference to the CIFS service.

## Investigation Objectives 

•  Understand the differences between Golden Ticket and Silver Ticket attacks. 

•  Identify authentication artifacts associated with forged Kerberos tickets. 

•  Detect suspicious Kerberos authentication activity using Splunk. 

•  Compare observed users against an established authentication baseline. 

•  Identify previously unseen or anomalous user accounts. 

•  Correlate Windows Security events, user activity, and privilege assignments to support attribution. 

•  Identify the service targeted by a suspected forged Kerberos ticket. 

•  Map observed behavior to the MITRE ATT&CK framework.

## Background 

### Golden Ticket vs Silver Ticket 

| Feature | Golden Ticket | Silver Ticket |
|---------|---------------|---------------|
| **Forged Ticket** | Ticket Granting Ticket (TGT) | Service Ticket (TGS) |
| **Compromised Secret** | KRBTGT account hash | Service or computer account hash |
| **Authentication Scope** | Potentially broad domain access, depending on the forget ticket and privileges | Specific service only |
| **Typical Target** | Domain Controllers and domain resources | Individual Kerberos-enabled services (e.g., CIFS, MSSQL, HTTP) |
| **KDC Communication** | Forged TGTs are typically presented to the KDC to request service tickets | Often bypassed after ticket creation because some services validate tickets locally |
| **Persistence** | May enable continued access while the compromised key remains usable | May enable repeated access to the affected service |
| **Detection Focus** | KRBTGT compromise, abnormal TGT activity, privileged authentication anomalies | Service-specific authentication, SPN usage and user anomalies |

### Key Detection Artifacts

#### Golden Ticket Detection Artifacts 

•	KRBTGT compromise 

•	DCSync activity 

•	LSASS access on Domain Controllers 

•	NTDS.dit extraction 

•	Abnormal Kerberos ticket issuance 

•	Privileged authentication anomalies

#### Silver Ticket Detection Artifacts 

•	Service-specific authentication 

•	Unknown or non-baselined users 

•	Authentication anomalies, including Event ID 4648 (Explicit Credentials) where relevant to the investigated activity

•	Privileged logon context from Event ID 4672 (Special Privileges Assigned) 

•	Service Principal Names (SPNs) 

•	Target service correlation 

These artifacts provide investigation context rather than definitive indicators of ticket forgery. Event IDs 4648 and 4672 can occur during legitimate authentication and administrative activity.

## Why Silver Tickets Are Difficult to Detect 

Silver Ticket attacks are often more difficult to detect than Golden Ticket attacks because the forged Ticket Granting Service (TGS) is created using a compromised service account hash rather than the KRBTGT account hash. Since many services validate Kerberos service tickets locally, authentication may occur without contacting the Key Distribution Center (KDC), resulting in fewer Kerberos authentication events and reduced visibility in domain controller logs. As a result, defenders must rely on behavioral indicators such as anomalous service access, explicit credential usage, privilege assignments, Service Principal Name (SPN) analysis, and deviations from established authentication baselines rather than individual Kerberos events alone.

This makes service-side authentication telemetry, unusual account activity, SPN analysis, and correlation with available endpoint evidence important during investigations of suspected forged service tickets.

## MITRE ATT&CK Mapping (Background) 

| Technique | ATT&CK ID |
|-----------|-----------|
| Golden Ticket | T1558.001 |
| Silver Ticket | T1558.002 |

## Data Sources 

| Source | Purpose |
|---------|----------|
| Splunk Index (`main`) | Centralized collection and analysis of Windows event data |
| Windows Security Logs | Kerberos authentication, logon, and privilege events |
| Lookup Table (`users.csv`) | Baseline user validation |
| Event ID 4624 | Successful logon detection |
| Event ID 4648 | Explicit credential logon analysis |
| Event ID 4672 | Privileged logon identification |
| Service Principal Names (SPNs) | Identification of targeted Kerberos services |

**Additional observed event**: Event ID 4634 (Logoff) was returned by the second investigation query.

The documented SPL searches directly use Event ID 4624 and subsequently identify Events 4634, 4648, and 4672. Although Kerberos Events 4768, 4769, and 4770 are relevant to ticket investigations, the supplied queries do not demonstrate analysis of those event IDs.

## Investigation Scope 

The investigation focused on identifying unusual authentication activity that could warrant further analysis for potential Silver Ticket abuse. The practical workflow compared successful logons against a user baseline, identified an unexpected account, examined related Windows Security events, and investigated the service associated with the recorded authentication activity.

## Investigation Methodology 

The investigation followed a structured correlation process designed to identify authentication activity consistent with a forged Kerberos service ticket:

1.	Import the baseline user list into Splunk for user validation.
   
2.	Compare observed authentication activity against the established baseline.
   
3.	Identify newly observed or anomalous user accounts.
   
4.	Validate successful authentication events associated with suspicious users.
   
5.	Correlate related Windows Security Events, including explicit credential usage and privilege assignments.
   
6.	Identify the service accessed during the authentication sequence.
   
7.	Assess whether the observed authentication pattern is consistent with the use of a forged Silver Ticket.

## Baseline Validation and Anomalous User Identification   

### Purpose:

Identify successful logons performed by users who are not present in the expected baseline by comparing authentication events against the imported users.csv lookup table.

### SPL:

```spl 
index=main latest=1690545656 EventCode=4624
| stats min(_time) as firstTime values(ComputerName) as ComputerName values(EventCode) as EventCode by user
| eval last24h=1690451977
| where firstTime > last24h
| convert ctime(firstTime)
| convert ctime(last24h)
| lookup users.csv user as user OUTPUT EventCode as Events
| where isnull(Events)
```
### Results:

| Field | Value |
|--------|-------|
| Suspicious User | `Barbi` |
| Computer | `SQLSERVER.corp.local` |

### Figure 8 - Baseline Validation and Anomalous User Identification 

![Silver Ticket Baseline Validation](../images/kerberos-ticket-forgery-investigation/silver-ticket-baseline-validation.jpeg)

**Query validation note**: The search identifies users whose earliest observed successful logon within the searched dataset falls after the specified cutoff and who do not match the lookup. The field **Events** must exist in **users.csv** for the final null check to work as intended. If the lookup contains only a **user** column, a different existence-check method is required.

The use of **firstTime** also depends on the search's time coverage. Without a clearly defined historical window, the query cannot independently establish that an account has never appeared before.

### Query Analysis:

The query identifies successful logons (Event ID 4624) and compares authenticated users against the imported users.csv lookup table representing the expected user baseline. By filtering for users absent from the lookup, the search highlights newly observed or anomalous accounts requiring further investigation.

The recorded results identified **Barbi** on **SQLSERVER.corp.local** as an account not matched to the expected baseline. This finding warranted further investigation but did not independently establish that the account was unauthorized or that a forged Kerberos ticket was used.

## Authentication Event Correlation

### Purpose: 

Retrieve all Windows Security Events associated with the suspicious user and affected workstation to identify authentication artifacts, privilege assignments, and explicit credential usage relevant to the investigation.

### SPL:

```spl 
index=main "Barbi" "SQLSERVER"
| stats count by EventCode
```

### Results: 

| Event Code | Description |
|------------|-------------|
| 4624 | Successful Logon |
| 4634 | Logoff |
| 4648 | Logon Attempt Using Explicit Credentials |
| 4672 | Special Privileges Assigned to New Logon |

### Figure 9 - Authentication Event Correlation 

![Silver Ticket Authentication Events](../images/kerberos-ticket-forgery-investigation/silver-ticket-authentication-events.jpeg)

### Query Analysis:

The query retrieves all Windows Security Events associated with the suspicious account Barbi and the affected host SQLSERVER.corp.local. Rather than examining individual logon events, this step establishes which authentication-related events are available for further investigation.

**Technical note**: The query searches for the terms **Barbi** and **SQLSERVER** across indexed events rather than explicitly filtering the user and **ComputerName** fields. The resulting events should be inspected individually to confirm that they refer to the intended account and host.

Among the returned events, Event ID 4648 is relevant because it records an attempt to log on using explicitly supplied credentials. Its event fields can help identify the account and target server associated with the attempt, but it does not independently establish Kerberos ticket forgery.

Event ID 4672 is also noteworthy because it indicates that privileged rights were assigned during the logon session. While this event alone does not confirm malicious activity, correlating it with explicit credential usage and service access helps reconstruct the available authentication sequence.

## Event ID 4648 - Target Service Investigation

### Purpose: 

Inspect the Event ID 4648 record to identify the account and target server associated with explicit credential usage and investigate the recorded service information.

### Investigation Step:

Open the Event ID 4648 (Logon Attempt Using Explicit Credentials) record identified during the previous query and review the event details to determine the target service associated with the authentication request.

### Results: 

| Field | Value |
|--------|-------|
| Account | `Barbi` |
| Target Server | `SQLSERVER.corp.local` |
| Target Service | `cifs` |

### Figure 10 - Event ID 4648 Target Service Investigation 

![Silver Ticket CIFS Service Investigation](../images/kerberos-ticket-forgery-investigation/silver-ticket-cifs-service-investigation.jpeg)

### Query Analysis:

The recorded investigation findings associate account **Barbi** with an Event ID 4648 entry referencing **SQLSERVER.corp.local** and the CIFS service. Event ID 4648 records an explicit-credential logon attempt; by itself, it does not prove that authentication succeeded or that a forged Kerberos service ticket was used.

CIFS is a Kerberos service class commonly associated with SMB file-sharing access. Silver Ticket attacks can involve forged service tickets for specific SPNs, making service identification relevant to the investigative hypothesis. However, the exact SPN and its source event field should be verified before concluding that a particular Kerberos service ticket was presented.

The combined findings justify further investigation into possible Silver Ticket activity, but they do not directly demonstrate ticket creation, injection, or successful use of a forged service ticket.

## Investigation Findings 

The baseline comparison identified **Barbi** as an account requiring investigation on **SQLSERVER.corp.local**. Subsequent analysis returned Windows Security Event IDs 4624, 4634, 4648, and 4672, providing visibility into successful logons, logoffs, explicit credential usage, and privileged logon activity.

Inspection of the recorded Event ID 4648 findings associated the account with the CIFS service on **SQLSERVER.corp.local**. Together, these artifacts supported further investigation of a possible Silver Ticket scenario, although the available evidence did not independently confirm forged Kerberos ticket use.

The investigation established an authentication anomaly and related service-access context, rather than a definitive finding of Kerberos ticket forgery.

## Detection Logic

### Baseline Validation:

Compare authenticated users against an established organizational baseline to identify previously unseen or unexpected accounts. Users absent from the expected baseline should be prioritized for investigation, as they may indicate unauthorized account usage, newly created identities, or authentication performed using forged Kerberos tickets.

### New User Detection:

Identify successful authentication events generated by accounts that have not previously been observed within the environment. Newly appearing users should be validated against organizational records and correlated with additional authentication artifacts to determine whether the activity represents legitimate administration or potential credential abuse.

### Explicit Credential Monitoring:

Monitor Windows Security Event ID 4648 (Logon Attempt Using Explicit Credentials) to identify authentication performed using explicitly supplied credentials. Although this event is commonly associated with legitimate administrative activity, it may also reveal the target service accessed during a forged Kerberos authentication sequence and should therefore be correlated with other authentication events. 

This event is not a direct Silver Ticket indicator. It can provide additional authentication context when correlated with anomalous accounts, target server information, and other relevant telemetry.

### Privileged Authentication:

Review Windows Security Event ID 4672 (Special Privileges Assigned to New Logon) to identify authentication sessions that receive elevated privileges. While privileged logons are common for administrative accounts, correlating Event ID 4672 with anomalous users, explicit credential usage, and service access improves confidence when investigating potential Kerberos ticket forgery.

### Service Access Analysis:

Examine the Service Principal Name (SPN) associated with Kerberos authentication to determine the service targeted by the ticket. Particular attention should be given to commonly targeted services such as:

•	CIFS 

•	HOST 

•	HTTP 

•	MSSQLSvc 

Unexpected service access by anomalous accounts can provide useful investigation leads. However, identifying a forged Silver Ticket requires additional supporting evidence beyond baseline deviations or explicit credential events.

## Investigation Artifacts and Detection References

| IOC | Value |
|-----|-------|
| **User** | `Barbi` |
| **Host** | `SQLSERVER.corp.local` |
| **Relevant Event IDs** | `4624`, `4648`, `4672` |
| **Additional Event** | `4634` |

The source records the service as **cifs**, but does not provide enough information to independently verify the exact SPN **cifs/sqlserver**. The user, host, service, and event IDs should be described as investigation artifacts rather than confirmed IOCs.

## MITRE ATT&CK Mapping


| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Credential Access | Silver Ticket | T1558.002 | Forging service tickets (TGSs) for specific Service Principal Names (SPNs) |

**Mapping note**: T1558.002 (Silver Ticket) is the primary technique associated with the investigation hypothesis, rather than an observed technique confirmed by the documented evidence.

T1558.001 (Golden Ticket) was discussed as background but was not practically investigated. T1078, TA0005, and TA0008 should not be presented as confirmed techniques or outcomes based on the supplied results.

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Kerberos Ticket Forgery | Golden Ticket and Silver Ticket attacks abuse forged Kerberos tickets but differ significantly in scope, required secrets, and detection opportunities. |
| Baseline Validation | Comparing authenticated users against an established baseline is an effective method for identifying previously unseen or suspicious accounts. |
| Explicit Credential Monitoring | Event ID 4648 provides valuable context regarding explicit credential usage and may reveal the target server accessed during authentication. |
| Service Correlation | Identifying the accessed Service Principal Name (SPN) helps determine the intended target of a Kerberos service ticket. |
| Event Correlation | Correlating successful logons, explicit credential usage, privilege assignments, and service access provides additional investigative context compared with analyzing individual events in isolation. |
| Behavioral Detection | Kerberos ticket forgery requires supporting evidence beyond isolated authentication anomalies. |
| Silver Ticket Detection | Silver Ticket attacks may avoid KDC-side ticket issuance events, making service-specific investigation particularly important. |
| Threat Hunting | Combining baseline validation with authentication telemetry and SPN analysis provides a structured approach for investigating potential ticket forgery in Active Directory environments. |

## Conclusion

This investigation demonstrated a Splunk-based workflow for examining authentication anomalies potentially associated with Silver Ticket abuse. Baseline validation identified the account **Barbi** on **SQLSERVER.corp.local**, while subsequent Windows Security event analysis identified logon, explicit credential, and privilege-related activity, including a recorded association with the CIFS service.

The investigation illustrates how user baseline comparisons and authentication event correlation can support Kerberos ticket forgery threat hunting. Although the available results did not independently confirm a forged service ticket, the documented workflow provides a foundation for further service-specific authentication analysis and detection engineering.

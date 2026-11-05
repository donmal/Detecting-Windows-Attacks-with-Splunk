# 04 - Kerberos Ticket Forgery Investigation 

## Executive Summary 

This investigation focused on detecting Kerberos ticket forgery within an Active Directory environment using Splunk by analyzing Kerberos authentication events, user baseline validation, explicit credential usage, privilege assignments, and service-specific authentication activity.

The investigation introduces the two primary Kerberos ticket forgery techniques—Golden Ticket and Silver Ticket—and demonstrates how multiple Windows Security events can be correlated to identify authentication behavior consistent with forged Kerberos tickets.

Although both techniques are presented to establish the investigative context, the practical investigation primarily focuses on identifying a suspected Silver Ticket attack by correlating user activity, authentication events, privilege assignments, and accessed services.

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
| **Forged Ticket** | Ticket Granting Ticket (TGT) | Ticket Granting Service (TGS) |
| **Compromised Secret** | KRBTGT account hash | Service or computer account hash |
| **Authentication Scope** | Entire Active Directory domain | Specific service only |
| **Typical Target** | Domain Controllers and domain resources | Individual Kerberos-enabled services (e.g., CIFS, MSSQL, HTTP) |
| **KDC Communication** | Required initially to obtain or validate tickets | Often bypassed after ticket creation because some services validate tickets locally |
| **Persistence** | High (domain-wide persistence) | Medium (service-specific persistence) |
| **Detection Focus** | KRBTGT compromise, abnormal TGT activity, privileged authentication anomalies | Service-specific authentication, SPN usage, explicit credential events, and user anomalies |

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
•	Event ID 4648 (Explicit Credentials) 
•	Event ID 4672 (Special Privileges Assigned) 
•	Service Principal Names (SPNs) 
•	Target service correlation 

## Why Silver Tickets Are Difficult to Detect 

Silver Ticket attacks are often more difficult to detect than Golden Ticket attacks because the forged Ticket Granting Service (TGS) is created using a compromised service account hash rather than the KRBTGT account hash. Since many services validate Kerberos service tickets locally, authentication may occur without contacting the Key Distribution Center (KDC), resulting in fewer Kerberos authentication events and reduced visibility in domain controller logs. As a result, defenders must rely on behavioral indicators such as anomalous service access, explicit credential usage, privilege assignments, Service Principal Name (SPN) analysis, and deviations from established authentication baselines rather than individual Kerberos events alone.

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
| Sysmon | Process and system activity correlation (where applicable) |
| Lookup Table (`users.csv`) | Baseline user validation |
| Event ID 4624 | Successful logon detection |
| Event ID 4648 | Explicit credential logon analysis |
| Event ID 4672 | Privileged logon identification |
| Event ID 4768 | Kerberos Authentication Service (AS-REQ/TGT) requests |
| Event ID 4769 | Kerberos Service Ticket (TGS) requests |
| Event ID 4770 | Kerberos ticket renewal activity |
| Service Principal Names (SPNs) | Identification of targeted Kerberos services |

## Investigation Scope 

The investigation focused on identifying forged Kerberos ticket activity by correlating Kerberos authentication events, user baseline validation, privilege assignments, explicit credential usage, and service-specific authentication telemetry. Although both Golden Ticket and Silver Ticket techniques are introduced to establish the investigative context, the practical investigation primarily examines a suspected Silver Ticket attack by identifying users absent from the expected baseline and correlating authentication events with the accessed service to determine whether the observed behavior is consistent with the use of a forged service ticket.

## Investigatoin Methodology 

The investigation followed a structured correlation process designed to identify authentication activity consistent with a forged Kerberos service ticket:

1.	Import the baseline user list into Splunk for user validation. 
2.	Compare observed authentication activity against the established baseline. 
3.	Identify newly observed or anomalous user accounts. 
4.	Validate successful authentication events associated with suspicious users. 
5.	Correlate related Windows Security Events, including explicit credential usage and privilege assignments. 
6.	Identify the service accessed during the authentication sequence. 
7.	Assess whether the observed authentication pattern is consistent with the use of a forged Silver Ticket.

## Challenge Context

During this investigation, the SOC team analyzed Splunk logs after authentication events revealed activity associated with a previously unseen user account. The objective was to determine whether the observed authentication pattern represented legitimate administrative activity or the use of a forged Kerberos service ticket consistent with a Silver Ticket attack.

Rather than relying on a single authentication event, the investigation required analysts to:

•	validate observed users against an organizational baseline, 
•	identify newly observed or anomalous user accounts, 
•	review successful authentication events, 
•	correlate explicit credential usage and privilege assignments, 
•	identify the service accessed during authentication, 
•	determine whether the observed behavior was consistent with the use of a forged Kerberos service ticket.

## Investigation Overview 

Before examining individual events, the investigation adopted a hypothesis-driven approach to determine whether the observed authentication activity was consistent with Kerberos ticket forgery. Rather than relying on a single Windows Security Event, multiple authentication artifacts were correlated with user baseline validation, explicit credential usage, privilege assignments, and service access information to reconstruct the complete authentication sequence.

The investigation focused on determining:

•	whether the authenticated account was present in the expected user baseline, 
•	whether explicit credentials were used during authentication, 
•	which service was accessed through the Kerberos ticket, 
•	whether the observed authentication pattern was consistent with the use of a forged Silver Ticket.

## Investigation Query #1  

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

### Query Analysis:

The query identifies successful logons (Event ID 4624) and compares authenticated users against the imported users.csv lookup table representing the expected user baseline. By filtering for users absent from the lookup, the search highlights newly observed or anomalous accounts requiring further investigation.

The results identified Barbi as a previously unseen user who successfully authenticated to SQLSERVER.corp.local. Because the account was not present in the established baseline, additional investigation was required to determine whether the authentication activity represented legitimate administrative behavior or the use of a forged Kerberos service ticket.

## Investigation Query #2 

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

### Query Analysis:

The query retrieves all Windows Security Events associated with the suspicious account Barbi and the affected host SQLSERVER.corp.local. Rather than examining individual logon events, this step establishes which authentication-related events are available for further investigation.

Among the returned events, Event ID 4648 (Logon Attempt Using Explicit Credentials) is particularly significant because it records authentication performed using explicitly supplied credentials. In the context of Kerberos ticket forgery, this event may reveal the target service accessed during authentication and therefore provides a valuable investigative lead for identifying potential Silver Ticket activity.

Event ID 4672 is also noteworthy because it indicates that privileged rights were assigned during the logon session. While this event alone does not confirm malicious activity, correlating it with explicit credential usage and service access helps reconstruct the complete authentication sequence.

## Investigation Query #3

### Purpose: 

Inspect the Event ID 4648 record to identify the target service accessed through explicit credentials and determine whether the authentication activity is consistent with a forged Kerberos service ticket.

### Investigation Step:

Open the Event ID 4648 (Logon Attempt Using Explicit Credentials) record identified during the previous query and review the event details to determine the target service associated with the authentication request.

### Results: 

| Field | Value |
|--------|-------|
| Account | `Barbi` |
| Target Server | `SQLSERVER.corp.local` |
| Target Service | `cifs` |

### Query Analysis:

Inspection of Event ID 4648 revealed that the suspicious account Barbi authenticated using explicitly supplied credentials to access the CIFS service hosted on SQLSERVER.corp.local.

The CIFS Service Principal Name (SPN) identifies the target service associated with the Kerberos authentication request. Because Silver Ticket attacks forge service tickets (TGS) for specific SPNs rather than Ticket Granting Tickets (TGTs), identifying the accessed service is a critical step in confirming the intended target of the forged ticket.

Although Event ID 4648 alone does not prove the existence of a Silver Ticket attack, correlating the accessed service with the anomalous user account, successful authentication events, and privilege assignments provides strong evidence supporting the investigative hypothesis.

## Investigation Findings 

Comparison against the established user baseline identified the previously unseen account Barbi. Subsequent investigation revealed successful authentication to SQLSERVER.corp.local, followed by Event ID 4648, indicating the use of explicitly supplied credentials during the authentication process. Inspection of the event identified the CIFS service as the target of the authentication request. When correlated with the baseline deviation, authentication activity, and service-specific access, the observed behavior was determined to be consistent with a suspected Silver Ticket attack.

No single event independently confirmed Kerberos ticket forgery; rather, the conclusion was reached by correlating baseline validation, authentication events, explicit credential usage, and service access throughout the investigation.

## Detection Logic

### Baseline Validation:

Compare authenticated users against an established organizational baseline to identify previously unseen or unexpected accounts. Users absent from the expected baseline should be prioritized for investigation, as they may indicate unauthorized account usage, newly created identities, or authentication performed using forged Kerberos tickets.

### New User Detection:

Identify successful authentication events generated by accounts that have not previously been observed within the environment. Newly appearing users should be validated against organizational records and correlated with additional authentication artifacts to determine whether the activity represents legitimate administration or potential credential abuse.

### Explicit Credential Monitoring:

Monitor Windows Security Event ID 4648 (Logon Attempt Using Explicit Credentials) to identify authentication performed using explicitly supplied credentials. Although this event is commonly associated with legitimate administrative activity, it may also reveal the target service accessed during a forged Kerberos authentication sequence and should therefore be correlated with other authentication events. 

### Privileged Authentication:

Review Windows Security Event ID 4672 (Special Privileges Assigned to New Logon) to identify authentication sessions that receive elevated privileges. While privileged logons are common for administrative accounts, correlating Event ID 4672 with anomalous users, explicit credential usage, and service access improves confidence when investigating potential Kerberos ticket forgery.

### Service Access Analysis:

Examine the Service Principal Name (SPN) associated with Kerberos authentication to determine the service targeted by the ticket. Particular attention should be given to commonly targeted services such as:

•	CIFS 
•	HOST 
•	HTTP 
•	MSSQLSvc 

Unexpected access to these services by anomalous users or through explicit credential events may indicate the use of a forged Silver Ticket, especially when combined with deviations from the expected authentication baseline.

## •	IOC Summary 

| IOC | Value |
|-----|-------|
| **User** | `Barbi` |
| **Host** | `SQLSERVER.corp.local` |
| **Target Service (SPN)** | `cifs/sqlserver` |
| **Relevant Event IDs** | `4624`, `4648`, `4672` |

## Figures

### Figure 1. Downloading the investigation resources (users.csv).

### Figure 2. Uploading the users.csv lookup table into Splunk.

### Figure 3. Baseline comparison identifying the suspicious user Barbi.

### Figure 4. Event code distribution associated with Barbi on SQLSERVER.

### Figure 5. Event ID 4648 confirming access to the CIFS service on SQLSERVER.

## MITRE ATT&CK Mapping


| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Credential Access | Golden Ticket | T1558.001 | Forging Ticket Granting Tickets (TGTs) using the KRBTGT account hash |
| Credential Access | Silver Ticket | T1558.002 | Forging service tickets (TGSs) for specific Service Principal Names (SPNs) |
| Credential Access | Steal or Forge Kerberos Tickets | T1558 | Abuse of forged Kerberos authentication tickets |
| Credential Access | Valid Accounts | T1078 | Impersonation of legitimate user accounts through forged Kerberos tickets |
| Defense Evasion | Defense Evasion | TA0005 | Bypassing normal Kerberos authentication using forged tickets |
| Lateral Movement | Lateral Movement | TA0008 | Unauthorized access to remote systems and services using forged Kerberos tickets |


## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Kerberos Ticket Forgery | Golden Ticket and Silver Ticket attacks abuse forged Kerberos tickets but differ significantly in scope, required secrets, and detection opportunities. |
| Baseline Validation | Comparing authenticated users against an established baseline is an effective method for identifying previously unseen or suspicious accounts. |
| Explicit Credential Monitoring | Event ID 4648 provides valuable context regarding explicit credential usage and may reveal the target service accessed during authentication. |
| Service Correlation | Identifying the accessed Service Principal Name (SPN) helps determine the intended target of a forged Kerberos service ticket. |
| Event Correlation | Correlating successful logons, explicit credential usage, privilege assignments, and service access provides significantly higher confidence than analyzing individual events in isolation. |
| Behavioral Detection | Kerberos ticket forgery is more reliably detected through behavioral correlation than by relying on a single Windows Security Event. |
| Silver Ticket Detection | Silver Ticket attacks often generate fewer authentication artifacts than Golden Ticket attacks, making service-specific investigation particularly important. |
| Threat Hunting | Combining baseline validation with authentication telemetry and SPN analysis provides an effective methodology for hunting forged Kerberos ticket activity in Active Directory environments. |

## Conclusion

This investigation demonstrated how suspected Kerberos ticket forgery can be investigated by correlating Windows Security Events, user baseline validation, explicit credential usage, privilege assignments, and service-specific authentication activity within Splunk. Although both Golden Ticket and Silver Ticket techniques were examined conceptually, the practical investigation focused on identifying behavior consistent with a forged Silver Ticket through systematic event correlation. Combining baseline validation with authentication telemetry and Service Principal Name (SPN) analysis provides defenders with a structured methodology for detecting Kerberos ticket abuse while improving investigative confidence and reducing false positives.
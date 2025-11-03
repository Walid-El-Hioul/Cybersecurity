
The **Ticketing System** (often referred to as a **Case Management System**) is the essential administrative tool in a Security Operations Center (SOC). It serves as the official **system of record** for every security incident, providing a centralized platform for tracking, documenting, and managing the response from start to finish.

## 1. The Core Ticketing Workflow

The workflow outlines the standard sequence of steps a security alert follows, which is designed to ensure efficiency, accountability, and accurate reporting.

|**Step**|**Phase Name**|**T1 Analyst Action**|**Goal**|
|---|---|---|---|
|**1**|**Creation & Acknowledgment**|A new ticket is automatically created by the **SIEM** or **EDR**, or manually reported by a user (e.g., phishing email). T1 analyst takes ownership.|Start the clock on **Mean Time to Respond (MTTR)** and assign accountability.|
|**2**|**Triage & Prioritization**|T1 analyst quickly reviews the alert details. The key decision is to assign the appropriate **Priority/Severity** level (e.g., P1, P2, P3).|Align the response effort with the potential **Business Impact**. Determine if it is a **True Positive** or a **False Positive**.|
|**3**|**Initial Investigation**|T1 performs basic data enrichment and analysis based on the playbook. This includes gathering **IOCs**, checking logs for related activity, and identifying the **Affected Asset/User**.|Collect enough evidence to either resolve the alert or justify an escalation. **Document every action taken.**|
|**4**|**Action & Handoff**|**If False Positive/Trivial:** Close the ticket with detailed notes on the finding. **If True Positive/Complex:** Escalate to Tier 2 (T2) or an Incident Handler.|Resolve low-hanging issues quickly to reduce volume, and escalate confirmed incidents with a clear, concise summary.|
|**5**|**Resolution & Closure**|(Typically managed by T2/T3, but finalized by T1/T2). Once the threat is contained, eradicated, and systems are recovered, the ticket is formally closed.|Provide a final summary (**Resolution Notes**) to capture the root cause and ensure all steps were followed for audit purposes.|

---

## 2. Essential Ticketing System Fields

Regardless of the platform (e.g., ServiceNow, Jira, TheHive), an effective security ticket must contain specific fields to enable fast triage, clear handoffs, and accurate metrics like **MTTD** and **MTTR**.

### A. Identification and Tracking Fields

These fields are critical for the administrative management and audit trail of the incident.

- **Ticket ID:** The unique numerical identifier for the case (e.g., `INC-1234`).
    
- **Status:** The current state of the ticket (e.g., _New_, _In Progress_, _On Hold_, _Escalated to T2_, _Resolved_, _Closed_).
    
- **Assigned To:** The specific analyst or team currently responsible for the ticket.
    
- **Source/Detector:** The tool or system that generated the alert (e.g., _SIEM - Brute Force Rule_, _EDR - Malware Detected_, _User Reported - Phishing_).
    
- **Category:** A high-level classification of the incident type (e.g., _Malware_, _Phishing_, _Unauthorized Access_, _Policy Violation_).
    

### B. Priority and Impact Fields

These fields dictate how quickly the incident must be handled and who needs to be involved. T1 analysts are responsible for accurately setting these values.

- **Priority/Severity:** A rating (e.g., **P1/Critical**, P2/High, P3/Medium) that combines the security **Severity** with the **Business Impact**.
    
- **Business Impact:** A short description of the affected service or business function (e.g., _Full Production Outage_, _Compromise of Executive Account_, _Single Workstation Infected_).
    
- **SLA Timer:** A dynamic timer that tracks the time remaining before the Service Level Agreement (SLA) for a specific step (e.g., Triage, Containment) is violated.
    

### C. Investigation and Documentation Fields

These are the body of the ticket, where the analyst’s work is stored. They are the most important fields for the **chain of custody**.

- **Description/Alert Summary:** The raw alert data from the tool, followed by a brief summary written by the T1 analyst in plain English.
    
- **Affected Asset/User:** The primary target (e.g., **Hostname**, **IP Address**, **User Account Name**) involved in the incident.
    
- **Initial Actions Taken:** A clear, chronological list of all actions performed by the T1 analyst (e.g., "Checked for AV status," "Isolated host via EDR," "Searched Proxy logs for C2 connection").
    
- **IOCs (Indicators of Compromise):** A structured list of all identified malicious artifacts (e.g., file **Hash**, malicious **IP Address**, malware **File Name**, unusual **Command Line** strings).
    
- **Escalation Notes:** A concise, formal summary used when handing the ticket off to T2, detailing the evidence found and the reason for the handoff.
    
- **Resolution Notes:** The final section, explaining the **Root Cause** of the incident and the final **Eradication/Recovery** steps taken.

---

## 3. CVSS: Severity vs. Operational Priority

The **Common Vulnerability Scoring System (CVSS)** is an essential metric in cybersecurity, but it is critical to understand how it differs from the ticket's **Operational Priority (P1, P2, etc.)**.

CVSS is a score that helps you understand **how bad the underlying flaw is**, but it does not tell you **how much the business is currently impacted**.

|**Metric**|**Focus**|**What the Score Measures**|**T1 Action**|
|---|---|---|---|
|**CVSS Score**|**Vulnerability Severity** (e.g., 9.8)|The theoretical technical risk of a flaw (e.g., ease of exploit, impact on CIA).|Primarily used during **Root Cause Analysis** or in **Vulnerability Management** tickets.|
|**P1/P2/P3**|**Operational Priority** (P1/Critical)|The real-time business risk (e.g., system downtime, data loss, regulatory urgency).|Used in the **Triage & Prioritization** phase of a live incident.|

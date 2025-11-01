## SOC Alert Handling Workflow

1. **Alert/Event**
2. **Tier 1 (T1) Triage & Initial Investigation**
3. **If False Positive / True Positive**
   - **False Positive:** Close the alert and document findings.
   - **True Positive:** Proceed to escalation.
4. **Escalation to Tier 2 (T2)**
5. **Deep Investigation & Containment**
6. **If False Positive / True Positive**
   - **False Positive:** Close the case after validation.
   - **True Positive:** Escalate to Incident Handler/Manager.
7. **Escalation to Incident Handler/Manager**
8. **Resolution & Post-Mortem**

---

### Your Goal for This Step

Understand the distinct roles, responsibilities, and skill sets of each SOC tier so you can:
1.  Perform your own job (T1) effectively.
2.  Know exactly when and why to escalate an alert.
3.  See a clear path for your career growth.

---

### What You Need to Learn & Do

Here is a detailed breakdown of the typical responsibilities for each tier, written from the perspective of what you, as a new T1, need to know.

#### 1. SOC Tier 1 (T1) - The Front Line / The Triage Engine

*   **Primary Mission:** **Volume and Velocity.** To monitor, triage, and perform initial investigation on a high volume of security alerts.
*   **Key Responsibilities:**
    *   **Alert Acknowledgment:** Be the first set of eyes on alerts from the SIEM, EDR, IDS, and other tools.
    *   **Initial Triage:** Quickly determine if an alert is a **false positive**, a **true positive**, or requires more info.
    *   **Follow Playbooks:** Execute standardized procedures (playbooks) for common alert types (e.g., "Phishing Email Triage," "Brute Force Alert Investigation").
    *   **Basic Investigation:** Gather initial facts: "Who, What, When, Where?"
        *   Check IP/Domain reputation (VirusTotal, Threat Intel Feeds).
        *   Look up file hashes.
        *   Correlate a few basic logs in the SIEM.
    *   **Decision Making:**
        *   If False Positive: Document reasoning and close the ticket.
        *   If True Positive or Inconclusive: **Escalate to Tier 2** with clear, concise notes.
*   **Mindset:** **Efficiency and Process.** Your goal is to clear the queue of noise so T2 can focus on real threats. You are the filter.
*   **What You Should Do Now:** As a T1, your entire focus in the first few months is to master this role. Practice your investigations, learn the tools, and get faster and more accurate at triage.

---

#### 2. SOC Tier 2 (T2) - The Incident Responder / The Hunter

*   **Primary Mission:** **Depth and Scope.** To perform deep-dive investigation on escalated alerts, confirm incidents, determine the scope of compromise, and begin containment.
*   **Key Responsibilities:**
    *   **Deep-Dive Analysis:** Investigate alerts that T1 could not resolve. This involves advanced log analysis, EDR telemetry review, and forensic artifact examination.
    *   **Scope Expansion:** Take a confirmed malicious indicator (e.g., a bad IP) and hunt for it across the entire environment. "Is this just one machine, or fifty?"
    *   **Incident Confirmation:** Officially declare a security incident.
    *   **Containment:** Take initial actions to stop the threat from spreading (e.g., isolate a host from the network, disable a user account).
    *   **Mentorship:** Often provides guidance and feedback to T1 analysts.
*   **Mindset:** **Investigation and Correlation.** You're connecting the dots to understand the full story of an attack.
*   **What This Means For You (as T1):**
    *   When you escalate to T2, you are handing off a puzzle. A good handoff includes all the pieces you've already found.
    *   **Your goal is to become a T2.** The skills in your P1 and P2 categories are what will get you there.

---

#### 3. SOC Tier 3 (T3) - The Expert / The Threat Hunter

*   **Primary Mission:** **Expertise and Proactivity.** To handle the most complex incidents, conduct proactive threat hunting, and improve the SOC's overall capabilities.
*   **Key Responsibilities:**
    *   **Complex Incident Response:** Lead the response for major breaches (e.g., ransomware, advanced persistent threats).
    *   **Threat Hunting:** Proactively search for hidden threats that bypassed automated detection.
    *   **Malware Analysis:** Reverse engineer malicious software to understand its capabilities.
    *   **Tool & Rule Development:** Create advanced detection rules for the SIEM and improve security tools.
    *   **Strategic Improvement:** Identify gaps in the SOC's processes and technologies.
*   **Mindset:** **Innovation and Mastery.** You are no longer just reacting; you are thinking like an adversary and building defenses against them.

---

### Action Plan for You to Complete This Step

Don't just read this—**do this**.

| Action Item | Description | Why It's Important |
| :--- | :--- | :--- |
| **1. Find Your SOC's Org Chart** | Ask your manager or a senior colleague: "Is there a document that outlines our specific T1/T2/T3 roles and escalation paths?" | Your organization might have slight variations. Knowing the exact expectations and who to escalate to is critical. |
| **2. Study Escalation Criteria** | In your ticketing system (ServiceNow, Jira, etc.), look at past tickets. Find ones that were escalated from T1 to T2. Read the **comments and notes**. What did the T1 analyst say? What evidence did they provide? | This is real-world learning. You will see what a good (and bad) escalation looks like in your environment. |
| **3. Practice the Handoff** | When you escalate a ticket, use a mental checklist: <br> - [ ] I have provided all relevant IOCs (IPs, Hashes, Users). <br> - [ ] I have summarized what I checked and what I found. <br> - [ ] I have clearly stated why I need T2's help. | A clear handoff makes T2 more efficient and makes you look professional. It builds trust. |
| **4. Talk to a T2** | During a quiet period, ask a T2 analyst: "What is the one thing you wish every T1 would do when escalating a ticket?" | You will get the most valuable, direct feedback possible. It also shows initiative. |
| **5. Self-Assess** | At the end of your shift, ask yourself: <br> - "Did I close any tickets that should have been escalated?" <br> - "Did I escalate any tickets that I could have solved myself?" <br> - "What was the most challenging alert today and why?" | This reflective practice is how you move from following steps to developing true analytical judgment. |

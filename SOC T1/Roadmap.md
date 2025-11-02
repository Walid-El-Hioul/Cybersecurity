# SOC Tier 1 Analyst - Complete Learning Roadmap with Integrated Mini-Projects

## **P0: The Absolute Fundamentals**

### **1. SOC Fundamentals**

#### 📚 **Theory Checklist**

- [x] SOC tier structure (T1/T2/T3 responsibilities)
- [x] Security incident lifecycle phases
- [x] Ticketing system workflow and fields
- [ ] Escalation procedures and criteria
- [ ] Documentation standards and chain of custody
- [ ] Basic KPIs (MTTD, MTTR)

#### 🛠️ **Mini-Projects Checklist**

- [ ] **Python Ticket Generator** ⭐ PRIMARY
    
    ```
    Description: Build a CLI tool that generates realistic incident tickets
    
    Technical Requirements:
    - Create ticket class with fields: ID, Severity (Critical/High/Medium/Low/None), 
      Status (Open/In Progress/Escalated/Closed), Category (Malware/Phishing/Brute Force/DLP)
    - Implement CVSS v3.1 calculator for vulnerability scoring
    - Auto-assign based on severity (Critical → T2, High → T1 Senior, Medium/Low → T1)
    - Generate timestamps following incident lifecycle phases
    - Export to CSV/JSON for SIEM ingestion practice
    
    Learning Outcomes:
    ✓ Understand ticket anatomy and required fields
    ✓ Practice severity classification logic
    ✓ Learn escalation trigger points
    ✓ Master documentation standards
    
    Files to Create:
    - ticket_generator.py
    - tickets_database.json
    - severity_rules.yaml
    ```
    
- [ ] **Incident Timeline Creator**
    
    ```
    Description: Parse tickets and create visual incident timelines
    
    Technical Requirements:
    - Parse tickets from previous project
    - Create timeline with phases: Detection → Analysis → Containment → 
      Eradication → Recovery → Lessons Learned
    - Track MTTD (Mean Time To Detect) and MTTR (Mean Time To Respond)
    - Include fields: Timestamp, Phase, Action Taken, Analyst Name, Evidence Links
    - Generate visual timeline (matplotlib or HTML/CSS)
    
    Learning Outcomes:
    ✓ Internalize incident lifecycle phases
    ✓ Practice calculating KPIs
    ✓ Understand importance of timestamping
    ✓ Build chain of custody documentation
    
    Files to Create:
    - timeline_builder.py
    - incident_timeline.html
    - kpi_calculator.py
    ```
    
- [ ] **Alert Triage Simulator**
    
    ```
    Description: Decision-tree CLI game for alert classification practice
    
    Technical Requirements:
    - Present randomized alerts with partial information
    - Analyst must classify: True Positive, False Positive, Benign Positive
    - Provide feedback on decisions with explanations
    - Track accuracy percentage and average decision time
    - Include 50+ alert scenarios covering all major categories
    
    Learning Outcomes:
    ✓ Build triage muscle memory
    ✓ Learn to ask right investigative questions
    ✓ Understand TP/FP/BP differences
    ✓ Practice working under time pressure
    
    Files to Create:
    - triage_simulator.py
    - alert_scenarios.json
    - scoring_system.py
    ```
    
- [ ] **Shift Handover Report Generator**
    
    ```
    Description: Template-based handover documentation tool
    
    Technical Requirements:
    - Template sections: Open Tickets, Escalated Issues, Watch Items, 
      Actions Taken, Pending Tasks, Environmental Notes
    - Auto-populate from ticket database
    - Highlight critical items requiring immediate attention
    - Generate timestamp and analyst signature
    - Export to PDF/Markdown
    
    Learning Outcomes:
    ✓ Master handover best practices
    ✓ Understand continuity of operations
    ✓ Practice clear communication
    ✓ Learn what information is critical for next shift
    
    Files to Create:
    - handover_generator.py
    - handover_template.md
    - critical_items_highlighter.py
    ```
    
- [ ] **SLA Compliance Tracker**
    
    ```
    Description: Monitor and report on SLA adherence
    
    Technical Requirements:
    - Define SLAs: Critical (1hr response), High (4hr), Medium (24hr), Low (72hr)
    - Calculate time between ticket creation and first response
    - Flag SLA breaches with alerting
    - Generate compliance reports (% meeting SLA by severity)
    - Create trend graphs showing performance over time
    
    Learning Outcomes:
    ✓ Understand business importance of SLAs
    ✓ Learn time management in SOC operations
    ✓ Practice metrics reporting
    ✓ Identify process bottlenecks
    
    Files to Create:
    - sla_tracker.py
    - sla_config.yaml
    - compliance_report.html
    ```
    

#### 🎯 **Integration Exercise: Build a Complete SOC Workflow Simulation**

```
Project: Simulate a full shift in your "SOC"

Steps:
1. Generate 20 tickets for your shift using Python Ticket Generator
2. Triage 10 alerts using Alert Triage Simulator
3. Work 5 tickets through complete lifecycle with Timeline Creator
4. Generate Shift Handover Report for next analyst
5. Run SLA Compliance Tracker to check your performance

Deliverable: Complete documentation package showing:
- Initial ticket queue
- Triage decisions with justifications
- 5 complete incident timelines
- Shift handover report
- SLA compliance metrics

Time Investment: 4-6 hours
```

---

### **2. Networking & Protocols**

#### 📚 **Theory Checklist**

- [ ] OSI/TCP-IP model layers
- [ ] IP addressing and subnetting basics
- [ ] Common ports and services (SSH-22, HTTP-80, HTTPS-443, DNS-53, SMTP-25)
- [ ] Protocol basics: HTTP/S, DNS, DHCP, SMTP
- [ ] Network segmentation and VLAN concepts
- [ ] Packet structure (headers, payload, flags)

#### 🛠️ **Mini-Projects Checklist**

- [ ] **Custom Packet Sniffer** ⭐ PRIMARY
    
    ```
    Description: Build a packet capture tool using Scapy
    
    Technical Requirements:
    - Capture packets on specified interface
    - Filter by protocol (TCP/UDP/ICMP/HTTP/DNS)
    - Extract and display: Source/Dest IP, Source/Dest Port, Protocol, Flags, 
      Payload preview (first 50 bytes)
    - Save captures to PCAP format
    - Compare output with Wireshark captures for accuracy
    - Add color coding for different protocols
    
    Learning Outcomes:
    ✓ Understand packet structure at binary level
    ✓ Learn protocol headers (TCP/IP/Ethernet)
    ✓ Practice packet filtering logic
    ✓ Map OSI layers to real traffic
    
    Files to Create:
    - packet_sniffer.py
    - protocol_parser.py
    - capture_analyzer.py
    
    Prerequisites: Install Scapy (pip install scapy)
    ```
    
- [ ] **Port Scanner with Python**
    
    ```
    Description: Network reconnaissance tool for identifying open ports
    
    Technical Requirements:
    - Scan target IP range (only YOUR VMs!)
    - Check common ports: 21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080
    - Implement TCP SYN scan and TCP Connect scan
    - Identify service banners when possible
    - Map ports to common services (80→HTTP, 22→SSH, etc.)
    - Generate network inventory report
    - Add timing options (fast/normal/slow to avoid detection)
    
    Learning Outcomes:
    ✓ Understand TCP handshake process
    ✓ Learn service enumeration techniques
    ✓ Practice network reconnaissance from attacker perspective
    ✓ Identify what attackers see during initial access
    
    Files to Create:
    - port_scanner.py
    - service_identifier.py
    - network_inventory_report.json
    
    Ethical Note: ONLY scan networks/systems you own or have permission to test
    ```
    
- [ ] **DNS Query Logger**
    
    ```
    Description: Capture and analyze DNS traffic for anomaly detection
    
    Technical Requirements:
    - Capture DNS queries (UDP port 53) from your VM
    - Extract: Query domain, Query type (A/AAAA/MX/TXT), Response IP, TTL
    - Build baseline of "normal" DNS activity
    - Flag suspicious patterns:
      * Unusually long domain names (DGA - Domain Generation Algorithms)
      * High volume of NXDomain responses
      * Queries to suspicious TLDs (.tk, .ml, .ga, .cf)
      * Base64-encoded subdomains (data exfiltration)
      * DNS tunneling indicators (high volume to single domain)
    - Log to JSON for SIEM ingestion later
    
    Learning Outcomes:
    ✓ Understand DNS protocol operation
    ✓ Learn DNS-based attack techniques
    ✓ Practice baseline vs anomaly identification
    ✓ Recognize C2 communication patterns
    
    Files to Create:
    - dns_logger.py
    - dns_analyzer.py
    - suspicious_domains_list.txt
    ```
    
- [ ] **HTTP Header Analyzer**
    
    ```
    Description: Deep dive into HTTP/HTTPS traffic analysis
    
    Technical Requirements:
    - Parse HTTP traffic from Wireshark PCAP files
    - Extract headers: User-Agent, Host, Referer, Cookie, Content-Type, 
      Content-Length, X-Forwarded-For
    - Identify anomalies:
      * Suspicious User-Agent strings (tools, malware)
      * Unusual Content-Types for endpoints
      * Missing standard headers
      * Obfuscated cookies
      * Command injection attempts in parameters
    - Decode URL encoding and base64 in parameters
    - Flag potential web attacks (SQL injection, XSS, path traversal patterns)
    
    Learning Outcomes:
    ✓ Master HTTP protocol structure
    ✓ Understand request/response cycle
    ✓ Learn web attack indicators
    ✓ Practice log analysis for web threats
    
    Files to Create:
    - http_parser.py
    - header_analyzer.py
    - web_attack_detector.py
    ```
    
- [ ] **Network Traffic Generator**
    
    ```
    Description: Simulate various network traffic types for detection testing
    
    Technical Requirements:
    - Generate legitimate traffic: HTTP requests, DNS queries, ICMP pings
    - Simulate attack traffic (in isolated lab only!):
      * TCP SYN flood
      * UDP flood
      * ICMP flood (ping flood)
      * Port scan simulation
      * DNS amplification
    - Control traffic rate (packets per second)
    - Capture all generated traffic with your packet sniffer
    - Compare normal vs attack traffic characteristics
    
    Learning Outcomes:
    ✓ Understand DoS/DDoS attack mechanics
    ✓ Learn traffic volume baselines
    ✓ Practice identifying attack signatures
    ✓ See packet-level attack indicators
    
    Files to Create:
    - traffic_generator.py
    - attack_simulator.py (ETHICAL USE ONLY)
    - traffic_analyzer.py
    
    Ethical Warning: NEVER run attack simulations outside your isolated lab
    ```
    

#### 🎯 **Integration Exercise: Complete Traffic Analysis Investigation**

```
Project: "Investigate the Web Server"

Setup:
1. Deploy a simple web server on VM1 (Apache/nginx)
2. Access it from VM2 using curl/browser
3. Run your Custom Packet Sniffer on both VMs
4. Simultaneously capture with Wireshark

Tasks:
A. Document the complete HTTP request/response cycle:
   - Capture TCP 3-way handshake (SYN, SYN-ACK, ACK)
   - Capture HTTP GET request with all headers
   - Capture HTTP 200 response with headers and payload
   - Capture TCP connection teardown (FIN, ACK, FIN, ACK)

B. DNS Resolution Analysis:
   - Run DNS Query Logger
   - Perform DNS lookup for test domain
   - Document: Query sent, DNS server response, TTL, IP resolution

C. Port Scanning Detection:
   - Run your Port Scanner against web server VM
   - Capture the scan with Packet Sniffer
   - Analyze: What does a port scan look like in packet captures?
   - Document detection signatures

D. Attack Traffic Analysis:
   - Generate SYN flood with Traffic Generator
   - Capture with Wireshark and your sniffer
   - Compare normal traffic vs flood traffic
   - Document observable differences (packet rate, flags, patterns)

Deliverable: Comprehensive report with:
- Annotated packet captures for each scenario
- OSI/TCP-IP layer mapping for each protocol
- Detection signatures for port scan and SYN flood
- Comparison table: Your Sniffer vs Wireshark outputs

Time Investment: 8-10 hours
```

---

### **3. Operating Systems (Windows)**

#### 📚 **Theory Checklist**

- [ ] Windows Event Log types (Security, System, Application)
- [ ] Critical Event IDs (4624/4625 logons, 4688 process creation, 4732 group membership)
- [ ] File system structure and key directories
- [ ] Process and service management
- [ ] User account types and permissions
- [ ] Registry basics and important keys

#### 🛠️ **Mini-Projects Checklist**

- [ ] **Event Log Parser** ⭐ PRIMARY
    
    ```
    Description: Extract and analyze Windows Event Logs programmatically
    
    Technical Requirements:
    - Parse Security.evtx, System.evtx, Application.evtx files
    - Focus on critical Event IDs:
      * 4624 - Successful logon (extract: Username, Source IP, Logon Type)
      * 4625 - Failed logon (extract: Username, Source IP, Failure Reason)
      * 4688 - Process creation (extract: Process Name, Command Line, Parent Process)
      * 4732 - User added to group (extract: Group Name, User Added, Who Added)
      * 4720 - User account created
      * 4672 - Special privileges assigned to logon
    - Export to CSV with normalized fields
    - Create timeline of authentication events
    - Flag suspicious patterns (multiple 4625s, off-hours logons, privilege escalations)
    
    Learning Outcomes:
    ✓ Master Windows logging architecture
    ✓ Understand where evidence lives
    ✓ Practice log parsing and normalization
    ✓ Learn authentication attack indicators
    
    Files to Create:
    - event_log_parser.py
    - event_id_definitions.json
    - suspicious_pattern_detector.py
    
    Tools: Use python-evtx library or PowerShell with Python subprocess
    ```
    
- [ ] **Registry Change Monitor**
    
    ```
    Description: Detect persistence mechanisms via registry monitoring
    
    Technical Requirements:
    - Monitor critical persistence locations:
      * HKLM\Software\Microsoft\Windows\CurrentVersion\Run
      * HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
      * HKCU\Software\Microsoft\Windows\CurrentVersion\Run
      * HKLM\System\CurrentControlSet\Services (new services)
      * HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    - Create baseline snapshot of registry keys
    - Periodically check for changes (new keys, modified values)
    - Alert on suspicious additions:
      * Executables in temp directories
      * Obfuscated key names
      * Unusual file paths (AppData, ProgramData)
    - Log all changes with timestamp and action (added/modified/deleted)
    
    Learning Outcomes:
    ✓ Understand Windows persistence mechanisms
    ✓ Learn registry structure and important keys
    ✓ Practice malware behavior analysis
    ✓ Master baseline vs anomaly detection
    
    Files to Create:
    - registry_monitor.py
    - registry_baseline.json
    - persistence_detector.py
    
    Test: Install EICAR test file configured to run at startup, detect the registry change
    ```
    
- [ ] **Process Tree Visualizer**
    
    ```
    Description: Map parent-child process relationships to detect malicious chains
    
    Technical Requirements:
    - Enumerate all running processes with: PID, PPID (Parent PID), Name, 
      Command Line, User, Start Time
    - Build process tree showing parent-child relationships
    - Visualize as ASCII tree or graphical diagram (graphviz)
    - Flag suspicious process chains:
      * Office apps → PowerShell/cmd.exe (macro malware)
      * Browsers → unexpected executables
      * PowerShell → network connections
      * Process injection patterns (legitimate process with suspicious children)
    - Highlight processes with no parent (orphaned/injected)
    
    Learning Outcomes:
    ✓ Understand process creation hierarchy
    ✓ Learn malware execution patterns
    ✓ Practice identifying process injection/hollowing
    ✓ Master host-based threat hunting
    
    Files to Create:
    - process_tree_builder.py
    - process_analyzer.py
    - suspicious_chains_detector.py
    
    Tools: Use psutil library or WMI queries
    ```
    
- [ ] **User Account Auditor**
    
    ```
    Description: Enumerate and audit local user accounts and groups
    
    Technical Requirements:
    - List all local users with attributes: Username, SID, Enabled/Disabled, 
      Last Logon, Password Last Set, Groups Membership
    - List all local groups with members
    - Flag security issues:
      * Users in Administrators group (should be minimal)
      * Accounts with "Password Never Expires" set
      * Dormant accounts (no logon in 90+ days)
      * Accounts created recently (last 7 days)
      * Guest account enabled
      * Multiple accounts with same name patterns (backdoors)
    - Generate compliance report for least privilege audit
    
    Learning Outcomes:
    ✓ Understand Windows user management
    ✓ Learn privilege escalation paths
    ✓ Practice access control auditing
    ✓ Identify account-based persistence
    
    Files to Create:
    - user_auditor.py
    - privilege_checker.py
    - compliance_report.html
    ```
    
- [ ] **File System Integrity Checker**
    
    ```
    Description: Detect unauthorized file modifications and malware drops
    
    Technical Requirements:
    - Calculate hashes (MD5, SHA256) for files in critical directories:
      * C:\Windows\System32
      * C:\Windows\SysWOW64
      * C:\Program Files
      * User startup folders
    - Create baseline database of file hashes
    - Periodically scan and compare against baseline
    - Alert on changes:
      * New files in system directories
      * Modified system binaries
      * Deleted critical files
      * Suspicious file extensions in startup folders (.exe, .bat, .vbs, .ps1)
    - Log: Filename, Path, Hash, Timestamp, Change Type
    
    Learning Outcomes:
    ✓ Understand file system forensics
    ✓ Learn malware dropper behavior
    ✓ Practice integrity monitoring
    ✓ Master hash-based detection
    
    Files to Create:
    - file_integrity_monitor.py
    - hash_database.json
    - change_detector.py
    
    Test: Drop EICAR file in System32, detect it immediately
    ```
    

#### 🎯 **Integration Exercise: EICAR Test File Investigation**

```
Project: "Complete Host-Based Investigation of Test Malware"

Setup:
1. Create Windows VM with your monitoring tools installed
2. Enable Windows auditing (auditpol /set /category:* /success:enable /failure:enable)
3. Install Sysmon for enhanced logging
4. Take baseline snapshots (registry, file system, process list, accounts)

Execute Attack Simulation:
1. Download EICAR test file (safe malware test file)
2. Configure it to achieve persistence (add to Run registry key)
3. Execute the file

Investigation Tasks:

A. Registry Analysis:
   - Run Registry Change Monitor
   - Document: What registry keys were modified?
   - Identify: Persistence mechanism used

B. Event Log Analysis:
   - Run Event Log Parser on Security.evtx
   - Find: Event ID 4688 (process creation) for EICAR execution
   - Extract: Command line, parent process, timestamp
   - Find: Event ID 4657 (registry value modification) if available

C. Process Analysis:
   - Run Process Tree Visualizer during execution
   - Document: Process hierarchy leading to EICAR
   - Identify: Parent process (explorer.exe? cmd.exe? browser?)

D. File System Analysis:
   - Run File System Integrity Checker
   - Document: File path, hash, creation timestamp
   - Identify: Additional files dropped (if any)

E. User Account Audit:
   - Run User Account Auditor
   - Verify: No unauthorized accounts created
   - Check: No privilege escalation occurred

Deliverable: Complete Incident Report including:
- Executive summary (1 paragraph: what happened)
- Detailed timeline with evidence from all sources
- Registry artifacts with screenshots
- Event log evidence with Event IDs
- Process execution chain diagram
- File system changes documented with hashes
- IOCs extracted (file paths, hashes, registry keys)
- Remediation steps (how to remove persistence)
- Detection rule recommendations

Time Investment: 6-8 hours

This exercise simulates a real T1 analyst investigation workflow!
```

---

## **P1: Core Analyst Skills**

### **4. SIEM Mastery**

#### 📚 **Theory Checklist**

- [ ] SIEM architecture and components
- [ ] Log collection and normalization
- [ ] Correlation rules and alert creation
- [ ] Basic query writing and search syntax
- [ ] Alert triage workflow
- [ ] False positive identification

#### 🛠️ **Mini-Projects Checklist**

- [ ] **Log Ingestion Pipeline** ⭐ PRIMARY
    
    ```
    Description: Build end-to-end log collection infrastructure with Wazuh/Elastic
    
    Technical Requirements:
    
    Phase 1 - Sysmon Setup:
    - Install Sysmon on Windows VM with SwiftOnSecurity config
    - Verify logging: Process creation (Event ID 1), Network connections (3), 
      File creation (11), Registry changes (12, 13)
    - Forward Sysmon logs to SIEM
    
    Phase 2 - Windows Event Logs:
    - Configure Wazuh agent to forward Security, System logs
    - Enable advanced auditing policies
    - Test by generating events (failed logins, process creation)
    
    Phase 3 - Network Logs:
    - Deploy pfSense VM or enable Windows Firewall logging
    - Forward firewall logs to SIEM
    - Verify: Allowed/blocked connections, source/dest IPs, ports
    
    Phase 4 - Verification:
    - Check SIEM for incoming logs from all sources
    - Verify field extraction (timestamps, source IPs, usernames parsed correctly)
    - Create index patterns/data views
    - Build basic dashboard showing log volume by source
    
    Learning Outcomes:
    ✓ Understand SIEM architecture (agents, forwarders, indexers)
    ✓ Master log collection configuration
    ✓ Learn data ingestion troubleshooting
    ✓ Practice multi-source log aggregation
    
    Files to Create:
    - wazuh_agent_config.xml
    - sysmon_config.xml
    - ingestion_verification_checklist.md
    - log_sources_dashboard.json
    
    Time: 4-6 hours for initial setup
    ```
    
- [ ] **Custom Correlation Rule Builder**
    
    ```
    Description: Create detection rules that correlate events across log sources
    
    Technical Requirements:
    
    Rule 1: Brute Force Detection
    - Trigger: 5+ failed logins (Event ID 4625) within 5 minutes from same source IP
    - Severity: High
    - Action: Generate alert with source IP, targeted account, failure count
    - Test: Simulate failed RDP logins, verify alert fires
    
    Rule 2: Suspicious Process Execution
    - Trigger: Office application (Word/Excel/PowerPoint) spawns PowerShell or cmd.exe
    - Data Source: Sysmon Event ID 1 (process creation)
    - Condition: ParentImage contains "WINWORD.EXE" OR "EXCEL.EXE" 
                 AND Image contains "powershell.exe" OR "cmd.exe"
    - Severity: Critical
    - Test: Create macro that launches PowerShell, verify detection
    
    Rule 3: Privilege Escalation
    - Trigger: User added to Administrators group (Event ID 4732) 
               outside business hours (6PM-8AM)
    - Severity: Critical
    - Action: Alert with username added, who added them, timestamp
    - Test: Manually add user to admin group, verify alert
    
    Rule 4: Lateral Movement via RDP
    - Trigger: Successful logon (4624, Logon Type 10 = RemoteInteractive) 
               to multiple hosts within 10 minutes
    - Correlation: Same username across different computer names
    - Severity: High
    - Test: RDP to multiple VMs, verify detection
    
    Rule 5: Data Exfiltration Indicator
    - Trigger: Large volume of outbound connections (>100MB) to single 
               external IP in 1 hour
    - Data Source: Firewall logs + Sysmon network events
    - Severity: High
    
    Learning Outcomes:
    ✓ Master correlation rule logic
    ✓ Understand detection engineering
    ✓ Learn threshold tuning
    ✓ Practice testing detection efficacy
    
    Files to Create:
    - detection_rules.yaml
    - rule_testing_procedures.md
    - false_positive_analysis.csv
    ```
    
- [ ] **SIEM Query Optimizer**
    
    ```
    Description: Learn efficient query writing and performance optimization
    
    Technical Requirements:
    
    Exercise 1: Query Performance Comparison
    - Write INEFFICIENT query:
      * No time range filter
      * Search across all indices
      * No field-specific filtering
      * Use wildcards at beginning of search terms
    - Write OPTIMIZED version:
      * Narrow time range (last 1 hour)
      * Specific index pattern
      * Field-specific searches
      * Proper wildcard usage
    - Compare execution times
    
    Exercise 2: Complex Query Building
    - Task: Find failed SSH logins from external IPs that later succeeded
    - Steps:
      1. Find Event ID 4625 (failed logon) where Source IP is external
      2. Check if same Source IP has Event ID 4624 (success) within 1 hour
      3. Display: Username, Source IP, Failure count, Success timestamp
    
    Exercise 3: Statistical Queries
    - Calculate: Average logon events per hour by user
    - Identify: Users with >3 standard deviations from mean (anomalies)
    - Visualize: Timeline of authentication attempts
    
    Learning Outcomes:
    ✓ Master query syntax (SPL, KQL, or Lucene depending on SIEM)
    ✓ Learn performance optimization techniques
    ✓ Practice complex multi-stage queries
    ✓ Understand indexed vs non-indexed field impacts
    
    Files to Create:
    - query_optimization_guide.md
    - common_queries_library.txt
    - performance_benchmarks.csv
    ```
    
- [ ] **Alert Dashboard Creator**
    
    ```
    Description: Build operational dashboards for shift monitoring
    
    Technical Requirements:
    
    Dashboard 1: Alert Overview
    - Widgets:
      * Alert count by severity (pie chart)
      * Alerts over time (line graph, last 24 hours)
      * Top 10 alert types (bar chart)
      * Open vs closed alerts (gauge)
      * MTTD/MTTR metrics (single stat)
    
    Dashboard 2: Authentication Monitoring
    - Widgets:
      * Failed login attempts by user (table)
      * Geographic map of login source IPs
      * Successful logins outside business hours (table)
      * Account lockouts (counter)
      * Top 10 source IPs for failed logins
    
    Dashboard 3: Network Activity
    - Widgets:
      * Blocked connections by firewall (time series)
      * Top talkers (source IPs by connection count)
      * Unusual ports accessed (table)
      * DNS query volume (histogram)
      * Outbound connections to external IPs (table)
    
    Dashboard 4: Endpoint Activity
    - Widgets:
      * New processes created (time series)
      * PowerShell executions (counter)
      * Registry modifications (table)
      * New scheduled tasks (table)
      * Service installations (table)
    
    Learning Outcomes:
    ✓ Understand operational visibility requirements
    ✓ Learn effective visualization selection
    ✓ Practice dashboard design principles
    ✓ Master at-a-glance threat identification
    
    Files to Create:
    - dashboard_configs.json (export from SIEM)
    - dashboard_usage_guide.md
    - widget_query_reference.txt
    ```
    
- [ ] **Log Normalization Script**
    
    ```
    Description: Unify log formats from disparate sources for correlation
    
    Technical Requirements:
    
    Input Sources:
    - Windows Event Logs (XML format)
    - Linux Syslog (standard syslog format)
    - Firewall logs (CSV or proprietary format)
    - Web server logs (Apache/nginx access logs)
    
    Normalization Fields (unified schema):
    - timestamp (ISO 8601 format)
    - source_ip
    - destination_ip
    - source_port
    - destination_port
    - username
    - event_type (authentication, network, file_access, process_creation)
    - severity (info, warning, error, critical)
    - action (allow, deny, create, modify, delete)
    - result (success, failure)
    - description (free text)
    
    Output Format: JSON or CEF (Common Event Format)
    
    Processing Steps:
    1. Parse original log format
    2. Extract relevant fields
    3. Map to unified schema
    4. Handle missing fields (set to null or "unknown")
    5. Validate output format
    6. Export for SIEM ingestion
    
    Learning Outcomes:
    ✓ Understand why normalization is critical
    ✓ Learn common log formats
    ✓ Practice data transformation
    ✓ Master schema design for correlation
    
    Files to Create:
    - log_normalizer.py
    - unified_schema.json
    - format_mappings.yaml
    - normalization_tests.py
    ```
    

#### 🎯 **Integration Exercise: Build Your SOC Detection Lab**

```
Project: "Deploy Production-Grade SIEM with Full Detection Coverage"

Phase 1: Infrastructure Setup (3-4 hours)
1. Deploy Wazuh Manager on Linux VM (or Elastic Stack)
2. Install Wazuh agents on 2 Windows VMs
3. Configure Sysmon on both Windows VMs
4. Setup pfSense firewall (or enable Windows Firewall logging)
5. Complete Log Ingestion Pipeline project
6. Verify all logs flowing to SIEM

Phase 2: Detection Engineering (4-5 hours)
1. Implement all 5 correlation rules from Custom Correlation Rule Builder
2. Test each rule by simulating the attack it detects
3. Document: Alert trigger conditions, tuning notes, false positive rate
4. Create Alert Dashboard with all widgets

Phase 3: Detection Validation (2-3 hours)
Simulate these attacks and verify your rules detect them:
- Brute Force: Run Hydra or manually try 10 failed logins
- Macro Malware: Create Word doc with macro launching PowerShell
- Privilege Escalation: Add test user to Administrators group
- Lateral Movement: RDP from VM1 → VM2 → VM3
- Port Scan: Run nmap against your systems

Phase 4: Query Mastery (2 hours)
Write queries to answer these investigative questions:
1. "Show me all failed logins from external IPs in last 24 hours"
2. "Which users have logged in from more than 3 different IPs today?"
3. "What processes were launched by PowerShell in the last week?"
4. "Show me all outbound connections to port 443 from suspicious processes"
5. "Find registry modifications in Run keys in last 30 days"

Deliverable: Complete SIEM Lab Documentation including:
- Architecture diagram showing all components
- Log sources inventory with sample logs from each
- All 5
```
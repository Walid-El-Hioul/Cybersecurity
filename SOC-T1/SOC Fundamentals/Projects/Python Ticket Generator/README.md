# SOC Ticket Generator

A command-line tool for generating realistic security incident tickets with CVSS v3.1 scoring, automatic team assignment, and lifecycle timestamp generation. Perfect for SOC training, SIEM ingestion testing, and incident response drills.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration Files](#configuration-files)
- [Ticket Structure](#ticket-structure)
- [CVSS v3.1 Scoring](#cvss-v31-scoring)
- [Team Assignment Logic](#team-assignment-logic)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Use Cases](#use-cases)

---

## Features

- **Realistic Ticket Generation**: Creates incident tickets with authentic SOC analyst notes and timestamps
- **CVSS v3.1 Calculator**: Automatically calculates vulnerability scores from CVSS vectors
- **Smart Team Assignment**: Routes tickets based on severity (Critical → Tier 2, High → Tier 1 Senior, etc.)
- **Multiple Export Formats**: Export to CSV, JSON, or both for SIEM ingestion
- **Configurable Templates**: Load custom incident scenarios from JSON
- **Lifecycle Timestamps**: Generates realistic detection, assignment, and escalation times
- **Status Simulation**: Tickets distributed across Open, In Progress, Escalated, and Closed states

---

## Installation

### Requirements

- Python 3.6+
- Required packages:
  ```bash
  pip install pyyaml
  ```

### Setup

1. Quick Download
   
   **Download this project only:** [Click here to download](https://minhaskamal.github.io/DownGit/#/home?url=https://github.com/Walid-El-Hioul/Cybersecurity/tree/main/SOC%20T1/SOC%20Fundamentals/Projects/Python%20Ticket%20Generator)

2. Initialize configuration files:
   ```bash
   python ticket_generator.py --init
   ```

This creates:
- `tickets_database.json` - 8 pre-configured incident templates
- `severity_rules.yaml` - Severity level definitions and SLA times

---

## Quick Start

```bash
# Initialize the tool (first time only)
python ticket_generator.py --init

# Generate 10 tickets
python ticket_generator.py --generate 10

# Generate 50 tickets to CSV
python ticket_generator.py -g 50 -o csv -f my_incidents.csv

# Verbose output with both formats
python ticket_generator.py -g 25 -o both -v
```

---

## Usage

### Command-Line Arguments

```
python ticket_generator.py [OPTIONS]

Options:
  -g, --generate N          Number of tickets to generate
  -o, --output FORMAT       Export format: csv, json, or both (default: both)
  -f, --file PATH          Output filename (without extension)
  -l, --load JSON          Load templates from JSON file (default: tickets_database.json)
  -v, --verbose            Enable verbose output
  --init                   Initialize sample config files and templates
  -h, --help               Show help message
```

### Status Indicators

The tool uses standard CLI status indicators:

| Indicator | Meaning |
|-----------|---------|
| `[+]` | Success or positive action completed |
| `[-]` | Error or failure occurred |
| `[*]` | Information or processing status |
| `[i]` | Tips or hints for the user |
| `[!]` | Warning message |

---

## Configuration Files

### tickets_database.json

Contains incident templates that are randomly selected during generation. Each template includes:

```json
{
  "templates": [
    {
      "title": "Suspicious PowerShell Execution Detected",
      "description": "Encoded PowerShell command executed from unusual parent process...",
      "category": "Malware",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
      "affected_systems": ["WKST-HR-042", "WKST-FIN-018"],
      "indicators": {
        "ip": "185.220.101.43",
        "hash": "a3d2c1e4f5b6..."
      }
    }
  ]
}
```

**Default Templates Include:**
- PowerShell malware execution
- Spear phishing with malicious attachments
- Brute force attacks
- Data exfiltration (DLP violations)
- Ransomware detection
- Credential harvesting
- C2 beaconing
- Privilege escalation attempts

### severity_rules.yaml

Defines severity levels, score ranges, and SLA requirements:

```yaml
severity_levels:
  - name: Critical
    min_score: 9.0
    max_score: 10.0
    sla_response: 15 minutes
    escalation: Immediate
  - name: High
    min_score: 7.0
    max_score: 8.9
    sla_response: 1 hour
    escalation: Within 2 hours
  # ... additional levels
```

---

## Ticket Structure

Each generated ticket contains the following fields:

### Core Fields

| Field | Description | Example |
|-------|-------------|---------|
| `id` | Unique ticket identifier | `TICKET-000042` |
| `title` | Brief incident description | `Suspicious PowerShell Execution Detected` |
| `description` | Detailed incident information | Full description text |
| `category` | Incident type | `Malware`, `Phishing`, `Brute Force`, `DLP` |
| `severity` | Calculated severity level | `Critical`, `High`, `Medium`, `Low`, `None` |
| `cvss_score` | Numerical CVSS v3.1 score | `8.8` |
| `cvss_vector` | Full CVSS vector string | `CVSS:3.1/AV:N/AC:L/PR:N/...` |

### Assignment Fields

| Field | Description | Example |
|-------|-------------|---------|
| `assigned_team` | Team handling the incident | `Tier 2 - Critical Response Team` |
| `analyst` | Assigned analyst name | `Sarah Chen` |
| `status` | Current ticket status | `Open`, `In Progress`, `Escalated`, `Closed` |

### Additional Data

| Field | Description |
|-------|-------------|
| `timestamps` | Detection, assignment, in_progress, escalated (if applicable) |
| `affected_systems` | List of impacted hosts/systems |
| `indicators` | IOCs (IPs, hashes, domains, etc.) |
| `notes` | Analyst comments and observations |

---

## CVSS v3.1 Scoring

The tool implements the complete CVSS v3.1 specification for vulnerability scoring.

### CVSS Vector Components

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
```

| Metric | Values | Description |
|--------|--------|-------------|
| **AV** (Attack Vector) | N, A, L, P | Network, Adjacent, Local, Physical |
| **AC** (Attack Complexity) | L, H | Low, High |
| **PR** (Privileges Required) | N, L, H | None, Low, High |
| **UI** (User Interaction) | N, R | None, Required |
| **S** (Scope) | U, C | Unchanged, Changed |
| **C** (Confidentiality) | N, L, H | None, Low, High |
| **I** (Integrity) | N, L, H | None, Low, High |
| **A** (Availability) | N, L, H | None, Low, High |

### Score Interpretation

| Score Range | Severity | Assignment |
|-------------|----------|------------|
| 9.0 - 10.0 | Critical | Tier 2 - Critical Response Team |
| 7.0 - 8.9 | High | Tier 1 Senior - Advanced Analysis |
| 4.0 - 6.9 | Medium | Tier 1 - Standard Analysis |
| 0.1 - 3.9 | Low | Tier 1 - Standard Analysis |
| 0.0 | None | Tier 1 - Routine Monitoring |

---

## Team Assignment Logic

Tickets are automatically assigned to appropriate teams based on severity:

### Assignment Rules

```python
Critical (9.0-10.0)
  ├─ Team: Tier 2 - Critical Response Team
  ├─ Analysts: Sarah Chen, Marcus Rodriguez, Aisha Patel
  ├─ SLA: 15 minutes
  └─ Escalation: Immediate

High (7.0-8.9)
  ├─ Team: Tier 1 Senior - Advanced Analysis
  ├─ Analysts: David Kim, Rachel Thompson, Omar Hassan
  ├─ SLA: 1 hour
  └─ Escalation: Within 2 hours

Medium (4.0-6.9)
  ├─ Team: Tier 1 - Standard Analysis
  ├─ Analysts: Emily Watson, James Lee, Sofia Martinez, Alex Chen
  ├─ SLA: 4 hours
  └─ Escalation: If unresolved in 24h

Low (0.1-3.9)
  ├─ Team: Tier 1 - Standard Analysis
  ├─ Analysts: Tyler Brown, Jessica Park, Chris Anderson, Maya Singh
  ├─ SLA: 24 hours
  └─ Escalation: If unresolved in 72h
```

### Status Distribution

Tickets are randomly assigned statuses with realistic probabilities:

- **Open**: 30%
- **In Progress**: 40%
- **Escalated**: 15% (Critical/High only), 5% (others)
- **Closed**: 20%

---

## Examples

### Basic Generation

Generate 10 tickets with default settings:

```bash
python ticket_generator.py --generate 10
```

Output:
```
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║               SOC Ticket Generator v1.0                          ║
║           Realistic Incident Ticket Generation Tool              ║
║                                                                   ║
║           [ Developed for Security Operations Training ]         ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

======================================================================
               TICKET GENERATION SUMMARY
======================================================================

[*] Total Tickets Generated: 10

[+] By Severity:
    Critical   ## (1)
    High       #### (2)
    Medium     ########## (5)
    Low        #### (2)

[+] By Category:
    Malware        ############ (6)
    Phishing       #### (2)
    Brute Force    ## (1)
    DLP            ## (1)

[+] By Status:
    Open           #### (2)
    In Progress    ######## (4)
    Escalated      ## (1)
    Closed         ###### (3)

======================================================================

[+] Successfully generated 10 tickets!
```

### CSV Export Only

Generate 50 tickets and export to CSV:

```bash
python ticket_generator.py -g 50 -o csv -f security_incidents.csv -v
```

Output:
```
[*] Loading templates from tickets_database.json...
[*] Generating 50 tickets...

[*] Exported 50 tickets to security_incidents.csv

[+] Successfully generated 50 tickets!
```

### Custom Templates

Create your own template file and use it:

```bash
# Create custom_scenarios.json
cat > custom_scenarios.json << 'EOF'
{
  "templates": [
    {
      "title": "Unauthorized API Access Attempt",
      "description": "Multiple 401 errors from external IP attempting to access admin API endpoints",
      "category": "Brute Force",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
      "affected_systems": ["API-GATEWAY-01"],
      "indicators": {"source_ip": "203.0.113.42"}
    }
  ]
}
EOF

# Generate using custom templates
python ticket_generator.py -l custom_scenarios.json -g 20 -v
```

### Batch Processing for SIEM

Generate large datasets for SIEM ingestion testing:

```bash
# Generate 1000 tickets in JSON format
python ticket_generator.py -g 1000 -o json -f siem_test_data.json

# Generate daily batches
for day in {1..7}; do
  python ticket_generator.py -g 100 -o both -f "day${day}_incidents"
done
```

---

## Troubleshooting

### Common Issues

#### Template File Not Found

```
[-] Template file not found: tickets_database.json
[i] Run with --init to create sample templates
```

**Solution**: Run initialization first:
```bash
python ticket_generator.py --init
```

#### Invalid CVSS Vector

```
[!] Bad CVSS vector: Missing AV
```

**Solution**: Ensure CVSS vectors follow the format:
```
CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X
```

All metrics (AV, AC, PR, UI, S, C, I, A) are required.

#### Empty Template File

```
[-] No templates found in file
```

**Solution**: Verify your JSON file has the correct structure:
```json
{
  "templates": [
    { /* template object */ }
  ]
}
```

#### Import Error for PyYAML

```
ModuleNotFoundError: No module named 'yaml'
```

**Solution**: Install required dependency:
```bash
pip install pyyaml
```

---

## Use Cases

### 1. SOC Analyst Training

Generate realistic tickets for new analysts to practice:

```bash
# Create training dataset
python ticket_generator.py -g 100 -o both -f training_tickets

# Distribute files to trainees for triage practice
```

### 2. SIEM Rule Testing

Test detection rules and parsing logic:

```bash
# Generate diverse incidents
python ticket_generator.py -g 500 -o json -f siem_test.json

# Import into SIEM for rule validation
```

### 3. Incident Response Drills

Create scenarios for IR team exercises:

```bash
# Generate critical incidents only (modify templates to have high CVSS)
python ticket_generator.py -g 10 -o both -f ir_drill_$(date +%Y%m%d)
```

### 4. Workflow Automation Testing

Test ticketing system integrations:

```bash
# Generate and push to ticketing API
python ticket_generator.py -g 50 -o json -f api_test.json
curl -X POST -H "Content-Type: application/json" \
  -d @api_test.json http://ticketing-system/api/bulk-import
```

### 5. Metrics and Reporting

Generate historical data for dashboard testing:

```bash
# Create 6 months of synthetic data
for month in {1..6}; do
  python ticket_generator.py -g 200 -o csv -f "historical_month${month}.csv"
done

# Import into BI tool for metric visualization
```

---

## Advanced Configuration

### Custom Severity Rules

Modify `severity_rules.yaml` to adjust thresholds:

```yaml
severity_levels:
  - name: Critical
    min_score: 8.5  # Lower threshold for faster escalation
    max_score: 10.0
    sla_response: 10 minutes
    escalation: Immediate
```

### Adding New Analysts

Edit the `_pick_analyst()` method in the script to add your team members:

```python
analysts = {
    'Critical': ['Sarah Chen', 'Marcus Rodriguez', 'Your Name Here'],
    'High': ['David Kim', 'Rachel Thompson', 'Another Analyst'],
    # ...
}
```

### Custom Categories

Add new incident categories to your templates:

```json
{
  "title": "Cryptocurrency Mining Detected",
  "category": "Unauthorized Activity",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H"
}
```

---

## Output Format Specifications

### CSV Format

```csv
ID,Title,Category,Severity,CVSS Score,Assigned Team,Analyst,Status,Detected
TICKET-000001,Suspicious PowerShell Execution,Malware,High,8.8,Tier 1 Senior,David Kim,In Progress,2024-11-02T14:32:15
```

### JSON Format

```json
{
  "generated_at": "2024-11-02T15:45:30.123456",
  "ticket_count": 10,
  "tickets": [
    {
      "id": "TICKET-000001",
      "title": "Suspicious PowerShell Execution Detected",
      "description": "Encoded PowerShell command executed...",
      "category": "Malware",
      "severity": "High",
      "cvss_score": 8.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
      "assigned_team": "Tier 1 Senior - Advanced Analysis",
      "analyst": "David Kim",
      "status": "In Progress",
      "timestamps": {
        "detected": "2024-11-02T14:32:15",
        "assigned": "2024-11-02T14:45:20",
        "in_progress": "2024-11-02T15:10:45",
        "escalated": "2024-11-02T16:30:12"
      },
      "affected_systems": ["WKST-HR-042", "WKST-FIN-018"],
      "indicators": {
        "ip": "185.220.101.43",
        "hash": "a3d2c1e4f5b6..."
      },
      "notes": [
        "Initial triage completed. Correlating with threat intel feeds.",
        "Escalating to IR team for deeper forensic analysis."
      ]
    }
  ]
}
```

---

## License

This tool is provided for educational and training purposes. Use responsibly and in accordance with your organization's security policies.

---

## Contributing

To add new features or templates:

1. Fork the repository
2. Create feature branch
3. Add templates to `tickets_database.json`
4. Update documentation
5. Submit pull request

---

## Support

For issues, questions, or feature requests:

- Check the [Troubleshooting](#troubleshooting) section
- Review existing templates in `tickets_database.json`
- Validate CVSS vectors at https://www.first.org/cvss/calculator/3.1

---

**Version**: 1.0  
**Last Updated**: November 2024  
**Developed for Security Operations Training**
# Description: Build a CLI tool that generates realistic incident tickets

# Technical Requirements:
# - Create ticket class with fields: ID, Severity (Critical/High/Medium/Low/None), 
#     Status (Open/In Progress/Escalated/Closed), Category (Malware/Phishing/Brute Force/DLP)
# - Implement CVSS v3.1 calculator for vulnerability scoring
# - Auto-assign based on severity (Critical → T2, High → T1 Senior, Medium/Low → T1)
# - Generate timestamps following incident lifecycle phases
# - Export to CSV/JSON for SIEM ingestion practice

# Learning Outcomes:
# ✓ Understand ticket anatomy and required fields
# ✓ Practice severity classification logic
# ✓ Learn escalation trigger points
# ✓ Master documentation standards

# Files to Create:
# - ticket_generator.py
# - tickets_database.json
# - severity_rules.yaml

"""
SOC Ticket Generator - Creates realistic security incident tickets for practice

Handles ticket creation with CVSS scoring, auto-assignment, and timestamp generation.
Useful for training exercises and SIEM ingestion testing.
"""

import yaml
import json
import csv
import argparse
import sys
from datetime import datetime, timedelta
import random
from pathlib import Path


# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Additional colors for variety
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'


class Ticket:
    _counter = 0
    
    METRICS = {
        "attack_vector": {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2},
        "attack_complexity": {"low": 0.77, "high": 0.44},
        "privileges_required": {"none": 0.85, "low": 0.62, "high": 0.27},
        "user_interaction": {"none": 0.85, "required": 0.62},
        "scope": {"unchanged": 1.0, "changed": 1.08},
        "confidentiality_impact": {"none": 0.0, "low": 0.22, "high": 0.56},
        "integrity_impact": {"none": 0.0, "low": 0.22, "high": 0.56},
        "availability_impact": {"none": 0.0, "low": 0.22, "high": 0.56}
    }

    def __init__(self, ticket_data):
        Ticket._counter += 1
        self.id = f"TICKET-{Ticket._counter:06d}"
        self.title = ticket_data.get('title', '')
        self.description = ticket_data.get('description', '')
        self.category = ticket_data.get('category', 'Malware')
        self.cvss_vector = ticket_data.get('cvss_vector', '')
        self.affected_systems = ticket_data.get('affected_systems', [])
        self.indicators = ticket_data.get('indicators', {})
        
        if self.cvss_vector:
            try:
                self.cvss_score = self._calc_cvss_from_vector(self.cvss_vector)
                self.severity = self._score_to_severity(self.cvss_score)
            except ValueError as e:
                print(f"{Colors.WARNING}[!]{Colors.RESET} Bad CVSS vector: {e}")
                self.cvss_score = 0.0
                self.severity = "None"
        else:
            self.cvss_score = 0.0
            self.severity = "None"

        self.assigned_team = self._pick_team()
        self.analyst = self._pick_analyst()
        self.timestamps = self._gen_timestamps()
        self.status = self._determine_status()
        self.notes = self._gen_notes()

    def _calc_cvss_from_vector(self, vector):
        if not vector.startswith("CVSS:3.1/"):
            raise ValueError("Need a CVSS:3.1/ vector")
        
        parts = vector.replace("CVSS:3.1/", "").split('/')
        raw_metrics = {}
        for part in parts:
            if ':' in part:
                k, v = part.split(':', 1)
                raw_metrics[k] = v
        
        mapping = {
            'AV': ('attack_vector', {'N': 'network', 'A': 'adjacent', 'L': 'local', 'P': 'physical'}),
            'AC': ('attack_complexity', {'L': 'low', 'H': 'high'}),
            'PR': ('privileges_required', {'N': 'none', 'L': 'low', 'H': 'high'}),
            'UI': ('user_interaction', {'N': 'none', 'R': 'required'}),
            'S': ('scope', {'U': 'unchanged', 'C': 'changed'}),
            'C': ('confidentiality_impact', {'H': 'high', 'L': 'low', 'N': 'none'}),
            'I': ('integrity_impact', {'H': 'high', 'L': 'low', 'N': 'none'}),
            'A': ('availability_impact', {'H': 'high', 'L': 'low', 'N': 'none'})
        }
        
        metrics = {}
        for code, (name, vals) in mapping.items():
            if code not in raw_metrics:
                raise ValueError(f"Missing {code}")
            short = raw_metrics[code]
            if short not in vals:
                raise ValueError(f"Bad value {short} for {code}")
            metrics[name] = vals[short]
        
        return self._calc_cvss(metrics)

    def _calc_cvss(self, m):
        AV = self.METRICS["attack_vector"][m["attack_vector"]]
        AC = self.METRICS["attack_complexity"][m["attack_complexity"]]
        PR = self.METRICS["privileges_required"][m["privileges_required"]]
        UI = self.METRICS["user_interaction"][m["user_interaction"]]
        S = self.METRICS["scope"][m["scope"]]
        C = self.METRICS["confidentiality_impact"][m["confidentiality_impact"]]
        I = self.METRICS["integrity_impact"][m["integrity_impact"]]
        A = self.METRICS["availability_impact"][m["availability_impact"]]
        
        ISS = 1 - ((1 - C) * (1 - I) * (1 - A))
        
        if S == 1.0:
            Impact = 6.42 * ISS
        else:
            Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02) ** 15
        
        Exploitability = 8.22 * AV * AC * PR * UI
        
        if Impact <= 0:
            return 0.0
        
        if S == 1.0:
            score = min(Impact + Exploitability, 10)
        else:
            score = min(1.08 * (Impact + Exploitability), 10)
        
        return round(score, 1)

    def _score_to_severity(self, score):
        try:
            with open("severity_rules.yaml", "r") as f:
                config = yaml.safe_load(f)
                levels = config.get('severity_levels', [])
        except FileNotFoundError:
            levels = [
                {'name': 'Critical', 'min_score': 9.0, 'max_score': 10.0},
                {'name': 'High', 'min_score': 7.0, 'max_score': 8.9},
                {'name': 'Medium', 'min_score': 4.0, 'max_score': 6.9},
                {'name': 'Low', 'min_score': 0.1, 'max_score': 3.9},
                {'name': 'None', 'min_score': 0.0, 'max_score': 0.0}
            ]
        
        for level in levels:
            if level['min_score'] <= score <= level['max_score']:
                return level['name']
        
        return 'Unknown'

    def _pick_team(self):
        assignments = {
            'Critical': 'Tier 2 - Critical Response Team',
            'High': 'Tier 1 Senior - Advanced Analysis',
            'Medium': 'Tier 1 - Standard Analysis',
            'Low': 'Tier 1 - Standard Analysis',
            'None': 'Tier 1 - Routine Monitoring'
        }
        return assignments.get(self.severity, 'Tier 1 - Standard Analysis')

    def _pick_analyst(self):
        analysts = {
            'Critical': ['Sarah Chen', 'Marcus Rodriguez', 'Aisha Patel'],
            'High': ['David Kim', 'Rachel Thompson', 'Omar Hassan'],
            'Medium': ['Emily Watson', 'James Lee', 'Sofia Martinez', 'Alex Chen'],
            'Low': ['Tyler Brown', 'Jessica Park', 'Chris Anderson', 'Maya Singh']
        }
        pool = analysts.get(self.severity, analysts['Medium'])
        return random.choice(pool)

    def _gen_timestamps(self):
        detected = datetime.now() - timedelta(hours=random.randint(1, 24))
        
        times = {
            'detected': detected.isoformat(),
            'assigned': (detected + timedelta(minutes=random.randint(5, 30))).isoformat(),
            'in_progress': (detected + timedelta(minutes=random.randint(30, 120))).isoformat()
        }
        
        if self.severity in ['Critical', 'High']:
            times['escalated'] = (detected + timedelta(hours=random.randint(1, 4))).isoformat()
        
        return times

    def _determine_status(self):
        weights = {
            'Open': 0.3,
            'In Progress': 0.4,
            'Escalated': 0.15 if self.severity in ['Critical', 'High'] else 0.05,
            'Closed': 0.2
        }
        return random.choices(list(weights.keys()), weights=list(weights.values()))[0]

    def _gen_notes(self):
        notes_pool = [
            "Initial triage completed. Correlating with threat intel feeds.",
            "Checking for lateral movement indicators across the network.",
            "User contacted for additional context. Awaiting response.",
            "EDR telemetry shows no further suspicious activity.",
            "Escalating to IR team for deeper forensic analysis.",
            "False positive - benign application behavior confirmed.",
            "Containment measures applied. Monitoring for reoccurrence.",
            "Indicators added to blocklist. SIEM rules updated."
        ]
        return random.sample(notes_pool, k=random.randint(1, 3))

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'assigned_team': self.assigned_team,
            'analyst': self.analyst,
            'status': self.status,
            'timestamps': self.timestamps,
            'affected_systems': self.affected_systems,
            'indicators': self.indicators,
            'notes': self.notes
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

    def to_csv_row(self):
        return [
            self.id, self.title, self.category, self.severity, 
            self.cvss_score, self.assigned_team, self.analyst, 
            self.status, self.timestamps.get('detected', '')
        ]


def print_banner():
    """Display Kali-style ASCII banner"""
    banner = f"""
{Colors.CYAN}
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║{Colors.BOLD}               SOC Ticket Generator v1.0                           {Colors.RESET}{Colors.CYAN}║
║{Colors.WHITE}           Realistic Incident Ticket Generation Tool               {Colors.RESET}{Colors.CYAN}║
║                                                                   ║
║           [ Developed for Security Operations Training ]          ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def create_sample_database():
    """Generate tickets_database.json with realistic incident scenarios"""
    templates = [
        {
            "title": "Suspicious PowerShell Execution Detected",
            "description": "Encoded PowerShell command executed from unusual parent process. Command attempts to download remote payload from suspicious domain.",
            "category": "Malware",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "affected_systems": ["WKST-HR-042", "WKST-FIN-018"],
            "indicators": {"ip": "185.220.101.43", "hash": "a3d2c1e4f5b6..."}
        },
        {
            "title": "Spear Phishing Email with Malicious Attachment",
            "description": "Employee reported suspicious email claiming to be from IT department. Contains macro-enabled Excel document with invoice theme.",
            "category": "Phishing",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
            "affected_systems": ["MAIL-USER-jane.doe@company.com"],
            "indicators": {"sender": "it-supp0rt@c0mpany-tech.com", "subject": "URGENT: Invoice Payment Required"}
        },
        {
            "title": "Multiple Failed Login Attempts - Brute Force Attack",
            "description": "Abnormal number of failed authentication attempts detected from multiple IP addresses targeting admin accounts over 15-minute window.",
            "category": "Brute Force",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
            "affected_systems": ["VPN-GATEWAY-01", "DC-PRIMARY"],
            "indicators": {"source_ips": ["45.142.212.61", "193.218.118.74"], "target_account": "admin"}
        },
        {
            "title": "Sensitive Data Uploaded to Unauthorized Cloud Storage",
            "description": "DLP policy triggered on large file transfer to personal Dropbox account. File contains customer PII and financial records.",
            "category": "DLP",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "affected_systems": ["WKST-SALES-089"],
            "indicators": {"user": "john.smith", "destination": "dropbox.com", "file_size": "245MB"}
        },
        {
            "title": "Ransomware Indicators Detected on File Server",
            "description": "Rapid file encryption activity observed. Multiple files renamed with .locked extension. Ransom note created in shared directories.",
            "category": "Malware",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "affected_systems": ["FILE-SRV-03", "BACKUP-SRV-01"],
            "indicators": {"process": "svchost32.exe", "note_file": "README_DECRYPT.txt"}
        },
        {
            "title": "Credential Harvesting Attempt via Fake Login Page",
            "description": "Users reported being redirected to convincing clone of company portal. Domain registered 3 days ago, hosting credential phishing site.",
            "category": "Phishing",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
            "affected_systems": ["Multiple user workstations"],
            "indicators": {"phishing_domain": "company-l0gin.com", "registrar": "NameCheap"}
        },
        {
            "title": "Unusual Outbound Traffic to Known C2 Infrastructure",
            "description": "Firewall logs show sustained connection to IP address associated with Emotet botnet. Encrypted traffic patterns consistent with C2 beaconing.",
            "category": "Malware",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
            "affected_systems": ["WKST-IT-007"],
            "indicators": {"c2_ip": "104.168.155.129", "port": "8080", "malware_family": "Emotet"}
        },
        {
            "title": "Privilege Escalation Attempt on Database Server",
            "description": "Non-privileged account attempted to execute commands requiring elevated permissions. Multiple CVE exploitation attempts logged.",
            "category": "Malware",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:L",
            "affected_systems": ["DB-PROD-02"],
            "indicators": {"account": "webservice_user", "cve": "CVE-2023-12345"}
        }
    ]
    
    with open("tickets_database.json", "w") as f:
        json.dump({"templates": templates}, f, indent=2)
    
    print(f"{Colors.GREEN}[+]{Colors.RESET} Created tickets_database.json with 8 incident templates")


def create_severity_rules():
    """Generate severity_rules.yaml configuration file"""
    config = {
        'severity_levels': [
            {'name': 'Critical', 'min_score': 9.0, 'max_score': 10.0, 
             'sla_response': '15 minutes', 'escalation': 'Immediate'},
            {'name': 'High', 'min_score': 7.0, 'max_score': 8.9,
             'sla_response': '1 hour', 'escalation': 'Within 2 hours'},
            {'name': 'Medium', 'min_score': 4.0, 'max_score': 6.9,
             'sla_response': '4 hours', 'escalation': 'If unresolved in 24h'},
            {'name': 'Low', 'min_score': 0.1, 'max_score': 3.9,
             'sla_response': '24 hours', 'escalation': 'If unresolved in 72h'},
            {'name': 'None', 'min_score': 0.0, 'max_score': 0.0,
             'sla_response': 'Best effort', 'escalation': 'Not applicable'}
        ]
    }
    
    with open("severity_rules.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)
    
    print(f"{Colors.GREEN}[+]{Colors.RESET} Created severity_rules.yaml with SLA definitions")


def load_templates(filepath):
    """Load ticket templates from JSON file"""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            return data.get('templates', [])
    except FileNotFoundError:
        print(f"{Colors.RED}[-]{Colors.RESET} Template file not found: {Colors.YELLOW}{filepath}{Colors.RESET}")
        print(f"{Colors.CYAN}[i]{Colors.RESET} Run with --init to create sample templates")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"{Colors.RED}[-]{Colors.RESET} Invalid JSON in template file: {Colors.YELLOW}{filepath}{Colors.RESET}")
        sys.exit(1)


def export_to_csv(tickets, filepath, verbose=False):
    """Export tickets to CSV format"""
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'Title', 'Category', 'Severity', 'CVSS Score', 
                        'Assigned Team', 'Analyst', 'Status', 'Detected'])
        
        for ticket in tickets:
            writer.writerow(ticket.to_csv_row())
    
    if verbose:
        print(f"{Colors.BLUE}[*]{Colors.RESET} Exported {Colors.BOLD}{len(tickets)}{Colors.RESET} tickets to {Colors.YELLOW}{filepath}{Colors.RESET}")


def export_to_json(tickets, filepath, verbose=False):
    """Export tickets to JSON format"""
    data = {
        'generated_at': datetime.now().isoformat(),
        'ticket_count': len(tickets),
        'tickets': [ticket.to_dict() for ticket in tickets]
    }
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    if verbose:
        print(f"{Colors.BLUE}[*]{Colors.RESET} Exported {Colors.BOLD}{len(tickets)}{Colors.RESET} tickets to {Colors.YELLOW}{filepath}{Colors.RESET}")


def display_summary(tickets):
    """Show a nice summary of generated tickets"""
    print("\n" + Colors.CYAN + "="*70)
    print(f"{Colors.BOLD}               TICKET GENERATION SUMMARY{Colors.RESET}")
    print(Colors.CYAN + "="*70 + Colors.RESET)
    
    by_severity = {}
    by_category = {}
    by_status = {}
    
    for ticket in tickets:
        by_severity[ticket.severity] = by_severity.get(ticket.severity, 0) + 1
        by_category[ticket.category] = by_category.get(ticket.category, 0) + 1
        by_status[ticket.status] = by_status.get(ticket.status, 0) + 1
    
    print(f"\n{Colors.BLUE}[*]{Colors.RESET} Total Tickets Generated: {Colors.BOLD}{len(tickets)}{Colors.RESET}")
    
    print(f"\n{Colors.GREEN}[+]{Colors.RESET} By Severity:")
    severity_colors = {
        'Critical': Colors.RED,
        'High': Colors.YELLOW,
        'Medium': Colors.BLUE,
        'Low': Colors.GREEN,
        'None': Colors.WHITE
    }
    for severity in ['Critical', 'High', 'Medium', 'Low', 'None']:
        count = by_severity.get(severity, 0)
        if count > 0:
            color = severity_colors.get(severity, Colors.WHITE)
            bar = "#" * (count * 2)
            print(f"    {color}{severity:<10}{Colors.RESET} {Colors.BOLD}{bar}{Colors.RESET} ({count})")
    
    print(f"\n{Colors.GREEN}[+]{Colors.RESET} By Category:")
    for cat, count in by_category.items():
        bar = "#" * (count * 2)
        print(f"    {Colors.CYAN}{cat:<14}{Colors.RESET} {Colors.BOLD}{bar}{Colors.RESET} ({count})")
    
    print(f"\n{Colors.GREEN}[+]{Colors.RESET} By Status:")
    status_colors = {
        'Open': Colors.YELLOW,
        'In Progress': Colors.BLUE,
        'Escalated': Colors.RED,
        'Closed': Colors.GREEN
    }
    for status, count in by_status.items():
        color = status_colors.get(status, Colors.WHITE)
        bar = "#" * (count * 2)
        print(f"    {color}{status:<14}{Colors.RESET} {Colors.BOLD}{bar}{Colors.RESET} ({count})")
    
    print("\n" + Colors.CYAN + "="*70 + Colors.RESET)


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='SOC Ticket Generator - Create realistic security incident tickets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --generate 10 --output both
  %(prog)s --generate 50 --output csv --file incidents.csv
  %(prog)s --load custom_templates.json --generate 20 --verbose
  %(prog)s --init  # Create sample config files
        '''
    )
    
    parser.add_argument('--generate', '-g', type=int, metavar='N',
                       help='Number of tickets to generate')
    parser.add_argument('--output', '-o', choices=['csv', 'json', 'both'],
                       default='both', help='Export format (default: both)')
    parser.add_argument('--file', '-f', type=str, metavar='PATH',
                       help='Output filename (without extension)')
    parser.add_argument('--load', '-l', type=str, metavar='JSON',
                       default='tickets_database.json',
                       help='Load templates from JSON file (default: tickets_database.json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--init', action='store_true',
                       help='Initialize sample config files and templates')
    
    args = parser.parse_args()
    
    # Handle initialization
    if args.init:
        print(f"{Colors.BLUE}[*]{Colors.RESET} Initializing SOC Ticket Generator...\n")
        create_sample_database()
        create_severity_rules()
        print(f"\n{Colors.GREEN}[+]{Colors.RESET} Setup complete! Run with --generate to create tickets.")
        return
    
    # Require --generate if not --init
    if not args.generate:
        parser.print_help()
        print(f"\n{Colors.CYAN}[i]{Colors.RESET} Tip: Run with --init first to create sample templates")
        return
    
    if args.verbose:
        print(f"{Colors.BLUE}[*]{Colors.RESET} Loading templates from {Colors.YELLOW}{args.load}{Colors.RESET}...")
    
    templates = load_templates(args.load)
    
    if not templates:
        print(f"{Colors.RED}[-]{Colors.RESET} No templates found in file")
        return
    
    # Generate tickets
    if args.verbose:
        print(f"{Colors.BLUE}[*]{Colors.RESET} Generating {Colors.BOLD}{args.generate}{Colors.RESET} tickets...\n")
    
    tickets = []
    for _ in range(args.generate):
        template = random.choice(templates)
        tickets.append(Ticket(template))
    
    # Determine output filename
    if args.file:
        base_filename = args.file
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = "incidents_{}".format(timestamp)
    
    # Export
    if args.output in ['csv', 'both']:
        csv_file = "{}.csv".format(base_filename) if not args.file or not args.file.endswith('.csv') else args.file
        export_to_csv(tickets, csv_file, args.verbose)
    
    if args.output in ['json', 'both']:
        json_file = "{}.json".format(base_filename) if not args.file or not args.file.endswith('.json') else args.file
        export_to_json(tickets, json_file, args.verbose)
    
    # Display summary
    display_summary(tickets)
    
    print(f"\n{Colors.GREEN}[+]{Colors.RESET} Successfully generated {Colors.BOLD}{args.generate}{Colors.RESET} tickets!")
    if not args.verbose:
        print(f"{Colors.CYAN}[i]{Colors.RESET} Run with --verbose for detailed export information")


if __name__ == "__main__":
    main()
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
from datetime import datetime, timedelta
import random


class Ticket:
    _counter = 0
    
    # CVSS v3.1 metric values - yeah these are standardized
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
        
        # Try to calculate CVSS, fall back gracefully if it fails
        if self.cvss_vector:
            try:
                self.cvss_score = self._calc_cvss_from_vector(self.cvss_vector)
                self.severity = self._score_to_severity(self.cvss_score)
            except ValueError as e:
                print(f"Bad CVSS vector: {e}")
                self.cvss_score = 0.0
                self.severity = "None"
        else:
            self.cvss_score = 0.0
            self.severity = "None"

        self.assigned_team = self._pick_team()
        self.timestamps = self._gen_timestamps()
        self.status = "Open"

    def _calc_cvss_from_vector(self, vector):
        """Parse CVSS vector and calculate the score"""
        if not vector.startswith("CVSS:3.1/"):
            raise ValueError("Need a CVSS:3.1/ vector")
        
        # Parse the vector string
        parts = vector.replace("CVSS:3.1/", "").split('/')
        raw_metrics = {}
        for part in parts:
            if ':' in part:
                k, v = part.split(':', 1)
                raw_metrics[k] = v
        
        # Map short codes to full names
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
        """The actual CVSS v3.1 calculation - this is straight from the spec"""
        AV = self.METRICS["attack_vector"][m["attack_vector"]]
        AC = self.METRICS["attack_complexity"][m["attack_complexity"]]
        PR = self.METRICS["privileges_required"][m["privileges_required"]]
        UI = self.METRICS["user_interaction"][m["user_interaction"]]
        S = self.METRICS["scope"][m["scope"]]
        C = self.METRICS["confidentiality_impact"][m["confidentiality_impact"]]
        I = self.METRICS["integrity_impact"][m["integrity_impact"]]
        A = self.METRICS["availability_impact"][m["availability_impact"]]
        
        # Impact sub-score
        ISS = 1 - ((1 - C) * (1 - I) * (1 - A))
        
        # Calculate impact based on scope
        if S == 1.0:
            Impact = 6.42 * ISS
        else:
            Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02) ** 15
        
        # Exploitability
        Exploitability = 8.22 * AV * AC * PR * UI
        
        # Final score
        if Impact <= 0:
            return 0.0
        
        if S == 1.0:
            score = min(Impact + Exploitability, 10)
        else:
            score = min(1.08 * (Impact + Exploitability), 10)
        
        return round(score, 1)

    def _score_to_severity(self, score):
        """Map CVSS score to severity level"""
        # Try loading from config, otherwise use defaults
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
        """Assign to appropriate team based on severity"""
        assignments = {
            'Critical': 'Tier 2 - Critical Response Team',
            'High': 'Tier 1 Senior - Advanced Analysis',
            'Medium': 'Tier 1 - Standard Analysis',
            'Low': 'Tier 1 - Standard Analysis',
            'None': 'Tier 1 - Routine Monitoring'
        }
        return assignments.get(self.severity, 'Tier 1 - Standard Analysis')

    def _gen_timestamps(self):
        """Generate timestamps that look like a real incident timeline"""
        # Start somewhere in the last 24 hours
        detected = datetime.now() - timedelta(hours=random.randint(1, 24))
        
        times = {
            'detected': detected.isoformat(),
            'assigned': (detected + timedelta(minutes=random.randint(5, 30))).isoformat(),
            'in_progress': (detected + timedelta(minutes=random.randint(30, 120))).isoformat()
        }
        
        # Critical/High tickets get escalated
        if self.severity in ['Critical', 'High']:
            times['escalated'] = (detected + timedelta(hours=random.randint(1, 4))).isoformat()
        
        return times

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
            'status': self.status,
            'timestamps': self.timestamps
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

    def to_csv_row(self):
        return f"{self.id},{self.title},{self.category},{self.severity},{self.cvss_score},{self.assigned_team},{self.status}"
    

# TODO: Build the CLI interface
# - Import argparse for command-line args
# - Add main() function with:
#   * --generate N (number of tickets to create)
#   * --output [csv|json|both] (export format)
#   * --file <path> (output filename)
#   * --load <json> (load ticket templates from tickets_database.json)
# - Create sample tickets_database.json with realistic incident scenarios
# - Write export_to_csv() and export_to_json() functions
# - Add if __name__ == "__main__": block to run the CLI
# - Maybe throw in a --verbose flag for debugging

# The class is done, just needs the CLI wrapper to actually use it
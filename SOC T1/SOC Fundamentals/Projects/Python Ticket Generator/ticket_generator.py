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

import yaml
import json
from datetime import datetime, timedelta
import random

class Ticket:
    _id_counter = 0

    def __init__(self, ticket_data):
        Ticket._id_counter += 1
        self.id = f"TICKET-{Ticket._id_counter:06d}"
        self.ticket_title = ticket_data.get('title', '')
        self.ticket_description = ticket_data.get('description', '')
        self.ticket_cvss_vector = ticket_data.get('cvss_vector', '')  # Fixed typo
        self.category = ticket_data.get('category', 'Malware')
        self.cvss_config = self.load_cvss_config()
        
        # Initialize CVSS metrics
        self.CVSS_METRICS = {
            "attack_vector": {
                "network": 0.85,
                "adjacent": 0.62,
                "local": 0.55,
                "physical": 0.2
            },
            "attack_complexity": {
                "low": 0.77,
                "high": 0.44
            },
            "privileges_required": {
                "none": 0.85,
                "low": 0.62,
                "high": 0.27
            },
            "user_interaction": {
                "none": 0.85,
                "required": 0.62
            },
            "scope": {
                "unchanged": 1.0,
                "changed": 1.08
            },
            "confidentiality_impact": {
                "none": 0.0,
                "low": 0.22,
                "high": 0.56
            },
            "integrity_impact": {
                "none": 0.0,
                "low": 0.22,
                "high": 0.56
            },
            "availability_impact": {
                "none": 0.0,
                "low": 0.22,
                "high": 0.56
            }
        }

        # Calculate CVSS score and severity
        if self.ticket_cvss_vector:
            try:
                self.cvss_score = self.calculate_from_vector(self.ticket_cvss_vector)
                self.severity = self.get_severity_from_score(self.cvss_score)
            except ValueError as e:
                print(f"Error parsing CVSS vector: {e}")
                self.cvss_score = 0.0
                self.severity = "None"
        else:
            self.cvss_score = 0.0
            self.severity = "None"

        # Auto-assign based on severity
        self.assigned_team = self.auto_assign_team()
        
        # Generate timestamps
        self.timestamps = self.generate_timestamps()
        
        # Set initial status
        self.status = "Open"

    def load_cvss_config(self, file_path="severity_rules.yaml"):
        try:
            with open(file_path, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return {
                'severity_levels': [
                    {'name': 'Critical', 'min_score': 9.0, 'max_score': 10.0},
                    {'name': 'High', 'min_score': 7.0, 'max_score': 8.9},
                    {'name': 'Medium', 'min_score': 4.0, 'max_score': 6.9},
                    {'name': 'Low', 'min_score': 0.1, 'max_score': 3.9},
                    {'name': 'None', 'min_score': 0.0, 'max_score': 0.0}
                ]
            }

    def calculate_cvss_score(self, metrics):
        """
        Calculate CVSS v3.1 Base Score
        """
        # Get values from metrics
        AV = self.CVSS_METRICS["attack_vector"][metrics["attack_vector"]]
        AC = self.CVSS_METRICS["attack_complexity"][metrics["attack_complexity"]]
        PR = self.CVSS_METRICS["privileges_required"][metrics["privileges_required"]]
        UI = self.CVSS_METRICS["user_interaction"][metrics["user_interaction"]]
        S = self.CVSS_METRICS["scope"][metrics["scope"]]
        C = self.CVSS_METRICS["confidentiality_impact"][metrics["confidentiality_impact"]]
        I = self.CVSS_METRICS["integrity_impact"][metrics["integrity_impact"]]
        A = self.CVSS_METRICS["availability_impact"][metrics["availability_impact"]]
        
        # Calculate Impact Sub-Score (ISS)
        ISS = 1 - ((1 - C) * (1 - I) * (1 - A))
        
        # Calculate Impact
        if S == 1.0:  # unchanged
            Impact = 6.42 * ISS
        else:  # changed
            Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02) ** 15
        
        # Calculate Exploitability
        Exploitability = 8.22 * AV * AC * PR * UI
        
        # Calculate Base Score
        if Impact <= 0:
            BaseScore = 0
        else:
            if S == 1.0:  # unchanged
                BaseScore = min(Impact + Exploitability, 10)
            else:
                BaseScore = min(1.08 * (Impact + Exploitability), 10)
        
        return round(BaseScore, 1)
    
    def parse_cvss_vector(self, cvss_vector):
        """
        Parse CVSS v3.1 vector string and return metrics dictionary
        """
        if not cvss_vector or not cvss_vector.startswith("CVSS:3.1/"):
            raise ValueError("Invalid CVSS v3.1 vector format")
        
        vector_string = cvss_vector.replace("CVSS:3.1/", "")
        
        metrics = {}
        for metric in vector_string.split('/'):
            if ':' in metric:
                key, value = metric.split(':', 1)
                metrics[key] = value
        
        metric_mapping = {
            'AV': ('attack_vector', {
                'N': 'network', 'A': 'adjacent', 
                'L': 'local', 'P': 'physical'
            }),
            'AC': ('attack_complexity', {
                'L': 'low', 'H': 'high'
            }),
            'PR': ('privileges_required', {
                'N': 'none', 'L': 'low', 'H': 'high'
            }),
            'UI': ('user_interaction', {
                'N': 'none', 'R': 'required'
            }),
            'S': ('scope', {
                'U': 'unchanged', 'C': 'changed'
            }),
            'C': ('confidentiality_impact', {
                'H': 'high', 'L': 'low', 'N': 'none'
            }),
            'I': ('integrity_impact', {
                'H': 'high', 'L': 'low', 'N': 'none'
            }),
            'A': ('availability_impact', {
                'H': 'high', 'L': 'low', 'N': 'none'
            })
        }
        
        parsed_metrics = {}
        for short_key, (full_key, value_map) in metric_mapping.items():
            if short_key in metrics:
                short_value = metrics[short_key]
                if short_value in value_map:
                    parsed_metrics[full_key] = value_map[short_value]
                else:
                    raise ValueError(f"Invalid value '{short_value}' for metric '{short_key}'")
            else:
                raise ValueError(f"Missing required metric: {short_key}")
        
        return parsed_metrics

    def calculate_from_vector(self, cvss_vector):
        """
        Calculate CVSS score directly from vector string
        """
        metrics = self.parse_cvss_vector(cvss_vector)
        return self.calculate_cvss_score(metrics)

    def get_severity_from_score(self, score):
        """
        Determine severity level based on CVSS score
        """
        severity_levels = self.cvss_config.get('severity_levels', [])
        
        for level in severity_levels:
            min_score = level['min_score']
            max_score = level['max_score']
            if min_score <= score <= max_score:
                return level['name']
        
        return 'Unknown'

    def auto_assign_team(self):
        """
        Auto-assign team based on severity
        """
        assignment_rules = {
            'Critical': 'Tier 2 - Critical Response Team',
            'High': 'Tier 1 Senior - Advanced Analysis',
            'Medium': 'Tier 1 - Standard Analysis',
            'Low': 'Tier 1 - Standard Analysis',
            'None': 'Tier 1 - Routine Monitoring'
        }
        return assignment_rules.get(self.severity, 'Tier 1 - Standard Analysis')

    def generate_timestamps(self):
        """
        Generate realistic incident lifecycle timestamps
        """
        base_time = datetime.now() - timedelta(hours=random.randint(1, 24))
        
        timestamps = {
            'detected': base_time.isoformat(),
            'assigned': (base_time + timedelta(minutes=random.randint(5, 30))).isoformat(),
            'in_progress': (base_time + timedelta(minutes=random.randint(30, 120))).isoformat()
        }
        
        # Add escalation for high/critical tickets
        if self.severity in ['Critical', 'High']:
            timestamps['escalated'] = (base_time + timedelta(hours=random.randint(1, 4))).isoformat()
        
        return timestamps

    def to_dict(self):
        """
        Convert ticket to dictionary for export
        """
        return {
            'id': self.id,
            'title': self.ticket_title,
            'description': self.ticket_description,
            'category': self.category,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.ticket_cvss_vector,
            'assigned_team': self.assigned_team,
            'status': self.status,
            'timestamps': self.timestamps
        }

    def to_json(self):
        """
        Convert ticket to JSON string
        """
        return json.dumps(self.to_dict(), indent=2)

    def to_csv_row(self):
        """
        Convert ticket to CSV row format
        """
        return f"{self.id},{self.ticket_title},{self.category},{self.severity},{self.cvss_score},{self.assigned_team},{self.status}"


if __name__ == "__main__":  # Fixed this line
    # Example usage:
    ticket_data = {
        'title': 'Remote Code Execution Vulnerability',
        'description': 'Critical RCE in web server',
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  # Score: 9.8
        'category': 'Malware'
    }

    ticket = Ticket(ticket_data)
    print(f"Ticket ID: {ticket.id}")
    print(f"CVSS Score: {ticket.cvss_score}")
    print(f"Severity: {ticket.severity}")
    print(f"Assigned Team: {ticket.assigned_team}")
    print(f"Status: {ticket.status}")
    print("\nJSON Export:")
    print(ticket.to_json())
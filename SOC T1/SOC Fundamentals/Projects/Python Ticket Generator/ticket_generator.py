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

class Ticket:
    _id_counter = 0

    def __init__(self, ticket):
        Ticket._id_counter += 1
        self.id = Ticket._id_counter
        self.severity = ["None", "Low", "Medium", "High", "Critical"]
        self.status = ["Open", "In Progress", "Escalated", "Closed"]
        self.category = ["Malware", "Phishing", "BruteForce", "DLP"]
        self.cvss = self.load_cvss_config()

    def load_cvss_config(self, file_path="severity_rules.py"):
        with open(file_path, "r") as f:
            return yaml.safe_load(f)
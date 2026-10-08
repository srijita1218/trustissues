MITRE_MAPPINGS = {
    "TI-001": {
        "technique": "T1204.002",
        "name": "User Execution: Malicious File",
    },
    "TI-002": {
        "technique": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
    },
    "TI-003": {
        "technique": "T1204.002",
        "name": "User Execution: Malicious File",
    },
    "CORR-001": {
        "technique": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
    },
    "CORR-002": {
        "technique": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
    },
}


def get_mitre_mapping(rule_id: str):
    return MITRE_MAPPINGS.get(rule_id)
BEHAVIOR_RULES = {
    "B001": ("Dynamic code execution", "HIGH", 25),
    "B002": ("System command execution", "HIGH", 30),
    "B003": ("Network communication", "MEDIUM", 15),
    "B004": ("Sensitive environment access", "HIGH", 25),
    "B005": ("Obfuscation or encoding", "MEDIUM", 15),
    "B006": ("Obfuscated execution pattern", "CRITICAL", 45),
    "B007": ("Download and execute pattern", "CRITICAL", 50),
    "B008": ("Possible exfiltration pattern", "CRITICAL", 50),
    "B009": ("Suspicious import", "LOW", 5),
    "B010": ("Persistence-like behavior", "HIGH", 30),
    "B011": ("Suspicious binary drop", "HIGH", 30),
    "B012": ("Remote command execution pattern", "CRITICAL", 50),
}

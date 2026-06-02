METADATA_RULES = {
    "M001": ("Missing repository URL", "LOW", 5),
    "M002": ("Very short description", "LOW", 5),
    "M003": ("Suspicious package name similarity", "MEDIUM", 20),
    "M004": ("Suspicious setup.py content", "HIGH", 30),
    "M005": ("Suspicious console script entrypoint", "MEDIUM", 15),
    "M006": ("Unusual version pattern", "LOW", 5),
    "M007": ("Missing author contact", "LOW", 5),
    "M008": ("Suspicious project URL domain", "MEDIUM", 15),
    "M009": ("Metadata mismatch across files", "MEDIUM", 15),
    "M010": ("Custom build backend", "MEDIUM", 15),
}

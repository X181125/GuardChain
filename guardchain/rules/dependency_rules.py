DEPENDENCY_RULES = {
    "D001": ("Known suspicious demo dependency", "CRITICAL", 60),
    "D002": ("Typosquatting dependency", "HIGH", 30),
    "D003": ("Direct URL dependency", "MEDIUM", 20),
    "D004": ("Unpinned dependency", "LOW", 5),
    "D005": ("VCS dependency", "MEDIUM", 15),
    "D006": ("Local path dependency", "MEDIUM", 15),
    "D007": ("Imported but not declared dependency", "LOW", 5),
    "D008": ("Declared but not imported dependency", "LOW", 3),
    "D009": ("Suspicious dependency name pattern", "MEDIUM", 15),
    "D010": ("Editable dependency", "MEDIUM", 15),
}

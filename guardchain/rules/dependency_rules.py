DEPENDENCY_RULES = {
    "D001": ("Known suspicious demo dependency", "CRITICAL", 60),
    "D002": ("Typosquatting dependency", "HIGH", 30),
    "D003": ("Direct URL dependency", "MEDIUM", 20),
    "D004": ("Unpinned dependency", "LOW", 5),
    "D005": ("Local path dependency", "MEDIUM", 15),
    "D006": ("VCS dependency", "MEDIUM", 15),
    "D007": ("Suspicious extras or marker", "LOW", 5),
    "D008": ("Imported but not declared dependency", "LOW", 5),
}

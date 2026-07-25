import os
import requests
from dotenv import load_dotenv

# Load API key từ file .env
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def check_virustotal_hash(file_hash):
    """Tra cứu mã băm SHA-256 trên VirusTotal API v3"""
    if not VT_API_KEY or VT_API_KEY == "dien_api_key_virustotal_cua_ban_vào_day":
        return "No API Key", "GRAY"

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            total = sum(stats.values())
            
            if malicious > 0:
                return f"{malicious}/{total} Detects", "RED"
            return f"0/{total} Clean", "GREEN"
        elif response.status_code == 404:
            return "Not Found in VT", "YELLOW"
        else:
            return f"API Error ({response.status_code})", "GRAY"
    except Exception:
        return "Connection Error", "GRAY"

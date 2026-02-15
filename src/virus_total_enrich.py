import os
import requests
from dotenv import load_dotenv

load_dotenv()

def enrich_ip_data(ip_address):
    VT_API_KEY = os.getenv("VT_API_KEY")
    virus_total_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    response = requests.get(virus_total_url, headers=headers)

    response.raise_for_status()

    return response.json()
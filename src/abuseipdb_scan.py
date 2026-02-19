import requests
from config import env_variables

def aipdb_scan_ip_address(ip_address, api_key):
    max_report_age = 30 #Need to determine baseline value
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    parameters = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_report_age
    }
    try:
        response = requests.get(url, headers=headers, params=parameters)
        response.raise_for_status()

        data = response.json()
        attributes = data.get("data", {})

        abuse_rating = attributes.get("abuseConfidenceScore", 0)
        whitelisted_ip = attributes.get("isWhitelisted", False)
        tor_traffic = attributes.get("isTor", False)

        usage_type = attributes.get("usageType", "Unknown")
        domain_name = attributes.get("domain", "Unknown")

        return {
            "verdict": {
                "abuse_score": abuse_rating,
                "whitelisted": whitelisted_ip,
                "tor_traffic": tor_traffic
            },
            "context": {
                "usage_type": usage_type,
                "domain_name": domain_name
            }
        }
    
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP Error: {e}"}
    except Exception as e:
        return {"error": f"General Error: {e}"}
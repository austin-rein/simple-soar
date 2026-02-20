import requests
from config import env_variables

def gn_scan_ip_address(ip_address, api_key):
    url = f"https://api.greynoise.io/v3/ip/{ip_address}"
    headers = {
        "key": api_key,
        "Accept": "application/json"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status

        data = response.json()
        
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        classification = data.get("classification", "Unknown")
        name = data.get("name", "Unknown")

        return {
            "verdict": {
                "mass_scanner": noise,
                "rule_it_out": riot
            },
            "context": {
                "classification": classification,
                "name": name
            }
        }

    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP Error: {e}"}
    except Exception as e:
        return {"error": f"General Error: {e}"}
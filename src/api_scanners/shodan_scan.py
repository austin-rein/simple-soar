import requests
from config import env_variables

def shodan_scan_ip_address(ip_address, api_key):
    url = f"https://api.shodan.io/shodan/host/{ip_address}"
    headers = {
        "Accept": "application/json"
    }
    parameters = {
        "key": api_key
    }
    try:
        response = requests.get(url, headers=headers, params=parameters)
        response.raise_for_status()

        data = response.json()

        ports = data.get("ports", [])
        vulnerabilites = data.get("vulns", [])
        organization = data.get("org", "Unknown")
        operating_system = data.get("os", "Unknown")

        return {
            "verdict": {
                "open_ports": ports,
                "vulnerabilites": vulnerabilites
            },
            "context": {
                "organization": organization,
                "operating_system": operating_system
            }
        }

    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP Error: {e}"}
    except Exception as e:
        return {"error": f"General Error: {e}"}
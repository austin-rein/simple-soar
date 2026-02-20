import requests

def av_scan_ip_address(ip_address, api_key):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
    headers = {
        "X-OTX-API-KEY": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=3)
        response.raise_for_status()

        data = response.json()
        

        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses",[])
        reputation = data.get("reputation", 0)
        tags = set()
        adversaries = set()
        whois_link = data.get("whois", "Unknown")
        
        for pulse in pulses:
            for tag in pulse.get("tags", []):
                tags.add(tag)
            
            adversary = pulse.get("adversary")
            if adversary:
                adversaries.add(adversary)

        return {
            "verdict": {
                "pulse_count": pulse_count,
                "reputation_score": reputation
            },
            "context": {
                "tags": list(tags), 
                "adversaries": list(adversaries),
                "whois": whois_link
            }
        }
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP Error: {e}"}
    except Exception as e:
        return {"error": f"General Error: {e}"}
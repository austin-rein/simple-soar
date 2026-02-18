import requests

from config import env_variables

def vt_scan_ip_address(ip_address, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept" : "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})

        #Engine stats
        stats = attributes.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        undetected_count = stats.get("undetected", 0)
        harmless_count = stats.get("harmless", 0)

        #Community votes
        votes = attributes.get("total_votes", {})
        votes_malicious = votes.get("malicious", 0)
        votes_harmless = votes.get("harmless", 0)
        
        #Reputation score (Calculated by VT)
        reputation = attributes.get("reputation", 0)
        
        #Context
        tags = attributes.get("tags", [])
        as_owner = attributes.get("as_owner", "Unknown")
        jarm = attributes.get("jarm", None)

        return {
            "verdict": {
                "malicious_score": malicious_count,
                "suspicious_score": suspicious_count,
                "undetected_score": undetected_count,
                "harmless_score": harmless_count,
                "community_votes_malicious": votes_malicious,
                "community_votes_harmless": votes_harmless,
                "community_reputation": reputation
            },
            "context": {
                "tags": tags,
                "owner": as_owner,
                "jarm_fingerprint": jarm
            }
        }
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP Error: {e}"}
    except Exception as e:
        return {"error": f"General Error: {e}"}
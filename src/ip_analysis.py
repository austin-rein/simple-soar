import asyncio

from src.api_scanners.virus_total_scan import vt_scan_ip_address
from src.api_scanners.abuseipdb_scan import aipdb_scan_ip_address
from src.api_scanners.greynoise_scan import gn_scan_ip_address
from src.api_scanners.shodan_scan import shodan_scan_ip_address
from src.api_scanners.alien_vault_scan import av_scan_ip_address

'''
Each calculationg is based on a max potential score of 100
The total threshold for each API will be 100, so the total will be based on the 
following calculation:

    # API * 100 = max_threat_rating
'''

def calculate_vt_rating(vt_results):
    threat_rating = 0.0

    if not vt_results:
        return None

    verdict = vt_results.get("verdict", {})
    context = vt_results.get("context", {})

    if "error" in verdict or "error" in context:
            return None

    malicious_engines = verdict.get("malicious_score", 0)
    suspicious_engines = verdict.get("suspicious_score", 0)
    community_reputation = verdict.get("community_reputation", 0)

    if malicious_engines == 0 and suspicious_engines == 0 and community_reputation > 10:
       return 0.0 

    # Values will require tuning
    engine_calculation = (malicious_engines * 15.0) + (suspicious_engines * 5.0)
    threat_rating += engine_calculation

    if community_reputation < 0:
        # Restrics the community rating to only contributing a max value of 25.0
        community_reputation_rating = min(abs(community_reputation), 25.0)
        threat_rating += community_reputation_rating

    # Prevents a single API result from dicating the verdict too heavily
    threat_rating = min(threat_rating, 100.0)

    return round(threat_rating, 2)
    
def calculate_aipdb_rating(aipdb_results):
    # This is very simple as abuse ipdb uses a rating system from 0-100
    threat_rating = 0.0
    
    if not aipdb_results:
        return None
    
    verdict = aipdb_results.get("verdict", {})
    context = aipdb_results.get("context", {})

    if "error" in verdict or "error" in context:
            return None

    threat_rating = verdict.get("abuse_score", 0)

    # Casting as a float for consistency
    return float(round(threat_rating, 2))

def calculate_gn_rating(gn_results):
    threat_rating = 0.0

    if not gn_results:
        return None
    
    verdict = gn_results.get("verdict", {})
    context = gn_results.get("context", {})

    if "error" in verdict or "error" in context:
        return None

    if (verdict.get("mass_scanner") is False and 
        verdict.get("rule_it_out") is False and 
        context.get("classification", "Unknown").lower() == "unknown"):
        return None

    classification = context.get("classification", "Unknown").lower()

    if verdict.get("rule_it_out", {}) is True or classification == "benign":
        return 0.0

    if classification == "malicious":
        threat_rating = 100.0

    if verdict.get("mass_scanner", {}) is True and classification != "malicious":
        threat_rating = 50.0

    return threat_rating

def calculate_shodan_rating(shodan_results):
    threat_rating = 0.0

    if not shodan_results:
        return None

    verdict = shodan_results.get("verdict", {})
    context = shodan_results.get("context", {})

    if "error" in verdict or "error" in context:
            return None

    vulnerabilities = verdict.get("vulnerabilites", [])
    if vulnerabilities:
        threat_rating += min(len(vulnerabilities) * 25.0, 50.0)

    risky_ports = { 
            21, 23, 69, 161, 162, 3389, 5900, 5985, 5986, 111, 135, 139, 445,
            873, 2049, 1433, 1521, 3306, 5432, 5984, 6379, 9200, 11211, 27017
        }

    open_ports = verdict.get("open_ports", [])
    open_risky_ports = set(open_ports).intersection(risky_ports)

    if open_risky_ports:
        threat_rating += (len(open_risky_ports) * 10.0)

    if not open_ports and not vulnerabilities:
        return None

    threat_rating = min(threat_rating, 100.0)

    return round(threat_rating, 2)

def calculate_av_rating(av_results):
    threat_rating = 0.0

    if not av_results:
        return None
    
    verdict = av_results.get("verdict", {})
    context = av_results.get("context", {})

    if "error" in verdict or "error" in context:
        return None

    pulse_count = verdict.get("pulse_count", 0)
    reputation_score = verdict.get("reputation_score", 0)

    threat_rating += reputation_score

    if pulse_count > 0:
        threat_rating += min(pulse_count * 10.0, 50.0)

    threat_rating = min(threat_rating, 100.0)

    return round(threat_rating, 2)

def analyze_ip_scan_results(results):
    total_rating = 0.0
    number_of_hits = 0
    
    calculation_functions = [
        calculate_vt_rating,
        calculate_aipdb_rating,
        calculate_gn_rating,
        calculate_shodan_rating,
        calculate_av_rating,
    ]

    for calculation_function, result in zip(calculation_functions, results):
        rating = calculation_function(result)

        #testing purposes
        print(rating)

        if rating is not None:
            total_rating += rating
            number_of_hits += 1
        
    if number_of_hits == 0:
        return 0.0
    
    final_rating = total_rating / number_of_hits

    return round(final_rating, 2)
    

async def initiate_ip_scans(ip_address,env_variables):
    block = False
    final_rating = 0

    results = await asyncio.gather(
            asyncio.to_thread(vt_scan_ip_address, ip_address, env_variables.VT_API_KEY),
            asyncio.to_thread(aipdb_scan_ip_address, ip_address, env_variables.AIPDB_API_KEY),
            asyncio.to_thread(gn_scan_ip_address, ip_address, env_variables.GN_API_KEY),
            asyncio.to_thread(shodan_scan_ip_address, ip_address, env_variables.SHODAN_API_KEY),
            asyncio.to_thread(av_scan_ip_address, ip_address, env_variables.AV_API_KEY)
        )

    vt_results, aipdb_results, gn_results, shodan_results, av_results = results
    final_rating = analyze_ip_scan_results(results)

    # 80 might be too high, reducing to 70 for now
    if final_rating > 70:
        block = True
    else:
        block = False

    return {
        "vt_results": vt_results,
        "aipdb_results": aipdb_results,
        "gn_results": gn_results,
        "shodan_results": shodan_results,
        "av_results": av_results,
        "final_rating": final_rating,
        "block": block
    }
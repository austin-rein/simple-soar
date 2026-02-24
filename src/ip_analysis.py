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
    threat_rating = min(threat_rating, 100)

    return round(threat_rating, 2)
    
def calculate_aipdb_rating(aipdb_results):
    # This is very simple as abuse ipdb uses a rating system from 0-100
    threat_rating = 0.0
    
    if not aipdb_results:
        return 0.0
    
    verdict = aipdb_results.get("verdict", {})
    threat_rating = verdict.get("abuse_score", 0)

    return threat_rating

def calculate_gn_rating(gn_results):
    threat_rating = 0.0

    if not gn_results:
        return None
    
    return None

def calculate_shodan_rating(shodan_results):
    return None

def calculate_av_rating(av_results):
    return None

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

    # Requires tuning
    if final_rating > 80:
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
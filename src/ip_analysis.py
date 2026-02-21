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
        return 0.0

    verdict = vt_results.get("vt_verdict", {})
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
        community_reputation_rating = min(abs(community_reputation_rating), 25.0)
        threat_rating += community_reputation_rating

    # Prevents a single API result from dicating the verdict too heavily
    threat_rating = min(threat_rating, 100)

    return round(threat_rating, 2)
    
def calculate_aipdb_rating(aipdb_results):
    return 0.0

def calculate_gn_rating(gn_results):
    return 0.0

def calculate_shodan_rating(shodan_results):
    return 0.0

def calculate_av_rating(av_results):
    return 0.0

def analyze_ip_scan_results(results):
    vt_results, aipdb_results, gn_results, shodan_results, av_results = results

    vt_rating = calculate_vt_rating(vt_results)
    aipdb_rating = calculate_aipdb_rating(aipdb_results)
    gn_rating = calculate_gn_rating(gn_results)
    shodan_rating = calculate_shodan_rating(shodan_results)
    av_rating = calculate_av_rating(av_results)

    final_ip_rating = \
        vt_rating + \
        aipdb_rating + \
        gn_rating + \
        shodan_rating + \
        av_rating

    return final_ip_rating

async def initiate_ip_scans(ip_address,env_variables):
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

    # return {
    #   ip: ip_address,
    #   block: block,
    #   threat_score: final_rating
    # }

    return {
        "vt_results": vt_results,
        "aipdb_results": aipdb_results,
        "gn_results": gn_results,
        "shodan_results": shodan_results,
        "av_results": av_results
    }
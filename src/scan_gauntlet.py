import requests, asyncio

from src.virus_total_scan import vt_scan_ip_address
from src.abuseipdb_scan import aipdb_scan_ip_address
from src.greynoise_scan import gn_scan_ip_address
from src.shodan_scan import shodan_scan_ip_address
from src.alien_vault_scan import av_scan_ip_address

def analyze_scan_results(results):
    vt_results, aipdb_results, gn_results, shodan_results, av_results = results
     


async def initiate_ip_scans(ip_address,env_variables):
    results = await asyncio.gather(
            asyncio.to_thread(vt_scan_ip_address, ip_address, env_variables.VT_API_KEY),
            asyncio.to_thread(aipdb_scan_ip_address, ip_address, env_variables.AIPDB_API_KEY),
            asyncio.to_thread(gn_scan_ip_address, ip_address, env_variables.GN_API_KEY),
            asyncio.to_thread(shodan_scan_ip_address, ip_address, env_variables.SHODAN_API_KEY),
            asyncio.to_thread(av_scan_ip_address, ip_address, env_variables.AV_API_KEY)
        )

    vt_results, aipdb_results, gn_results, shodan_results, av_results = results
    # Used to fulfill the requirements of the response model
    vt_verdict = vt_results.get('verdict', {})
    vt_malicious_count = vt_verdict.get('malicious_score', 0)

    return {
        "vt_results": vt_results,
        "aipdb_results": aipdb_results,
        "gn_results": gn_results,
        "shodan_results": shodan_results,
        "av_results": av_results
    }
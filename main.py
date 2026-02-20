from fastapi import FastAPI 
import asyncio

# Load custom module
from src.virus_total_scan import *
from src.abuseipdb_scan import aipdb_scan_ip_address
from src.greynoise_scan import gn_scan_ip_address
from src.shodan_scan import shodan_scan_ip_address
from src.alien_vault_scan import av_scan_ip_address
from src.scan_gauntlet import *

from config import env_variables # object that contains the .env variables
from models import *

app = FastAPI()

# Returns a basic message explaining what the API is
@app.get("/")
async def root():
    return {"message": "Simple SOAR: A basic analysis and response API"}

# Primary endpoint used for reporting IP addrsses
@app.post("/report/ip_address/", response_model=TestModel)
async def scan_ip_address(report: ThreatReport):
    # Async function to replace sequential scans
    scan_results = await initiate_ip_scans(report.value,env_variables)

    vt_results = scan_results["vt_results"]
    aipdb_results = scan_results["aipdb_results"]
    gn_results = scan_results["gn_results"]
    shodan_results = scan_results["shodan_results"]
    av_results = scan_results["av_results"]

    #vt_results = vt_scan_ip_address(report.value, env_variables.VT_API_KEY)
    vt_malicious_count = vt_results['verdict']['malicious_score']
    #aipdb_results = aipdb_scan_ip_address(report.value, env_variables.AIPDB_API_KEY)
    #gn_results = gn_scan_ip_address(report.value, env_variables.GN_API_KEY)
    #shodan_results = shodan_scan_ip_address(report.value, env_variables.SHODAN_API_KEY)
    #av_results = av_scan_ip_address(report.value, env_variables.AV_API_KEY)

    return {
        "ip" : report.value,
        "block": vt_malicious_count > 0,
        "threat_score": vt_malicious_count,
        "vt_verdict": vt_results.get('verdict', {"error": "Data unavailable"}),
        "vt_context": vt_results.get('context', {"error": "Data unavailable"}),
        "aipdb_verdict": aipdb_results.get('verdict', {"error": "Data unavailable"}),
        "aipdb_context": aipdb_results.get('context', {"error": "Data unavailable"}),
        "gn_verdict": gn_results.get('verdict', {"error": "Data unavailable"}),
        "gn_context": gn_results.get('context', {"error": "Data unavailable"}),
        "shodan_verdict": shodan_results.get('verdict', {"error": "Data unavailable"}),
        "shodan_context": shodan_results.get('context', {"error": "Data unavailable"}),
        "av_verdict": av_results.get('verdict', {"error": "Data unavailable"}), 
        "av_context": av_results.get('context', {"error": "Data unavailable"})
    }

@app.post("/report/domain/",response_model=TestModel)
async def scan_domain_name(report: ThreatReport):
    pass

@app.post("/report/hash/",response_model=TestModel)
async def scan_hash(report: ThreatReport):
    pass
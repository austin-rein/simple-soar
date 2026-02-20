from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
import requests

# Load custom module
from src.virus_total_scan import vt_scan_ip_address
from src.abuseipdb_scan import aipdb_scan_ip_address
from src.greynoise_scan import gn_scan_ip_address
from src.shodan_scan import shodan_scan_ip_address

from config import env_variables # object that contains the .env variables
from models import *

app = FastAPI()

# Returns a basic message explaining what the API is
@app.get("/")
async def root():
    return {"message": "Simple SOAR: A basic IP data ennrichment API"}


# Primary endpoint used for reporting IP addrsses
@app.post("/report/ip_address/", response_model=TestModel)
async def scan_ip_address(report: ThreatReport):
    # Run the "Gauntlet"

    vt_results = vt_scan_ip_address(report.value, env_variables.VT_API_KEY)
    vt_malicious_count = vt_results['verdict']['malicious_score']

    aipdb_results = aipdb_scan_ip_address(report.value, env_variables.AIPDB_API_KEY)

    gn_results = gn_scan_ip_address(report.value, env_variables.GN_API_KEY)
    shodan_results = shodan_scan_ip_address(report.value, env_variables.SHODAN_API_KEY)
    #av_results

    return {
        # Why are my quotation marks not consistent?
        "ip" : report.value,
        "block": vt_malicious_count > 0,
        "threat_score": vt_malicious_count,
        "vt_verdict": vt_results['verdict'],
        "vt_context": vt_results['context'],
        "aipdb_verdict": aipdb_results['verdict'],
        "aipdb_context": aipdb_results['context'],
        "gn_verdict": gn_results['verdict'],
        "gn_context": gn_results['context'],
        "shodan_verdict": shodan_results['verdict'],
        "shodan_context": shodan_results['context']
    }


@app.post("/report/domain/",response_model=TestModel)
async def scan_domain_name(report: ThreatReport):
    pass

@app.post("/report/hash/",response_model=TestModel)
async def scan_hash(report: ThreatReport):
    pass


'''
User post -> API
API -> Validate input (Pydantic) -> Query other APIs in parallel -> Aggregate results
Determine action based on aggregate results -> Notify user + perform background alert/action
'''
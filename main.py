from fastapi import FastAPI 

from src.ip_analysis import *
from config import env_variables
from models import *

app = FastAPI()

# Returns a basic message explaining what the API is
@app.get("/")
async def root():
    return {"message": "Simple SOAR: A basic analysis and response API"}

# Primary endpoint used for reporting IP addrsses
@app.post("/report/ip_address/", response_model=TestModel)
async def scan_ip_address(ip_address):
    scan_results = await initiate_ip_scans(ip_address,env_variables)
    
    vt_results = scan_results["vt_results"]
    aipdb_results = scan_results["aipdb_results"]
    gn_results = scan_results["gn_results"]
    shodan_results = scan_results["shodan_results"]
    av_results = scan_results["av_results"]
    threat_score = scan_results["final_rating"]
    block = scan_results["block"]

    return {
        "ip" : ip_address,
        "block": block,
        "threat_score": threat_score,
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
async def scan_domain_name(domain):
    pass

@app.post("/report/hash/",response_model=TestModel)
async def scan_hash(hash):
    pass

@app.post("/report/url",response_model=TestModel)
async def scan_url(url):
    pass
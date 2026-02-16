from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
import requests

# Load custom module
from src.virus_total_enrich import enrich_ip_data

load_dotenv()
app = FastAPI()

# Standard input format for API requests
class ThreatReport(BaseModel):
    value: str 
    type: str # ip, domain, or hash
    

# Standard response format API requests
class AnalysisResults(BaseModel):
    ip: str
    block: bool
    threat_score: float

# Returns a basic message explaining what the API is
@app.get("/")
async def root():
    return {"message": "Simple SOAR: A basic IP data ennrichment API"}

# Primary endpoint used for reporting IP addrsses
@app.post("/report/", response_model=AnalysisResults)
async def report_ip(request: ThreatReport):
    try:
        # Ignoring type value for now
        ip_address = request.value
        virus_total_data = enrich_ip_data(ip_address)
        
        engine_analysis_stats = virus_total_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        malicious_value = engine_analysis_stats.get("malicious", 0)
        harmless_value = engine_analysis_stats.get("harmless", 0)
        undecided_value = engine_analysis_stats.get("undetected", 0)
        suspicious_value = engine_analysis_stats.get("suspicious", 0)

        engine_analysis_total = malicious_value + undecided_value + suspicious_value + harmless_value

        if engine_analysis_total > 0:
            threat_score = (malicious_value / engine_analysis_total) * 100
        else:
            threat_score = 0.0

        if threat_score > 0.80:
            block_threat = True
        else:
            block_threat = False

        return {
            "ip": ip_address,
            "block": block_threat,
            "threat_score": round(threat_score, 2)
        }

    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        if status_code == 401:
            raise HTTPException(status_code=500, detail="Invalid API key")
        if status_code == 404:
            raise HTTPException(status_code=404, detail="IP not found in VirusTotal")
        
        raise HTTPException(status_code=500, detail="Virus Total API error") 
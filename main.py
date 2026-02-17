from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests

# Load custom module
from src.virus_total_enrich import enrich_ip_data
from config import env_variables

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
    pass
    # Re-writing for modulatiry
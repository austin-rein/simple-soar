from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests

# Load custom module
from src.virus_total_enrich import enrich_ip_data
from config import env_variables
from models import *

app = FastAPI()

# Returns a basic message explaining what the API is
@app.get("/")
async def root():
    return {"message": "Simple SOAR: A basic IP data ennrichment API"}

# Primary endpoint used for reporting IP addrsses
@app.post("/report/", response_model=AnalysisResults)
async def report_ip(request: ThreatReport):
    pass
    # Re-writing for modulatiry

'''
User post -> API
API -> Validate input (Pydantic) -> Query other APIs in parallel -> Aggregate results
Determine action based on aggregate results -> Notify user + perform background alert/action
'''
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class IP_Report(BaseModel):
    ip: str
    threat_score: float

@app.get("/")
async def root():
    return {"message": "Simple SOAR: A basic IP data ennrichment API"}

@app.post("/report/", response_model=IP_Report)
async def report_ip(report: IP_Report):
    return report
    
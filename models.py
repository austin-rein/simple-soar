from pydantic import BaseModel
from typing import Dict, Any

class ThreatReport(BaseModel):
    value: str 
    type: str # ip, domain, or hash
    
class AnalysisResults(BaseModel):
    ip: str
    block: bool
    threat_score: float

#Copy of AnalysisResults for now
class TestModel(BaseModel):
    ip: str
    block: bool
    threat_score: float
    verdict: Dict[str, Any]
    context: Dict[str, Any]
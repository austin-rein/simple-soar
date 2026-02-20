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
    vt_verdict: Dict[str, Any]
    vt_context: Dict[str, Any]
    aipdb_verdict: Dict[str, Any]
    aipdb_context: Dict[str, Any]
    gn_verdict: Dict[str, Any]
    gn_context: Dict[str, Any]
    shodan_verdict: Dict[str, Any]
    shodan_context: Dict[str, Any]
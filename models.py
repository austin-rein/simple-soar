from pydantic import BaseModel

class ThreatReport(BaseModel):
    value: str 
    type: str # ip, domain, or hash
    
class AnalysisResults(BaseModel):
    ip: str
    block: bool
    threat_score: float

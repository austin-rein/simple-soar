import requests
from config import env_variables

def enrich_ip_data(ip_address):
    max_report_age = 0 #Need to determine baseline value
    """
    - data.abuseConfidenceScore (major identifier)
    - data.isWhitelisted (major identifier)
    - data.usageType (context)
    - data.isTor (context)
    - totalReports (tuning value)
    """
    pass
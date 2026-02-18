import requests
from config import env_variables

def enrich_ip_data(ip_address):
    '''
    - data.attributes.last_analysis_stats. (major identifier)
    - data.attributes.reputation (analysis tuner)
    - data.attributes.total_votes.harmless (analysis tuner)
    - data.attributes.total_votes.malicious (analysis tuner)
    - data.attriutes.tags (context)
    '''
    pass
# A simple SOAR API
Personal project to develop an API based SOAR application

## Current status:
The API is currently able to pull data from five sources for IP enrichment data. I will work on creating a new file to run everything asynchronously then consolidate the verdict data into a final score to be used to determine the response. Once the analysis logic is completed and tested I will move on to alerting.

## ROADMAP:
- IP data enrichment:
    - VirusTotal
    - AbuseIPDB
    - GreyNoise
    - Shodan
- Domain data enrichment:
    - VirusTotal
- Hash data enrichment:
    - VirusTotal
- Automated Ansible playbooks:
    - Firewall level block (opnsense/cisco ios)
    - Endpoint level block (iptables/nftables)
- Report tracking DB (PostgreSQL)
- Report cache (Valkey)
- Alert platforms:
    - Slack
    - Mattermost
    - Teams
    - PagerDuty(?)
    - Signal
- Containerized deployment
- Web frontend for reviewing active reports

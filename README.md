# A simple SOAR API
Personal project to develop an API based SOAR application

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

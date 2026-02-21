# A simple SOAR API
Personal project to develop an API based SOAR application

## Current status:
The API now is able to call all of the APIs asynchonously. I need to define the logic to determine whether to block the IP or not. Based on the logic I will develop other formulas to determine blocking for the following types of reports:
    - Domain
    - Hash
    - URL

Once everything is "fully working" I will start on the 

## ROADMAP:
Threat Intelligence Tools:
    - [ ] VirusTotal (IP, Domain, Hash, URL)
    - [ ] AbuseIPDB (IP)
    - [ ] GreyNoise (IP)
    - [ ] AlienVault OTX (IP, Domain, , Hash, URL)
    - [ ] Shodan (IP, Domain)
    - [ ] URLScan.io (IP, Domain, URL)
    - [ ] Pulsedive (IP, Domain, Hash, URL)
    - [ ] URLhause (Domain, URL)
    - [ ] MalwareBazaar (Hash)
    - [ ] ThreatFox (IP, Domain, Hash)
    - [ ] Censys (IP, Domain)
    - [ ] Google Safe Browsing (Domain, URL)
    - [ ] Hybrid Analysis (Hash, URL)
    - [ ] ANY.RUN (Hash, URL)
    - [ ] IPQualtiyScore (IP, URL)
    - [ ] IBM X-Force Exchange (IP, Domain, Hash, URL)
    - [ ] Project Honey Pot (IP)
    - [ ] CIRCL Hashlookup (Hash)

Automated Response:
    - Ansible playbooks:
        - Endpoint level blocking (pf, iptables, nftables):
            - [ ] pf
            - [ ] nftables
            - [ ] iptables
        - Network level blocking (OpnSense, Cisco IOS)
    - Alert platforms:
        - [ ] Slack
        - [ ] Mattermost
        - [ ] Signal
        - [ ] Teams(?)
        - [ ] PagerDuty(?)

Databases:
    - [ ] Postgresql (Report reviewing and retention) 
    - [ ] Valkey (Response data caching)

Deployment options:
    - [ ] Baremetal
    - [ ] Container (Podman, Kubernetes)

Misc:
    - Web frontend for viewing full report data

## Resources:
- [FastAPI](https://fastapi.tiangolo.com/)
- [Requests](https://requests.readthedocs.io/en/latest/)
- [Pydantic](https://docs.pydantic.dev/latest/)
- [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
- [asyncio](https://docs.python.org/3/library/asyncio.html)
- [typing](https://docs.python.org/3/library/typing.html)

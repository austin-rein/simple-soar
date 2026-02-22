# simple-soar
A personal project to develop SOAR API based on aggregating data from external API providers.

## Current status:
The API now is able to call all of the APIs asynchonously. The general logic has been determined for how to score an IP's threat rating. Once I am able to calulate based on the five sources I will work on adding the other three report types.
Once everything is "fully working" I will add the automated response actions likely starting with a basic alert via one of the messaging platforms. Until I am able to setup a virtualized test environment I will not be able to test the ansible playbooks, so I will just use drafts to simulate the responses.

# ROADMAP:
## Threat Intelligence Tools:
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

## Automated Response:
### Ansible playbooks:
#### Endpoint level blocking (pf, iptables, nftables):
- [ ] pf
- [ ] nftables
- [ ] iptables
#### Network level blocking (OpnSense, Cisco IOS)
### Alert platforms:
- [ ] Slack
- [ ] Mattermost
- [ ] Signal
- [ ] Teams(?)
- [ ] PagerDuty(?)

## Databases:
- [ ] Postgresql (Report reviewing and retention) 
- [ ] Valkey (Response data caching)

## Deployment options:
- [ ] Baremetal
- [ ] Container (Podman, Kubernetes)

## Misc:
- [ ] Web frontend for viewing full report data (Svelte + Tailwind?)
- [ ] Internal analysis engine?

# Resources:
- [FastAPI](https://fastapi.tiangolo.com/)
- [Requests](https://requests.readthedocs.io/en/latest/)
- [Pydantic](https://docs.pydantic.dev/latest/)
- [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
- [asyncio](https://docs.python.org/3/library/asyncio.html)
- [typing](https://docs.python.org/3/library/typing.html)

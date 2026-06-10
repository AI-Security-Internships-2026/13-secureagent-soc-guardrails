# Datasets — SecureAgent-SOC

**Do NOT commit raw datasets to this repository.**

## Recommended datasets for this project

| Dataset | Type | URL | Notes |
|---|---|---|---|
| CICIDS-2017 | Network intrusion | https://www.unb.ca/cic/datasets/ids-2017.html | Labelled flows |
| UNSW-NB15 | Network anomaly | https://research.unsw.edu.au/projects/unsw-nb15-dataset | 9 attack types |
| CTU-13 | Botnet traffic | https://www.stratosphereips.org/datasets-ctu13 | PCAP + flows |
| MITRE ATT&CK | Threat intel | https://attack.mitre.org | TTP taxonomy |
| NVD CVE feed | Vulnerability | https://nvd.nist.gov/vuln/data-feeds | CVE JSON feeds |

## How to document a dataset

Create `datasets/<name>.md` with:
- Source URL and licence
- Download command
- Preprocessing steps
- Train/val/test split

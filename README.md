SOC Labs — LetsDefend

SOC analyst labs conducted on the platform of LetsDefend, consisting of analyzing security alerts, investigating suspicious elements, analyzing evidence, and mapping attacker techniques in accordance with MITRE ATT&CK framework.

Objectives

- Analysis of security alerts from the point of view of SOC analyst
- Investigation of suspicious emails, files, domains, IP addresses, and URLs
- Indicators of compromise detection
- Evidence correlation from different security tools
- Mapping of attacker's actions with the help of MITRE ATT&CK techniques
  Investigation Workflow

Each investigation proceeds using the following steps:

1. Alert Triage

	- Analyzing the alert to determine its severity
	- Finding out who was the target of the alert, be it user, host, or asset

2. Evidence Gathering

	- Reviewing the emails, their headers, attachments, links (URLs), IP addresses and domain names
	- Identifying IOCs

3. IOC Investigation

	- Performing WHOIS and DNS analysis
	- Checking the domains and IPs against the threat intelligence databases
	- Analyzing file hashes and suspicious attachments

4. Threat Analysis

	- Deciding on the nature of the activity, that is whether it is malicious, suspicious or benign
	- Identifying the attack vector

5. MITRE ATT&CK Techniques Mapping

	- Mapping attacker’s activities to MITRE ATT&CK techniques

6. Conclusion

	- Providing conclusions about the investigation
	- Documenting the evidence and conclusions reached by the analyst
	- Recommending further actions

Tools & Technologies

- LetsDefend
- VirusTotal
- WHOIS
- DNS / MXToolbox
- CyberChef
- MITRE ATT&CK
- Email Header Analysis
- Threat Intelligence
- IOC Analysis

Repository Structure

LetsDefend-SOC-Labs/
│
├── README.md
│
├── LAB/
│   ├── README.md
│   └── screeenshots
│
├── LAB/
│   ├── README.md
│   └── screeenshots
│
├── LAB/
│   ├── README.md
│   └── screeenshots

Reports

Each lab contains a detailed investigation report covering:

- Alert information
- Incident summary
- Evidence
- Indicators of compromise
- Investigation steps
- Threat intelligence findings
- MITRE ATT&CK mapping
- Analyst conclusion
- Recommended actions

Disclaimer

All investigations documented in this repository were performed in authorized training environments for educational purposes. No unauthorized systems or real-world targets were accessed.

Progress

This repository is continuously updated as additional SOC labs and investigations are completed.

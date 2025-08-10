# FUTURE_CS_02
# SIEM Log Analysis & Incident Response – Task 2 Given by Future Interns

## 📌 Project Overview
This project demonstrates **Security Information and Event Management (SIEM)** log ingestion, analysis, and incident reporting using **Splunk Free Trial**.  
The task simulates real SOC (Security Operations Center) work, including suspicious activity detection, incident classification, and stakeholder communication.

## 🎯 Objectives
- Set up and explore a free/demo SIEM tool (Splunk Free Trial).
- Analyze incoming security alerts and logs (provided sample data).
- Identify suspicious activities such as failed logins, unusual IP addresses, and malware alerts.
- Categorize and prioritize alerts based on severity.
- Draft an **Incident Response Report** with threat details, impact, and remediation steps.
- Simulate communication with stakeholders.
- Learn SOC dashboard tracking and playbook processes.

## 🛠 Tools & Data
- **SIEM Tool**: Splunk Free Trial (Splunk.com)
- **Log File**: `SOC_Task2_Sample_Logs.txt`
- **Report Writing**: Microsoft Word / Google Docs
- **Data**:  
  - Simulated system logs with timestamps  
  - Network connection logs  
  - Authentication logs (successful/failed logins)  
  - Malware detection alerts

## 📊 Key Findings from Analysis
From the provided logs:
- Multiple malware detections (`Trojan`, `Worm`) on different hosts.
- Failed login attempts indicating possible brute-force attempts.
- Access from unusual or non-standard IPs.

## 🚨 Example Indicators of Compromise (IOCs)
| Timestamp           | User     | IP Address     | Alert Type                  |
|---------------------|----------|---------------|-----------------------------|
| 2025-07-03 05:48:14 | bob      | 10.0.0.5      | Malware Detected - Trojan   |
| 2025-07-03 07:02:14 | alice    | 203.0.113.77  | Login Failed                |
| 2025-07-03 04:29:14 | alice    | 192.168.1.101 | Malware Detected - Trojan   |
| 2025-07-03 07:45:14 | charlie  | 172.16.0.3    | Malware Detected - Trojan   |
| 2025-07-03 05:06:14 | bob      | 203.0.113.77  | Malware Detected - Worm     |

## 🔥 Alert Classification
| Alert Description                        | Severity | Reason                                   |
|-------------------------------------------|----------|------------------------------------------|
| Multiple malware detections from Bob      | High     | Active threat on system                  |
| Login failure from Alice's account        | Medium   | Possible brute-force attempt             |
| Trojan detected on Charlie's system       | High     | Requires immediate isolation             |
| Malware detection on Alice's machine      | High     | System compromise likely                 |
| Worm alert on Bob’s IP                    | High     | Potential network propagation            |

## 🛡 Recommendations
- Isolate compromised systems immediately.
- Conduct full malware scans.
- Block suspicious IP addresses.
- Enforce MFA for all accounts.
- Update endpoint protection.
- Review and analyze user activity logs.

## 📁 Deliverables
- [Incident Response Report]
- Splunk dashboard screenshots (not included in repo for security reasons).
- Alert classification table.
- Example stakeholder email draft.

---

**Author:** Nitin Bhatt – SOC Analyst Intern  
**Date:** July 3, 2025

# Phishing-Email-Forensics
Phishing remains one of the most common and successful attack vectors used by cybercriminals. Effective email forensics helps security teams detect malicious activity, trace the origin of attacks, and strengthen organizational defenses. This report provides a high-level overview of key steps and techniques used in phishing email investigations.
## What is Phishing Email Forensics?
Phishing email forensics is the process of analyzing suspicious emails to determine:
- Whether the email is malicious.
- How it was delivered.
- What the attacker attempted to achieve.
- Indicators of compromise (IoCs) to block future threat.
It combines metadata analysis, content inspection, link/attachment investigation, and threat intelligence correlation.

## Key Steps in Phishing Email Forensics
## 1. Collect the Evidence
- Obtain the full email header.
- Export the email in .eml or .msg format.
- Preserve attachments and URLs.
Document everything to maintain chain of custody.

## 2. Analyze Email Metadata
- Inspect From, Return-Path, and Reply-To for spoofing.
- Review Received headers for unusual routing.
- Validate SPF, DKIM, and DMARC results.
- Check sender IP reputation using threat intelligence sources.

## 3. Inspect the Email Body
Look for social engineering indicators:
- Urgency or scare tactics.
- Brand impersonation.
- Generic greetings.
Capture IoCs such as malicious links or suspicious signatures.

## 4. Examine Links and Redirects
Use sandboxed tools to inspect:
- URL redirects.
- Obfuscated parameters.
- Typosquatting domains.
Check domain age, WHOIS details, SSL certificate validity.

## 5. Analyze Attachments Safely
Detonate files in a sandbox
Check for:
- Macros.
- Embedded scripts.
- Hidden payloads.
Extract IoCs such as file hashes or command-and-control URLs

## 6. Correlate with Threat Intelligence
- Identify known phishing kits.
- Match IoCs against public or commercial feeds.
- Look for campaign patterns or reused attacker infrastructure.

## 7. Report Findings
Document:
- Attack summary.
- IoCs.
- Potential impact.
- Mitigation steps.
Share IoCs with SOC, IT, and email security teams for blocking and monitoring.

## Best Practices
- Train users regularly to recognize phishing signals.
- Use multi-layered email security filtering.
- Enable and enforce SPF, DKIM, and DMARC.
- Monitor for anomalous authentication activity.
- Implement logging and retention for forensic visibility.

## Useful Tools
- Header Analysis: MXToolbox, Google Admin Toolbox, MessageHeaderAnalyzer
- URL/Sandbox: VirusTotal, Any.Run, urlscan.io
- Attachment Analysis: Cuckoo Sandbox, CAPE Sandbox
- Threat Intelligence: AbuseIPDB, AlienVault OTX, PhishTank
## Summary
Phishing email forensics is essential to understanding threats, preventing successful attacks, and improving your security posture. By analyzing metadata, links, and attachments—and correlating with threat intelligence—you can quickly determine the legitimacy and risk of suspicious emails.

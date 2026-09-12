SOC-Machines

A collection of blue-team / defensive security writeups — log analysis, DFIR, and SOC-analyst-style investigations, separated out from my offensive practice.

🎯 Purpose

While Offsec-Machines tracks exploitation and attack-path practice, this repo focuses on the other side: triage, investigation, and reconstructing what an attacker did using logs and evidence — the core day-to-day skillset of a SOC analyst.

📂 Contents

Writeups currently include:

Slingshot (THM) — SOC Level 2 / DFIR room using Kibana (ELK stack) to reconstruct an attacker's full timeline from Apache/ModSecurity logs: recon (Nmap), directory enumeration (Gobuster), brute-force (Hydra), web shell upload, LFI for DB credentials, and final data exfiltration via phpMyAdmin.
A Bucket of Phish (THM) — Phishing email investigation: header analysis, sender verification, attachment/link inspection, and IOC extraction.

(This list grows as more rooms/challenges are completed and moved in.)

🗂️ Structure

Each writeup documents an investigation rather than an exploit chain:

Scenario — what evidence/access is provided and what needs to be determined
Investigation — the queries, filters, and analysis steps taken
Findings — IOCs, attacker timeline, or root cause identified
Key Concepts — the underlying detection/analysis technique the exercise reinforced
🧠 Skills Covered

Log analysis · Timeline reconstruction · Phishing/email investigation · IOC identification · Alert triage · DFIR fundamentals . Malware Analysis . Forensics

📌 Related

Offensive writeups (exploitation, privilege escalation, CTF challenges) are tracked separately in Offsec-Machines.


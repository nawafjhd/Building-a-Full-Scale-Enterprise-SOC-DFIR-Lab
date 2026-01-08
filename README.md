# Building-a-Full-Scale-Enterprise-SOC-DFIR-Lab
This project is a full enterprise-style SOC &amp; DFIR home lab designed to simulate a real corporate environment for Blue Team, SOC, and DFIR training. 
🔐 Enterprise SOC & DFIR Home Lab

(Active Directory • SIEM • IDS/IPS • Blue Team • DFIR)

📌 Overview

This project is a full enterprise-style SOC & DFIR home lab designed to simulate a real corporate security environment from scratch.

The lab focuses on building, securing, attacking, detecting, and investigating a Windows-based enterprise infrastructure using industry-standard tools and architectures.

This is not a CTF lab.
It is a realistic Blue Team / SOC / DFIR environment designed to mirror how security operations work in real organizations.

🎯 Project Goals

The main goals of this project are:

Build a realistic enterprise network

Deploy and secure Active Directory (Windows + Linux)

Implement network and endpoint security layers

Centralize logs using SIEM / XDR

Perform attack simulations (Purple Team)

Detect, analyze, and investigate security incidents

Gain hands-on SOC & DFIR experience

🧠 High-Level Architecture
Kali Linux (Attacker)
        |
[ Firewall + IDS/IPS (pfSense) ]
        |
------------------------------------------------
|              |              |               |
Win10 User   Win10 User     Win10 IT      Linux AD
Endpoints    Endpoints     Endpoint       (SSSD)
        |              |              |               |
        -------------------- AD Network ----------------
                          |
                Active Directory (DC)
                          |
              --------------------------------
              |                              |
      Windows Member Server        Ubuntu Security Server
                                      (IDS / YARA / AV)
                          |
                    SIEM / XDR (Wazuh)
                          |
               Vulnerability Management
                 (OpenVAS / Nuclei)

🧩 Security Layers Model

This lab is designed using a layered security approach similar to enterprise environments:

Layer 0 – Virtualization & Networking
Layer 1 – Firewall & Network Segmentation
Layer 2 – Identity & Access Management (Active Directory)
Layer 3 – Endpoints (Windows & Linux)
Layer 4 – Network Security (IDS / IPS)
Layer 5 – Endpoint Security (AV / EDR)
Layer 6 – SIEM / XDR
Layer 7 – Vulnerability Management
Layer 8 – Attack Simulation & Purple Team

🖥️ Hardware & Requirements
Minimum Recommended Specs

RAM: 16 GB (32 GB preferred)

CPU: 4–8 Cores

Storage: 400 GB SSD

Virtualization: Enabled in BIOS

Virtualization Platform

✅ VMware Workstation (recommended)

VirtualBox (works but less stable)

🌐 Network Design

The environment uses network segmentation to simulate a real enterprise:

Network	Purpose
AD_NET	Domain Controllers, Servers, Clients
SEC_NET	SIEM, Security Monitoring Servers
ATTACK_NET	Kali Linux (Attacker)

The pfSense firewall sits between these networks and controls all traffic.

🏛️ Active Directory Environment
Domain Controller

OS: Windows Server 2019 / 2022

Domain: corp.local

Services:

Active Directory Domain Services (AD DS)

DNS

AD Structure

Organizational Units (OUs):

Users

IT

HR

Servers

Users:

Standard users

IT admins

Service accounts

Groups:

Domain Admins

IT Support

HR

Group Policies (GPOs)

Password & account lockout policies

Logon / logoff auditing

Object access auditing

PowerShell logging

SMBv1 disabled

🖥️ Windows Endpoints
Systems

3 × Windows 10

Joined to corp.local

Security & Visibility

Sysmon (SwiftOnSecurity configuration)

Windows Defender

Wazuh Agent

Collected Telemetry

Logon events (4624 / 4625)

Process creation

PowerShell activity

Persistence indicators

🐧 Linux Integration with Active Directory
Linux AD Member

OS: Ubuntu Server 22.04

Integrated using:

SSSD

Kerberos

realmd

Purpose

Simulate mixed Windows/Linux enterprise environments

Monitor Linux authentication via Active Directory

Collect Kerberos and authentication logs

🔥 Firewall & Network Security
Firewall

pfSense / OPNsense

Static routing and segmentation

Firewall rules for controlled access

IDS / IPS

Suricata enabled

Initially deployed in IDS mode

Can be switched to IPS (inline) mode

Visibility

Network-based attack detection

Traffic inspection between segments

🛡️ Ubuntu Security Server

This server acts as a network and malware analysis layer.

Installed Tools

Suricata

Snort

YARA

ClamAV

tcpdump

Purpose

Network threat detection

Malware scanning

PCAP analysis

Signature and behavior-based detection

📊 SIEM / XDR (Wazuh)
Deployment

Wazuh All-in-One on Ubuntu Server

Centralized log collection and analysis

Integrated Sources

Windows endpoints

Linux servers

Active Directory logs

Firewall logs

IDS alerts

Capabilities

Alerting and correlation

MITRE ATT&CK mapping

Dashboards and timelines

Endpoint threat detection

🧪 Vulnerability Management
Tools Used

OpenVAS

Nuclei

Nmap

Activities

Scan Active Directory environment

Scan servers and endpoints

Identify misconfigurations and vulnerabilities

Generate vulnerability reports

🔴 Attack Simulation (Purple Team)
Attacker Platform

Kali Linux

Tools

Impacket

BloodHound

CrackMapExec

Atomic Red Team

Attack Scenarios

Password spraying

Kerberoasting

Credential dumping

Lateral movement

Exploiting vulnerable services

All attacks are observed and analyzed through the SIEM and IDS layers.

🔍 Detection & Investigation
Detection

SIEM alerts

IDS/IPS signatures

Endpoint telemetry

MITRE ATT&CK techniques

Investigation

Timeline analysis

Log correlation

Host and network evidence review

Root cause identification

Output

Incident reports

Detection improvements

Lessons learned

🚀 Project Outcome

After completing this project, the following skills are demonstrated:

Building a full enterprise SOC lab from scratch

Deep understanding of Active Directory security

Endpoint and network threat detection

SIEM/XDR deployment and tuning

DFIR investigation workflows

Blue Team and Purple Team operations

👨‍💼 Target Roles

This project directly prepares for roles such as:

SOC Analyst (Tier 1 / Tier 2)

DFIR Analyst (Junior – Mid)

Blue Team Engineer

Detection Engineer (Junior)

📌 Final Notes

This lab is designed to be iterative and extensible.
New detections, attacks, and improvements can be continuously added.

Build → Attack → Detect → Investigate → Improve

This cycle represents real-world security operations.

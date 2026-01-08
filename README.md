## 🧠 Lab Architecture

```text
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

___________________________________________________________

🎯 Current Project Status

✅ Active Directory Domain Controller (Windows Server)
✅ Firewall & Network Segmentation (pfSense)
✅ Windows 10 Domain-Joined User Endpoints



Layer 0 – Virtualization & Networking
Layer 1 – Firewall & Network Segmentation
Layer 2 – Identity & Access Management (Active Directory)
Layer 3 – Endpoints (Windows 10)

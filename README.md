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

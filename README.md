# Proxmox Homelab - Enterprise Security Lab 


## Overview / Purpose
This project is a fully virtualized enterprise security lab built on proxmox to replicate a real-world corporate environment. It combines **system administration, network security, adversarial testing, and SIEM implementation** to simulate both attacker and defender perspectives.

The goal of this lab was to design, deploy, and secure a small enterprise network while gaining hands-on experience with Active Directory administration, firewall and IPS/IDS configuration, adversarial attack simulation, and centralized log monitoring with a SIEM.


## Key Skills Demonstrated
1. **Virtualization and Networking**
   - Proxmox VM provisioning.
   - Network segmentation (WAN/LAN interface seperation).
   - NAT and firewall rules.
2. **Firewall and Intrusion Prevention System / Intrusion Detection System**
   - pfsense firewall configuration.
   - Suricata IPS/IDS (inline block and alert modes).
   - Rule tuning.
3. **Enterprise Windows Administration**
   - Windows Server 2022 Active Directory Domain Services (reddy.lab).
   - Organizational Units (OUs) and Group Policy Objects (GPOs) for LabUsers, Workstations, and domain-wide security policies.
   - Windows 11 domain join and policy enforcement testing.
4. **Adversarial Simulation (Red Team Testing)**
   - Kali Linux attacks (Nmap scans, Hydra brute force, SMB enumeration, ICMP floods).
   - Validation of attacker activity in pfsense firewall logs, Suricata eve.json, Windows Event Viewer, and SIEM dashboard.
5. **Security Information and Event Management (SIEM)**
   - Wazuh deployment on Ubuntu Server.
   - Windows agents installation and enrollment.
   - Centralized log collection and monitoring.
   - Detection and investigation of security events (failed logons, brute force, account lockouts).
6. **General Security Operations**
   - Log analysis across firewall, IPS/IDS, endpoint, and domain controller.
   - Detection-to-response workflow simulation (attack -> detection -> investigation).
   - Practical SOC analyst skills including correlation and incident documentation.


### VM List
| VM Name           | OS / Role                   | RAM | vCPUs | Purpose                                 |
|------------------|----------------------------|-----|-------|-----------------------------------------|
| pfSense           | FreeBSD / Firewall         | 4GB | 2   | WAN/LAN routing, IPS/IDS                |
| AD-Server2022     | Windows Server 2022 / Domain Controller   | 6GB | 2   | Domain Controller, AD services          |
| Win11-Enterprise  | Windows 11 Enterprise      | 6GB | 2   | Endpoint testing                        |
| Kali-Linux        | Debian / Penetration       | 4GB | 2   | Attack simulations (nmap, hydra, etc.)  |
| Wazuh-SIEM        | Ubuntu Server 22.04        | 4GB | 2   | SIEM, log aggregation, dashboard        |

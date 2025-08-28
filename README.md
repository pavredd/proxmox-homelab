# Proxmox Homelab - Enterprise Security Lab 


## Table of Contents
1. [Overview / Purpose](#overview--purpose)
2. [Key Skills Demonstrated](#key-skills-demonstrated)
3. [Lab Environment](#lab-environment)
     - [VM List](#vm-list)
4. [Project Setup and Configuration](#project-setup-and-configuration)
5. [Testing and Results](#testing-and-results)
6. [Conclusion](#conclusion)


## Overview / Purpose
This project is a fully virtualized enterprise security lab built on proxmox to replicate a real-world corporate environment. It combines **system administration, network security, adversarial testing, and SIEM implementation** to simulate both attacker and defender perspectives.

The goal of this lab was to design, deploy, and secure a small enterprise network while gaining hands-on experience with Active Directory administration, firewall and IPS/IDS configuration, adversarial attack simulation, and centralized log monitoring with a SIEM.


## Key Skills Demonstrated
1. **Virtualization and Networking**
   - Proxmox VM provisioning.
   - Snapshot management.
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

## Lab Environment
This homelab is built on a **Proxmox VE 8.4.11** hypervisor running on a host with:
1. **Host Hardware:** 16 vCPUs, 32 GB RAM.
2. **Networking:**
   - pfsense provides WAN and LAN segmentation.
   - WAN interface connected to external network (internet).
   - LAN interface hosts internal lab environment (AD, endpoints, and SIEM).
3. **Virtual Machines:** 5 VMs (see [VM List](#vm-list))
4. **Security Stack:**
   - pfsense with Suricata IPS/IDS
   - Wazuh SIEM on Ubuntu Server for centralized log collection, monitoring and dashboards.

### VM List
| VM Name          | OS / Role                          | RAM | vCPUs | Purpose                                                                 |
|------------------|-------------------------------------|-----|-------|-------------------------------------------------------------------------|
| pfSense          | FreeBSD / Firewall & Router         | 4GB | 2     | WAN/LAN segmentation, firewall rules, Suricata IPS/IDS                  |
| AD-Server2022    | Windows Server 2022 / Domain Controller | 6GB | 2 | Domain Controller, Active Directory, Group Policy management            |
| Win11-ENT1       | Windows 11 Enterprise Workstation   | 6GB | 2     | Domain-joined endpoint for user/GPO testing, Windows event logging      |
| Kali-Linux       | Debian / Penetration Testing        | 4GB | 2     | Attack simulations (nmap, hydra, SMB enumeration, ICMP flood)           |
| Wazuh-SIEM       | Ubuntu Server 22.04 / SIEM          | 4GB | 2     | Centralized log aggregation, alerting, dashboards via Wazuh & ELK stack |


## Project Setup and Configuration
### Proxmox Host
1. **Version:** Proxmox VE 8.4.11
2. **Resources:** 16 vCPUs, 32 GB RAM, 1 TB SSD storage.
3. **VM Allocation:** 5 VMs with dedicated CPU, RAM, and thin provisioned storage for realistic enterprise simulation.
4. **Networking:**
   - `vmbr0` (WAN bridge) - connected to physical uplink for internet access.
   - `vmbr1` (LAN bridge) - isolated internal network for domain, endpoints, attacker, and SIEM.
5. **Management:** Proxmox web UI accessible at `https://<management_interface_IP>:8006`. Host configured with lab-only FQDN `pve.lab` (appears as node `pve` in the UI).


<br>
<p align="center">
  <img src="images/proxmox-vm-list.png" alt="Proxmox VM List" width="400"/><br>
  <em>Proxmox VM Inventory</em>
</p>
<br>
<p align="center">
  <img src="images/proxmox-network-bridges.png" alt="Proxmox Network Bridges" width="400"/><br>
  <em>Proxmox Network Interface and Bridges</em>
</p>
<br>


### pfsense Firewall and Suricata IPS/IDS
1. **pfsense Configuration:**
   - **Management** - pfsense web UI accessible at `https://<LAN_interface_IP>` for configuration and monitoring.
   - **WAN Interface** -  configured with static / private IP for controlled internet acces. IPv6 disabled.
   - **LAN Interface** - configured with static IP to serve the internal lab network for AD, endpoints, and SIEM.
   - **Firewall Rules Setup:**
     - **WAN Rules**
       - Block private networks {RFC1918) from WAN.
       - Block bogon networks.
     - **LAN rules**
       - Anti-Lockout Rule - ensures admin access to pfsense is never blocked.
       - Default Allow LAN to Any - permits lab VM communications within LAN and outbound traffic.
   - **NAT configuration**:
     - **Port forwarding** - RDP (TCP 3389) forwarded to AD-Server2022 and win11-ENT1 to test external attack scenarios.
     - **Temporary testing** - NAT reflection and Outbound NAT enabled for internal testing and reverted afterward.  
2. **Suricata Setup:**
   - **Mode Configuration:**
     - **WAN Interface** - Inline mode with block offenders enabled to actively drop malicious traffic.
     - **LAN Interface** - Alert-only mode for monitoring internal network traffic without blocking.
   - **Rule Categories Enabled:**
     - ET SCAN
     - ET ATTACK_RESPONSE
     - ET EXPLOIT
     - ET MALWARE
     - ET SHELLCODE
     - ET DOS
     - ET BOTCC
     - ET WORM
   - **Rule Action Customization:**
     - Modified selected ET rules to `drop`, ensuring traffic that matched these signatures was both alerted and blocked.
     - **Custom Rules:**
       - Local RDP Brute Force Attempt rule - created to detect and block unauthorized RDP login attempts.
       - Local ICMP Flood Detection rule - created for ICMP flood testing. However, detections were ultimately handled by the existing GPL SCAN Nmap Ping rule in the ET SCAN category, demonstrating Suricata’s rule precedence.
     - **Logging** - enabled Eve JSON Logging to capture all alerts and drops in `eve.json`. Logs were accessible through both the pfSense web UI and console for review.
    

### Active Directory Domain Services

## Testing and Results

## Conclusion

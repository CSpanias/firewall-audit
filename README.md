# Firewall-Audit

A Python-based tool designed to make firewall configuration reviews more efficient and identify areas requiring deeper review.

Currently supports:
* Cisco Firepower Threat Defense (FTD)
* Cisco Adaptive Security Appliance (ASA)
* Fortinet FortiGate

Developed as an educational tool to accompany [Firewall Security Explained](https://mollysec.com/posts/firewall-security-explained/).

It analyses firewall configurations and provides a structured assessment consisting of:

```text
Configuration → Discovery → Security Context → Review Focus
```

## Installation

Recommended ([uv](https://docs.astral.sh/uv/getting-started/installation/#standalone-installer)):

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install firewall-audit via UV
uv tool install git+https://github.com/CSpanias/firewall-audit

# Verify installation
firewall-audit -h

# Update
uv tool upgrade firewall-audit
```

Clone locally:

> **Note**: Python 3 must be installed and available in your `PATH`.

```bash
# Clone the repository
git clone https://github.com/CSpanias/firewall-audit /opt/firewall-audit

# Make the script executable
chmod +x /opt/firewall-audit/firewall_audit.py

# Create a symbolic link
sudo ln -s /opt/firewall-audit/firewall_audit.py /usr/local/bin/firewall-audit

# Verify installation
firewall-audit -h
```

## Features

The tool follows the same methodology typically used during a firewall security review:

### 1. Device discovery

* Vendor identification
* Hostname extraction
* Software version identification
* Device model detection (where available)

### 2. Network architecture analysis

* Interface discovery
* Security-zone identification
* Internet-facing interface detection
* Management interface identification
* Trust-boundary mapping

### 3. Access control review

* Firewall object inventory
* Object-group inventory
* ACL / policy enumeration
* Permit and deny rule statistics
* Identification of potentially risky rules
* Detection of broad `any any` access

### 4. VPN analysis

* SSL VPN / WebVPN detection
* Remote-access VPN discovery
* Site-to-site VPN identification
* Disabled VPN detection

### 5. Administration and authentication

* TACACS detection
* RADIUS detection
* SAML detection
* AAA infrastructure discovery
* Authentication source identification
* AAA-related object discovery

### 6. Monitoring and logging

* SNMP detection
* Syslog detection
* Monitoring platform discovery
* Logging destination identification

### 7. Control plane and network services

* Control-plane protection analysis
* Management service identification
* NAT usage detection
* Static NAT / VIP discovery

### 8. Remote Access VPN Security

* WebVPN detection
* SSL VPN detection
* HSTS detection (Cisco)
* Content Security Policy detection (Cisco)
* TLS configuration review (Cisco)

## Usage

### Configuration Review

```bash
firewall-audit <config.log>
```

Example:

```bash
firewall-audit firepower-config.txt
```

## Example Output

```bash
firewall-audit firepower-config.txt
```

```text
================================================================================
DEVICE INFORMATION
================================================================================
Vendor   : Cisco
Hostname : FW-EDGE-01
Version  : 7.6.2
Model    : Cisco Firepower 1150 Threat Defense v7.6.2 (build 329)

Firmware versions affect security features, support status, and vulnerability
exposure.
```

```text
================================================================================
NETWORK ARCHITECTURE
================================================================================
Named Segments       : 11
Security Zones       : 5
Internet Interfaces  : 1
VPN Zones            : 1
Management Interfaces: 1

PUBLICLY EXPOSED NETWORKS

  - INTERNET

MANAGEMENT INTERFACES

  - management

MANAGEMENT ACCESS

  - 10.99.99.0/24 (MGMT)
  - 10.10.10.0/24 (MGMT)

Understanding the architecture helps identify trust boundaries and assess how
traffic flows between them.
```

```text
================================================================================
ACCESS CONTROL
================================================================================
ACL Entries       : 9
Permit Rules      : 8
Deny Rules        : 1
Disabled Policies : 0
Network Objects   : 14
Object Groups     : 4

ANY-ANY RULES

  None identified

ACLs determine which systems can communicate and how traffic is permitted across
trust boundaries.
```

```text
================================================================================
VPN SECURITY
================================================================================
Remote Access VPN Pools : 2
WebVPN Enabled          : Yes
Site-to-Site VPNs       : 2
Disabled VPNs           : 1

REMOTE ACCESS VPNS (2)

  - ANYCONNECT_POOL
  - MGMT_VPN_POOL

WEBVPN

HSTS               : Yes
Content Security   : Yes
TLS 1.2 Configured : Yes

SITE-TO-SITE VPNS (2)

  - AZURE-VTI-PRIMARY
  - AWS-VTI

DISABLED VPNS (1)

  - Tunnel3

VPNs extend trust boundaries by providing remote users and external
networks access to internal resources.
```

```text
================================================================================
ADMINISTRATION & AUTHENTICATION
================================================================================

AUTHENTICATION METHODS

TACACS+ : Yes
RADIUS  : Yes
SAML    : Yes

AAA SERVERS IN USE

  - RADIUS  : 10.99.99.110
  - TACACS  : 10.99.99.100

SAML IDENTITY PROVIDERS

  - Microsoft Entra ID

AAA RELATED OBJECTS

  - ISE-PRIMARY
  - RADIUS-SERVER
  - TACACS-SERVER

Centralised AAA reduces reliance on local accounts and improves authentication,
authorisation, and auditing.
```

```text
================================================================================
CONTROL PLANE PROTECTION
================================================================================
Control Plane ACL  : CONTROL_PLANE_BLOCK
Protected Interface: INTERNET

Control Plane ACLs restrict traffic destined to the firewall itself rather than
traffic traversing the firewall.
```

```text
================================================================================
LOGGING
================================================================================
Logging Enabled : Yes
Syslog          : Yes

SYSLOG SERVERS

  - MGMT : 10.99.99.210

Logging provides visibility into security events, administrative actions,
and policy violations.
```

```text
================================================================================
MONITORING
================================================================================
SNMP   : Yes

MONITORING PLATFORMS

  - SOLARWINDS

Monitoring provides visibility into firewall health, performance, and
availability.
```

```text
================================================================================
NAT
================================================================================
NAT Enabled : Yes

Dynamic NAT Rules : 1
Static NAT Rules  : 1

NAT determines how traffic is translated between networks but does not control
whether the traffic is permitted.
```

## Requirements

### Core

* Python 3

## Limitations

* The tool provides configuration visibility and review guidance but does not perform vulnerability assessment.
* Findings requiring review are indicators only and may be justified depending on business requirements.
* Security posture cannot be determined solely from configuration analysis.
* Dynamic behaviour, traffic flows, and runtime policy enforcement are outside the scope of the tool.

## Roadmap

* Exportable assessment reports (`.xml`, `.json`, `.html`)
* Palo Alto support
* Firewall rule risk scoring
* Verbose review modes (`--net-arch`, `--acls`, etc.)
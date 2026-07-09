# Firewall-Audit

A Python-based tool designed to make firewall configuration reviews more efficient and identify areas requiring deeper review.

Currently supports:
* Cisco Firepower Threat Defense (FTD)
* Cisco Adaptive Security Appliance (ASA)

Developed as an educational tool to accompany [Firewall Security Explained](https://mollysec.com/posts/email-security-explained/).

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

* Hostname extraction
* Software version identification
* Cisco Firepower model detection

### 2. Network architecture analysis

* Interface discovery
* Security-zone identification
* Internet-facing interface detection
* Management interface identification
* Trust-boundary mapping

### 3. Access control review

* Firewall object inventory
* Object-group inventory
* ACL enumeration
* Permit and deny rule statistics
* Identification of potentially risky rules
* Detection of broad `any any` access

### 4. VPN analysis

* Remote-access VPN pool discovery
* Site-to-site tunnel identification
* Disabled tunnel detection

### 5. Administration and authentication

* TACACS detection
* RADIUS detection
* SAML detection
* Cisco ISE identification
* AAA infrastructure discovery

### 6. Monitoring and logging

* SNMP detection
* Syslog detection
* Monitoring platform discovery
* Logging destination identification

### 7. Infrastructure services

* BGP routing detection
* NAT usage detection
* Control-plane ACL identification

### 8. WebVPN security review

* HSTS detection
* Content Security Policy detection
* TLS configuration review
* Cipher suite extraction

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
1. DEVICE & MANAGEMENT PLANE
================================================================================

Hostname : FTD-EDGE-01
Version  : 7.4.1
Model    : Cisco Firepower Threat Defense
```

```text
================================================================================
2. NETWORK ARCHITECTURE
================================================================================

Interfaces Found : 18

Internet Facing Interfaces:
  - INTERNET

Management Interfaces:
  - MANAGEMENT

Review Focus:
  - Internet -> Corp access
  - Internet -> Management access
  - DMZ segregation
  - Trust boundaries
```

```text
================================================================================
3. ACCESS CONTROL
================================================================================

Network Objects : 482
Object Groups   : 156
ACL Entries     : 2158
Permit Rules    : 1934
Deny Rules      : 224
```

```text
================================================================================
5. POTENTIAL FINDINGS
================================================================================

Rules Requiring Review: 4

  access-list OUTSIDE-IN extended permit ip any any
  access-list VPN-IN extended permit tcp any any eq 3389
```

```text
================================================================================
6. REMOTE CONNECTIVITY
================================================================================

VPN Pools:
  - RA-VPN-POOL

Tunnel Interfaces:
  - AWS Production VTI
  - Azure DR VTI

Disabled Tunnels:
  - Tunnel102
```

```text
================================================================================
7. ADMINISTRATION & AUTHENTICATION
================================================================================

TACACS : Yes
RADIUS : No
SAML   : Yes

Cisco ISE Servers:
  - ISE-PRIMARY
  - ISE-SECONDARY
```

```text
================================================================================
9. MONITORING
================================================================================

SNMP   : Yes
Syslog : Yes

Monitoring Platforms:
  - SOLARWINDS
  - NOC-MONITORING
```

```text
================================================================================
CONTROL PLANE PROTECTION
================================================================================

Control Plane ACL:
  control-plane access-group MGMT-ACL in interface MANAGEMENT
```

## Requirements

### Core

* Python 3

### Optional

* Cisco Firepower Threat Defense (FTD) configuration exports

## Limitations

* The tool provides configuration visibility and review guidance but does not perform vulnerability assessment.
* Findings requiring review are indicators only and may be justified depending on business requirements.
* Security posture cannot be determined solely from configuration analysis.
* Dynamic behaviour, traffic flows, and runtime policy enforcement are outside the scope of the tool.

## Roadmap

* Firewall rule risk scoring
* Detection of unused objects and object groups
* Shadowed and duplicate rule analysis
* Exportable assessment reports (`.xml`, `.json`, `.html`)
* Multi-firewall comparison mode
* Palo Alto support
* Cisco ASA support
* Fortinet support
* Management-plane security assessment
* Interface exposure mapping
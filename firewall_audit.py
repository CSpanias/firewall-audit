#!/usr/bin/env python3

import re
import sys
import ipaddress

class FirewallAudit:

    # Colour definitions
    COLOR_BLUE = "\033[0;34m"
    COLOR_CYAN = "\033[0;36m"
    COLOR_YELLOW = "\033[0;33m"
    COLOR_RED = "\033[0;31m"
    COLOR_BOLD = "\033[1m"
    COLOR_RESET = "\033[0m"

    def __init__(self):

        # -----------------------------
        # Device Information
        # -----------------------------

        self.hostname = None
        self.version = None
        self.model = None
        self.vendor = "Unknown"

        # -----------------------------
        # Network Architecture
        # -----------------------------

        # Network Identification
        self.interfaces = []
        self.nameifs = []

        # Security Zones
        self.zones = set()
        self.zone_members = {}
        self.vpn_zones_count = 0
        self.vpn_zones = []

        # Trust Boundaries
        self.trust_boundaries = []
        self.trust_levels = {}

        # Publicly Exposed Networks
        self.internet_interfaces = []
        self.internet_vpn_termination = []

        # Management Access Sources
        self.management_interfaces = []
        self.management_access = []

        # -----------------------------
        # Access Control
        # -----------------------------

        # Objects
        self.object_count = 0
        self.objects = []

        # Object Groups
        self.object_group_count = 0
        self.object_groups = []

        # Access Control Lists (ACLs)
        self.acls = []
        self.acl_count = 0

        self.forti_policies = []

        # ACLs Applied to Interfaces
        self.interface_acls = set()

        self.permit_rules_count = 0
        self.deny_rules_count = 0
        self.disabled_policy_count = 0

        self.any_any_rules = []

        # --------------------------------------
        # Virtual Private Network (VPN) Security
        # --------------------------------------

        # VPN Pools (Remote Access VPNs)
        self.vpn_pools = []

        # WebVPN
        self.webvpn = False

        self.webvpn_hsts = False
        self.webvpn_csp = False
        self.webvpn_tls = False
        self.webvpn_ciphers = set()

        # Site-to-Site VPNs
        self.tunnel_descriptions = []

        # Disabled VPNs
        self.disabled_tunnels = []

        # FortiGate VPN Definitions
        self.forti_vpns = []
        self.ssl_vpn_port = None

        # -----------------------------
        # Administrator Authentication
        # -----------------------------

        # Authentication, Authorization, and Accounting (AAA)
        self.tacacs = False
        self.radius = False
        self.saml = False

        # Identify Providers
        self.identity_providers = set()

        # AAA Servers In Use
        self.aaa_hosts = {}

        # AAA Related Objects
        self.aaa_related_objects = set()

        # -----------------------------
        # Control Plane Protection
        # -----------------------------

        # Cisco
        self.control_plane_acl = None
        
        # Fortinet
        self.control_plane_interfaces = []

        # -----------------------------
        # Logging
        # -----------------------------

        self.syslog = False
        self.logging_enabled = False
        self.logging_destinations = set()

        # -----------------------------
        # Monitoring
        # -----------------------------

        # SNMP
        self.snmp = False

        # Monitoring Infrastructure
        self.monitoring_platforms = set()

        # ----------------------------------
        # Network Address Translation (NAT)
        # ----------------------------------

        self.nat = False
        
        self.dynamic_nat = 0
        self.static_nat = 0

    # Parsing the configuration file
    def parse(self, filepath):

        # State Variables
        current_interface = None
        current_is_tunnel = False
        current_zone = None

        inside_forti_interfaces = False
        inside_forti_zones = False

        current_forti_zone = None

        inside_forti_addresses = False
        inside_forti_addrgrp = False

        inside_forti_policy = False

        current_forti_policy_disabled = False
        current_forti_policy_action = None

        current_forti_policy_id = None
        current_forti_policy_srcaddr = None
        current_forti_policy_dstaddr = None
        current_forti_policy_service = None

        inside_forti_phase1 = False

        current_forti_vpn = None
        current_forti_vpn_disabled = False
        inside_forti_ssl_vpn = False

        inside_forti_radius = False
        inside_forti_ldap = False

        current_forti_radius = None
        current_forti_ldap = None

        current_forti_interface_name = None

        inside_forti_syslog = False

        inside_forti_snmp = False
        inside_forti_snmp_hosts = False

        inside_forti_vip = False

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        # -----------------------------
        # Vendor Detection
        # -----------------------------

        vendor_fingerprints = {
            "Fortinet": [
                "config system interface",
                "config firewall policy",
                "config firewall address",
                "config firewall addrgrp",
                "config vpn ipsec phase1-interface",
                "config vpn ssl settings",
                "config user radius",
                "config system snmp"
            ],

            "Cisco": [
                "nameif ",
                "access-list ",
                "object network ",
                "object-group ",
                "aaa-server ",
                "webvpn",
                "tunnel-group "
            ]
        }

        scores = {vendor: 0 for vendor in vendor_fingerprints}

        for raw_line in lines:
            line = raw_line.strip()

            for vendor, fingerprints in vendor_fingerprints.items():
                for fp in fingerprints:
                    if line.startswith(fp):
                        scores[vendor] += 1

        if max(scores.values()) > 0:
            self.vendor = max(scores, key=scores.get)  

        for raw_line in lines:

            line = raw_line.strip()
            lowered = line.lower()

            # -----------------------------
            # Device Information
            # -----------------------------

            # Cisco Device Information
            if ("Cisco Firepower" in line and "Threat Defense" in line):
                self.model = line

            # Hostname
            match = re.match(r"hostname\s+(.+)", line)
            if match:
                self.hostname = match.group(1)

            # Version
            match = re.match(r"NGFW Version\s+(.+)", line)
            if match:
                self.version = match.group(1)

            # FortiGate Device Information

            # Hostname
            match = re.match(r"set hostname \"?(.+?)\"?$", line)
            if match:
                self.hostname = match.group(1)

            # -----------------------------
            # Network Architecture
            # -----------------------------

            # Cisco ASA / FTD Interfaces
            match = re.match(r"interface\s+(.+)", line)

            if match:
                current_interface = match.group(1)
                self.interfaces.append(current_interface)
                current_is_tunnel = (current_interface.startswith("Tunnel"))

            # Cisco ASA / FTD Interface Names
            match = re.match(r"nameif\s+(.+)", line)

            if match:
                nameif = match.group(1)

                self.nameifs.append(nameif)

                if "internet" in nameif.lower():
                    self.internet_interfaces.append(nameif)

                if ("mgt" in nameif.lower() or "management" in nameif.lower()):
                    self.management_interfaces.append(nameif)

            # Cisco ASA / FTD Security Zones

            # Leave the current zone block
            if line.startswith("object-group ") and "security-zone" not in line:
                current_zone = None

            # Zone Definition
            zone_match = re.match(r"object-group interface (.+?) security-zone", line)

            if zone_match:
                current_zone = zone_match.group(1)

                self.zones.add(current_zone)

                if current_zone not in self.zone_members:
                    self.zone_members[current_zone] = []

            # Zone Members
            member_match = re.match(r"interface-object interface-name (.+)", line)

            if member_match and current_zone:
                self.zone_members[current_zone].append(member_match.group(1))

            # Cisco ASA / FTD VPN Termination Interfaces
            match = re.match(r"tunnel source interface (.+)", line)

            if match:
                source_interface = match.group(1)

                if "internet" in source_interface.lower():
                    self.internet_vpn_termination.append(source_interface)

            # Cisco ASA / FTD Management Access
            if line.startswith("ssh "):

                parts = line.split()

                if len(parts) >= 4:

                    network = ipaddress.IPv4Network(
                        f"{parts[1]}/{parts[2]}",
                        strict=False
                    )

                    self.management_access.append({
                        "network": str(network),
                        "interface": parts[3]
                    })

            # FortiGate Interfaces
            if line == "config system interface":
                inside_forti_interfaces = True

            elif inside_forti_interfaces and line == "end":
                inside_forti_interfaces = False

            # FortiGate Interface Names
            match = re.match(r'edit\s+"(.+)"', line)

            if inside_forti_interfaces and match:

                interface_name = match.group(1)

                current_forti_interface_name = interface_name

                self.interfaces.append(interface_name)
                self.nameifs.append(interface_name)

                lowered_name = interface_name.lower()

                if lowered_name.startswith("wan"):
                    self.internet_interfaces.append(interface_name)

                if ("mgmt" in lowered_name or "management" in lowered_name):
                    self.management_interfaces.append(interface_name)

            # FortiGate Security Zones
            if line == "config system zone":
                inside_forti_zones = True

            elif inside_forti_zones and line == "end":
                inside_forti_zones = False
                current_forti_zone = None

            # FortiGate Zone Definition
            match = re.match(r'edit\s+"(.+)"', line)

            if inside_forti_zones and match:

                current_forti_zone = match.group(1)
                self.zones.add(current_forti_zone)

                if current_forti_zone not in self.zone_members:
                    self.zone_members[current_forti_zone] = []

            # FortiGate Zone Members
            match = re.match(r'set interface (.+)', line)

            if current_forti_zone and match:

                interfaces = re.findall(r'"([^"]+)"', match.group(1))

                self.zone_members[current_forti_zone].extend(
                    interfaces
                )

            # Trust Boundaries
            # TODO: Implement trust boundary detection logic here

            # -----------------------------
            # Access Control
            # -----------------------------

            # Cisco ASA / FTD Network Objects
            match = re.match(r"object network (.+)", line)

            if match:
                self.object_count += 1
                self.objects.append(match.group(1))

            # Cisco ASA / FTD Object Groups
            match = re.match(r"object-group (.+)", line)

            if (
                match
                and "security-zone" not in line
            ):
                self.object_group_count += 1
                self.object_groups.append(match.group(1))

            # Cisco ASA / FTD Access Control Lists (ACLs)
            if line.startswith("access-list "):

                lowered = line.lower()

                self.acls.append(line)
                self.acl_count += 1

                # Permit Rules
                if " permit " in lowered:
                    self.permit_rules_count += 1

                # Deny Rules
                if " deny " in lowered:
                    self.deny_rules_count += 1

            # Cisco ASA / FTD ACL Bindings
            if (
                line.startswith("access-group")
                and " interface " in line
            ):

                parts = line.split()

                acl_name = parts[1]
                self.interface_acls.add(acl_name)

            # FortiGate Address Objects
            if line == "config firewall address":
                inside_forti_addresses = True

            elif inside_forti_addresses and line == "end":
                inside_forti_addresses = False

            match = re.match(r'edit\s+"(.+)"', line)

            if inside_forti_addresses and match:

                object_name = match.group(1)

                self.object_count += 1
                self.objects.append(object_name)

            # FortiGate Address Groups
            if line == "config firewall addrgrp":
                inside_forti_addrgrp = True

            elif inside_forti_addrgrp and line == "end":
                inside_forti_addrgrp = False

            match = re.match(r'edit\s+"(.+)"', line)

            if inside_forti_addrgrp and match:

                group_name = match.group(1)

                self.object_group_count += 1
                self.object_groups.append(group_name)

            # FortiGate Firewall Policies
            if line == "config firewall policy":
                inside_forti_policy = True

            elif inside_forti_policy and line == "end":
                inside_forti_policy = False

            if inside_forti_policy and line.startswith("edit "):
                current_forti_policy_disabled = False
                current_forti_policy_action = None

                current_forti_policy_id = line.split()[1]
                current_forti_policy_srcaddr = None
                current_forti_policy_dstaddr = None
                current_forti_policy_service = None

            # FortiGate any-any rules
            match = re.match(r'set srcaddr "(.+)"', line)

            if inside_forti_policy and match:
                current_forti_policy_srcaddr = match.group(1)

            match = re.match(r'set dstaddr "(.+)"', line)
            if inside_forti_policy and match:
                current_forti_policy_dstaddr = match.group(1)

            match = re.match(r'set service "(.+)"', line)
            if inside_forti_policy and match:
                current_forti_policy_service = match.group(1)

            if inside_forti_policy and "set action accept" in lowered:
                current_forti_policy_action = "accept"

            if inside_forti_policy and "set action deny" in lowered:
                current_forti_policy_action = "deny"

            if inside_forti_policy and "set status disable" in lowered:
                current_forti_policy_disabled = True

            if inside_forti_policy and line == "next":

                self.forti_policies.append({
                    "id": current_forti_policy_id,
                    "disabled": current_forti_policy_disabled,
                    "action": current_forti_policy_action,
                    "srcaddr": current_forti_policy_srcaddr,
                    "dstaddr": current_forti_policy_dstaddr,
                    "service": current_forti_policy_service
                })

                if current_forti_policy_disabled:
                    self.disabled_policy_count += 1

                else:
                    self.acl_count += 1

                    if current_forti_policy_action == "accept":
                        self.permit_rules_count += 1

                    elif current_forti_policy_action == "deny":
                        self.deny_rules_count += 1

                # Reset policies
                current_forti_policy_disabled = False
                current_forti_policy_action = None

                current_forti_policy_id = None
                current_forti_policy_srcaddr = None
                current_forti_policy_dstaddr = None
                current_forti_policy_service = None

            # -----------------------------
            # VPN Security
            # -----------------------------

            # Cisco ASA / FTD Remote Access VPN Pools
            match = re.match(r"ip local pool\s+(\S+)", line)

            if match:
                self.vpn_pools.append(match.group(1))

            # Cisco ASA / FTD WebVPN
            if line.startswith("webvpn"):
                self.webvpn = True

            if "hsts-server" in lowered or "hsts-client" in lowered:
                self.webvpn_hsts = True

            if "content-security-policy" in lowered:
                self.webvpn_csp = True

            if line.startswith("ssl cipher tlsv1.2"):
                self.webvpn_tls = True

            # Cisco ASA / FTD Site-to-Site VPNs
            if (
                line.startswith("description ")
                and "VTI" in line.upper()
            ):
                desc = line.replace("description", "").strip()
                self.tunnel_descriptions.append(desc)

            # Cisco ASA / FTD Disabled VPNs
            if (
                line == "shutdown"
                and current_is_tunnel
                and current_interface
            ):
                self.disabled_tunnels.append(current_interface)

            # FortiGate SSL VPN
            if line == "config vpn ssl settings":
                self.webvpn = True

            # FortiGate IPsec VPNs
            if line == "config vpn ipsec phase1-interface":
                inside_forti_phase1 = True

            elif inside_forti_phase1 and line == "end":
                inside_forti_phase1 = False

            # FortiGate VPN Definition
            match = re.match(r'edit\s+"(.+)"', line)

            if inside_forti_phase1 and match:

                current_forti_vpn = match.group(1)
                current_forti_vpn_disabled = False

            # FortiGate Disabled VPNs
            if inside_forti_phase1 and "set status disable" in lowered:
                current_forti_vpn_disabled = True

            # Finalise VPN
            if inside_forti_phase1 and line == "next":

                self.forti_vpns.append({
                    "name": current_forti_vpn,
                    "disabled": current_forti_vpn_disabled
                })

                if current_forti_vpn_disabled:
                    self.disabled_tunnels.append(current_forti_vpn)

                else:
                    self.tunnel_descriptions.append(current_forti_vpn)

                current_forti_vpn = None
                current_forti_vpn_disabled = False
            
            # FortiGate SSL VPN
            if line == "config vpn ssl settings":
                inside_forti_ssl_vpn = True
                self.webvpn = True

            elif inside_forti_ssl_vpn and line == "end":
                inside_forti_ssl_vpn = False

            match = re.match(r"set port (\d+)", line)

            if inside_forti_ssl_vpn and match:
                self.ssl_vpn_port = match.group(1)

            # -----------------------------
            # Administrator Authentication
            # -----------------------------

            lowered = line.lower()

            # Cisco ASA / FTD Authentication Methods
            if line.startswith("aaa-server ") and "protocol tacacs+" in lowered:
                self.tacacs = True

            if line.startswith("aaa-server ") and "protocol radius" in lowered:
                self.radius = True

            if line.startswith("saml "):
                self.saml = True

            # Cisco ASA / FTD SAML Identity Providers
            if "login.microsoftonline.com" in lowered:
                self.identity_providers.add("Microsoft Entra ID")

            if "okta" in lowered:
                self.identity_providers.add("Okta")

            if "pingidentity" in lowered:
                self.identity_providers.add("Ping Identity")
            
            # Cisco ASA / FTD AAA Servers In Use
            match = re.match(r"aaa-server\s+(\S+)\s+\((.+?)\)\s+host\s+(\S+)", line, re.IGNORECASE)

            if match:
                server_group = match.group(1).upper()
                host = match.group(3)
                self.aaa_hosts[server_group] = host

            # Cisco ASA / FTD AAA Related Objects
            if line.startswith("object network"):

                name = line.split()[-1]
                upper_name = name.upper()

                if ("TACACS" in upper_name
                    or "RADIUS" in upper_name
                    or "ISE" in upper_name
                    or "NPS" in upper_name
                    or "LDAP" in upper_name
                    or "ENTRA" in upper_name
                    or "ACTIVE-DIRECTORY" in upper_name):

                    self.aaa_related_objects.add(name)

            # FortiGate RADIUS
            if line == "config user radius":
                inside_forti_radius = True

            elif inside_forti_radius and line == "end":
                inside_forti_radius = False

            match = re.match(r'edit\s+"(.+)"', line)

            if inside_forti_radius and match:

                current_forti_radius = match.group(1)

                self.radius = True

            match = re.match(r'set server "(.+)"', line)

            if inside_forti_radius and match:

                self.aaa_hosts["RADIUS"] = match.group(1)

            # FortiGate LDAP
            if line == "config user ldap":
                inside_forti_ldap = True

            elif inside_forti_ldap and line == "end":
                inside_forti_ldap = False

            match = re.match(r'edit\s+"(.+)"', line)

            if inside_forti_ldap and match:

                current_forti_ldap = match.group(1)

                self.aaa_related_objects.add(
                    current_forti_ldap
                )

            # -----------------------------
            # Control Plane Security
            # -----------------------------

            # Cisco
            if "control-plane" in lowered and "access-group" in lowered:
                self.control_plane_acl = line.strip()

            # Fortinet
            match = re.match(r"set allowaccess (.+)", line)

            if (
                inside_forti_interfaces
                and current_forti_interface_name
                and match
            ):
                self.control_plane_interfaces.append({
                    "interface": current_forti_interface_name,
                    "services": match.group(1)
                })

            # -----------------------------
            # Logging
            # -----------------------------

            # Cisco Logging
            if line.startswith("logging enable"):
                self.logging_enabled = True

            if line.startswith("logging host "):
                self.syslog = True
                parts = line.split()

                if len(parts) >= 4:
                    interface = parts[2]
                    host = parts[3]
                    self.logging_destinations.add(f"{interface} : {host}")

            # FortiGate Logging
            if line == "config log syslogd setting":
                inside_forti_syslog = True

            elif inside_forti_syslog and line == "end":
                inside_forti_syslog = False

            if inside_forti_syslog and "set status enable" in lowered:
                self.logging_enabled = True
                self.syslog = True

            match = re.match(r'set server "(.+)"', line)

            if inside_forti_syslog and match:
                self.logging_destinations.add(match.group(1))

            # -----------------------------
            # Monitoring
            # -----------------------------

            # Cisco Monitoring
            if line.startswith("snmp-server"):
                self.snmp = True

            # Cisco Monitoring Infrastructure
            upper = line.upper()

            if line.startswith("object network"):

                name = line.split()[-1]

                upper_name = name.upper()

                if (
                    "SOLARWINDS" in upper_name
                    or "ALERT-LOGIC" in upper_name
                    or upper_name.startswith("LM-")
                    or "NOC" in upper_name
                ):
                    self.monitoring_platforms.add(name)

            if line.startswith("object-group network"):
                name = line.split()[-1]
                upper_name = name.upper()

                if ("SOLARWINDS" in upper_name
                    or "ALERT-LOGIC" in upper_name
                    or upper_name.startswith("LM-")
                    or "NOC" in upper_name):
                    self.monitoring_platforms.add(name)

            # FortiGate Monitoring
            if line == "config system snmp community":
                inside_forti_snmp = True
                self.snmp = True

            elif inside_forti_snmp and line == "end":
                inside_forti_snmp = False

            if inside_forti_snmp and line == "config hosts":
                inside_forti_snmp_hosts = True

            elif inside_forti_snmp_hosts and line == "end":
                inside_forti_snmp_hosts = False

            match = re.match(r"set ip (\S+) \S+", line)

            if (inside_forti_snmp_hosts and match):
                self.monitoring_platforms.add(match.group(1))

            # ----------------------------------
            # Network Address Translation (NAT)
            # ----------------------------------

            # Cisco NAT
            if (line.startswith("nat ") or " nat " in f" {line} "):
                self.nat = True
                lowered = line.lower()

                if " dynamic " in lowered:
                    self.dynamic_nat += 1

                if " static " in lowered:
                    self.static_nat += 1

            # FortiGate NAT (Virtual IPs)
            if line == "config firewall vip":
                inside_forti_vip = True

            elif inside_forti_vip and line == "end":
                inside_forti_vip = False

            if inside_forti_vip and line.startswith("edit "):
                self.nat = True
                self.static_nat += 1

        # -----------------------------
        # Post-Processing
        # -----------------------------

        # Cisco ASA / FTD VPN Zones
        self.vpn_zones_count = sum(
            1 for zone in self.zones
            if (
                "vti" in zone.lower()
                or "vpn" in zone.lower()
            )
        )

        # Cisco ASA / FTD Any-Any Findings
        for acl in self.acls:

            parts = acl.split()
            acl_name = parts[1]
            lowered = acl.lower()

            if (
                acl_name in self.interface_acls
                and (
                    " permit ip any any" in lowered
                    or " permit tcp any any" in lowered
                    or " permit udp any any" in lowered
                )
            ):
                self.any_any_rules.append(acl)

        # FortiGate Any-Any Findings
        for policy in self.forti_policies:

            if policy["disabled"]:
                continue

            if (
                policy["action"] == "accept"
                and policy["srcaddr"] == "all"
                and policy["dstaddr"] == "all"
                and policy["service"] == "ALL"
            ):
                self.any_any_rules.append(f'Policy {policy["id"]}')

    # Section formatting
    def section(self, title):

        print()
        print(f"{self.COLOR_BLUE}{'=' * 80}{self.COLOR_RESET}")
        print(f"{self.COLOR_BOLD}{title}{self.COLOR_RESET}")
        print(f"{self.COLOR_BLUE}{'=' * 80}{self.COLOR_RESET}")

    # Subsection formatting
    def subsection(self, title):

        print(f"\n{self.COLOR_CYAN}{title}{self.COLOR_RESET}\n")

    # Report output formatting
    def report(self):

        self.section("FIREWALL AUDIT - CONFIGURATION OVERVIEW")

        # -----------------------------
        # Device Information
        # -----------------------------

        self.section("DEVICE INFORMATION")

        print(f"Vendor   : {self.vendor}")
        print(f"Hostname : {self.hostname or 'Unknown'}")
        print(f"Version  : {self.version or 'Unknown'}")
        print(f"Model    : {self.model or 'Unknown'}")

        print(f"\n{self.COLOR_YELLOW}"
            "Firmware versions affect security features, support status, and vulnerability \nexposure."
            f"{self.COLOR_RESET}")

        # -----------------------------
        # Network Architecture
        # -----------------------------

        self.section("NETWORK ARCHITECTURE")

        print(f"Named Segments       : {len(self.nameifs)}")
        print(f"Security Zones       : {len(self.zones)}")
        print(f"Internet Interfaces  : {len(self.internet_interfaces)}")
        print(f"VPN Zones            : {self.vpn_zones_count}")
        print(f"Management Interfaces: {len(self.management_interfaces)}")

        # To be implemented in the future for --network-architecture option 
        # self.subsection("SECURITY ZONE SUMMARY")

        # for zone in sorted(self.zone_members):

        #     members = self.zone_members[zone]
        #     count = len(members)

        #     suffix = "IF" if count == 1 else "IFs"

        #     print(f"  - {zone} ({count} {suffix})")

        if self.internet_interfaces:
            self.subsection("PUBLICLY EXPOSED NETWORKS")

            for iface in sorted(set(self.internet_interfaces)):
                print(f"  - {iface}")

        if self.management_interfaces:
            self.subsection("MANAGEMENT INTERFACES")

            for iface in sorted(set(self.management_interfaces)):
                print(f"  - {iface}")

        if self.management_access:
            self.subsection("MANAGEMENT ACCESS")

            for entry in self.management_access:
                print(f"  - {entry['network']} ({entry['interface']})")

        print(
            f"\n{self.COLOR_YELLOW}"
            f"Understanding the architecture helps identify trust boundaries and assess how \ntraffic flows between them."
            f"{self.COLOR_RESET}")

        # -----------------------------
        # Access Control
        # -----------------------------

        self.section("ACCESS CONTROL")

        print(f"ACL Entries       : {self.acl_count}")
        print(f"Permit Rules      : {self.permit_rules_count}")
        print(f"Deny Rules        : {self.deny_rules_count}")
        print(f"Disabled Policies : {self.disabled_policy_count}")
        print(f"Network Objects   : {self.object_count}")
        print(f"Object Groups     : {self.object_group_count}")

        if self.any_any_rules:
            self.subsection(f"ANY-ANY RULES ({len(self.any_any_rules)})")

            for rule in self.any_any_rules:
                print(f"  - {rule}")
        else:
            self.subsection("ANY-ANY RULES")
            print("  None identified")

        # Later for --acl option
        # if self.objects:

        #     self.subsection("EXAMPLE OBJECTS")

        #     for obj in self.objects[:5]:
        #         print(f"  - {obj}")

        # if self.object_groups:

        #     self.subsection("EXAMPLE OBJECT GROUPS")

        #     for group in self.object_groups[:5]:
        #         print(f"  - {group}")

        print(
            f"\n{self.COLOR_YELLOW}"
            "ACLs determine which systems can communicate and how traffic is permitted across \ntrust boundaries."
            f"{self.COLOR_RESET}")

        # -----------------------------
        # VPN Security
        # -----------------------------

        self.section("VPN SECURITY")

        print(f"Remote Access VPN Pools : {len(self.vpn_pools)}")
        print(f"WebVPN Enabled          : {'Yes' if self.webvpn else 'No'}")
        print(f"Site-to-Site VPNs       : {len(self.tunnel_descriptions)}")
        print(f"Disabled VPNs           : {len(self.disabled_tunnels)}")

        # Remote Access VPNs
        if self.vpn_pools:
            self.subsection(f"REMOTE ACCESS VPNS ({len(self.vpn_pools)})")

            for pool in self.vpn_pools:
                print(f"  - {pool}")

        # WebVPN / SSL VPN
        if self.webvpn:

            self.subsection("WEBVPN")

            if self.vendor == "Cisco":

                print(f"HSTS               : {'Yes' if self.webvpn_hsts else 'No'}")
                print(f"Content Security   : {'Yes' if self.webvpn_csp else 'No'}")
                print(f"TLS 1.2 Configured : {'Yes' if self.webvpn_tls else 'No'}")

            elif self.vendor == "Fortinet":

                print(f"SSL VPN Port       : {self.ssl_vpn_port}")

        # Site-to-Site VPNs
        if self.tunnel_descriptions:
            self.subsection(f"SITE-TO-SITE VPNS ({len(self.tunnel_descriptions)})")

            for tunnel in self.tunnel_descriptions:
                print(f"  - {tunnel}")

        # Disabled Tunnels
        if self.disabled_tunnels:
            self.subsection(f"DISABLED VPNS ({len(self.disabled_tunnels)})")

            for tunnel in self.disabled_tunnels:
                print(f"  - {tunnel}")

        print(f"\n{self.COLOR_YELLOW}"
            "VPNs extend trust boundaries by providing remote users and external "
            "\nnetworks access to internal resources."
            f"{self.COLOR_RESET}")

        # -----------------------------
        # Administrator Authentication
        # -----------------------------

        self.section("ADMINISTRATION & AUTHENTICATION")
        
        self.subsection("AUTHENTICATION METHODS")

        print(f"TACACS+ : {'Yes' if self.tacacs else 'No'}")
        print(f"RADIUS  : {'Yes' if self.radius else 'No'}")
        print(f"SAML    : {'Yes' if self.saml else 'No'}")
            
        self.subsection("AAA SERVERS IN USE")

        if self.aaa_hosts:

            for aaa_type, host in sorted(self.aaa_hosts.items()):
                print(f"  - {aaa_type:<7} : {host}")

        else:
            print("  None identified")

        if self.identity_providers:

            self.subsection("SAML IDENTITY PROVIDERS")

            for provider in sorted(self.identity_providers):
                print(f"  - {provider}")

        if self.aaa_related_objects:

            self.subsection("AAA RELATED OBJECTS")

            for obj in sorted(self.aaa_related_objects):
                print(f"  - {obj}")

        print(f"\n{self.COLOR_YELLOW}"
            "Centralised AAA reduces reliance on local accounts "
            "and improves authentication, \nauthorisation, and auditing."
        f"{self.COLOR_RESET}")

        # -----------------------------
        # Control Plane Security
        # -----------------------------

        self.section("CONTROL PLANE PROTECTION")

        # Cisco
        if self.control_plane_acl:

            parts = self.control_plane_acl.split()

            acl_name = parts[1]
            interface = parts[4]

            print(f"Control Plane ACL  : {acl_name}")
            print(f"Protected Interface: {interface}")

        # FortiGate
        elif self.control_plane_interfaces:

            self.subsection("MANAGEMENT SERVICES")

            for entry in self.control_plane_interfaces:

                print(f"  - {entry['interface']} ({entry['services']})")

        else:
            print("Control Plane ACL : None")

        print(f"\n{self.COLOR_YELLOW}"
                "Control Plane ACLs restrict traffic destined to the firewall itself rather than"
                "\ntraffic traversing the firewall."
            f"{self.COLOR_RESET}")
        
        # -----------------------------
        # Logging
        # -----------------------------

        self.section("LOGGING")

        print(f"Logging Enabled : {'Yes' if self.logging_enabled else 'No'}")
        print(f"Syslog          : {'Yes' if self.syslog else 'No'}")

        if self.logging_destinations:

            self.subsection("SYSLOG SERVERS")

            for destination in sorted(self.logging_destinations):
                print(f"  - {destination}")
        else:
            self.subsection("SYSLOG SERVERS")
            print("  None identified")

        print(f"\n{self.COLOR_YELLOW}"
            "Logging provides visibility into security events, "
            "administrative actions, \nand policy violations."
            f"{self.COLOR_RESET}")
        
        # -----------------------------
        # Monitoring
        # -----------------------------

        self.section("MONITORING")

        print(f"SNMP   : {'Yes' if self.snmp else 'No'}")

        if self.monitoring_platforms:
            self.subsection("MONITORING PLATFORMS")

            for platform in sorted(self.monitoring_platforms):
                print(f"  - {platform}")

        print(f"\n{self.COLOR_YELLOW}"
            "Monitoring provides visibility into firewall "
            "health, performance, and \navailability."
            f"{self.COLOR_RESET}")

        # ----------------------------------
        # Network Address Translation (NAT)
        # ----------------------------------

        self.section("NAT")

        print(f"NAT Enabled : {'Yes\n' if self.nat else 'No\n'}")

        if self.nat:
            print(f"Dynamic NAT Rules : {self.dynamic_nat}")
            print(f"Static NAT Rules  : {self.static_nat}")

        print(f"\n{self.COLOR_YELLOW}"
            "NAT determines how traffic is translated between networks "
            "but does not control \nwhether the traffic is permitted."
            f"{self.COLOR_RESET}")

def main():

    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        print(f"Usage: {sys.argv[0]} <config.log>")
        sys.exit(0)

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <config.log>")
        sys.exit(1)

    audit = FirewallAudit()
    audit.parse(sys.argv[1])
    audit.report()

if __name__ == "__main__":
    main()
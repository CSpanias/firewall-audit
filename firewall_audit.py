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

        # ACLs Applied to Interfaces
        self.interface_acls = set()

        self.permit_rules_count = 0
        self.deny_rules_count = 0

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

        self.control_plane_acl = None

        # -----------------------------
        # Logging
        # -----------------------------

        self.syslog = False
        self.logging_enabled = False
        self.logging_destinations = set()

        # -----------------------------
        # Monitoring
        # -----------------------------

        # SNPM
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

        current_interface = None
        current_is_tunnel = False
        current_zone = None

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for raw_line in lines:

            line = raw_line.strip()
            lowered = line.lower()

            # -----------------------------
            # Device Information
            # -----------------------------

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

            # -----------------------------
            # Network Architecture
            # -----------------------------

            # Network Identification
            match = re.match(r"interface\s+(.+)",line)

            if match:
                current_interface = match.group(1)
                self.interfaces.append(current_interface)
                current_is_tunnel = (current_interface.startswith("Tunnel"))

            # Interface Names
            match = re.match(r"nameif\s+(.+)", line)

            if match:
                nameif = match.group(1)
                self.nameifs.append(nameif)

                if "internet" in nameif.lower():
                    self.internet_interfaces.append(nameif)

                if ("mgt" in nameif.lower() or "management" in nameif.lower()):
                    self.management_interfaces.append(nameif)

            # Security Zones

            # Leave the current zone block
            if line.startswith("object-group ") and "security-zone" not in line:
                current_zone = None

            # Zone Definition
            zone_match = re.match(r"object-group interface (.+?) security-zone",line)

            if zone_match:
                current_zone = zone_match.group(1)
                self.zones.add(current_zone)

                if current_zone not in self.zone_members:
                    self.zone_members[current_zone] = []

            # Zone Members
            member_match = re.match(r"interface-object interface-name (.+)",line)

            if member_match and current_zone:
                self.zone_members[current_zone].append(member_match.group(1))

            # Trust Boundaries
            # TODO: Implement trust boundary detection logic here

            # Publicly Exposed Networks
            match = re.match(r"tunnel source interface (.+)",line)

            if match:
                source_interface = match.group(1)

                if "internet" in source_interface.lower():
                    self.internet_vpn_termination.append(source_interface)

            # Management Access
            if line.startswith("ssh "):
                parts = line.split()

                if len(parts) >= 4:

                    network = ipaddress.IPv4Network(f"{parts[1]}/{parts[2]}", strict=False)
                    self.management_access.append({
                        "network": str(network),
                        "interface": parts[3]
                        })

            # VPN Zones
            self.vpn_zones_count = sum(1 for zone in self.zones if ("vti" in zone.lower() or "vpn" in zone.lower()))

            # -----------------------------
            # Access Control
            # -----------------------------

            # Objects
            match = re.match(r"object network (.+)", line)
            
            if match:
                self.object_count +=1
                self.objects.append(match.group(1))

            # Object Groups
            match = re.match(r"object-group (.+)", line)

            if (match and "security-zone" not in line):
                self.object_group_count += 1
                self.object_groups.append(match.group(1))

            # Access Control Lists (ACLs)
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

            if line.startswith("access-group") and " interface " in line:
                parts = line.split()
                acl_name = parts[1]
                self.interface_acls.add(acl_name)

            # -----------------------------
            # VPN Security
            # -----------------------------

            # VPN Pools (Remote Access VPNs)
            match = re.match(r"ip local pool\s+(\S+)",line)

            if match:
                self.vpn_pools.append(match.group(1))

            # WebVPN
            if line.startswith("webvpn"):
                self.webvpn = True

            if "hsts-server" in lowered or "hsts-client" in lowered:
                self.webvpn_hsts = True

            if "content-security-policy" in lowered:
                self.webvpn_csp = True

            if line.startswith("ssl cipher tlsv1.2"):
                self.webvpn_tls = True

            # Tunnel Descriptions (Site-to-Site VPNs)
            if (line.startswith("description ") and "VTI" in line.upper()):
                desc = (line.replace("description","").strip())
                self.tunnel_descriptions.append(desc)
            
            # Disabled Tunnels
            if (line == "shutdown" and current_is_tunnel and current_interface):
                self.disabled_tunnels.append(current_interface)

            # -----------------------------
            # Administrator Authentication
            # -----------------------------

            lowered = line.lower()

            # Authentication Methods
            if line.startswith("aaa-server ") and "protocol tacacs+" in lowered:
                self.tacacs = True

            if line.startswith("aaa-server ") and "protocol radius" in lowered:
                self.radius = True

            if line.startswith("saml "):
                self.saml = True

            # SAML Identity Providers
            if "login.microsoftonline.com" in lowered:
                self.identity_providers.add("Microsoft Entra ID")

            if "okta" in lowered:
                self.identity_providers.add("Okta")

            if "pingidentity" in lowered:
                self.identity_providers.add("Ping Identity")
            
            # AAA Servers In Use
            match = re.match(r"aaa-server\s+(\S+)\s+\((.+?)\)\s+host\s+(\S+)", line, re.IGNORECASE)

            if match:
                server_group = match.group(1).upper()
                host = match.group(3)
                self.aaa_hosts[server_group] = host

            # AAA Related Objects
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

            # -----------------------------
            # Control Plane Security
            # -----------------------------

            if "control-plane" in lowered and "access-group" in lowered:
                self.control_plane_acl = line.strip()

            # -----------------------------
            # Logging
            # -----------------------------

            if line.startswith("logging enable"):
                self.logging_enabled = True

            if line.startswith("logging host "):
                parts = line.split()

                if len(parts) >= 4:
                    interface = parts[2]
                    host = parts[3]
                    self.logging_destinations.add(f"{interface} : {host}")

            # -----------------------------
            # Monitoring
            # -----------------------------

            if line.startswith("snmp-server"):
                self.snmp = True

            # Monitoring Infrastructure #
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

            # ----------------------------------
            # Network Address Translation (NAT)
            # ----------------------------------

            if (line.startswith("nat ") or " nat " in f" {line} "):
                self.nat = True
                lowered = line.lower()

                if " dynamic " in lowered:
                    self.dynamic_nat += 1

                if " static " in lowered:
                    self.static_nat += 1

        # -----------------------------
        # Post-Processing
        # -----------------------------

        # Build Any-Any Findings (Interface ACLs Only)
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

        print(f"Hostname : {self.hostname}")
        print(f"Version  : {self.version}")
        print(f"Model    : {self.model}")

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

        # WebVPN
        if self.webvpn:

            self.subsection("WEBVPN")

            print(f"HSTS               : {'Yes' if self.webvpn_hsts else 'No'}")
            print(f"Content Security   : {'Yes' if self.webvpn_csp else 'No'}")
            print(f"TLS 1.2 Configured : {'Yes' if self.webvpn_tls else 'No'}")

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
        print(f"RADIUS : {'Yes' if self.radius else 'No'}")
        print(f"SAML   : {'Yes' if self.saml else 'No'}")
            
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

        if self.control_plane_acl:
            parts = self.control_plane_acl.split()
            acl_name = parts[1]
            interface = parts[4]

            print(f"Control Plane ACL : {acl_name}")
            print(f"Protected Interface: {interface}")

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
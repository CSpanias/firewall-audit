#!/usr/bin/env python3

import re
import sys

class FirewallAudit:

    # Colour definitions
    COLOR_BLUE = "\033[0;34m"
    COLOR_CYAN = "\033[0;36m"
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

        # Trust Boundaries
        self.trust_boundaries = []
        self.trust_levels = {}

        # Publicly Exposed Networks
        self.internet_interfaces = []
        self.internet_vpn_termination = []

        # Management Interfaces
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
        self.acl_count = 0
        self.permit_rules = 0
        self.deny_rules = 0

        self.review_rules = []
        self.any_any_rules = []
        self.tunnel_rules = []
        self.default_deny_rules = []
        self.acls = []

        # -----------------------------
        # VPN Security
        # -----------------------------

        # VPN Pools
        self.vpn_pools = []

        # Tunnel Descriptions
        self.tunnels = []

        # Disabled Tunnels
        self.disabled_tunnels = []

        # -----------------------------
        # Administrator Authentication
        # -----------------------------

        # Authentication, Authorization, and Accounting (AAA)
        self.tacacs = False
        self.radius = False
        self.saml = False

        # AAA Infrastructure
        self.tacacs_servers = set()
        self.radius_servers = set()
        self.ise_servers = set()

        # -----------------------------
        # Monitoring & Logging
        # -----------------------------

        # Monitoring
        self.snmp = False

        # Monitoring Infrastructure
        self.monitoring_platforms = set()

        # Logging
        self.syslog = False
        self.logging_enabled = False
        self.logging_destinations = set()

        # -----------------------------
        # Control Plane Protection
        # -----------------------------

        # Control Plane
        self.control_plane_acl = None

        # WebVPN
        self.webvpn_hsts = False
        self.webvpn_csp = False
        self.webvpn_tls = False
        self.webvpn_ciphers = set()

        # -----------------------------
        # Network Services
        # -----------------------------

        # Routing
        self.bgp = False

        # Network Address Translation (NAT)
        self.nat = False

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
                self.management_access.append(line)

            # -----------------------------
            # Disabled Tunnels
            # -----------------------------

            if (line == "shutdown" and current_is_tunnel and current_interface):
                self.disabled_tunnels.append(current_interface)

            # -----------------------------
            # VPN Pools 
            # -----------------------------

            match = re.match(r"ip local pool\s+(\S+)",line)

            if match:
                self.vpn_pools.append(match.group(1))

            # -----------------------------
            # Tunnel Descriptions 
            # -----------------------------

            if (line.startswith("description ") and "VTI" in line.upper()):

                desc = (line.replace("description","").strip())
                self.tunnels.append(desc)

            # -----------------------------
            # Objects
            # -----------------------------

            match = re.match(r"object network (.+)", line)
            
            if match:
                self.object_count +=1
                self.objects.append(match.group(1))

            # -----------------------------
            # Object Groups
            # -----------------------------

            match = re.match(r"object-group (.+)", line)
            
            if match:
                self.object_group_count += 1
                self.object_groups.append(match.group(1))

            # -----------------------------
            # Access Control Lists
            # -----------------------------

            if line.startswith("access-list "):

                lowered = line.lower()
                self.acls.append(line)
                self.acl_count += 1

                if (
                    " permit gre any any " in lowered
                    or " permit ipinip any any " in lowered
                    or " permit 41 any any " in lowered
                ):
                    self.tunnel_rules.append(line)

                if (
                    " any any " in lowered
                    and " permit gre any any " not in lowered
                    and " permit ipinip any any " not in lowered
                    and " permit 41 any any " not in lowered
                ):
                    self.review_rules.append(line)

                if " permit " in lowered:
                    self.permit_rules += 1

                if " deny " in lowered:
                    self.deny_rules += 1

                if (" permit " in lowered and " any any " in lowered):
                    self.any_any_rules.append(line)

                if " deny ip any any " in lowered:
                    self.default_deny_rules.append(line)

            # -----------------------------
            # AAA
            # -----------------------------

            lowered = line.lower()

            if "tacacs" in lowered:
                self.tacacs = True

            if "radius" in lowered:
                self.radius = True

            if "saml" in lowered:
                self.saml = True

            #---------------#
            # Control Plane #
            #---------------#
            if "control-plane" in lowered and "access-group" in lowered:
                self.control_plane_acl = line.strip()
            
            #--------------------#
            # AAA Infrastructure #
            #--------------------#
            if line.startswith("object network"):

                name = line.split()[-1]

                upper_name = name.upper()

                if "TACACS" in upper_name:
                    self.tacacs_servers.add(name)

                if "RADIUS" in upper_name:
                    self.radius_servers.add(name)

                if "ISE" in upper_name:
                    self.ise_servers.add(name)

            #------------#
            # Monitoring #
            #------------#
            if "snmp" in lowered:
                self.snmp = True

            if "syslog" in lowered:
                self.syslog = True

            #---------------------------#
            # Monitoring Infrastructure #
            #---------------------------#
            upper = line.upper()

            if line.startswith("object network"):

                name = line.split()[-1]

                upper_name = name.upper()

                if (
                    "SOLARWINDS" in upper_name
                    or "SYSLOG" in upper_name
                    or "ALERT-LOGIC" in upper_name
                    or upper_name.startswith("LM-")
                    or "NOC" in upper_name
                ):
                    self.monitoring_platforms.add(name)

            if line.startswith("object-group network"):

                name = line.split()[-1]

                upper_name = name.upper()

                if (
                    "SOLARWINDS" in upper_name
                    or "SYSLOG" in upper_name
                    or "ALERT-LOGIC" in upper_name
                    or upper_name.startswith("LM-")
                    or "NOC" in upper_name
                ):
                    self.monitoring_platforms.add(name)

            #---------#
            # Logging #
            #---------#
            if line.startswith("logging enable"):
                self.logging_enabled = True

            if line.startswith("object network"):

                name = line.split()[-1]

                if "SYSLOG" in name.upper():
                    self.logging_destinations.add(name)

            if line.startswith("object-group network"):

                name = line.split()[-1]

                if "SYSLOG" in name.upper():
                    self.logging_destinations.add(name)

            #--------#
            # WebVPN #
            #--------#
            if "hsts-server" in lowered or "hsts-client" in lowered:
                self.webvpn_hsts = True

            if "content-security-policy" in lowered:
                self.webvpn_csp = True

            if line.startswith("ssl cipher tlsv1.2"):
                self.webvpn_tls = True

                if '"' in line:
                    cipher_string = line.split('"')[1]

                    for cipher in cipher_string.split(":"):
                        self.webvpn_ciphers.add(cipher.strip())

            #---------#
            # Routing #
            #---------#
            if line.startswith(
                "router bgp"
            ):
                self.bgp = True

            #-----#
            # NAT #
            #-----#
            if (
                line.startswith("nat ")
                or " nat " in f" {line} "
            ):
                self.nat = True

    def print_authentication(self):

        print(f"TACACS : {'Yes' if self.tacacs else 'No'}")
        print(f"RADIUS : {'Yes' if self.radius else 'No'}")
        print(f"SAML   : {'Yes' if self.saml else 'No'}")

        if self.tacacs_servers:

            print("\nTACACS Servers:")

            for server in sorted(self.tacacs_servers):
                print(f"  - {server}")

        if self.radius_servers:

            print("\nRADIUS Services:")

            for server in sorted(self.radius_servers):
                print(f"  - {server}")

        if self.ise_servers:

            print("\nCisco ISE Servers:")

            for server in sorted(self.ise_servers):
                print(f"  - {server}")

        print("\nLearning:")
        print("  TACACS is commonly used for administrator authentication.")
        print()
        print("  RADIUS is often used with MFA solutions.")
        print()
        print("  SAML typically indicates Azure AD / Entra integration.")

    def print_logging(self):

        print(f"Logging Enabled : {'Yes' if self.logging_enabled else 'No'}")

        if self.logging_destinations:

            print("\nLogging Destinations:")

            for destination in sorted(self.logging_destinations):
                print(f"  - {destination}")


    def print_webvpn(self):

        print(f"HSTS                 : {'Yes' if self.webvpn_hsts else 'No'}")
        print(f"Content Security     : {'Yes' if self.webvpn_csp else 'No'}")
        print(f"TLS 1.2 Configured   : {'Yes' if self.webvpn_tls else 'No'}")

        if self.webvpn_ciphers:

            print("\nTLS Cipher Suites:")

            for cipher in sorted(self.webvpn_ciphers):
                print(f"  - {cipher}")

        print("\nLearning:")
        print("  HSTS helps prevent protocol downgrade attacks.")
        print()
        print("  Content Security Policy helps reduce browser-based attacks.")
        print()
        print("  Restricting TLS cipher suites improves cryptographic security.")

    def section(self, title):

        print()
        print(f"{self.COLOR_BLUE}{'=' * 80}{self.COLOR_RESET}")
        print(f"{self.COLOR_BOLD}{title}{self.COLOR_RESET}")
        print(f"{self.COLOR_BLUE}{'=' * 80}{self.COLOR_RESET}")

    def subsection(self, title):

        print(f"\n{self.COLOR_CYAN}{title}{self.COLOR_RESET}\n")

    def report(self):

        self.section("FIREWALL AUDIT - CONFIGURATION OVERVIEW")

        # -----------------------------
        # Device Information
        # -----------------------------

        self.section("1. DEVICE INFORMATION")

        print(f"Hostname : {self.hostname}")
        print(f"Version  : {self.version}")
        print(f"Model    : {self.model}")

        print("\nWhy this matters:")
        print("  Firmware versions determine security features, support status and potential vulnerabilities.")

        # -----------------------------
        # Network Architecture
        # -----------------------------

        self.section("2. NETWORK ARCHITECTURE")

        vpn_zones = sum(1 for zone in self.zones if "vti" in zone.lower())

        print(f"Named Segments       : {len(self.nameifs)}")
        print(f"Security Zones       : {len(self.zones)}")
        print(f"Internet Interfaces  : {len(self.internet_interfaces)}")
        print(f"VPN Zones            : {vpn_zones}")
        print(f"Management Interfaces: {len(self.management_interfaces)}")

        self.subsection("SECURITY ZONE SUMMARY")

        for zone in sorted(self.zone_members):

            members = self.zone_members[zone]
            count = len(members)

            suffix = "IF" if count == 1 else "IFs"

            print(f"  - {zone} ({count} {suffix})")

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
                print(f"  - {entry}")

        # -----------------------------
        # Access Control Lists (ACLs)
        # -----------------------------

        self.section("3. ACCESS CONTROL")
        print(f"Network Objects : {self.object_count}")
        print(f"Object Groups   : {self.object_group_count}")
        print(f"ACL Entries     : {self.acl_count}")
        print(f"Permit Rules    : {self.permit_rules}")
        print(f"Deny Rules      : {self.deny_rules}")
        print("\nExample Objects:\n")
        
        for obj in self.objects[:20]:
            print(f" - {obj}")
        
        print("\nExample Object Groups:\n")
        
        for group in self.object_groups[:20]:
            print(f" - {group}")

        print("\nWhy this matters:")
        print("Firewall rules determine who can communicate with whom.")

        #
        # ACLs
        #
        
        self.section("4. ACL PREVIEW")
        
        print("\nFirst 20 ACL Entries:\n")
        
        for acl in self.acls[:20]:
            print(f" {acl}")
        
        #
        # ANY ANY
        #

        self.section("5. POTENTIAL FINDINGS")

        if self.review_rules:

            print(f"Rules Requiring Review: {len(self.review_rules)}")
            print()

            for rule in self.review_rules[:10]:
                print(f"  {rule}")
                
        else:
            print("No obvious 'permit ip any any' rules found.")

        #
        # VPN
        #

        self.section("6. REMOTE CONNECTIVITY")

        print("\nVPN Pools:")

        for pool in self.vpn_pools:
            print(f"  - {pool}")
        print("\nTunnel Interfaces:")

        for tunnel in sorted(set(self.tunnels)):
            print(f"  - {tunnel}")
        print("\nDisabled Tunnels:")

        if self.disabled_tunnels:
            for tunnel in self.disabled_tunnels:
                print(f"  - {tunnel}")
        else:
            print("  None detected")

        print("\nLearning:")
        print("  VPN Pools = IP ranges given to remote users.")
        print()
        print("  Tunnel Interfaces = network-to-network VPNs.")

        #
        # AUTH
        #

        self.section("7. ADMINISTRATION & AUTHENTICATION")
        self.print_authentication()


        #
        # ROUTING / NAT
        #

        self.section("8. NETWORK SERVICES")
        print(f"BGP : {'Yes' if self.bgp else 'No'}")
        print(f"NAT : {'Yes' if self.nat else 'No'}")

        print("\nLearning:")
        print("  NAT maps one address space to another.")
        print()
        print("  Routing determines where traffic travels.")

        #
        # MONITORING
        #

        self.section("9. MONITORING")

        print(f"SNMP   : {'Yes' if self.snmp else 'No'}")
        print(f"Syslog : {'Yes' if self.syslog else 'No'}")

        if self.monitoring_platforms:

            print("\nMonitoring Platforms:")

            for platform in sorted(self.monitoring_platforms):
                print(f"  - {platform}")

        print("\nLearning:")
        print("  SNMP is used for monitoring.")
        print()
        print("  Syslog exports security")
        print("  and operational events.")

        #
        # LOGGING
        #

        self.section("10. LOGGING")
        self.print_logging()

        #
        # WEBVPN
        #

        self.section("8. WEBVPN SECURITY")
        self.print_webvpn()

        #
        # CONTROL PLANE
        #

        self.section("CONTROL PLANE PROTECTION")

        if self.control_plane_acl:

            print("Control Plane ACL:")
            print(f"  {self.control_plane_acl}")

        else:

            print("No control-plane ACL identified.")

        #
        # ROADMAP
        #

        self.section("10. WHAT SHOULD I LOOK AT NEXT?")
        print("1. Internet-Facing Interfaces")
        print(f"   -> {len(self.internet_interfaces)} found")
        print()
        print("2. VPN Architecture")
        print(f"   -> {len(self.vpn_pools)} VPN pools")
        print(f"   -> {len(self.tunnels)} tunnel definitions")
        print()
        print("3. Firewall Rules")
        print(f"   -> {self.acl_count} ACL entries")
        print()
        print("4. Authentication Controls")
        print(f"   -> TACACS={self.tacacs}, "f"RADIUS={self.radius}, "f"SAML={self.saml}")
        print()
        print("5. Monitoring")
        print(f"   -> SNMP={self.snmp}, "f"Syslog={self.syslog}")
        print()
        print("Goal: Understand the architecture before attempting to identify security findings.")


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
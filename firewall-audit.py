#!/usr/bin/env python3

import re
import sys


class FirewallAudit:

    def __init__(self):

        # Device
        self.hostname = None
        self.version = None
        self.model = None

        # Interfaces / Zones
        self.interfaces = []
        self.zones = set()

        self.internet_interfaces = []
        self.management_interfaces = []
        self.nameifs = []

        # VPN
        self.vpn_pools = []
        self.tunnels = []
        self.disabled_tunnels = []

        # Objects
        self.object_count = 0
        self.object_group_count = 0
        
        self.objects = []
        self.object_groups = []

        # ACL
        self.acl_count = 0
        self.permit_rules = 0
        self.deny_rules = 0

        self.review_rules = []
        self.acls = []

        # AAA
        self.tacacs = False
        self.radius = False
        self.saml = False

        # Monitoring
        self.snmp = False
        self.syslog = False

        # Routing / NAT
        self.bgp = False
        self.nat = False

    def parse(self, filepath):

        current_interface = None
        current_is_tunnel = False

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for raw_line in lines:

            line = raw_line.strip()

            #
            # DEVICE
            #

            if (
                "Cisco Firepower" in line
                and "Threat Defense" in line
            ):
                self.model = line

            match = re.match(r"hostname\s+(.+)", line)
            if match:
                self.hostname = match.group(1)

            match = re.match(r"NGFW Version\s+(.+)", line)
            if match:
                self.version = match.group(1)

            #
            # INTERFACES
            #

            match = re.match(
                r"interface\s+(.+)",
                line
            )

            if match:

                current_interface = match.group(1)
                self.interfaces.append(current_interface)

                current_is_tunnel = (
                    current_interface.startswith("Tunnel")
                )

            #
            # DISABLED TUNNELS
            #

            if (
                line == "shutdown"
                and current_is_tunnel
                and current_interface
            ):
                self.disabled_tunnels.append(
                    current_interface
                )

            #
            # INTERFACE NAMES
            #

            match = re.match(r"nameif\s+(.+)", line)

            if match:
                nameif = match.group(1)
                self.nameifs.append(nameif)

                if "internet" in nameif.lower():
                    self.internet_interfaces.append(nameif)

                if ("mgt" in nameif.lower() or "management" in nameif.lower()):
                    self.management_interfaces.append(nameif)

            #
            # VPN POOLS
            #

            match = re.match(
                r"ip local pool\s+(\S+)",
                line
            )

            if match:
                self.vpn_pools.append(
                    match.group(1)
                )

            #
            # TUNNEL DESCRIPTIONS
            #

            if (
                line.startswith("description ")
                and "VTI" in line.upper()
            ):

                desc = (
                    line.replace(
                        "description",
                        ""
                    )
                    .strip()
                )

                self.tunnels.append(desc)

            #
            # ZONES
            #

            if "security-zone" in line:

                zone_match = re.match(
                    r"object-group interface (.+?) security-zone",
                    line
                )

                if zone_match:
                    self.zones.add(
                        zone_match.group(1)
                    )

            #
            # OBJECTS
            #

            match = re.match(r"object network (.+)", line)
            
            if match:
                self.object_count +=1
                self.objects.append(match.group(1))

            #
            # OBJECT GROUPS
            #

            match = re.match(r"object-group (.+)", line)
            
            if match:
                self.object_group_count += 1
                self.object_groups.append(match.group(1))

            #
            # ACLS
            #

            if line.startswith("access-list "):

                if " any any " in f" {line.lower()} ":
                    self.review_rules.append(line)

                if " permit " in lowered:
                    self.permit_rules += 1

                if " deny " in lowered:
                    self.deny_rules += 1

                if (
                    " permit ip any any "
                    in lowered
                ):

                    self.any_any_rules.append(
                        line
                    )

            #
            # AAA
            #

            lowered = line.lower()

            if "tacacs" in lowered:
                self.tacacs = True

            if "radius" in lowered:
                self.radius = True

            if "saml" in lowered:
                self.saml = True

            #
            # MONITORING
            #

            if "snmp" in lowered:
                self.snmp = True

            if "syslog" in lowered:
                self.syslog = True

            #
            # ROUTING
            #

            if line.startswith(
                "router bgp"
            ):
                self.bgp = True

            #
            # NAT
            #

            if (
                line.startswith("nat ")
                or " nat " in f" {line} "
            ):
                self.nat = True

    def section(self, title):

        print()
        print("=" * 80)
        print(title)
        print("=" * 80)

    def report(self):

        self.section("FIREWALL AUDIT - CONFIGURATION OVERVIEW")

        #
        # DEVICE
        #

        self.section("1. DEVICE & MANAGEMENT PLANE")

        print(f"Hostname : {self.hostname}")
        print(f"Version  : {self.version}")
        print(f"Model    : {self.model}")

        print("\nWhy this matters:")
        print("  Firmware versions determine security features, support status and potential vulnerabilities.")

        #
        # ARCHITECTURE
        #

        self.section("2. NETWORK ARCHITECTURE")

        print(f"Interfaces Found : {len(self.interfaces)}")
        print(f"\nName Interfaces:")
        
        for iface in sorted(set(self.nameifs)):
            print(f" - {iface}")
        
        print("\nZones:")

        for zone in sorted(self.zones):
            print(f"  - {zone}")
        print("\nInternet Facing Interfaces:")

        for iface in sorted(set(self.internet_interfaces)):
            print(f"  - {iface}")

        print("\nManagement Interfaces:")

        for iface in sorted(set(self.management_interfaces)):
            print(f"  - {iface}")
        print("\nReview Focus:")
        print("  - Internet -> Corp access")
        print("  - Internet -> Management access")
        print("  - DMZ segregation")
        print("  - Trust boundaries")

        #
        # ACCESS CONTROL
        #

        self.section("3. ACCESS CONTROL")
        print(f"Network Objects : {self.object_count}")
        print(f"Object Groups   : {self.object_group_count}")
        print(f"ACL Entries     : {self.acl_count}")
        print("\nExample Objects:\n")
        
        for obj in self.objects[:20]:
            print(f" - {obj}")
        
        print("\nExample Object Groups:\n")
        
        for group in self.object_groups[:20]:
            print(f" - {group}")
        
        print(f"Permit Rules    : {self.permit_rules}")
        print(f"Deny Rules      : {self.deny_rules}")

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

        print(f"TACACS : {'Yes' if self.tacacs else 'No'}")
        print(f"RADIUS : {'Yes' if self.radius else 'No'}")
        print(f"SAML   : {'Yes' if self.saml else 'No'}")
        
        print("\nLearning:")
        print("  TACACS is commonly used for administrator authentication.")
        print()
        print("  RADIUS is often used with MFA solutions.")
        print()
        print("  SAML typically indicates Azure AD / Entra integration.")

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

        print("\nLearning:")
        print("  SNMP is used for monitoring.")
        print()
        print("  Syslog exports security")
        print("  and operational events.")

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

    if len(sys.argv) != 2:

        print(
            f"Usage: {sys.argv[0]} <config.log>"
        )

        sys.exit(1)

    audit = FirewallAudit()

    audit.parse(sys.argv[1])

    audit.report()


if __name__ == "__main__":
    main()
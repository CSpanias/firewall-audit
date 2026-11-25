# VPN and NAT inventory

The report inventories enabled and disabled IPsec phase-one definitions,
available SSL VPN settings, virtual IPs, and policies with source NAT enabled.

## VPN review

Review each tunnel's state, interface, remote gateway, and associated
networks. Disabled definitions may represent retired connections that should
be confirmed and removed when no longer needed. The parser does not verify
runtime tunnel state, cryptographic negotiation, or phase-two traffic selectors
in this release.

## NAT review

VIPs are listed with their external and mapped addresses, external interface,
and port-forwarding fields. Policies using NAT are listed separately because
translation and access control are distinct configuration decisions.

Confirm each published service against the matching policy, source scope, and
business owner. NAT configuration alone does not prove that a service is
reachable or permitted.

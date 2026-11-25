# Administrative exposure

Firewall administration is part of the control plane. The tool highlights
configuration paths that may expose management services, without asserting
that a connection is reachable from the internet.

## Management services on WAN interfaces

Enabled interfaces identified as WAN-facing are checked for configured
`allowaccess` services such as HTTP, HTTPS, SSH, and Telnet. The finding
identifies the interface and enabled services.

## Administrative services through VIPs

Enabled allow policies are checked for references to public or WAN-facing
VIPs and services associated with SSH, Telnet or RDP. Built-in services,
configured custom TCP destination ports, and service groups are considered.
A broad service such as `ALL` can match. For port-forwarding VIPs, the mapped
port must include one of these services; a VIP forwarding only HTTPS is not
classified as administrative. VIPs without explicit port forwarding are
reviewed based on the policy's service definitions. Negated destinations and
groups with exclusions are not treated as positive VIP references.
Port-forwarding VIPs without a recognisable mapped port are not classified
by this check.

Check the source scope, VIP mapping, target system, and business owner. A VIP
may publish a management interface belonging to another device; the static
configuration alone cannot establish that context or actual reachability.
HTTP and HTTPS may still host administrative interfaces, and administrative
services may use non-standard ports; these require manual review.

## Management safeguards

Validate trusted source restrictions, MFA, host firewalls, jump-host access,
and upstream reachability separately. Remove obsolete management paths when
they are no longer required.

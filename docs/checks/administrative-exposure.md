# Administrative exposure

Firewall administration is part of the control plane. The tool highlights
configuration paths that may expose management services, without asserting
that a connection is reachable from the internet.

## Management services on WAN interfaces

Enabled interfaces identified as WAN-facing are checked for configured
`allowaccess` services such as HTTP, HTTPS, SSH, and Telnet. The finding
identifies the interface and enabled services.

## Administrative services through VIPs

Enabled allow policies are checked for references to WAN-facing VIPs and
administrative services. Built-in services, configured custom-service ports,
and service groups are considered. A broad service such as `ALL` can match an
administrative service.

Check the source scope, VIP mapping, target system, and business owner. A VIP
may publish a management interface belonging to another device; the static
configuration alone cannot establish that context.

## Management safeguards

Validate trusted source restrictions, MFA, host firewalls, jump-host access,
and upstream reachability separately. Remove obsolete management paths when
they are no longer required.

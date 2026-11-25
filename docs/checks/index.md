# Checks

Firewall-Audit extracts evidence across the review areas in the
[firewall security review methodology](https://mollysec.com/posts/firewall-security-explained/).
The table distinguishes current automated indicators from configuration
inventory; it does not claim that every control is completely assessed.

| Review area | Security question | Current output |
|---|---|---|
| [Network architecture](network-architecture.md) | What interfaces and zones define network boundaries? | Interface roles, addresses, management services, zones, and inventory |
| [Access control](access-control.md) | Which policies permit traffic, and are any unrestricted? | Policy inventory and allow policies with unrestricted endpoints |
| [Administrative exposure](administrative-exposure.md) | Can WAN-facing paths reach administration services? | Management services on WAN interfaces and admin services permitted to WAN VIPs |
| [Legacy services](legacy-services.md) | Do enabled policies reference clear-text or legacy protocols? | Named services, custom port definitions, and service-group references |
| [Administration](administration.md) | How are administrators authenticated? | Local administrator count, remote-auth count, and configured AAA servers |
| [Logging and monitoring](logging-monitoring.md) | Can events be investigated and time be trusted? | Remote logging configuration, explicit policy logging gaps, NTP, and SNMP inventory |
| [VPN and NAT](vpn-nat.md) | What remote connections and translated services are configured? | VPN, VIP, and NAT policy inventory |

Finding metadata lives in
[`common/findings.yaml`](https://github.com/CSpanias/firewall-audit/blob/main/common/findings.yaml).
Each finding includes a severity, evidence-based description, recommendation,
and an optional SureFormat ID.

!!! note "Configuration context matters"
    The checks do not emulate the firewall, resolve every dynamic or nested
    object, or validate routing and upstream controls. Use the evidence to
    focus manual review, not as a substitute for it.

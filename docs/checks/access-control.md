# Access control

The parser records FortiGate firewall policies in order, including their
interfaces, source and destination objects, services, action, enabled state,
schedule, logging setting, and NAT setting.

For Cisco ASA/FTD exports, the parser extracts extended and advanced ACL
entries and their bindings. The checks apply only to bound ACLs; standard
ACLs are excluded and reported as a parsing limitation.

## Unrestricted endpoints

The `broad-allow-rule` check identifies enabled allow policies whose source and
destination references include `all`, `any`, or an equivalent wildcard. It
reports the policy ID and references as evidence.
FortiOS rules with negated source or destination addresses are not classified
as unrestricted solely because they reference a wildcard.

This indicator does not calculate effective policy behavior. Address groups,
policy order, routing, schedules, and other features can affect the actual
traffic decision. Review the referenced objects and intended business purpose.

## WAN VIP policy paths

Policies potentially permitting SSH, Telnet or RDP through a public or
WAN-facing VIP are reported separately. See
[Administrative exposure](administrative-exposure.md) for the scope and
limitations of that check.

## Potential temporary access

The `temporary-access-review` check flags enabled allow rules whose names or
comments contain temporary or testing-related terms, or which explicitly
reference a host supplied using `--assessment-ip`. A matching subnet alone is
not treated as proof that a rule is for testing. Evidence includes source
references and supported resolved scopes, services, the configured schedule
and the reason for review. Cisco checks are limited to bound ACLs.
Rules dedicated exclusively to supplied assessment hosts are excluded from
all automated rule findings; shared rules are still reviewed.

These are indicators for owner review, not proof that access is temporary,
expired or no longer required. Creation dates, ownership and the effective
expiry of named schedules cannot be established by this check.

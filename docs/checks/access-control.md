# Access control

The parser records FortiGate firewall policies in order, including their
interfaces, source and destination objects, services, action, enabled state,
schedule, logging setting, and NAT setting.

## Unrestricted endpoints

The `broad-allow-rule` check identifies enabled allow policies whose source and
destination references include `all`, `any`, or an equivalent wildcard. It
reports the policy ID and references as evidence.

This indicator does not calculate effective policy behavior. Address groups,
policy order, routing, schedules, and other features can affect the actual
traffic decision. Review the referenced objects and intended business purpose.

## WAN VIP policy paths

Policies permitting administrative services to a configured WAN-facing VIP
are reported separately. See [Administrative exposure](administrative-exposure.md)
for the scope and limitations of that check.

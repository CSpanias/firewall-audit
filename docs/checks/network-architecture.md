# Network architecture

The parser inventories interfaces, zones, address objects, and address groups
to help establish the configuration's network context.

## Evidence collected

For interfaces, the report includes the configured address, role,
description, state, and `allowaccess` management services. It marks an
interface as WAN-facing when its FortiOS role is `wan` or the assigned
address appears externally routable. This is a configuration heuristic, not a
reachability test.

Zones are reported with their member interfaces. Address objects and groups
are recorded by name and supported address fields so policy references can be
reviewed in context.

For FortiOS exports, the version header's identifier is retained as a platform
identifier rather than treated as a device model. The `FGVMAZ` identifier is
displayed as `FortiGate-VM (Azure)`; other identifiers remain uninterpreted
unless a platform can be established.

## Review considerations

Confirm that interface roles and zone membership match the intended trust
boundaries. Check that management access is limited to dedicated management
networks, and validate public exposure against routing, upstream ACLs, and
deployment topology.

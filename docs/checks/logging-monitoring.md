# Logging and monitoring

The report inventories Syslog and FortiAnalyzer destinations without exporting
credentials. It also summarizes policy logging settings, NTP, SNMP counts, and
configured session helpers.

## Logging

`logging-coverage-gap` is raised when no explicitly enabled remote destination
with a server is identified in the parsed Syslog or FortiAnalyzer settings.
Other logging mechanisms are not assessed. `policy-logging-gap` reports enabled
allow or deny policies that
explicitly disable traffic logging; policies whose logging behavior is not
explicitly set are not assumed to be disabled.

Validate event categories, deny-rule coverage, reliable delivery, retention,
access controls, alerting, and ingestion at the central platform.

## Time synchronization

`ntp-server-review` is raised when NTP synchronisation is explicitly disabled
or no explicit NTP server entry is found. The
check does not verify time synchronization or trustworthiness of a configured
provider. Confirm approved time sources and restrict NTP access appropriately.

## SNMP and session helpers

SNMP community and SNMPv3 user counts are reported without community values.
Session helpers are inventoried because legacy helpers can affect protocol
handling; no helper is automatically declared vulnerable.

# Clear-text and legacy services

The `legacy-service-policy` check reviews enabled allow policies for services
commonly associated with clear-text or legacy protocols. These include HTTP,
FTP, Telnet, RSH/Rlogin, NetBIOS, SNMP, and TFTP.

The parser considers built-in service names, configured custom TCP/UDP/SCTP
destination port ranges, and service groups. FortiOS source-port constraints
are not treated as destination ports. A policy referencing `ALL` is a
broad-service review indicator because it can include legacy protocols.
Where every directly referenced VIP explicitly forwards only non-legacy ports,
the policy is not reported solely because of its service definition; complex
VIP groups and unrecognised mappings still require manual review.

Cisco ASA/FTD reviews bound permit and trust ACL entries and supported
service-group port definitions. Unresolved expressions are reported as
parsing limitations.

The check does not prove that a particular application uses a protocol
securely. Confirm the service, destination, business need, and compensating
controls. Prefer secure alternatives, disable unused services and helpers,
and explicitly restrict insecure protocols.

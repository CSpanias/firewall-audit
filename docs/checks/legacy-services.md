# Clear-text and legacy services

The `legacy-service-policy` check reviews enabled allow policies for services
commonly associated with clear-text or legacy protocols. These include HTTP,
FTP, Telnet, RSH/Rlogin, NetBIOS, SNMP, and TFTP.

The parser considers built-in service names, configured custom TCP/UDP/SCTP
port ranges, and service groups. A policy referencing `ALL` is treated as a
broad-service review indicator because it can include legacy protocols. When
an administrative VIP check already covers an `ALL` service, that policy is
not duplicated in this finding.

Cisco ASA/FTD reviews bound permit and trust ACL entries and supported
service-group port definitions. Unresolved expressions are reported as
parsing limitations.

The check does not prove that a particular application uses a protocol
securely. Confirm the service, destination, business need, and compensating
controls. Prefer secure alternatives, disable unused services and helpers,
and explicitly restrict insecure protocols.

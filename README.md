# Firewall-Audit

Firewall-Audit reviews exported firewall configurations and extracts
security-relevant context for an analyst. It supports FortiOS and Cisco
ASA/FTD text exports, and limited policy inventory from WatchGuard Firebox
configuration report PDFs.

The review follows the areas described in
[Firewall Security Explained](https://mollysec.com/posts/firewall-security-explained/):
network architecture, access control, VPNs, administration and authentication,
control-plane access, logging, monitoring, and NAT. Configuration findings are
review indicators, not proof of external reachability or exploitability.

## Installation

Install from a local checkout with [uv](https://docs.astral.sh/uv/):

```powershell
uv tool install .
```

Or install the project and its development dependencies:

```powershell
uv sync --group dev
```

## Usage

```powershell
firewall-audit --config firewall.conf
firewall-audit -C firewall.conf --output-dir reports
firewall-audit -C firewall.conf --assessment-ip 192.0.2.10
firewall-audit -C firewall.conf --evidence
firewall-audit -C firewall.conf --evidence legacy-service-policy
firewall-audit -C firewall.conf --evidence-full
firewall-audit -C firewall.conf --evidence-full legacy-service-policy
```

Each run generates a timestamped JSON report and a self-contained HTML report.
Repeat `--assessment-ip` for multiple testing hosts. Rules whose source or
destination consists exclusively of those hosts are excluded from findings;
shared and subnet rules remain in scope.
Use `--evidence` to display compact samples of selected configuration lines, or
supply a finding ID to display only that finding's evidence. Use
`--evidence-full` instead to show all selected lines without sample truncation;
it also accepts an optional finding ID.

The HTML report works offline and provides an executive summary, technical
commentary with supporting evidence, and remediation guidance. Each section
and the complete report can be copied as Markdown. Credential fields are not
included in exported reports.

## Current review coverage

The FortiOS parser extracts device metadata, interfaces and management
services, zones, address objects and groups, custom services and groups,
firewall and local-in policies, VIPs, IPsec and SSL VPN configuration,
administrator and central-authentication counts, remote logging, NTP, SNMP
counts, and session helpers.

FortiOS checks identify:

* Enabled allow policies with unrestricted source and destination.
* Management services enabled on WAN-facing interfaces.
* Potential SSH, Telnet or RDP access through public or WAN-facing VIPs.
* Enabled allow policies referencing clear-text or legacy services.
* Potential temporary or testing-related access requiring owner review.
* Unverified remote logging and explicitly disabled policy logging.
* Disabled NTP synchronisation or missing explicit NTP server entries.

Cisco checks review bound ACL entries for unrestricted endpoints, potential
temporary access, and clear-text, legacy, or unrestricted services. Standard
ACLs are not included.
The WatchGuard PDF parser currently inventories policy names, order, state,
action, and logging only; it does not run security checks.

Finding metadata is maintained in [`common/findings.yaml`](common/findings.yaml).

## Documentation

Browse the [MkDocs documentation](docs/index.md) and its [Checks reference](docs/checks/index.md).
Run `python -m mkdocs serve` to preview the site locally.

## Development

```powershell
python -m unittest discover -s tests
ruff check analysis cli common models parsers reporting tests
python -m mkdocs build --strict
```

## Limitations

* WatchGuard PDF source and destination addresses, services, and detailed
  settings are not parsed. The report is an inventory, not a security review.
* Cisco ACL checks do not calculate effective policy order or reachability.
* A static export cannot prove which interfaces or services are reachable from
  the internet, how upstream routing behaves, or whether a rule is justified.
* Service groups and address groups are reported and expanded for supported
  checks, but complex routing, policy ordering, dynamic objects, and runtime
  enforcement are not fully evaluated.
* Findings require validation against device behavior and organizational
  requirements; this is not a complete security assessment.

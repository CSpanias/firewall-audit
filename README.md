# Firewall-Audit

Firewall-Audit reviews exported firewall configurations and extracts
security-relevant context for an analyst. The current modular workflow supports
FortiOS text configuration backups.

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
firewall-audit audit --config firewall.conf
firewall-audit audit -C firewall.conf --output-dir reports --format both
firewall-audit audit -C firewall.conf --csacyber
```

The default output is a timestamped YAML report and a self-contained HTML
dashboard. `--format` accepts `yaml`, `json`, or `both`; HTML is always
generated. `--csacyber` additionally exports a SureFormat XML file containing
only findings with an explicitly configured CSA Cyber `sureformat_id`.
Unmapped findings are reported in the terminal and omitted from that XML.

The HTML dashboard works offline and includes device and inventory summaries,
interface and zone details, policy and VPN tables, administration, logging,
monitoring, NAT, and searchable/filterable findings with evidence and
recommendations. Credential values are not included in exported reports.

## Current review coverage

The FortiOS parser extracts device metadata, interfaces and management
services, zones, address objects and groups, custom services and groups,
firewall and local-in policies, VIPs, IPsec and SSL VPN configuration,
administrator and central-authentication counts, remote logging, NTP, SNMP
counts, and session helpers.

The current checks identify:

* Enabled allow policies with unrestricted source and destination.
* Management services enabled on WAN-facing interfaces.
* Administrative services permitted to WAN-facing VIPs.
* Enabled allow policies referencing clear-text or legacy services.
* Missing remote logging and explicitly disabled policy logging.
* Missing explicit NTP server entries.

Finding metadata and optional CSA Cyber mappings are maintained in
[`common/findings.yaml`](common/findings.yaml). Add a validated SureFormat ID to
a finding definition when a mapping is confirmed; IDs are not guessed.

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

* Cisco, ASA/FTD, and other vendor configurations are not yet supported by the
  modular parser.
* A static export cannot prove which interfaces or services are reachable from
  the internet, how upstream routing behaves, or whether a rule is justified.
* Service groups and address groups are reported and expanded for supported
  checks, but complex routing, policy ordering, dynamic objects, and runtime
  enforcement are not fully evaluated.
* Findings require validation against device behavior and organizational
  requirements; this is not a complete security assessment.

# Assessment workflow and reports

Only review configurations you are authorised to assess. FortiOS exports can
contain sensitive operational data; keep both the input and generated reports
in approved storage.

## Run an assessment

```powershell
firewall-audit audit --config firewall.conf
firewall-audit audit -C firewall.conf --output-dir reports --format both
firewall-audit audit -C firewall.conf --csacyber
```

The workflow validates the input, detects FortiOS, parses configuration
sections, runs the current review checks, and writes timestamped reports.
Progress and findings are shown in the terminal.

## Output files

By default, output is written to `firewall-audit-output` in the current
directory:

* `<config>-<timestamp>.yaml`: structured assessment data.
* `<config>-<timestamp>.html`: self-contained interactive report.
* `--format json` or `--format both` also writes a JSON report.
* `--csacyber` also writes SureFormat XML for findings with explicit mappings.

The HTML report presents device metadata, interface and zone inventory,
policies, VPNs, administration and authentication, logging, monitoring, NAT,
and findings. Findings can be searched and filtered by severity and review
area. It loads no remote assets.

The parser extracts selected configuration fields and does not export
administrator passwords, authentication secrets, SNMP community values, or
private keys. Reports still contain network and policy details; treat them as
sensitive assessment artifacts.

## CSA Cyber mappings

`--csacyber` uses the SureFormat XML structure. Finding definitions may specify
a validated `sureformat_id` in `common/findings.yaml`. IDs are not inferred or
guessed. Unmapped findings are reported in the terminal and omitted from the
XML; add mappings only after confirming the appropriate CSA Cyber identifier.

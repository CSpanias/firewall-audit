# Assessment workflow and reports

Only review configurations you are authorised to assess. Firewall exports can
contain sensitive operational data; keep both the input and generated reports
in approved storage.

## Run an assessment

```powershell
firewall-audit --config firewall.conf
firewall-audit -C firewall.conf --output-dir reports
firewall-audit -C firewall.conf --assessment-ip 192.0.2.10
```

The workflow validates the input, detects the vendor, parses supported
configuration sections, runs applicable review checks, and writes timestamped
reports. Progress, findings, and parsing limitations are shown in the terminal.

Use `--assessment-ip` for a known assessment host; repeat the flag to supply
multiple IPv4 or IPv6 addresses. Rules are excluded from automated findings
only when an entire source or destination consists of explicitly resolved
individual assessment hosts, including supported nested address groups.
Rules shared with other hosts, subnets or ranges remain in scope. Negated
addresses, wildcards, unresolved or dynamic objects, groups with exclusions,
and VIP/NAT mappings cannot establish a dedicated host scope. The structured
JSON retains matching and unresolved references and excluded rule identifiers
for auditing; the commentary contains only a concise note. Inventory counts
continue to describe the complete configuration. Firebox PDF inventories do
not include rule addresses and cannot be evaluated for exclusions.

The report's evidence tables summarise parsed configuration; validate findings
against the original export and capture any required source screenshots
separately. Review screenshots for sensitive information before sharing them.

## Output files

By default, output is written to `firewall-audit` in the current
directory:

* `<config>-<timestamp>.json`: structured assessment data.
* `<config>-<timestamp>.html`: self-contained interactive report.

The HTML report contains an executive summary of the observed issues and their
potential impact, technical commentary that groups related observations with
supporting evidence tables, and
prioritised remediation guidance with references relevant to the findings.
The summary distinguishes an inventory-only input from a
configuration review and notes the limits of static analysis. Copy controls
provide Markdown for each section or the whole report. It loads no remote assets.

The Firebox PDF parser extracts the policy summary table only. It does not
parse source and destination addresses, service definitions, or detailed
settings, and does not run security checks. Its limitations are displayed in
the terminal and report.

The parser extracts selected configuration fields and does not export
administrator passwords, authentication secrets, SNMP community values, or
private keys. Reports still contain network and policy details; treat them as
sensitive assessment artifacts.

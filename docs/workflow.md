# Assessment workflow and reports

Only review configurations you are authorised to assess. Firewall exports can
contain sensitive operational data; keep both the input and generated reports
in approved storage.

## Run an assessment

```powershell
firewall-audit --config firewall.conf
firewall-audit -C firewall.conf --output-dir reports
firewall-audit -C firewall.conf --assessment-ip 192.0.2.10
firewall-audit -C firewall.conf --evidence
firewall-audit -C firewall.conf --evidence legacy-service-policy
firewall-audit -C firewall.conf --evidence-full
firewall-audit -C firewall.conf --evidence-full legacy-service-policy
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

Use `--evidence` to print compact samples of selected original source lines
with line numbers, grouped by finding. Samples prioritise one affected rule
and may omit other rules, referenced objects or parts of long lines. The output
identifies omissions; use `--evidence-full` instead to display all selected
lines and complete line values. Either option accepts a finding ID to limit the
display to that finding.
FortiOS output omits unselected configuration fields, including passwords,
secrets and free-text comments; control characters are replaced. Cisco output
shows matching ACL lines but not referenced object definitions, and may contain
sensitive values. Absence-based
observations are explicitly labelled because an excerpt cannot prove absence.
The evidence is not added to the report files. Selected source lines can still
contain sensitive network details or other sensitive values; review screenshots
and share them only through approved channels.

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

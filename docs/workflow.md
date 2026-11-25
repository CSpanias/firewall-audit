# Assessment workflow and reports

Only review configurations you are authorised to assess. Firewall exports can
contain sensitive operational data; keep both the input and generated reports
in approved storage.

## Run an assessment

```powershell
firewall-audit --config firewall.conf
firewall-audit -C firewall.conf --output-dir reports
```

The workflow validates the input, detects the vendor, parses supported
configuration sections, runs applicable review checks, and writes timestamped
reports. Progress, findings, and parsing limitations are shown in the terminal.

## Output files

By default, output is written to `firewall-audit-output` in the current
directory:

* `<config>-<timestamp>.json`: structured assessment data.
* `<config>-<timestamp>.html`: self-contained interactive report.

The HTML report contains an executive summary, technical commentary with
supporting evidence tables, and remediation guidance. Copy controls provide
Markdown for each section or the whole report. It loads no remote assets.

The Firebox PDF parser extracts the policy summary table only. It does not
parse source and destination addresses, service definitions, or detailed
settings, and does not run security checks. Its limitations are displayed in
the terminal and report.

The parser extracts selected configuration fields and does not export
administrator passwords, authentication secrets, SNMP community values, or
private keys. Reports still contain network and policy details; treat them as
sensitive assessment artifacts.

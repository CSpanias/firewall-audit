# Firewall-Audit

Firewall-Audit turns supported firewall configuration exports into a structured
assessment and a self-contained HTML report. It focuses on the security
questions in [Firewall Security Explained](https://mollysec.com/posts/firewall-security-explained/):
what networks are connected, how policies allow traffic, how administration is
protected, and what is exposed through VPN and NAT configuration.

Start with [installation](installation.md), then run the
[assessment workflow](workflow.md). The [Checks reference](checks/index.md)
describes current findings and their evidence.

## What it produces

* A Rich terminal workflow with progress, configuration summaries, and
  severity-labelled findings.
* A timestamped JSON report.
* A standalone HTML report with an executive summary, technical commentary,
  remediation guidance, and Markdown copy controls.

FortiOS and Cisco ASA/FTD text exports are supported. WatchGuard Firebox
configuration report PDFs are supported for policy inventory only; no
automated security checks are run on those reports.
FortiOS VDOM-scoped exports are not supported and are rejected.

!!! warning "Review indicators"
    A static configuration export cannot establish runtime reachability,
    effective routing, policy behavior in every deployment, or business
    justification. Validate findings with the device owner and operational
    context.

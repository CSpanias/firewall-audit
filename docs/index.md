# Firewall-Audit

Firewall-Audit turns a FortiOS text configuration export into a structured
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
* A timestamped YAML report by default, or JSON with `--format json`.
* A standalone HTML report that works offline and contains inventory,
  configuration evidence, and searchable findings.
* Optional CSA Cyber SureFormat XML with `--csacyber`. Only findings with a
  confirmed `sureformat_id` mapping are included.

The current modular parser supports FortiOS configuration exports. It does not
yet support Cisco ASA/FTD or other firewall vendors.

!!! warning "Review indicators"
    A static configuration export cannot establish runtime reachability,
    effective routing, policy behavior in every deployment, or business
    justification. Validate findings with the device owner and operational
    context.

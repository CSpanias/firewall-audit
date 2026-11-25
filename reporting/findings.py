"""Structured assessment report construction and export."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from models.finding import Finding
from models.firewall import FirewallConfig


def build_report(
    config: FirewallConfig,
    findings: list[Finding],
    source_name: str,
) -> dict[str, Any]:
    """Create a versioned, vendor-neutral assessment document."""
    interfaces = [
        {
            "name": interface.name,
            "address": interface.address,
            "role": interface.role,
            "description": interface.description,
            "enabled": interface.enabled,
            "internet_facing": interface.internet_facing,
            "management_services": interface.management_services,
        }
        for interface in config.interface_details
    ]
    rules = [
        {
            "id": rule.id,
            "name": rule.name,
            "source_interfaces": rule.source_zones,
            "destination_interfaces": rule.destination_zones,
            "source_addresses": rule.source_addresses,
            "destination_addresses": rule.destination_addresses,
            "services": rule.services,
            "action": rule.action,
            "enabled": rule.enabled,
            "schedule": rule.schedule,
            "logging": rule.logging,
            "nat": rule.nat,
        }
        for rule in config.rules
    ]
    active_vpns = [vpn for vpn in config.vpns if vpn.enabled]
    severity_counts = {
        severity: sum(finding.severity.lower() == severity for finding in findings)
        for severity in ("critical", "high", "medium", "low", "info")
    }

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source_name,
        "device": {
            "vendor": config.vendor,
            "hostname": config.hostname,
            "version": config.version,
            "model": config.model,
            "build": config.config_build,
        },
        "inventory": {
            "interfaces": len(config.interfaces),
            "zones": len(config.zones),
            "address_objects": len(config.objects),
            "object_groups": len(config.object_groups),
            "rules": len(config.rules),
            "enabled_rules": sum(rule.enabled for rule in config.rules),
            "disabled_rules": sum(not rule.enabled for rule in config.rules),
            "virtual_ips": len(config.virtual_ips),
            "vpn_tunnels": len(config.vpns),
            "enabled_vpns": len(active_vpns),
            "disabled_vpns": len(config.vpns) - len(active_vpns),
            "administrator_accounts": config.admin_account_count,
            "central_authentication_servers": len(config.aaa_servers),
            "findings": len(findings),
        },
        "summary": {
            "severity_counts": severity_counts,
            "enabled_policies": sum(rule.enabled for rule in config.rules),
            "permitting_policies": sum(
                rule.enabled and rule.action.lower() == "accept" for rule in config.rules
            ),
        },
        "network_architecture": {
            "interfaces": interfaces,
            "zones": config.zones,
            "address_objects": config.address_definitions,
            "address_groups": config.address_groups,
        },
        "access_control": {
            "policies": rules,
            "local_in_policies": [
                {
                    "id": rule.id,
                    "interfaces": rule.source_zones,
                    "source_addresses": rule.source_addresses,
                    "services": rule.services,
                    "action": rule.action,
                    "enabled": rule.enabled,
                }
                for rule in config.local_in_rules
            ],
            "service_definitions": config.service_definitions,
            "service_groups": config.service_groups,
        },
        "remote_access": {
            "ipsec_vpns": [
                {
                    "name": vpn.name,
                    "enabled": vpn.enabled,
                    "interface": vpn.interface,
                    "remote_gateway": vpn.remote_gateway,
                }
                for vpn in config.vpns
                if vpn.kind == "ipsec"
            ],
            "ssl_vpn": config.ssl_vpn,
        },
        "administration": {
            "administrator_accounts": config.admin_account_count,
            "remote_auth_accounts": config.remote_auth_admin_count,
            "aaa_servers": config.aaa_servers,
            "management_interfaces": [
                interface for interface in interfaces if interface["management_services"]
            ],
            "management_services_on_wan": [
                interface
                for interface in interfaces
                if interface["internet_facing"] and interface["management_services"]
            ],
        },
        "logging": {
            "destinations": config.logging,
            "policies_with_logging_disabled": [
                rule.id
                for rule in config.rules
                if rule.enabled and rule.logging and rule.logging.lower() in {"disable", "off"}
            ],
            "policy_logging_explicitly_configured": sum(
                rule.enabled and rule.logging is not None for rule in config.rules
            ),
        },
        "monitoring": {
            "ntp": config.ntp,
            "snmp": config.snmp,
            "session_helpers": config.session_helpers,
        },
        "nat": {
            "virtual_ips": config.virtual_ips,
            "policies_with_nat_enabled": [
                rule.id for rule in config.rules if rule.enabled and rule.nat is True
            ],
        },
        "findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity,
                "description": finding.description,
                "recommendation": finding.recommendation,
                "affected_objects": finding.affected_objects,
                "evidence": finding.data,
                "sureformat_id": finding.sureformat_id,
            }
            for finding in findings
        ],
    }


def export_yaml(report: dict[str, Any], filepath: Path) -> Path:
    """Write an assessment report as YAML."""
    filepath.write_text(
        yaml.safe_dump(report, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return filepath


def export_json(report: dict[str, Any], filepath: Path) -> Path:
    """Write an assessment report as JSON."""
    filepath.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return filepath

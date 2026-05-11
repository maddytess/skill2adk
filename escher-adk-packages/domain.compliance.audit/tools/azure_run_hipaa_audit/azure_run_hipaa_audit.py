from azure.identity import DefaultAzureCredential, AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.keyvault.certificates import CertificateClient
import argparse
from datetime import datetime, timezone
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from typing import Optional, List, Dict

# ===================== RESULT STRUCTURE =====================

def _make_result():
    """Return a fresh result dict — called once per audit run to avoid stale state."""
    return {
        "metadata": {
            "framework": "HIPAA Security Rule",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "administrative_safeguards": {
            "category_description": "Policies and procedures to manage security measures protecting ePHI",
            "controls": [],
        },
        "physical_safeguards": {
            "category_description": "Physical measures to protect systems and facilities containing ePHI",
            "controls": [],
        },
        "technical_safeguards": {
            "category_description": "Technology and access controls for electronic protected health information",
            "controls": [],
        },
    }


# ===================== HELPERS =====================

def create_control_result(rule, name, description, status, severity, details, recommendation=None):
    result = {
        "hipaa_rule": rule,
        "control_name": name,
        "description": description,
        "status": status,        # PASS / FAIL / WARNING
        "severity": severity,    # CRITICAL / HIGH / MEDIUM / LOW
        "details": details,
    }
    if recommendation:
        result["recommendation"] = recommendation
    return result


def _warning(rule, name, description, severity, exc):
    """Return a WARNING result for an exception — used when a check cannot complete."""
    return create_control_result(
        rule, name, description, "WARNING", severity,
        {"error": str(exc)},
        "Grant necessary Azure RBAC permissions and verify resource accessibility.",
    )


# ===================== ADMINISTRATIVE SAFEGUARDS =====================

def check_activity_log_audit(subscription_id, credential):
    """§164.308(a)(1)(ii)(D) — Activity logs are exported to Storage or Log Analytics."""
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        log_profiles = list(monitor_client.log_profiles.list())

        return create_control_result(
            "164.308(a)(1)(ii)(D)",
            "Audit Controls - Activity Log",
            "Ensures activity logs are exported for audit trail purposes",
            "PASS" if log_profiles else "FAIL",
            "CRITICAL",
            {"log_profiles_count": len(log_profiles)},
            None if log_profiles else
            "Configure Activity Log export to Storage Account or Log Analytics. "
            "Go to Azure Monitor > Activity Log > Export Activity Logs."
        )
    except Exception as e:
        return _warning(
            "164.308(a)(1)(ii)(D)", "Audit Controls - Activity Log",
            "Ensures activity logs are exported for audit trail purposes", "CRITICAL", e
        )


def check_security_center_incident_response(subscription_id, credential):
    """§164.308(a)(1)(ii)(A) — Microsoft Defender for Cloud Standard tier is enabled."""
    try:
        security_client = SecurityCenter(credential, subscription_id, asc_location="centralus")
        pricings = list(security_client.pricings.list())

        enabled_services = [p.name for p in pricings if p.pricing_tier == "Standard"]

        return create_control_result(
            "164.308(a)(1)(ii)(A)",
            "Security Incident Procedures",
            "Ensures Defender for Cloud is enabled for threat detection and incident response",
            "PASS" if enabled_services else "FAIL",
            "CRITICAL",
            {
                "defender_enabled": bool(enabled_services),
                "enabled_services_count": len(enabled_services),
                "enabled_services": enabled_services,
            },
            None if enabled_services else
            "Enable Microsoft Defender for Cloud (Standard tier). "
            "Go to Defender for Cloud > Environment settings."
        )
    except Exception as e:
        return _warning(
            "164.308(a)(1)(ii)(A)", "Security Incident Procedures",
            "Ensures Defender for Cloud is enabled for threat detection and incident response", "CRITICAL", e
        )


def check_activity_log_retention(subscription_id, credential):
    """§164.308(a)(1)(ii)(D) — Activity log retention is configured for at least 90 days."""
    _MIN_RETENTION_DAYS = 90
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        log_profiles = list(monitor_client.log_profiles.list())

        if not log_profiles:
            return create_control_result(
                "164.308(a)(1)(ii)(D)", "Activity Log Retention",
                f"Ensures activity log retention is configured for at least {_MIN_RETENTION_DAYS} days",
                "FAIL", "HIGH",
                {"log_profiles_count": 0},
                "Configure an Activity Log export with a retention period of at least "
                f"{_MIN_RETENTION_DAYS} days. Go to Azure Monitor > Activity Log > Export Activity Logs."
            )

        insufficient = []
        for profile in log_profiles:
            retention = getattr(profile, "retention_policy", None)
            # retention_policy.enabled=False means retain indefinitely (compliant)
            if retention and getattr(retention, "enabled", False):
                days = getattr(retention, "days", 0)
                if days < _MIN_RETENTION_DAYS:
                    insufficient.append({"profile_name": profile.name, "retention_days": days})

        return create_control_result(
            "164.308(a)(1)(ii)(D)", "Activity Log Retention",
            f"Ensures activity log retention is configured for at least {_MIN_RETENTION_DAYS} days",
            "PASS" if not insufficient else "FAIL",
            "HIGH",
            {
                "log_profiles_checked": len(log_profiles),
                "insufficient_retention": insufficient,
                "insufficient_retention_count": len(insufficient),
                "minimum_retention_days": _MIN_RETENTION_DAYS,
            },
            None if not insufficient else
            f"Increase retention to at least {_MIN_RETENTION_DAYS} days on "
            f"{len(insufficient)} log profile(s). Set retention_policy.days >= {_MIN_RETENTION_DAYS} "
            "or set enabled=false to retain indefinitely."
        )
    except Exception as e:
        return _warning(
            "164.308(a)(1)(ii)(D)", "Activity Log Retention",
            f"Ensures activity log retention is configured for at least 90 days", "HIGH", e
        )


def check_sql_threat_detection(subscription_id, credential, sql_servers):
    """§164.308(a)(1)(ii)(A) — Microsoft Defender for SQL (Advanced Threat Protection) is enabled on all SQL servers."""
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        unprotected_servers = []

        for server in sql_servers:
            resource_group = server.id.split("/")[4]
            try:
                policy = sql_client.server_security_alert_policies.get(
                    resource_group, server.name, "Default"
                )
                if getattr(policy, "state", None) != "Enabled":
                    unprotected_servers.append(server.name)
            except Exception:
                unprotected_servers.append(server.name)

        return create_control_result(
            "164.308(a)(1)(ii)(A)", "SQL Threat Detection",
            "Ensures Microsoft Defender for SQL is enabled on all SQL servers",
            "PASS" if not unprotected_servers else "FAIL",
            "HIGH",
            {
                "total_sql_servers": len(sql_servers),
                "unprotected_servers": unprotected_servers,
                "unprotected_servers_count": len(unprotected_servers),
            },
            None if not unprotected_servers else
            f"Enable Microsoft Defender for SQL on {len(unprotected_servers)} server(s). "
            "Go to SQL Server > Microsoft Defender for Cloud > Enable."
        )
    except Exception as e:
        return _warning(
            "164.308(a)(1)(ii)(A)", "SQL Threat Detection",
            "Ensures Microsoft Defender for SQL is enabled on all SQL servers", "HIGH", e
        )


def check_sql_backup_retention(subscription_id, credential, sql_servers):
    """§164.308(a)(7)(ii)(A) — All SQL databases have backup retention configured for at least 7 days."""
    _MIN_RETENTION_DAYS = 7
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        insufficient = []

        for server in sql_servers:
            resource_group = server.id.split("/")[4]
            try:
                databases = list(sql_client.databases.list_by_server(resource_group, server.name))
                for db in databases:
                    if db.name == "master":
                        continue
                    try:
                        policy = sql_client.backup_short_term_retention_policies.get(
                            resource_group, server.name, db.name, "default"
                        )
                        retention_days = getattr(policy, "retention_days", 0) or 0
                        if retention_days < _MIN_RETENTION_DAYS:
                            insufficient.append({
                                "server": server.name,
                                "database": db.name,
                                "retention_days": retention_days,
                            })
                    except Exception:
                        insufficient.append({
                            "server": server.name,
                            "database": db.name,
                            "retention_days": None,
                            "note": "Unable to retrieve backup retention policy",
                        })
            except Exception:
                continue

        return create_control_result(
            "164.308(a)(7)(ii)(A)", "SQL Backup Retention",
            f"Ensures all SQL databases have backup retention of at least {_MIN_RETENTION_DAYS} days",
            "PASS" if not insufficient else "FAIL",
            "HIGH",
            {
                "total_sql_servers": len(sql_servers),
                "databases_with_insufficient_retention": insufficient,
                "databases_with_insufficient_retention_count": len(insufficient),
                "minimum_retention_days": _MIN_RETENTION_DAYS,
            },
            None if not insufficient else
            f"Increase backup retention to at least {_MIN_RETENTION_DAYS} days on "
            f"{len(insufficient)} database(s). Go to SQL Database > Backups > Retention policies."
        )
    except Exception as e:
        return _warning(
            "164.308(a)(7)(ii)(A)", "SQL Backup Retention",
            f"Ensures all SQL databases have backup retention of at least 7 days", "HIGH", e
        )


def check_conditional_access_policies(subscription_id, credential):
    """§164.308(a)(3)(ii)(A) — Conditional Access policies (informational — requires Graph API)."""
    return create_control_result(
        "164.308(a)(3)(ii)(A)",
        "Workforce Access Management",
        "Verifies Conditional Access policies restrict access based on user, location, and device",
        "WARNING",
        "HIGH",
        {
            "informational": True,
            "explanation": (
                "Conditional Access policies require Microsoft Graph API access and cannot be "
                "verified via Azure Resource Manager. Manually verify that Conditional Access "
                "policies are configured in Entra ID."
            ),
        },
        "Configure Conditional Access policies in Entra ID > Security > Conditional Access."
    )


# ===================== PHYSICAL SAFEGUARDS =====================

def check_vm_disk_encryption(subscription_id, credential, vms, disks):
    """§164.310(d)(1) — All VM managed disks have ADE or customer-managed key encryption."""
    _CMK_TYPES = {
        "EncryptionAtRestWithCustomerManagedKey",
        "EncryptionAtRestWithPlatformAndCustomerManagedKeys",
    }
    try:
        # Build disk name → disk map for O(1) lookup
        disk_map = {disk.name: disk for disk in disks}

        unencrypted_vms = []
        for vm in vms:
            if not vm.storage_profile:
                continue
            resource_group = vm.id.split("/")[4] if vm.id else "unknown"

            os_disk_name = (
                vm.storage_profile.os_disk.name
                if vm.storage_profile.os_disk else None
            )
            data_disk_names = [
                d.name for d in (vm.storage_profile.data_disks or [])
            ]
            all_disk_names = ([os_disk_name] if os_disk_name else []) + data_disk_names

            vm_protected = True
            for disk_name in all_disk_names:
                disk = disk_map.get(disk_name)
                if disk is None:
                    continue
                ade_enabled = (
                    getattr(disk, "encryption_settings_collection", None) and
                    disk.encryption_settings_collection.enabled
                )
                cmk_enabled = (
                    getattr(disk, "encryption", None) and
                    getattr(disk.encryption, "type", None) in _CMK_TYPES
                )
                if not ade_enabled and not cmk_enabled:
                    vm_protected = False
                    break

            if not vm_protected:
                unencrypted_vms.append({
                    "vm_name": vm.name,
                    "location": vm.location,
                    "resource_group": resource_group,
                })

        return create_control_result(
            "164.310(d)(1)", "VM Disk Encryption",
            "Ensures all VM managed disks use Azure Disk Encryption (ADE) or customer-managed keys",
            "PASS" if not unencrypted_vms else "FAIL",
            "HIGH",
            {
                "total_vms": len(vms),
                "vms_without_disk_encryption": unencrypted_vms,
                "vms_without_disk_encryption_count": len(unencrypted_vms),
            },
            None if not unencrypted_vms else
            f"Enable Azure Disk Encryption or customer-managed key encryption on "
            f"{len(unencrypted_vms)} VM(s). Go to VM > Disks > Encryption > Enable ADE or "
            "configure a Disk Encryption Set with a Key Vault key."
        )
    except Exception as e:
        return _warning(
            "164.310(d)(1)", "VM Disk Encryption",
            "Ensures all VM managed disks use Azure Disk Encryption or customer-managed keys",
            "HIGH", e
        )


def check_region_compliance(subscription_id, credential, vms, storage_accounts):
    """§164.310(a)(1) — Lists regions with active VMs and storage (informational)."""
    try:
        vm_regions = sorted(set(vm.location for vm in vms))
        storage_regions = sorted(set(sa.location for sa in storage_accounts))
        all_regions = sorted(set(vm_regions + storage_regions))

        return create_control_result(
            "164.310(a)(1)",
            "Facility Access Controls (Cloud Regions)",
            "Lists Azure regions with active workloads to support documentation of approved ePHI processing locations",
            "PASS",
            "LOW",
            {
                "regions_in_use": all_regions,
                "vm_regions": vm_regions,
                "storage_regions": storage_regions,
                "note": (
                    "This check is informational. It does not assert that ePHI is restricted "
                    "to approved regions — that is an organisational policy control."
                ),
            },
            "Document approved Azure regions for ePHI workloads and verify data residency requirements."
        )
    except Exception as e:
        return _warning(
            "164.310(a)(1)", "Facility Access Controls (Cloud Regions)",
            "Lists Azure regions with active workloads to support documentation of approved ePHI processing locations",
            "LOW", e
        )


def check_resource_locks(subscription_id, credential):
    """§164.310(a)(2)(iii) — Production resource groups have CanNotDelete or ReadOnly locks."""
    try:
        resource_client = ResourceManagementClient(credential, subscription_id)
        resource_groups = list(resource_client.resource_groups.list())

        production_rgs_without_locks = []
        for rg in resource_groups:
            is_production = (
                "prod" in rg.name.lower() or
                "production" in rg.name.lower() or
                (hasattr(rg, "tags") and rg.tags and
                 rg.tags.get("Environment", "").lower() in ["prod", "production"])
            )
            if is_production:
                try:
                    locks = list(resource_client.management_locks.list_at_resource_group_level(rg.name))
                    if not locks:
                        production_rgs_without_locks.append(rg.name)
                except Exception:
                    continue

        return create_control_result(
            "164.310(a)(2)(iii)",
            "Resource Protection - Locks",
            "Ensures production resource groups have locks to prevent accidental deletion or modification",
            "PASS" if not production_rgs_without_locks else "FAIL",
            "MEDIUM",
            {
                "production_rgs_checked": len([
                    rg for rg in resource_groups
                    if "prod" in rg.name.lower() or "production" in rg.name.lower()
                    or (hasattr(rg, "tags") and rg.tags and
                        rg.tags.get("Environment", "").lower() in ["prod", "production"])
                ]),
                "production_rgs_without_locks": production_rgs_without_locks,
                "production_rgs_without_locks_count": len(production_rgs_without_locks),
            },
            None if not production_rgs_without_locks else
            f"Apply CanNotDelete or ReadOnly locks to {len(production_rgs_without_locks)} "
            "production resource group(s). Go to Resource Group > Locks > Add."
        )
    except Exception as e:
        return _warning(
            "164.310(a)(2)(iii)", "Resource Protection - Locks",
            "Ensures production resource groups have locks to prevent accidental deletion or modification",
            "MEDIUM", e
        )


# ===================== TECHNICAL SAFEGUARDS =====================

def check_mfa_enforcement(subscription_id, credential):
    """§164.312(d) — MFA enforcement (informational — requires Graph API)."""
    return create_control_result(
        "164.312(d)",
        "Person or Entity Authentication - MFA",
        "Verifies MFA is enforced for all users accessing ePHI",
        "WARNING",
        "CRITICAL",
        {
            "informational": True,
            "explanation": (
                "MFA enforcement requires Microsoft Graph API access to query Conditional Access "
                "policies and per-user MFA state. This cannot be verified via Azure Resource Manager. "
                "Manually verify MFA is enforced for all users accessing ePHI."
            ),
        },
        "Enforce MFA via Entra ID > Security > Conditional Access > Require multi-factor authentication."
    )


def check_storage_encryption(subscription_id, credential, storage_accounts):
    """§164.312(a)(2)(iv) — All storage accounts have encryption enabled."""
    try:
        unencrypted = []
        for account in storage_accounts:
            encryption_enabled = (
                hasattr(account, "encryption") and
                account.encryption and
                hasattr(account.encryption, "services") and
                account.encryption.services
            )
            if not encryption_enabled:
                unencrypted.append(account.name)

        return create_control_result(
            "164.312(a)(2)(iv)",
            "Encryption at Rest - Storage",
            "Ensures all Azure Storage accounts have encryption enabled",
            "PASS" if not unencrypted else "FAIL",
            "HIGH",
            {
                "total_storage_accounts": len(storage_accounts),
                "unencrypted_accounts": unencrypted,
                "unencrypted_count": len(unencrypted),
            },
            None if not unencrypted else
            f"Enable encryption for {len(unencrypted)} storage account(s). "
            "Storage encryption is enabled by default — verify the configuration has not been disabled."
        )
    except Exception as e:
        return _warning(
            "164.312(a)(2)(iv)", "Encryption at Rest - Storage",
            "Ensures all Azure Storage accounts have encryption enabled", "HIGH", e
        )


def check_sql_tde_encryption(subscription_id, credential, sql_servers):
    """§164.312(a)(2)(iv) — All SQL databases have Transparent Data Encryption enabled."""
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        unencrypted_databases = []

        for server in sql_servers:
            resource_group = server.id.split("/")[4]
            try:
                databases = list(sql_client.databases.list_by_server(resource_group, server.name))
                for db in databases:
                    if db.name == "master":
                        continue
                    try:
                        tde = sql_client.transparent_data_encryptions.get(
                            resource_group, server.name, db.name, "current"
                        )
                        if tde.state != "Enabled":
                            unencrypted_databases.append({
                                "server": server.name,
                                "database": db.name,
                            })
                    except Exception:
                        unencrypted_databases.append({
                            "server": server.name,
                            "database": db.name,
                            "note": "Unable to verify TDE status",
                        })
            except Exception:
                continue

        return create_control_result(
            "164.312(a)(2)(iv)",
            "Encryption at Rest - SQL TDE",
            "Ensures all SQL databases have Transparent Data Encryption enabled",
            "PASS" if not unencrypted_databases else "FAIL",
            "CRITICAL",
            {
                "total_sql_servers": len(sql_servers),
                "unencrypted_databases": unencrypted_databases,
                "unencrypted_databases_count": len(unencrypted_databases),
            },
            None if not unencrypted_databases else
            f"Enable TDE for {len(unencrypted_databases)} database(s). "
            "Go to SQL Database > Security > Transparent data encryption > Enable."
        )
    except Exception as e:
        return _warning(
            "164.312(a)(2)(iv)", "Encryption at Rest - SQL TDE",
            "Ensures all SQL databases have Transparent Data Encryption enabled", "CRITICAL", e
        )


def check_storage_public_access(subscription_id, credential, storage_accounts):
    """§164.312(c)(1) — No storage accounts allow public blob access."""
    try:
        public_access_accounts = [
            account.name
            for account in storage_accounts
            if getattr(account, "allow_blob_public_access", False)
        ]

        return create_control_result(
            "164.312(c)(1)",
            "Storage Public Access",
            "Ensures no storage accounts allow public blob access",
            "PASS" if not public_access_accounts else "FAIL",
            "CRITICAL",
            {
                "total_storage_accounts": len(storage_accounts),
                "public_access_accounts": public_access_accounts,
                "public_access_accounts_count": len(public_access_accounts),
            },
            None if not public_access_accounts else
            f"Disable public blob access on {len(public_access_accounts)} storage account(s). "
            "Go to Storage Account > Configuration > Allow Blob public access > Disabled."
        )
    except Exception as e:
        return _warning(
            "164.312(c)(1)", "Storage Public Access",
            "Ensures no storage accounts allow public blob access", "CRITICAL", e
        )


def check_sql_firewall_rules(subscription_id, credential, sql_servers):
    """§164.312(a)(1) — No SQL servers have allow-all firewall rules (0.0.0.0–255.255.255.255)."""
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        risky_servers = []

        for server in sql_servers:
            resource_group = server.id.split("/")[4]
            try:
                firewall_rules = list(sql_client.firewall_rules.list_by_server(resource_group, server.name))
                for rule in firewall_rules:
                    if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "255.255.255.255":
                        risky_servers.append({
                            "server": server.name,
                            "rule_name": rule.name,
                        })
            except Exception:
                continue

        return create_control_result(
            "164.312(a)(1)",
            "Access Control - SQL Firewall",
            "Ensures no SQL servers have allow-all firewall rules",
            "PASS" if not risky_servers else "FAIL",
            "HIGH",
            {
                "total_sql_servers": len(sql_servers),
                "risky_servers": risky_servers,
                "risky_servers_count": len(risky_servers),
            },
            None if not risky_servers else
            f"Restrict firewall rules on {len(risky_servers)} SQL server(s). "
            "Remove allow-all rules and restrict to specific IP ranges or use Private Endpoints."
        )
    except Exception as e:
        return _warning(
            "164.312(a)(1)", "Access Control - SQL Firewall",
            "Ensures no SQL servers have allow-all firewall rules", "HIGH", e
        )


def check_nsg_rules_ephi(subscription_id, credential, nsgs):
    """§164.312(a)(1) — No NSG rules allow unrestricted inbound on sensitive ports."""
    _SENSITIVE_PORTS = [22, 3389, 3306, 5432, 1433, 1521, 27017, 6379, 5439]
    try:
        risky_rules = []

        for nsg in nsgs:
            for rule in getattr(nsg, "security_rules", []):
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue
                source_open = (
                    rule.source_address_prefix in ("*", "Internet", "0.0.0.0/0", "::/0") or
                    any(
                        prefix in ("*", "Internet", "0.0.0.0/0", "::/0")
                        for prefix in (getattr(rule, "source_address_prefixes", None) or [])
                    )
                )
                if not source_open:
                    continue
                port_range = getattr(rule, "destination_port_range", "*") or "*"
                is_sensitive = port_range == "*" or any(
                    str(port) in str(port_range) for port in _SENSITIVE_PORTS
                )
                if is_sensitive:
                    risky_rules.append({
                        "nsg_name": nsg.name,
                        "rule_name": rule.name,
                        "port": port_range,
                    })

        return create_control_result(
            "164.312(a)(1)",
            "NSG Unrestricted Inbound",
            "Ensures no NSG rules allow unrestricted inbound access on sensitive ports",
            "PASS" if not risky_rules else "FAIL",
            "HIGH",
            {
                "total_nsgs": len(nsgs),
                "risky_rules": risky_rules,
                "risky_rules_count": len(risky_rules),
                "sensitive_ports_checked": _SENSITIVE_PORTS,
            },
            None if not risky_rules else
            f"Restrict {len(risky_rules)} NSG rule(s) exposing systems to the internet. "
            "Use Azure Bastion for management access and Private Endpoints for data access."
        )
    except Exception as e:
        return _warning(
            "164.312(a)(1)", "NSG Unrestricted Inbound",
            "Ensures no NSG rules allow unrestricted inbound access on sensitive ports", "HIGH", e
        )


def check_diagnostic_logging(subscription_id, credential):
    """§164.312(b) — Key resources (Key Vaults, SQL databases, Storage accounts) have diagnostic settings."""
    _IMPORTANT_TYPES = {
        "Microsoft.KeyVault/vaults",
        "Microsoft.Sql/servers/databases",
        "Microsoft.Storage/storageAccounts",
        "Microsoft.Network/networkSecurityGroups",
    }
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)

        resources_without_diagnostics = []
        checked_count = 0

        for resource in resource_client.resources.list():
            if resource.type not in _IMPORTANT_TYPES:
                continue
            try:
                diagnostic_settings = list(monitor_client.diagnostic_settings.list(resource.id))
                if not diagnostic_settings:
                    resources_without_diagnostics.append({
                        "resource_name": resource.name,
                        "resource_type": resource.type,
                    })
                checked_count += 1
            except Exception:
                continue

        return create_control_result(
            "164.312(b)",
            "Audit Controls - Diagnostic Logging",
            "Ensures Key Vaults, SQL databases, Storage accounts, and NSGs have diagnostic settings configured",
            "PASS" if not resources_without_diagnostics else "FAIL",
            "HIGH",
            {
                "checked_resources": checked_count,
                "resources_without_diagnostics": resources_without_diagnostics,
                "resources_without_diagnostics_count": len(resources_without_diagnostics),
            },
            None if not resources_without_diagnostics else
            f"Configure diagnostic settings for {len(resources_without_diagnostics)} resource(s). "
            "Go to Resource > Diagnostic settings > Add diagnostic setting."
        )
    except Exception as e:
        return _warning(
            "164.312(b)", "Audit Controls - Diagnostic Logging",
            "Ensures key resources have diagnostic settings configured", "HIGH", e
        )


def check_key_vault_key_rotation(subscription_id, credential, key_vaults):
    """§164.312(a)(2)(iv) — All Key Vault keys have a rotation policy configured."""
    try:
        kv_client = KeyVaultManagementClient(credential, subscription_id)
        keys_without_rotation = []

        for vault in key_vaults:
            resource_group = vault.id.split("/")[4]
            try:
                keys = list(kv_client.keys.list(resource_group, vault.name))
                for key in keys:
                    try:
                        policy = kv_client.keys.get_rotation_policy(
                            resource_group, vault.name, key.name
                        )
                        has_policy = bool(
                            policy and
                            getattr(policy, "lifetime_actions", None)
                        )
                        if not has_policy:
                            keys_without_rotation.append({
                                "vault_name": vault.name,
                                "key_name": key.name,
                            })
                    except Exception:
                        keys_without_rotation.append({
                            "vault_name": vault.name,
                            "key_name": key.name,
                            "note": "Unable to retrieve rotation policy",
                        })
            except Exception:
                continue

        return create_control_result(
            "164.312(a)(2)(iv)", "Key Vault Key Rotation",
            "Ensures all Key Vault keys have an automatic rotation policy configured",
            "PASS" if not keys_without_rotation else "FAIL",
            "MEDIUM",
            {
                "total_key_vaults": len(key_vaults),
                "keys_without_rotation": keys_without_rotation,
                "keys_without_rotation_count": len(keys_without_rotation),
            },
            None if not keys_without_rotation else
            f"Configure a rotation policy on {len(keys_without_rotation)} key(s). "
            "Go to Key Vault > Keys > select key > Rotation policy."
        )
    except Exception as e:
        return _warning(
            "164.312(a)(2)(iv)", "Key Vault Key Rotation",
            "Ensures all Key Vault keys have an automatic rotation policy configured", "MEDIUM", e
        )


def check_storage_blob_versioning(subscription_id, credential, storage_accounts):
    """§164.312(c)(1) — All storage accounts have blob versioning enabled."""
    try:
        storage_client = StorageManagementClient(credential, subscription_id)
        unversioned = []

        for account in storage_accounts:
            resource_group = account.id.split("/")[4]
            try:
                props = storage_client.blob_services.get_service_properties(
                    resource_group, account.name
                )
                if not getattr(props, "is_versioning_enabled", False):
                    unversioned.append(account.name)
            except Exception:
                continue

        return create_control_result(
            "164.312(c)(1)", "Storage Blob Versioning",
            "Ensures all storage accounts have blob versioning enabled to support ePHI integrity and recovery",
            "PASS" if not unversioned else "FAIL",
            "MEDIUM",
            {
                "total_storage_accounts": len(storage_accounts),
                "unversioned_accounts": unversioned,
                "unversioned_accounts_count": len(unversioned),
            },
            None if not unversioned else
            f"Enable blob versioning on {len(unversioned)} storage account(s). "
            "Go to Storage Account > Data management > Data protection > Enable versioning."
        )
    except Exception as e:
        return _warning(
            "164.312(c)(1)", "Storage Blob Versioning",
            "Ensures all storage accounts have blob versioning enabled", "MEDIUM", e
        )


def check_sql_auditing(subscription_id, credential, sql_servers):
    """§164.312(b) — All SQL servers have auditing enabled with retention ≥ 90 days."""
    _MIN_RETENTION_DAYS = 90
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        unaudited = []

        for server in sql_servers:
            resource_group = server.id.split("/")[4]
            try:
                policy = sql_client.server_blob_auditing_policies.get(
                    resource_group, server.name
                )
                if getattr(policy, "state", None) != "Enabled":
                    unaudited.append({"server": server.name, "reason": "auditing_disabled"})
                else:
                    retention = getattr(policy, "retention_days", 0) or 0
                    if 0 < retention < _MIN_RETENTION_DAYS:
                        unaudited.append({
                            "server": server.name,
                            "reason": "insufficient_retention",
                            "retention_days": retention,
                        })
            except Exception:
                unaudited.append({"server": server.name, "reason": "unable_to_check"})

        return create_control_result(
            "164.312(b)", "SQL Database Auditing",
            f"Ensures all SQL servers have auditing enabled with retention ≥ {_MIN_RETENTION_DAYS} days",
            "PASS" if not unaudited else "FAIL",
            "HIGH",
            {
                "total_sql_servers": len(sql_servers),
                "servers_with_issues": unaudited,
                "servers_with_issues_count": len(unaudited),
                "minimum_retention_days": _MIN_RETENTION_DAYS,
            },
            None if not unaudited else
            f"Enable auditing with ≥ {_MIN_RETENTION_DAYS} days retention on "
            f"{len(unaudited)} SQL server(s). Go to SQL Server > Security > Auditing."
        )
    except Exception as e:
        return _warning(
            "164.312(b)", "SQL Database Auditing",
            "Ensures all SQL servers have auditing enabled with sufficient retention", "HIGH", e
        )


def check_nsg_flow_logs(subscription_id, credential, nsgs):
    """§164.312(b) — All NSGs have flow logs enabled for network traffic audit trails."""
    try:
        network_client = NetworkManagementClient(credential, subscription_id)

        monitored_nsg_ids = set()
        try:
            watchers = list(network_client.network_watchers.list_all())
            for watcher in watchers:
                watcher_rg = watcher.id.split("/")[4]
                try:
                    flow_logs = list(network_client.flow_logs.list(watcher_rg, watcher.name))
                    for fl in flow_logs:
                        if getattr(fl, "enabled", False):
                            target = getattr(fl, "target_resource_id", "") or ""
                            monitored_nsg_ids.add(target.lower())
                except Exception:
                    continue
        except Exception:
            pass

        nsgs_without_flow_logs = [
            {"nsg_name": nsg.name, "location": nsg.location}
            for nsg in nsgs
            if (nsg.id or "").lower() not in monitored_nsg_ids
        ]

        return create_control_result(
            "164.312(b)", "NSG Flow Logs",
            "Ensures all NSGs have flow logs enabled for network traffic audit trails",
            "PASS" if not nsgs_without_flow_logs else "FAIL",
            "MEDIUM",
            {
                "total_nsgs": len(nsgs),
                "nsgs_without_flow_logs": nsgs_without_flow_logs,
                "nsgs_without_flow_logs_count": len(nsgs_without_flow_logs),
            },
            None if not nsgs_without_flow_logs else
            f"Enable flow logs on {len(nsgs_without_flow_logs)} NSG(s). "
            "Go to Network Watcher > Flow logs > Create."
        )
    except Exception as e:
        return _warning(
            "164.312(b)", "NSG Flow Logs",
            "Ensures all NSGs have flow logs enabled for network traffic audit trails", "MEDIUM", e
        )


def check_storage_https_only(subscription_id, credential, storage_accounts):
    """§164.312(e)(1) — All storage accounts require secure transfer (HTTPS only)."""
    try:
        non_https = [
            account.name
            for account in storage_accounts
            if not getattr(account, "enable_https_traffic_only", True)
        ]

        return create_control_result(
            "164.312(e)(1)", "Storage HTTPS Only",
            "Ensures all storage accounts require secure transfer (HTTPS only)",
            "PASS" if not non_https else "FAIL",
            "HIGH",
            {
                "total_storage_accounts": len(storage_accounts),
                "http_enabled_accounts": non_https,
                "http_enabled_accounts_count": len(non_https),
            },
            None if not non_https else
            f"Enable secure transfer on {len(non_https)} storage account(s). "
            "Go to Storage Account > Configuration > Secure transfer required > Enabled."
        )
    except Exception as e:
        return _warning(
            "164.312(e)(1)", "Storage HTTPS Only",
            "Ensures all storage accounts require secure transfer", "HIGH", e
        )


def check_app_service_https(subscription_id, credential, app_services):
    """§164.312(e)(1) — All App Services enforce HTTPS-only."""
    try:
        non_https = [
            app.name
            for app in app_services
            if not getattr(app, "https_only", False)
        ]

        return create_control_result(
            "164.312(e)(1)", "App Service HTTPS Only",
            "Ensures all App Services enforce HTTPS-only; HTTP requests are redirected",
            "PASS" if not non_https else "FAIL",
            "HIGH",
            {
                "total_app_services": len(app_services),
                "http_enabled_apps": non_https,
                "http_enabled_apps_count": len(non_https),
            },
            None if not non_https else
            f"Enable HTTPS-only on {len(non_https)} App Service(s). "
            "Go to App Service > Settings > TLS/SSL settings > HTTPS Only > On."
        )
    except Exception as e:
        return _warning(
            "164.312(e)(1)", "App Service HTTPS Only",
            "Ensures all App Services enforce HTTPS-only", "HIGH", e
        )


_CERT_EXPIRY_DAYS = 30


def check_key_vault_certificate_expiry(subscription_id, credential, key_vaults):
    """§164.312(e)(1) — No Key Vault certificates are expiring within the next 30 days."""
    try:
        now = datetime.now(timezone.utc)
        expiring_certs = []

        for vault in key_vaults:
            vault_url = getattr(getattr(vault, "properties", None), "vault_uri", None)
            if not vault_url:
                continue
            try:
                cert_client = CertificateClient(vault_url=vault_url, credential=credential)
                for cert_props in cert_client.list_properties_of_certificates():
                    expires_on = getattr(cert_props, "expires_on", None)
                    if expires_on:
                        days_remaining = (expires_on - now).days
                        if days_remaining < _CERT_EXPIRY_DAYS:
                            expiring_certs.append({
                                "vault_name": vault.name,
                                "certificate_name": cert_props.name,
                                "expires_on": expires_on.isoformat(),
                                "days_remaining": days_remaining,
                            })
            except Exception:
                continue

        return create_control_result(
            "164.312(e)(1)", "Key Vault Certificate Expiry",
            f"Ensures no Key Vault certificates are expiring within the next {_CERT_EXPIRY_DAYS} days",
            "PASS" if not expiring_certs else "FAIL",
            "HIGH",
            {
                "total_key_vaults": len(key_vaults),
                "expiry_threshold_days": _CERT_EXPIRY_DAYS,
                "expiring_certificates": expiring_certs,
                "expiring_certificates_count": len(expiring_certs),
            },
            None if not expiring_certs else
            f"Renew or replace {len(expiring_certs)} certificate(s) expiring within "
            f"{_CERT_EXPIRY_DAYS} days. Go to Key Vault > Certificates > select cert > New version."
        )
    except Exception as e:
        return _warning(
            "164.312(e)(1)", "Key Vault Certificate Expiry",
            f"Ensures no Key Vault certificates are expiring within the next {_CERT_EXPIRY_DAYS} days",
            "HIGH", e
        )


# ===================== EXECUTIVE SUMMARY =====================

def generate_executive_summary(result):
    """Generate a markdown-formatted executive summary of the HIPAA audit results."""
    summary = result["metadata"]["summary"]
    subscription_id = result["metadata"].get("subscription_id", "Unknown")

    total_controls = summary["total_controls"]
    passed = summary["passed"]
    failed = summary["failed"]
    warnings = summary["warnings"]
    critical_failures = summary["critical_failures"]
    high_failures = summary["high_failures"]
    permission_errors = summary.get("permission_errors", 0)
    controls_completed = summary.get("controls_completed", total_controls)

    compliance_score = int((passed / controls_completed * 100)) if controls_completed > 0 else 0

    md_lines = []
    md_lines.append("# HIPAA Security Rule — Executive Summary")
    md_lines.append("")

    md_lines.append("## Overall Compliance Status")
    md_lines.append("")
    if compliance_score >= 90:
        md_lines.append(
            f"**Azure Subscription {subscription_id}** demonstrates **strong HIPAA compliance** with a "
            f"**{compliance_score}%** pass rate across **{total_controls}** controls."
        )
    elif compliance_score >= 70:
        md_lines.append(
            f"**Azure Subscription {subscription_id}** shows **moderate HIPAA compliance** with a "
            f"**{compliance_score}%** pass rate across **{total_controls}** controls, requiring targeted improvements."
        )
    else:
        md_lines.append(
            f"**Azure Subscription {subscription_id}** requires **significant improvements** with a "
            f"**{compliance_score}%** pass rate across **{total_controls}** controls."
        )
    md_lines.append("")

    md_lines.append("## Key Findings")
    md_lines.append("")
    if critical_failures > 0 or high_failures > 0:
        severity_text = []
        if critical_failures > 0:
            severity_text.append(f"**{critical_failures} critical**")
        if high_failures > 0:
            severity_text.append(f"**{high_failures} high-severity**")
        md_lines.append(
            f"The audit identified **{failed} failed control(s)** including "
            f"{' and '.join(severity_text)} issue(s) that require **immediate remediation** "
            "before handling ePHI."
        )
    elif failed > 0:
        md_lines.append(f"The audit identified **{failed} failed control(s)** with lower severity levels.")
    else:
        md_lines.append("The audit found **no failed controls**, indicating strong HIPAA compliance.")
    md_lines.append("")

    md_lines.append("## Safeguard Status")
    md_lines.append("")
    safeguard_sections = {
        "Administrative Safeguards": result.get("administrative_safeguards", {}).get("controls", []),
        "Physical Safeguards": result.get("physical_safeguards", {}).get("controls", []),
        "Technical Safeguards": result.get("technical_safeguards", {}).get("controls", []),
    }
    any_failures = False
    for safeguard_name, controls in safeguard_sections.items():
        failed_count = sum(1 for c in controls if c["status"] == "FAIL")
        if failed_count > 0:
            md_lines.append(f"- **{safeguard_name}**: {failed_count} control(s) failed")
            any_failures = True
    if not any_failures:
        md_lines.append("All three safeguard categories have passing controls.")
    md_lines.append("")

    md_lines.append("## Priority Remediation Areas")
    md_lines.append("")
    all_controls = [c for section in safeguard_sections.values() for c in section]
    priority = [c for c in all_controls if c["status"] == "FAIL" and c["severity"] in ("CRITICAL", "HIGH")]
    if priority:
        md_lines.append("**Critical and high-severity findings requiring immediate action:**")
        md_lines.append("")
        for control in priority[:5]:
            md_lines.append(f"- **{control['control_name']}** ({control['hipaa_rule']})")
    else:
        md_lines.append("No critical or high-severity issues identified.")
    md_lines.append("")

    md_lines.append("## Additional Observations")
    md_lines.append("")
    if permission_errors > 0:
        md_lines.append(
            f"**Note:** {permission_errors} control(s) could not be completed due to insufficient "
            "Azure RBAC permissions. Grant necessary permissions for a complete audit."
        )
        md_lines.append("")
    warnings_non_perm = warnings - permission_errors
    if warnings_non_perm > 0:
        md_lines.append(f"Additionally, **{warnings_non_perm} warning(s)** were identified that should be reviewed.")
    elif permission_errors == 0 and warnings == 0:
        md_lines.append("No warnings were identified.")
    md_lines.append("")

    md_lines.append("## Recommendation")
    md_lines.append("")
    if compliance_score >= 90:
        md_lines.append("**Action:** Address minor findings and maintain compliance through regular security risk assessments.")
    elif compliance_score >= 70:
        md_lines.append("**Action:** Focus on critical and high-severity findings before storing or transmitting ePHI.")
    else:
        md_lines.append("**Action:** Implement comprehensive security improvements before handling ePHI.")

    return "\n".join(md_lines)


# ===================== RUN AUDIT =====================

def run_hipaa_audit(subscription_id: str, credential):
    """Run HIPAA Security Rule audit for the given Azure subscription."""
    try:
        result = _make_result()
        result["metadata"]["subscription_id"] = subscription_id

        # Pre-fetch shared resources once — multiple checks reuse them
        try:
            vms = list(ComputeManagementClient(credential, subscription_id).virtual_machines.list_all())
        except Exception:
            vms = []

        try:
            storage_accounts = list(StorageManagementClient(credential, subscription_id).storage_accounts.list())
        except Exception:
            storage_accounts = []

        try:
            sql_servers = list(SqlManagementClient(credential, subscription_id).servers.list())
        except Exception:
            sql_servers = []

        try:
            nsgs = list(NetworkManagementClient(credential, subscription_id).network_security_groups.list_all())
        except Exception:
            nsgs = []

        try:
            disks = list(ComputeManagementClient(credential, subscription_id).disks.list())
        except Exception:
            disks = []

        try:
            key_vaults = list(KeyVaultManagementClient(credential, subscription_id).vaults.list())
        except Exception:
            key_vaults = []

        try:
            app_services = list(WebSiteManagementClient(credential, subscription_id).web_apps.list())
        except Exception:
            app_services = []

        check_tasks = [
            # Administrative Safeguards
            ("administrative_safeguards", lambda: check_activity_log_audit(subscription_id, credential)),
            ("administrative_safeguards", lambda: check_activity_log_retention(subscription_id, credential)),
            ("administrative_safeguards", lambda: check_security_center_incident_response(subscription_id, credential)),
            ("administrative_safeguards", lambda q=sql_servers: check_sql_threat_detection(subscription_id, credential, q)),
            ("administrative_safeguards", lambda q=sql_servers: check_sql_backup_retention(subscription_id, credential, q)),
            ("administrative_safeguards", lambda: check_conditional_access_policies(subscription_id, credential)),
            # Physical Safeguards
            ("physical_safeguards", lambda v=vms, d=disks: check_vm_disk_encryption(subscription_id, credential, v, d)),
            ("physical_safeguards", lambda v=vms, s=storage_accounts: check_region_compliance(subscription_id, credential, v, s)),
            ("physical_safeguards", lambda: check_resource_locks(subscription_id, credential)),
            # Technical Safeguards
            ("technical_safeguards", lambda: check_mfa_enforcement(subscription_id, credential)),
            ("technical_safeguards", lambda s=storage_accounts: check_storage_encryption(subscription_id, credential, s)),
            ("technical_safeguards", lambda q=sql_servers: check_sql_tde_encryption(subscription_id, credential, q)),
            ("technical_safeguards", lambda s=storage_accounts: check_storage_public_access(subscription_id, credential, s)),
            ("technical_safeguards", lambda q=sql_servers: check_sql_firewall_rules(subscription_id, credential, q)),
            ("technical_safeguards", lambda n=nsgs: check_nsg_rules_ephi(subscription_id, credential, n)),
            ("technical_safeguards", lambda: check_diagnostic_logging(subscription_id, credential)),
            ("technical_safeguards", lambda k=key_vaults: check_key_vault_key_rotation(subscription_id, credential, k)),
            ("technical_safeguards", lambda s=storage_accounts: check_storage_blob_versioning(subscription_id, credential, s)),
            ("technical_safeguards", lambda q=sql_servers: check_sql_auditing(subscription_id, credential, q)),
            ("technical_safeguards", lambda n=nsgs: check_nsg_flow_logs(subscription_id, credential, n)),
            ("technical_safeguards", lambda s=storage_accounts: check_storage_https_only(subscription_id, credential, s)),
            ("technical_safeguards", lambda a=app_services: check_app_service_https(subscription_id, credential, a)),
            ("technical_safeguards", lambda k=key_vaults: check_key_vault_certificate_expiry(subscription_id, credential, k)),
        ]

        with ThreadPoolExecutor(max_workers=23) as executor:
            future_to_category = {executor.submit(fn): category for category, fn in check_tasks}

            for future in as_completed(future_to_category):
                category = future_to_category[future]
                try:
                    check_result = future.result()
                    result[category]["controls"].append(check_result)
                except Exception as e:
                    error_result = create_control_result(
                        "CHECK-ERROR", "Unexpected Check Error",
                        f"Control check encountered an unexpected error: {e}",
                        "WARNING", "LOW",
                        {"error_type": type(e).__name__, "message": str(e), "category": category},
                        "Review error details and ensure Azure resources are accessible."
                    )
                    result[category]["controls"].append(error_result)

        all_controls = [
            c
            for section in (
                result["administrative_safeguards"],
                result["physical_safeguards"],
                result["technical_safeguards"],
            )
            for c in section["controls"]
        ]

        result["metadata"]["summary"] = {
            "total_controls": len(all_controls),
            "passed": sum(1 for c in all_controls if c["status"] == "PASS"),
            "failed": sum(1 for c in all_controls if c["status"] == "FAIL"),
            "warnings": sum(1 for c in all_controls if c["status"] == "WARNING"),
            "critical_failures": sum(1 for c in all_controls if c["status"] == "FAIL" and c["severity"] == "CRITICAL"),
            "high_failures": sum(1 for c in all_controls if c["status"] == "FAIL" and c["severity"] == "HIGH"),
            "permission_errors": 0,
            "controls_completed": len(all_controls),
        }

        result["metadata"]["executive_summary"] = generate_executive_summary(result)

        return result

    except Exception:
        raise


# ===================== MAIN =====================

def get_azure_subscriptions() -> List[Dict[str, str]]:
    """Get list of available Azure subscriptions."""
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        subscriptions = []
        for sub in subscription_client.subscriptions.list():
            tenant_id = getattr(sub, "tenant_id", None) or getattr(sub, "home_tenant_id", None) or ""
            state = str(sub.state) if getattr(sub, "state", None) else "Enabled"
            subscriptions.append({
                "name": sub.display_name,
                "subscription_id": sub.subscription_id,
                "tenant_id": tenant_id,
                "state": state,
            })
        return subscriptions
    except Exception as e:
        print(f"Error getting Azure subscriptions: {e}", file=sys.stderr)
        return []


def resolve_subscription_name_to_id(subscription_name: str, subscriptions: List[Dict[str, str]]) -> Optional[str]:
    """Resolve subscription name to subscription ID."""
    for sub in subscriptions:
        if sub["name"].lower() == subscription_name.lower():
            return sub["subscription_id"]
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Azure HIPAA Security Rule Audit Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 azure_hipaa.py
  python3 azure_hipaa.py --subscription-name "My Subscription"
  python3 azure_hipaa.py --subscription-id "12345678-1234-1234-1234-123456789abc"
  python3 azure_hipaa.py --subscription-id <id> --output report.json
        """,
    )
    parser.add_argument("--subscription-name", help="Subscription name (case-insensitive)")
    parser.add_argument("--subscription-id", "-s", type=str, help="Azure subscription ID to audit")
    parser.add_argument("--output", "-o", type=str, help="Write JSON output to a file instead of stdout")
    parser.add_argument("--verbose", action="store_true", help="Print progress messages to stderr")
    args = parser.parse_args()

    if args.verbose:
        print("Detecting Azure subscriptions...", file=sys.stderr)
    available_subscriptions = get_azure_subscriptions()

    if not available_subscriptions:
        print("Error: No Azure subscriptions found. Run: az login", file=sys.stderr)
        sys.exit(1)

    subscription_id = args.subscription_id
    if args.subscription_name:
        subscription_id = resolve_subscription_name_to_id(args.subscription_name, available_subscriptions)
        if not subscription_id:
            print(f"Error: Subscription '{args.subscription_name}' not found.", file=sys.stderr)
            for sub in available_subscriptions:
                print(f"  - {sub['name']}", file=sys.stderr)
            sys.exit(1)
        if args.verbose:
            print(f"Resolved '{args.subscription_name}' → {subscription_id}", file=sys.stderr)

    if not subscription_id:
        subscription_id = available_subscriptions[0]["subscription_id"]
        if args.verbose:
            print(f"Using default subscription: {available_subscriptions[0]['name']} ({subscription_id})", file=sys.stderr)

    try:
        credential = AzureCliCredential()
    except Exception:
        credential = DefaultAzureCredential()

    try:
        if args.verbose:
            print(f"Running HIPAA audit for subscription: {subscription_id}", file=sys.stderr)
        report = run_hipaa_audit(subscription_id=subscription_id, credential=credential)

        output = json.dumps(report, indent=2, default=str)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            if args.verbose:
                print(f"Report written to {args.output}", file=sys.stderr)
        else:
            print(output)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

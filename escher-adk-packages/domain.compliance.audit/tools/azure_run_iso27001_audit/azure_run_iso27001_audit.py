from azure.identity import DefaultAzureCredential, AzureCliCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
import requests as _requests
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.subscription import SubscriptionClient
from azure.keyvault.keys import KeyClient
import argparse
from datetime import datetime, timezone
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict
import sys

# ===================== HELPERS =====================

def create_control_result(control_id, name, description, status, severity, details, recommendation=None):
    result = {
        "iso_control": control_id,
        "control_name": name,
        "description": description,
        "status": status,       # PASS / FAIL / WARNING
        "severity": severity,   # CRITICAL / HIGH / MEDIUM / LOW
        "details": details
    }
    if recommendation:
        result["recommendation"] = recommendation
    return result


def _warning(control_id, name, description, severity, e):
    """Return a WARNING result for a check that failed due to an exception."""
    error_type = type(e).__name__
    return create_control_result(
        control_id, name, description,
        "WARNING", severity,
        {"error": error_type, "message": str(e)},
        f"Ensure the auditing role has permission to perform this check (error: {error_type})."
    )


def _fresh_result() -> dict:
    """Return a new, empty result structure for a single audit run."""
    return {
        "metadata": {
            "framework": "ISO/IEC 27001:2022",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "a8_access_control": {
            "category_description": "Access control and identity management ensuring only authorized users can access resources",
            "controls": [],
        },
        "a8_logging_monitoring": {
            "category_description": "Logging, monitoring, and detection capabilities to identify security incidents",
            "controls": [],
        },
        "a8_data_protection": {
            "category_description": "Data encryption and protection mechanisms to ensure confidentiality",
            "controls": [],
        },
        "a8_configuration_management": {
            "category_description": "Secure configuration and change management to maintain system integrity",
            "controls": [],
        },
        "a8_cloud_security": {
            "category_description": "Information security controls specific to cloud service usage",
            "controls": [],
        },
    }

# ===================== CACHING HELPERS =====================

class AzureResourceCache:
    """Cache for commonly accessed Azure resources to avoid redundant API calls"""
    def __init__(self, subscription_id, credential):
        self.subscription_id = subscription_id
        self.credential = credential
        self._storage_accounts = None
        self._sql_servers = None
        self._disks = None
        self._vms = None

    def get_storage_accounts(self):
        if self._storage_accounts is None:
            try:
                storage_client = StorageManagementClient(self.credential, self.subscription_id)
                self._storage_accounts = list(storage_client.storage_accounts.list())
            except Exception:
                self._storage_accounts = []
        return self._storage_accounts

    def get_sql_servers(self):
        if self._sql_servers is None:
            try:
                sql_client = SqlManagementClient(self.credential, self.subscription_id)
                self._sql_servers = list(sql_client.servers.list())
            except Exception:
                self._sql_servers = []
        return self._sql_servers

    def get_disks(self):
        if self._disks is None:
            try:
                compute_client = ComputeManagementClient(self.credential, self.subscription_id)
                self._disks = list(compute_client.disks.list())
            except Exception:
                self._disks = []
        return self._disks

    def get_vms(self):
        if self._vms is None:
            try:
                compute_client = ComputeManagementClient(self.credential, self.subscription_id)
                self._vms = list(compute_client.virtual_machines.list_all())
            except Exception:
                self._vms = []
        return self._vms

# ===================== A.8 ACCESS CONTROL =====================

def check_mfa_enforcement(subscription_id, credential):
    """A.8.2 — MFA is enforced via Conditional Access policies.

    Querying Conditional Access policies requires Microsoft Graph API access
    (the 'Policy.Read.All' Graph permission), which is outside the Azure Resource
    Manager SDK used by this script. This check always returns WARNING with
    guidance on how to verify manually or via Graph API.
    """
    return create_control_result(
        "A.8.2",
        "Secure Authentication",
        "Ensures MFA is enforced via Conditional Access policies",
        "WARNING",
        "HIGH",
        {
            "reason": (
                "Conditional Access policy data requires Microsoft Graph API access "
                "(Policy.Read.All permission), which is not available via the Azure "
                "Resource Manager SDK used by this script."
            ),
            "manual_check": (
                "Navigate to Entra ID > Security > Conditional Access > Policies "
                "and verify an MFA-enforcing policy covers all users."
            ),
        },
        "Enable MFA for all users via a Conditional Access policy. "
        "Navigate to Entra ID > Security > Conditional Access and create a policy "
        "that requires MFA for all cloud app sign-ins."
    )

# ===================== A.8 LOGGING & MONITORING =====================

def check_activity_log_enabled(subscription_id, credential):
    """A.8.15 — Subscription-level diagnostic settings export Activity Log with ≥90-day retention."""
    _MIN_RETENTION_DAYS = 90
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"
        settings = list(monitor_client.diagnostic_settings.list(scope))

        if not settings:
            return create_control_result(
                "A.8.15",
                "Audit Logging",
                "Ensures Activity Log is exported and retained for at least 90 days",
                "FAIL",
                "CRITICAL",
                {
                    "diagnostic_settings_count": 0,
                    "explanation": "No diagnostic settings found — Activity Log is not being exported or archived.",
                },
                "Create a diagnostic setting to export the Activity Log to a Log Analytics workspace "
                "or Storage Account with at least 90-day retention. Navigate to "
                "Monitor > Activity log > Export Activity Logs."
            )

        # Check each setting for adequate retention
        inadequate = []
        for s in settings:
            retention = None
            if s.retention_policy and s.retention_policy.enabled:
                retention = s.retention_policy.days
            if retention is not None and retention < _MIN_RETENTION_DAYS:
                inadequate.append({"name": s.name, "retention_days": retention})

        return create_control_result(
            "A.8.15",
            "Audit Logging",
            "Ensures Activity Log is exported and retained for at least 90 days",
            "PASS" if not inadequate else "FAIL",
            "CRITICAL",
            {
                "diagnostic_settings_count": len(settings),
                "settings_with_short_retention": inadequate,
            },
            None if not inadequate else (
                f"Increase retention to at least {_MIN_RETENTION_DAYS} days on "
                f"{len(inadequate)} diagnostic setting(s)."
            )
        )
    except Exception as e:
        return _warning("A.8.15", "Audit Logging",
                        "Ensures Activity Log is exported and retained for at least 90 days", "CRITICAL", e)

def check_security_center_enabled(subscription_id, credential):
    """A.8.16 — Microsoft Defender for Cloud Standard tier is active for key resource types."""
    try:
        security_client = SecurityCenter(credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"
        pricings = list(security_client.pricings.list(scope_id=scope))

        enabled_defenders = [
            p.name for p in pricings
            if getattr(p, "pricing_tier", None) == "Standard"
        ]
        disabled_defenders = [
            p.name for p in pricings
            if getattr(p, "pricing_tier", None) != "Standard"
        ]

        if enabled_defenders:
            return create_control_result(
                "A.8.16",
                "Security Monitoring",
                "Detects anomalous and malicious activities",
                "PASS",
                "CRITICAL",
                {
                    "enabled_plans": enabled_defenders,
                    "enabled_plans_count": len(enabled_defenders),
                    "disabled_plans": disabled_defenders,
                },
                None
            )
        return create_control_result(
            "A.8.16",
            "Security Monitoring",
            "Detects anomalous and malicious activities",
            "FAIL",
            "CRITICAL",
            {
                "enabled_plans": [],
                "enabled_plans_count": 0,
                "disabled_plans": disabled_defenders,
            },
            "Enable Microsoft Defender for Cloud (Standard tier) for Servers, Storage, SQL, "
            "and other resource types. Navigate to Defender for Cloud > Environment settings."
        )
    except Exception as e:
        return _warning("A.8.16", "Security Monitoring",
                        "Detects anomalous and malicious activities", "CRITICAL", e)

# ===================== A.8 DATA PROTECTION =====================

def check_sql_encryption(subscription_id, credential, cache=None):
    try:
        sql_servers = cache.get_sql_servers() if cache else list(SqlManagementClient(credential, subscription_id).servers.list())

        if not sql_servers:
            return create_control_result(
                "A.8.24",
                "SQL Encryption at Rest",
                "Ensures all Azure SQL databases have Transparent Data Encryption enabled",
                "PASS",
                "HIGH",
                {"total_servers": 0, "unencrypted_count": 0},
                None
            )

        unencrypted_dbs = []
        sql_client = SqlManagementClient(credential, subscription_id)

        for server in sql_servers:
            try:
                resource_group = server.id.split("/")[4]
                databases = list(sql_client.databases.list_by_server(resource_group, server.name))

                for db in databases:
                    if db.name == "master":
                        continue  # system database — TDE is not user-configurable
                    try:
                        tde = sql_client.transparent_data_encryptions.get(
                            resource_group, server.name, db.name, "current"
                        )
                        if getattr(tde, "state", None) != "Enabled":
                            unencrypted_dbs.append({
                                "server": server.name,
                                "database": db.name,
                                "resource_group": resource_group,
                            })
                    except Exception:
                        unencrypted_dbs.append({
                            "server": server.name,
                            "database": db.name,
                            "resource_group": resource_group,
                            "note": "Unable to verify TDE status",
                        })
            except Exception:
                continue

        return create_control_result(
            "A.8.24",
            "SQL Encryption at Rest",
            "Ensures all Azure SQL databases have Transparent Data Encryption enabled",
            "PASS" if not unencrypted_dbs else "FAIL",
            "HIGH",
            {
                "total_servers": len(sql_servers),
                "unencrypted_databases": unencrypted_dbs,
                "unencrypted_count": len(unencrypted_dbs),
            },
            None if not unencrypted_dbs else (
                f"Enable Transparent Data Encryption (TDE) for {len(unencrypted_dbs)} database(s). "
                "Navigate to SQL Database > Transparent data encryption."
            )
        )
    except Exception as e:
        return _warning("A.8.24", "SQL Encryption at Rest",
                        "Ensures all Azure SQL databases have Transparent Data Encryption enabled", "HIGH", e)

def check_storage_https_only(subscription_id, credential, cache=None):
    """A.8.24 — All storage accounts enforce HTTPS-only access (no unencrypted HTTP)."""
    try:
        storage_accounts = (
            cache.get_storage_accounts() if cache
            else list(StorageManagementClient(credential, subscription_id).storage_accounts.list())
        )

        if not storage_accounts:
            return _warning("A.8.24", "Storage HTTPS Only",
                            "Ensures storage accounts enforce HTTPS-only access", "HIGH",
                            Exception("No storage accounts found or insufficient permissions"))

        http_accounts = [
            {"account_name": a.name, "resource_group": a.id.split("/")[4]}
            for a in storage_accounts
            if not getattr(a, "enable_https_traffic_only", True)
        ]

        return create_control_result(
            "A.8.24",
            "Storage HTTPS Only",
            "Ensures storage accounts enforce HTTPS-only access",
            "PASS" if not http_accounts else "FAIL",
            "HIGH",
            {
                "total_accounts": len(storage_accounts),
                "http_enabled_accounts": http_accounts,
                "http_enabled_count": len(http_accounts),
            },
            None if not http_accounts else (
                f"Enable 'Secure transfer required' (HTTPS only) on {len(http_accounts)} "
                "storage account(s). Navigate to Storage Account > Configuration > Secure transfer required."
            )
        )
    except Exception as e:
        return _warning("A.8.24", "Storage HTTPS Only",
                        "Ensures storage accounts enforce HTTPS-only access", "HIGH", e)


def check_storage_public_access(subscription_id, credential, cache=None):
    """A.8.24 — No storage accounts allow anonymous public blob access."""
    try:
        storage_accounts = (
            cache.get_storage_accounts() if cache
            else list(StorageManagementClient(credential, subscription_id).storage_accounts.list())
        )

        if not storage_accounts:
            return _warning("A.8.24", "Storage Public Access",
                            "Ensures storage accounts do not allow public blob access", "HIGH",
                            Exception("No storage accounts found or insufficient permissions"))

        public_accounts = [
            {"account_name": a.name, "resource_group": a.id.split("/")[4]}
            for a in storage_accounts
            if getattr(a, "allow_blob_public_access", False)
        ]

        return create_control_result(
            "A.8.24",
            "Storage Public Access",
            "Ensures storage accounts do not allow public blob access",
            "PASS" if not public_accounts else "FAIL",
            "HIGH",
            {
                "total_accounts": len(storage_accounts),
                "public_access_accounts": public_accounts,
                "public_access_count": len(public_accounts),
            },
            None if not public_accounts else (
                f"Disable public blob access on {len(public_accounts)} storage account(s). "
                "Navigate to Storage Account > Configuration > Allow Blob public access > Disabled."
            )
        )
    except Exception as e:
        return _warning("A.8.24", "Storage Public Access",
                        "Ensures storage accounts do not allow public blob access", "HIGH", e)

# ===================== A.8 CONFIGURATION MANAGEMENT =====================

def check_policy_assignments(subscription_id, credential):
    """A.8.9 — Azure Policy assignments are active at the subscription scope."""
    _ARM_BASE = "https://management.azure.com"
    _API_VERSION = "2022-06-01"
    try:
        token = credential.get_token(f"{_ARM_BASE}/.default").token
        url = (
            f"{_ARM_BASE}/subscriptions/{subscription_id}"
            f"/providers/Microsoft.Authorization/policyAssignments"
            f"?api-version={_API_VERSION}"
        )
        resp = _requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
        resp.raise_for_status()
        assignments = resp.json().get("value", [])

        scope = f"/subscriptions/{subscription_id}"
        sub_assignments = [
            a for a in assignments
            if a.get("properties", {}).get("scope") in (scope,)
            or "managementGroups" in (a.get("properties", {}).get("scope") or "")
        ]

        if not sub_assignments:
            return create_control_result(
                "A.8.9",
                "Configuration Monitoring",
                "Ensures Azure Policy assignments enforce configuration standards",
                "FAIL",
                "HIGH",
                {
                    "total_assignments": len(assignments),
                    "subscription_scope_assignments": 0,
                },
                "Assign Azure Policy initiatives (e.g. Azure Security Benchmark) at the subscription "
                "scope to enforce configuration standards. Navigate to Azure Policy > Assignments."
            )

        return create_control_result(
            "A.8.9",
            "Configuration Monitoring",
            "Ensures Azure Policy assignments enforce configuration standards",
            "PASS",
            "HIGH",
            {
                "total_assignments": len(assignments),
                "subscription_scope_assignments": len(sub_assignments),
                "assignment_names": [
                    a.get("properties", {}).get("displayName") or a.get("name", "")
                    for a in sub_assignments[:20]
                ],
            },
            None
        )
    except Exception as e:
        return _warning("A.8.9", "Configuration Monitoring",
                        "Ensures Azure Policy assignments enforce configuration standards", "HIGH", e)

# ===================== A.8 CLOUD SECURITY =====================

def check_resource_locks(subscription_id, credential):
    """A.8.23 — All resource groups have at least one resource lock applied."""
    try:
        resource_client = ResourceManagementClient(credential, subscription_id)
        resource_groups = list(resource_client.resource_groups.list())

        if not resource_groups:
            return _warning("A.8.23", "Cloud Service Governance",
                            "Restricts cloud actions using organizational controls", "MEDIUM",
                            Exception("No resource groups found"))

        unlocked_rgs = []
        locked_rgs = []
        for rg in resource_groups:
            try:
                locks = list(resource_client.management_locks.list_at_resource_group_level(rg.name))
                if locks:
                    locked_rgs.append(rg.name)
                else:
                    unlocked_rgs.append(rg.name)
            except Exception:
                unlocked_rgs.append(rg.name)

        return create_control_result(
            "A.8.23",
            "Cloud Service Governance",
            "Restricts cloud actions using organizational controls",
            "PASS" if not unlocked_rgs else "FAIL",
            "MEDIUM",
            {
                "total_resource_groups": len(resource_groups),
                "locked_count": len(locked_rgs),
                "unlocked_count": len(unlocked_rgs),
                "unlocked_resource_groups": unlocked_rgs,
            },
            None if not unlocked_rgs else (
                f"Apply CanNotDelete or ReadOnly resource locks to {len(unlocked_rgs)} resource "
                "group(s) to prevent accidental modification or deletion."
            )
        )
    except Exception as e:
        return _warning("A.8.23", "Cloud Service Governance",
                        "Restricts cloud actions using organizational controls", "MEDIUM", e)

# ===================== A.8 ACCESS CONTROL (CONTINUED) =====================

# Built-in role definition UUIDs (stable across all Azure tenants)
_OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
_CONTRIBUTOR_ROLE_ID = "b24988ac-6180-42a0-ab88-20f7382dd24c"


def check_privileged_role_assignments(subscription_id, credential):
    """A.8.2 — No broad Owner/Contributor assignments at subscription scope outside of break-glass."""
    try:
        auth_client = AuthorizationManagementClient(credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"
        # atScope() returns only direct assignments at this scope, not inherited
        assignments = list(auth_client.role_assignments.list_for_scope(
            scope, filter="atScope()"
        ))

        privileged = []
        for a in assignments:
            role_uuid = (a.role_definition_id or "").split("/")[-1].lower()
            if role_uuid == _OWNER_ROLE_ID:
                role_name = "Owner"
            elif role_uuid == _CONTRIBUTOR_ROLE_ID:
                role_name = "Contributor"
            else:
                continue
            privileged.append({
                "principal_id": a.principal_id,
                "principal_type": getattr(a, "principal_type", "Unknown"),
                "role": role_name,
            })

        return create_control_result(
            "A.8.2",
            "Privileged Role Assignments",
            "Ensures Owner and Contributor roles are not broadly assigned at subscription scope",
            "PASS" if not privileged else "FAIL",
            "HIGH",
            {
                "privileged_assignments_count": len(privileged),
                "privileged_assignments": privileged,
            },
            None if not privileged else (
                f"Review and remove {len(privileged)} Owner/Contributor assignment(s) at subscription scope. "
                "Use Azure PIM for just-in-time privileged access instead of permanent assignments."
            )
        )
    except Exception as e:
        return _warning("A.8.2", "Privileged Role Assignments",
                        "Ensures Owner and Contributor roles are not broadly assigned at subscription scope",
                        "HIGH", e)


# ===================== A.8 LOGGING & MONITORING (CONTINUED) =====================

def check_nsg_flow_logs(subscription_id, credential):
    """A.8.15 — All NSGs have Network Watcher flow logs enabled."""
    try:
        network_client = NetworkManagementClient(credential, subscription_id)
        nsgs = list(network_client.network_security_groups.list_all())

        if not nsgs:
            return create_control_result(
                "A.8.15", "NSG Flow Logs",
                "Ensures all NSGs have flow logs enabled for network traffic monitoring",
                "PASS", "MEDIUM",
                {"total_nsgs": 0, "nsgs_without_flow_logs_count": 0},
                None
            )

        # Collect NSG IDs that have an active flow log
        flow_logged_nsg_ids = set()
        for watcher in network_client.network_watchers.list_all():
            watcher_rg = watcher.id.split("/")[4]
            try:
                for flow_log in network_client.flow_logs.list(watcher_rg, watcher.name):
                    if getattr(flow_log, "enabled", False):
                        flow_logged_nsg_ids.add(
                            (flow_log.target_resource_id or "").lower()
                        )
            except Exception:
                continue

        nsgs_without_logs = [
            {"nsg_name": nsg.name, "resource_group": nsg.id.split("/")[4]}
            for nsg in nsgs
            if nsg.id.lower() not in flow_logged_nsg_ids
        ]

        return create_control_result(
            "A.8.15", "NSG Flow Logs",
            "Ensures all NSGs have flow logs enabled for network traffic monitoring",
            "PASS" if not nsgs_without_logs else "FAIL",
            "MEDIUM",
            {
                "total_nsgs": len(nsgs),
                "nsgs_without_flow_logs": nsgs_without_logs,
                "nsgs_without_flow_logs_count": len(nsgs_without_logs),
            },
            None if not nsgs_without_logs else (
                f"Enable Network Watcher flow logs for {len(nsgs_without_logs)} NSG(s). "
                "Navigate to Network Watcher > NSG flow logs."
            )
        )
    except Exception as e:
        return _warning("A.8.15", "NSG Flow Logs",
                        "Ensures all NSGs have flow logs enabled for network traffic monitoring",
                        "MEDIUM", e)


def check_monitor_alerts(subscription_id, credential):
    """A.8.16 — Activity log alerts exist for key security operations."""
    _REQUIRED_OPERATIONS = {
        "microsoft.security/policies/write":               "Security policy changes",
        "microsoft.security/securitysolutions/delete":     "Security solution deletion",
        "microsoft.network/networksecuritygroups/write":   "NSG modification",
        "microsoft.network/networksecuritygroups/delete":  "NSG deletion",
        "microsoft.authorization/policyassignments/write": "Policy assignment changes",
    }
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        alerts = list(monitor_client.activity_log_alerts.list_by_subscription_id())

        covered_operations = set()
        for alert in alerts:
            if not getattr(alert, "enabled", True):
                continue
            condition = getattr(alert, "condition", None)
            if not condition:
                continue
            for clause in (getattr(condition, "all_of", None) or []):
                value = getattr(clause, "equals", None)
                if value:
                    covered_operations.add(value.lower())

        missing = {
            op: label
            for op, label in _REQUIRED_OPERATIONS.items()
            if op not in covered_operations
        }

        return create_control_result(
            "A.8.16", "Monitor Security Alerts",
            "Ensures activity log alerts exist for key security operations",
            "PASS" if not missing else "FAIL",
            "MEDIUM",
            {
                "total_alerts": len(alerts),
                "covered_operations_count": len(_REQUIRED_OPERATIONS) - len(missing),
                "missing_alerts": list(missing.values()),
            },
            None if not missing else (
                f"Create activity log alerts for: {', '.join(missing.values())}. "
                "Navigate to Monitor > Alerts > Create > Activity Log signal."
            )
        )
    except Exception as e:
        return _warning("A.8.16", "Monitor Security Alerts",
                        "Ensures activity log alerts exist for key security operations",
                        "MEDIUM", e)


# ===================== A.8 DATA PROTECTION (CONTINUED) =====================

def check_vm_disk_encryption(subscription_id, credential, cache=None):
    """A.8.24 — All VM disks are managed disks (automatic SSE); no unmanaged VHD disks."""
    try:
        vms = cache.get_vms() if cache else list(
            ComputeManagementClient(credential, subscription_id).virtual_machines.list_all()
        )

        if not vms:
            return create_control_result(
                "A.8.24", "VM Disk Encryption",
                "Ensures all VM disks use managed disks with automatic encryption at rest",
                "PASS", "HIGH",
                {"total_vms": 0, "unmanaged_disk_vms_count": 0},
                None
            )

        unmanaged_disk_vms = []
        for vm in vms:
            profile = getattr(vm, "storage_profile", None)
            if not profile:
                continue
            has_unmanaged = False
            os_disk = getattr(profile, "os_disk", None)
            if os_disk and not getattr(os_disk, "managed_disk", None):
                has_unmanaged = True
            if not has_unmanaged:
                for data_disk in (getattr(profile, "data_disks", None) or []):
                    if not getattr(data_disk, "managed_disk", None):
                        has_unmanaged = True
                        break
            if has_unmanaged:
                unmanaged_disk_vms.append({
                    "vm_name": vm.name,
                    "resource_group": vm.id.split("/")[4],
                })

        return create_control_result(
            "A.8.24", "VM Disk Encryption",
            "Ensures all VM disks use managed disks with automatic encryption at rest",
            "PASS" if not unmanaged_disk_vms else "FAIL",
            "HIGH",
            {
                "total_vms": len(vms),
                "unmanaged_disk_vms": unmanaged_disk_vms,
                "unmanaged_disk_vms_count": len(unmanaged_disk_vms),
            },
            None if not unmanaged_disk_vms else (
                f"Migrate {len(unmanaged_disk_vms)} VM(s) from unmanaged VHD disks to Azure Managed Disks "
                "to ensure automatic Storage Service Encryption at rest."
            )
        )
    except Exception as e:
        return _warning("A.8.24", "VM Disk Encryption",
                        "Ensures all VM disks use managed disks with automatic encryption at rest",
                        "HIGH", e)


def check_keyvault_key_rotation(subscription_id, credential):
    """A.8.24 — All customer-managed keys in Key Vault have an automatic rotation policy."""
    try:
        kv_client = KeyVaultManagementClient(credential, subscription_id)
        vaults = list(kv_client.vaults.list())

        if not vaults:
            return create_control_result(
                "A.8.24", "Key Vault Key Rotation",
                "Ensures customer-managed keys have automatic rotation policies",
                "PASS", "MEDIUM",
                {"total_vaults": 0, "keys_without_rotation_count": 0},
                None
            )

        keys_without_rotation = []
        inaccessible_vaults = []

        for vault in vaults:
            vault_url = f"https://{vault.name}.vault.azure.net/"
            try:
                key_client = KeyClient(vault_url=vault_url, credential=credential)
                for key_props in key_client.list_properties_of_keys():
                    try:
                        policy = key_client.get_key_rotation_policy(key_props.name)
                        if not getattr(policy, "lifetime_actions", None):
                            keys_without_rotation.append({
                                "vault": vault.name,
                                "key": key_props.name,
                            })
                    except Exception:
                        # Can't read rotation policy — treat as missing
                        keys_without_rotation.append({
                            "vault": vault.name,
                            "key": key_props.name,
                            "note": "Unable to read rotation policy",
                        })
            except Exception:
                inaccessible_vaults.append(vault.name)

        details = {
            "total_vaults": len(vaults),
            "keys_without_rotation": keys_without_rotation,
            "keys_without_rotation_count": len(keys_without_rotation),
        }
        if inaccessible_vaults:
            details["inaccessible_vaults"] = inaccessible_vaults

        return create_control_result(
            "A.8.24", "Key Vault Key Rotation",
            "Ensures customer-managed keys have automatic rotation policies",
            "PASS" if not keys_without_rotation else "FAIL",
            "MEDIUM",
            details,
            None if not keys_without_rotation else (
                f"Configure automatic rotation policies on {len(keys_without_rotation)} key(s). "
                "Navigate to Key Vault > Keys > select key > Rotation policy."
            )
        )
    except Exception as e:
        return _warning("A.8.24", "Key Vault Key Rotation",
                        "Ensures customer-managed keys have automatic rotation policies",
                        "MEDIUM", e)


# ===================== A.8 CONFIGURATION MANAGEMENT (CONTINUED) =====================

_SENSITIVE_PORTS = {22, 3389}


def check_nsg_unrestricted_access(subscription_id, credential):
    """A.8.20 — No NSGs allow unrestricted inbound access on SSH (22) or RDP (3389)."""
    try:
        network_client = NetworkManagementClient(credential, subscription_id)
        nsgs = list(network_client.network_security_groups.list_all())

        open_rules = []
        for nsg in nsgs:
            for rule in (nsg.security_rules or []):
                if getattr(rule, "direction", "") != "Inbound":
                    continue
                if getattr(rule, "access", "") != "Allow":
                    continue
                source = getattr(rule, "source_address_prefix", "") or ""
                if source not in ("*", "0.0.0.0/0", "Internet", "::/0"):
                    continue

                # Collect all destination port ranges from this rule
                port_ranges = list(getattr(rule, "destination_port_ranges", None) or [])
                single = getattr(rule, "destination_port_range", None)
                if single:
                    port_ranges.append(single)

                exposed_ports = _ports_in_ranges(port_ranges, _SENSITIVE_PORTS)
                if exposed_ports:
                    open_rules.append({
                        "nsg_name": nsg.name,
                        "resource_group": nsg.id.split("/")[4],
                        "rule_name": rule.name,
                        "exposed_ports": sorted(exposed_ports),
                        "source": source,
                    })

        return create_control_result(
            "A.8.20", "NSG Unrestricted Access",
            "Ensures no NSGs allow unrestricted inbound access on SSH (22) or RDP (3389)",
            "PASS" if not open_rules else "FAIL",
            "HIGH",
            {
                "open_rules_count": len(open_rules),
                "open_rules": open_rules,
            },
            None if not open_rules else (
                f"Restrict source IP ranges on {len(open_rules)} NSG rule(s) that expose SSH/RDP "
                "to the internet. Replace 0.0.0.0/0 with specific trusted IP ranges or use Azure Bastion."
            )
        )
    except Exception as e:
        return _warning("A.8.20", "NSG Unrestricted Access",
                        "Ensures no NSGs allow unrestricted inbound access on SSH (22) or RDP (3389)",
                        "HIGH", e)


def _ports_in_ranges(port_ranges: list, target_ports: set) -> set:
    """Return which target_ports are covered by the given list of port range strings.

    Each entry may itself be comma-separated (e.g. "22, 3389") as returned by
    the Azure SDK for rules created via the portal or ARM templates.
    """
    matched = set()
    for pr in port_ranges:
        # Flatten comma-separated entries before parsing
        for token in str(pr).split(","):
            token = token.strip()
            if token == "*":
                return set(target_ports)
            if "-" in token:
                try:
                    lo, hi = token.split("-", 1)
                    r = range(int(lo), int(hi) + 1)
                    matched |= {p for p in target_ports if p in r}
                except ValueError:
                    pass
            else:
                try:
                    if int(token) in target_ports:
                        matched.add(int(token))
                except ValueError:
                    pass
    return matched


# ===================== A.8 DATA PROTECTION (ADDITIONAL) =====================

def check_keyvault_soft_delete(subscription_id, credential):
    """A.8.24 — All Key Vaults have soft delete and purge protection enabled."""
    try:
        kv_client = KeyVaultManagementClient(credential, subscription_id)
        vaults = list(kv_client.vaults.list())

        if not vaults:
            return create_control_result(
                "A.8.24", "Key Vault Soft Delete",
                "Ensures Key Vaults have soft delete and purge protection enabled",
                "PASS", "HIGH",
                {"total_vaults": 0, "unprotected_vaults_count": 0},
                None
            )

        unprotected = []
        for vault in vaults:
            props = getattr(vault, "properties", None)
            soft_delete = getattr(props, "enable_soft_delete", False)
            purge_protection = getattr(props, "enable_purge_protection", False)
            if not soft_delete or not purge_protection:
                unprotected.append({
                    "vault_name": vault.name,
                    "soft_delete_enabled": bool(soft_delete),
                    "purge_protection_enabled": bool(purge_protection),
                })

        return create_control_result(
            "A.8.24", "Key Vault Soft Delete",
            "Ensures Key Vaults have soft delete and purge protection enabled",
            "PASS" if not unprotected else "FAIL",
            "HIGH",
            {
                "total_vaults": len(vaults),
                "unprotected_vaults": unprotected,
                "unprotected_vaults_count": len(unprotected),
            },
            None if not unprotected else (
                f"Enable soft delete and purge protection on {len(unprotected)} Key Vault(s). "
                "Navigate to Key Vault > Properties > Soft delete / Purge protection."
            )
        )
    except Exception as e:
        return _warning("A.8.24", "Key Vault Soft Delete",
                        "Ensures Key Vaults have soft delete and purge protection enabled", "HIGH", e)


def check_storage_minimum_tls(subscription_id, credential, cache=None):
    """A.8.24 — All storage accounts enforce a minimum TLS version of 1.2."""
    try:
        storage_accounts = (
            cache.get_storage_accounts() if cache
            else list(StorageManagementClient(credential, subscription_id).storage_accounts.list())
        )

        if not storage_accounts:
            return _warning("A.8.24", "Storage Minimum TLS",
                            "Ensures storage accounts enforce TLS 1.2 as minimum version", "MEDIUM",
                            Exception("No storage accounts found or insufficient permissions"))

        weak_tls_accounts = [
            {"account_name": a.name, "resource_group": a.id.split("/")[4],
             "minimum_tls_version": getattr(a, "minimum_tls_version", None)}
            for a in storage_accounts
            if getattr(a, "minimum_tls_version", None) not in ("TLS1_2", "TLS1_3")
        ]

        return create_control_result(
            "A.8.24", "Storage Minimum TLS",
            "Ensures storage accounts enforce TLS 1.2 as minimum version",
            "PASS" if not weak_tls_accounts else "FAIL",
            "MEDIUM",
            {
                "total_accounts": len(storage_accounts),
                "weak_tls_accounts": weak_tls_accounts,
                "weak_tls_count": len(weak_tls_accounts),
            },
            None if not weak_tls_accounts else (
                f"Set minimum TLS version to TLS 1.2 on {len(weak_tls_accounts)} storage account(s). "
                "Navigate to Storage Account > Configuration > Minimum TLS version."
            )
        )
    except Exception as e:
        return _warning("A.8.24", "Storage Minimum TLS",
                        "Ensures storage accounts enforce TLS 1.2 as minimum version", "MEDIUM", e)


def check_sql_advanced_threat_protection(subscription_id, credential):
    """A.8.16 — Microsoft Defender (Advanced Threat Protection) is enabled on all SQL servers."""
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        servers = list(sql_client.servers.list())

        if not servers:
            return create_control_result(
                "A.8.16", "SQL Advanced Threat Protection",
                "Ensures Microsoft Defender is enabled on all Azure SQL servers",
                "PASS", "HIGH",
                {"total_servers": 0, "unprotected_servers_count": 0},
                None
            )

        unprotected = []
        for server in servers:
            rg = server.id.split("/")[4]
            try:
                atp = sql_client.server_advanced_threat_protection_settings.get(
                    rg, server.name, "Default"
                )
                if getattr(atp, "state", None) != "Enabled":
                    unprotected.append({"server": server.name, "resource_group": rg})
            except Exception:
                unprotected.append({
                    "server": server.name,
                    "resource_group": rg,
                    "note": "Unable to verify ATP status",
                })

        return create_control_result(
            "A.8.16", "SQL Advanced Threat Protection",
            "Ensures Microsoft Defender is enabled on all Azure SQL servers",
            "PASS" if not unprotected else "FAIL",
            "HIGH",
            {
                "total_servers": len(servers),
                "unprotected_servers": unprotected,
                "unprotected_servers_count": len(unprotected),
            },
            None if not unprotected else (
                f"Enable Microsoft Defender for SQL on {len(unprotected)} server(s). "
                "Navigate to SQL Server > Microsoft Defender for Cloud > Enable."
            )
        )
    except Exception as e:
        return _warning("A.8.16", "SQL Advanced Threat Protection",
                        "Ensures Microsoft Defender is enabled on all Azure SQL servers", "HIGH", e)


# ===================== EXECUTIVE SUMMARY =====================

def generate_executive_summary(result):
    """Generate a markdown-formatted executive summary of the ISO 27001 audit results"""
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

    # Calculate compliance score based on completed controls only
    compliance_score = int((passed / controls_completed * 100)) if controls_completed > 0 else 0

    # Build markdown summary
    md_lines = []

    # Title
    md_lines.append("# ISO/IEC 27001:2022 Compliance Summary - Azure")
    md_lines.append("")

    # Overall compliance status
    md_lines.append("## Overall Compliance Status")
    md_lines.append("")
    if compliance_score >= 90:
        md_lines.append(f"**Azure Subscription {subscription_id}** demonstrates **strong ISO 27001 compliance** with a **{compliance_score}%** pass rate across **{total_controls}** security controls.")
    elif compliance_score >= 70:
        md_lines.append(f"**Azure Subscription {subscription_id}** shows **moderate ISO 27001 compliance** with a **{compliance_score}%** pass rate across **{total_controls}** security controls, requiring targeted improvements.")
    else:
        md_lines.append(f"**Azure Subscription {subscription_id}** requires **significant security improvements** with a **{compliance_score}%** pass rate across **{total_controls}** security controls.")
    md_lines.append("")

    # Key Findings
    md_lines.append("## Key Findings")
    md_lines.append("")
    if critical_failures > 0 or high_failures > 0:
        severity_text = []
        if critical_failures > 0:
            severity_text.append(f"**{critical_failures} critical**")
        if high_failures > 0:
            severity_text.append(f"**{high_failures} high-severity**")
        md_lines.append(f"The audit identified **{failed} failed control(s)** including {' and '.join(severity_text)} issue(s) that require **immediate remediation**.")
    elif failed > 0:
        md_lines.append(f"The audit identified **{failed} failed control(s)** with lower severity levels that should be addressed to improve security posture.")
    else:
        md_lines.append("The audit found **no failed controls**, indicating excellent security practices across all evaluated areas.")
    md_lines.append("")

    # Control Categories status
    md_lines.append("## ISO 27001 Control Categories")
    md_lines.append("")
    categories_with_issues = []
    if any(c["status"] == "FAIL" for c in result["a8_access_control"]["controls"]):
        categories_with_issues.append("**Access Control (A.8.2)**")
    if any(c["status"] == "FAIL" for c in result["a8_logging_monitoring"]["controls"]):
        categories_with_issues.append("**Logging & Monitoring (A.8.15-16)**")
    if any(c["status"] == "FAIL" for c in result["a8_data_protection"]["controls"]):
        categories_with_issues.append("**Data Protection (A.8.24)**")
    if any(c["status"] == "FAIL" for c in result["a8_configuration_management"]["controls"]):
        categories_with_issues.append("**Configuration Management (A.8.9)**")
    if any(c["status"] == "FAIL" for c in result["a8_cloud_security"]["controls"]):
        categories_with_issues.append("**Cloud Security (A.8.23)**")

    if categories_with_issues:
        md_lines.append(f"Control categories requiring attention: {', '.join(categories_with_issues)}")
    else:
        md_lines.append("All ISO 27001 Annex A.8 control categories meet compliance standards.")
    md_lines.append("")

    # Additional Observations
    md_lines.append("## Additional Observations")
    md_lines.append("")

    if permission_errors > 0:
        md_lines.append(f"**Note:** {permission_errors} control(s) could not be completed due to insufficient Azure RBAC permissions. Grant necessary permissions for a complete audit.")
        md_lines.append("")

    if warnings > 0:
        warnings_without_permission = warnings - permission_errors
        if warnings_without_permission > 0:
            md_lines.append(f"Additionally, **{warnings_without_permission} warning(s)** were identified that should be reviewed for continuous improvement.")
        elif permission_errors == 0:
            md_lines.append(f"**{warnings} warning(s)** were identified that should be reviewed for continuous improvement.")
    else:
        if permission_errors == 0:
            md_lines.append("No warnings were identified, indicating robust security configurations.")
    md_lines.append("")

    # Recommendation
    md_lines.append("## Recommendation")
    md_lines.append("")
    if compliance_score >= 90:
        md_lines.append("**Action:** Address minor findings and proceed with ISO 27001 certification preparation.")
    elif compliance_score >= 70:
        md_lines.append("**Action:** Focus on critical and high-severity findings before pursuing formal ISO 27001 certification.")
    else:
        md_lines.append("**Action:** Implement comprehensive security improvements across all categories before initiating ISO 27001 certification process.")

    return "\n".join(md_lines)

# ===================== RUN AUDIT =====================

def run_iso_audit(subscription_id: str, credential):
    """Run ISO 27001 audit for a given subscription ID."""
    try:
        result = _fresh_result()
        result["metadata"]["subscription_id"] = subscription_id

        cache = AzureResourceCache(subscription_id, credential)

        check_tasks = [
            # Access Control
            ("a8_access_control",           lambda: check_mfa_enforcement(subscription_id, credential)),
            ("a8_access_control",           lambda: check_privileged_role_assignments(subscription_id, credential)),
            # Logging & Monitoring
            ("a8_logging_monitoring",       lambda: check_activity_log_enabled(subscription_id, credential)),
            ("a8_logging_monitoring",       lambda: check_security_center_enabled(subscription_id, credential)),
            ("a8_logging_monitoring",       lambda: check_nsg_flow_logs(subscription_id, credential)),
            ("a8_logging_monitoring",       lambda: check_monitor_alerts(subscription_id, credential)),
            # Data Protection
            ("a8_data_protection",          lambda: check_sql_encryption(subscription_id, credential, cache)),
            ("a8_data_protection",          lambda: check_storage_https_only(subscription_id, credential, cache)),
            ("a8_data_protection",          lambda: check_storage_public_access(subscription_id, credential, cache)),
            ("a8_data_protection",          lambda: check_vm_disk_encryption(subscription_id, credential, cache)),
            ("a8_data_protection",          lambda: check_keyvault_key_rotation(subscription_id, credential)),
            ("a8_data_protection",          lambda: check_keyvault_soft_delete(subscription_id, credential)),
            ("a8_data_protection",          lambda: check_storage_minimum_tls(subscription_id, credential, cache)),
            ("a8_logging_monitoring",       lambda: check_sql_advanced_threat_protection(subscription_id, credential)),
            # Configuration Management
            ("a8_configuration_management", lambda: check_policy_assignments(subscription_id, credential)),
            ("a8_configuration_management", lambda: check_nsg_unrestricted_access(subscription_id, credential)),
            # Cloud Security
            ("a8_cloud_security",           lambda: check_resource_locks(subscription_id, credential)),
        ]

        with ThreadPoolExecutor(max_workers=len(check_tasks)) as executor:
            future_to_category = {executor.submit(fn): category for category, fn in check_tasks}

            for future in as_completed(future_to_category):
                category = future_to_category[future]
                try:
                    result[category]["controls"].append(future.result())
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
            for key in result
            if isinstance(result[key], dict) and "controls" in result[key]
            for c in result[key]["controls"]
        ]

        permission_errors = sum(
            1 for c in all_controls
            if c["status"] == "WARNING" and any(
                kw in str(c.get("details", {}).get("message", ""))
                for kw in ("AuthorizationFailed", "Forbidden", "does not have authorization",
                           "ClientAuthenticationError", "CredentialUnavailableError")
            )
        )

        result["metadata"]["summary"] = {
            "total_controls": len(all_controls),
            "passed": sum(1 for c in all_controls if c["status"] == "PASS"),
            "failed": sum(1 for c in all_controls if c["status"] == "FAIL"),
            "warnings": sum(1 for c in all_controls if c["status"] == "WARNING"),
            "critical_failures": sum(1 for c in all_controls if c["status"] == "FAIL" and c["severity"] == "CRITICAL"),
            "high_failures": sum(1 for c in all_controls if c["status"] == "FAIL" and c["severity"] == "HIGH"),
            "permission_errors": permission_errors,
            "controls_completed": len(all_controls) - permission_errors,
        }

        result["metadata"]["executive_summary"] = generate_executive_summary(result)

        return result

    except Exception as e:
        raise

# ===================== MAIN =====================

def get_azure_subscriptions() -> List[Dict[str, str]]:
    """Get list of available Azure subscriptions using Azure SDK."""
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)

        subscriptions = []
        for sub in subscription_client.subscriptions.list():
            # Get tenant_id - it may be in different attributes depending on SDK version
            tenant_id = ""
            if hasattr(sub, 'tenant_id'):
                tenant_id = sub.tenant_id or ""
            elif hasattr(sub, 'home_tenant_id'):
                tenant_id = sub.home_tenant_id or ""

            # Get state attribute safely
            state = "Enabled"
            if hasattr(sub, 'state'):
                state = str(sub.state) if sub.state else "Enabled"

            subscriptions.append({
                'name': sub.display_name,
                'subscription_id': sub.subscription_id,
                'tenant_id': tenant_id,
                'state': state
            })

        return subscriptions
    except Exception as e:
        print(f"Error getting Azure subscriptions: {e}", file=sys.stderr)
        return []


def resolve_subscription_name_to_id(subscription_name: str, subscriptions: List[Dict[str, str]]) -> Optional[str]:
    """Resolve subscription name to subscription ID."""
    for sub in subscriptions:
        if sub['name'].lower() == subscription_name.lower():
            return sub['subscription_id']
    return None

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Azure ISO 27001 Compliance Audit Script - Generate ISO/IEC 27001:2022 compliance reports.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate ISO audit report for default subscription
  python3 azure_iso.py

  # Generate ISO audit report for a specific subscription by name
  python3 azure_iso.py --subscription-name "Tessell QA BYOA"

  # Generate ISO audit report for a specific subscription by ID
  python3 azure_iso.py --subscription-id "12345678-1234-1234-1234-123456789abc"
        '''
    )

    parser.add_argument(
        '--subscription-name',
        help='Specify the subscription name (case-insensitive)'
    )

    parser.add_argument(
        "--subscription-id",
        "-s",
        type=str,
        help="Azure subscription ID (uses default subscription if not specified)",
        default=None
    )
    parser.add_argument("--verbose", action="store_true", help="Print progress messages to stderr")

    return parser.parse_args()

def main():
    """Main execution function."""
    args = parse_arguments()

    # Get Azure subscriptions using Azure CLI
    if args.verbose:
        print("Detecting Azure subscriptions...", file=sys.stderr)
    available_subscriptions = get_azure_subscriptions()

    if not available_subscriptions:
        print("Error: No Azure subscriptions found. Please authenticate using:", file=sys.stderr)
        print("    az login", file=sys.stderr)
        sys.exit(1)

    # Resolve subscription name to ID if provided
    subscription_id = args.subscription_id
    if args.subscription_name:
        subscription_id = resolve_subscription_name_to_id(args.subscription_name, available_subscriptions)
        if not subscription_id:
            print(f"Error: Subscription name '{args.subscription_name}' not found.", file=sys.stderr)
            print("Available subscriptions:", file=sys.stderr)
            for sub in available_subscriptions:
                print(f"  - {sub['name']}", file=sys.stderr)
            sys.exit(1)
        if args.verbose:
            print(f"Resolved subscription name '{args.subscription_name}' to ID '{subscription_id}'", file=sys.stderr)

    # If no subscription ID provided, use the first available subscription
    if not subscription_id:
        subscription_id = available_subscriptions[0]['subscription_id']
        subscription_name = available_subscriptions[0]['name']
        if args.verbose:
            print(f"Using default subscription: {subscription_name} ({subscription_id})", file=sys.stderr)

    # Create credential
    try:
        credential = AzureCliCredential()
    except Exception:
        credential = DefaultAzureCredential()

    # Use subscription_id for further processing
    try:
        if args.verbose:
            print(f"Running ISO 27001 audit for subscription: {subscription_id}", file=sys.stderr)
        raw_report = run_iso_audit(subscription_id=subscription_id, credential=credential)

        # Return flat format with categories containing controls directly
        report = {
            "metadata": raw_report["metadata"],
            "a8_access_control": raw_report["a8_access_control"],
            "a8_logging_monitoring": raw_report["a8_logging_monitoring"],
            "a8_data_protection": raw_report["a8_data_protection"],
            "a8_configuration_management": raw_report["a8_configuration_management"],
            "a8_cloud_security": raw_report["a8_cloud_security"]
        }

        return report
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    result = main()
    print(json.dumps(result, indent=2))

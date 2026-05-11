from azure.identity import DefaultAzureCredential, AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.subscription import SubscriptionClient
import argparse
from datetime import datetime, timezone
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import subprocess
from typing import Optional, List, Dict

# ===================== RESULT STRUCTURE =====================

RESULT = {
    "metadata": {
        "framework": "GDPR",
        "generated_at": datetime.now(timezone.utc).isoformat()
    },
    "article_5_integrity_confidentiality": {
        "category_description": "Personal data must be processed securely with integrity and confidentiality",
        "checks": []
    },
    "article_25_privacy_by_design": {
        "category_description": "Data protection by design and by default",
        "checks": []
    },
    "article_30_records_of_processing": {
        "category_description": "Records of processing activities",
        "checks": []
    },
    "article_32_security_of_processing": {
        "category_description": "Security of processing",
        "checks": []
    },
    "article_33_34_breach_management": {
        "category_description": "Detection, reporting, and communication of personal data breaches",
        "checks": []
    }
}

# ===================== HELPERS =====================

def create_check_result(article, name, description, status, severity, details, recommendation=None):
    result = {
        "gdpr_article": article,
        "check_name": name,
        "description": description,
        "status": status,        # PASS / FAIL / WARNING
        "severity": severity,    # CRITICAL / HIGH / MEDIUM / LOW
        "details": details
    }
    if recommendation:
        result["recommendation"] = recommendation
    return result

# ===================== CACHING HELPERS =====================

class AzureResourceCache:
    """Cache for commonly accessed Azure resources to avoid redundant API calls"""
    def __init__(self, subscription_id, credential):
        self.subscription_id = subscription_id
        self.credential = credential
        self._vms = None
        self._storage_accounts = None
        self._sql_servers = None

    def get_vms(self):
        if self._vms is None:
            try:
                compute_client = ComputeManagementClient(self.credential, self.subscription_id)
                self._vms = list(compute_client.virtual_machines.list_all())
            except Exception:
                self._vms = []
        return self._vms

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

# ===================== ARTICLE 5 - INTEGRITY & CONFIDENTIALITY =====================

def check_activity_log_enabled(subscription_id, credential):
    """Article 5(1)(f) - Audit logging for integrity and confidentiality"""
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        log_profiles = list(monitor_client.log_profiles.list())

        return create_check_result(
            "Article 5(1)(f)",
            "Activity Log Audit Trail",
            "Ensures audit logging is enabled to protect integrity and confidentiality of personal data",
            "PASS" if log_profiles else "FAIL",
            "CRITICAL",
            {
                "log_profiles_count": len(log_profiles),
                "log_profiles": [lp.name for lp in log_profiles]
            },
            None if log_profiles else "Enable Activity Log export to Storage Account or Log Analytics workspace. Go to Azure Monitor > Activity Log > Export Activity Logs"
        )
    except Exception as e:
        return create_check_result(
            "Article 5(1)(f)",
            "Activity Log Audit Trail",
            "Ensures audit logging is enabled to protect integrity and confidentiality of personal data",
            "WARNING",
            "CRITICAL",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.Insights/logProfiles/read"
        )

def check_storage_public_access(subscription_id, credential, cache=None):
    """Article 5(1)(f) - Prevent public exposure of personal data"""
    try:
        storage_accounts = cache.get_storage_accounts() if cache else list(StorageManagementClient(credential, subscription_id).storage_accounts.list())

        public_access_accounts = []
        for account in storage_accounts:
            allow_blob_public_access = (
                hasattr(account, 'allow_blob_public_access') and
                account.allow_blob_public_access
            )
            if allow_blob_public_access:
                public_access_accounts.append(account.name)

        return create_check_result(
            "Article 5(1)(f)",
            "Storage Account Public Access",
            "Checks whether personal data could be publicly exposed via Storage Accounts",
            "PASS" if not public_access_accounts else "FAIL",
            "CRITICAL",
            {
                "total_storage_accounts": len(storage_accounts),
                "public_access_accounts": public_access_accounts
            },
            None if not public_access_accounts else f"Disable public blob access for {len(public_access_accounts)} Storage Account(s) containing personal data. Go to Storage Account > Configuration > Allow Blob public access > Disabled"
        )
    except Exception as e:
        return create_check_result(
            "Article 5(1)(f)",
            "Storage Account Public Access",
            "Checks whether personal data could be publicly exposed via Storage Accounts",
            "WARNING",
            "CRITICAL",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.Storage/storageAccounts/read"
        )

def check_diagnostic_logging(subscription_id, credential):
    """Article 5(1)(f) - Logging for data integrity"""
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)

        resources = list(resource_client.resources.list())
        important_resource_types = [
            "Microsoft.Sql/servers/databases",
            "Microsoft.Storage/storageAccounts",
            "Microsoft.KeyVault/vaults"
        ]

        resources_without_diagnostics = []
        checked_count = 0

        for resource in resources:
            if resource.type in important_resource_types and checked_count < 20:
                try:
                    diagnostic_settings = list(monitor_client.diagnostic_settings.list(resource.id))
                    if not diagnostic_settings:
                        resources_without_diagnostics.append({
                            "resource_name": resource.name,
                            "resource_type": resource.type
                        })
                    checked_count += 1
                except Exception:
                    continue

        return create_check_result(
            "Article 5(1)(f)",
            "Diagnostic Logging",
            "Ensures logging is configured for resources processing personal data",
            "PASS" if not resources_without_diagnostics else "WARNING",
            "MEDIUM",
            {
                "checked_resources": checked_count,
                "resources_without_diagnostics": resources_without_diagnostics
            },
            None if not resources_without_diagnostics else f"Configure diagnostic settings for {len(resources_without_diagnostics)} resource(s) processing personal data"
        )
    except Exception as e:
        return create_check_result(
            "Article 5(1)(f)",
            "Diagnostic Logging",
            "Ensures logging is configured for resources processing personal data",
            "WARNING",
            "MEDIUM",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.Insights/diagnosticSettings/read"
        )

# ===================== ARTICLE 25 - PRIVACY BY DESIGN =====================

def check_storage_encryption(subscription_id, credential, cache=None):
    """Article 25 - Encryption by default for personal data"""
    try:
        storage_accounts = cache.get_storage_accounts() if cache else list(StorageManagementClient(credential, subscription_id).storage_accounts.list())

        unencrypted = []
        for account in storage_accounts:
            encryption_enabled = (
                hasattr(account, 'encryption') and
                account.encryption and
                hasattr(account.encryption, 'services') and
                account.encryption.services
            )
            if not encryption_enabled:
                unencrypted.append(account.name)

        return create_check_result(
            "Article 25",
            "Storage Encryption at Rest",
            "Verifies encryption by default for stored personal data",
            "PASS" if not unencrypted else "FAIL",
            "HIGH",
            {
                "total_storage_accounts": len(storage_accounts),
                "unencrypted_accounts": unencrypted
            },
            None if not unencrypted else f"Enable encryption for {len(unencrypted)} Storage Account(s). Encryption is enabled by default - verify configuration."
        )
    except Exception as e:
        return create_check_result(
            "Article 25",
            "Storage Encryption at Rest",
            "Verifies encryption by default for stored personal data",
            "WARNING",
            "HIGH",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.Storage/storageAccounts/read"
        )

def check_sql_tde_encryption(subscription_id, credential, cache=None):
    """Article 25 - Database encryption by default"""
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        sql_servers = cache.get_sql_servers() if cache else list(sql_client.servers.list())

        unencrypted_databases = []
        for server in sql_servers:
            resource_group = server.id.split("/")[4]
            try:
                databases = list(sql_client.databases.list_by_server(resource_group, server.name))
                for db in databases:
                    if db.name != "master":
                        try:
                            tde = sql_client.transparent_data_encryptions.get(
                                resource_group, server.name, db.name, "current"
                            )
                            if tde.state != "Enabled":
                                unencrypted_databases.append({
                                    "server": server.name,
                                    "database": db.name
                                })
                        except Exception:
                            pass
            except Exception:
                continue

        return create_check_result(
            "Article 25",
            "SQL Database Encryption at Rest",
            "Verifies encryption by default for databases storing personal data",
            "PASS" if not unencrypted_databases else "FAIL",
            "HIGH",
            {
                "total_sql_servers": len(sql_servers),
                "unencrypted_databases": unencrypted_databases
            },
            None if not unencrypted_databases else f"Enable Transparent Data Encryption (TDE) for {len(unencrypted_databases)} database(s). Go to SQL Database > Security > Transparent data encryption"
        )
    except Exception as e:
        return create_check_result(
            "Article 25",
            "SQL Database Encryption at Rest",
            "Verifies encryption by default for databases storing personal data",
            "WARNING",
            "HIGH",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.Sql/servers/read, Microsoft.Sql/servers/databases/read"
        )

def check_network_security_defaults(subscription_id, credential):
    """Article 25 - Secure by default network configuration"""
    try:
        network_client = NetworkManagementClient(credential, subscription_id)
        nsgs = list(network_client.network_security_groups.list_all())

        risky_rules = []
        for nsg in nsgs:
            if hasattr(nsg, 'security_rules'):
                for rule in nsg.security_rules:
                    if rule.direction == "Inbound" and rule.access == "Allow":
                        source_open = (
                            rule.source_address_prefix in ["*", "Internet", "0.0.0.0/0"]
                        )
                        if source_open and rule.destination_port_range == "*":
                            risky_rules.append({
                                "nsg_name": nsg.name,
                                "rule_name": rule.name
                            })

        return create_check_result(
            "Article 25",
            "Network Security by Default",
            "Ensures network security groups are configured securely by default",
            "PASS" if not risky_rules else "FAIL",
            "HIGH",
            {
                "total_nsgs": len(nsgs),
                "risky_rules": risky_rules
            },
            None if not risky_rules else f"Remove {len(risky_rules)} overly permissive NSG rule(s) allowing all ports from the internet"
        )
    except Exception as e:
        return create_check_result(
            "Article 25",
            "Network Security by Default",
            "Ensures network security groups are configured securely by default",
            "WARNING",
            "HIGH",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.Network/networkSecurityGroups/read"
        )

# ===================== ARTICLE 30 - RECORDS OF PROCESSING =====================

def check_regions_of_processing(subscription_id, credential, cache=None):
    """Article 30 - Identify regions where personal data is processed"""
    try:
        vms = cache.get_vms() if cache else list(ComputeManagementClient(credential, subscription_id).virtual_machines.list_all())
        storage_accounts = cache.get_storage_accounts() if cache else list(StorageManagementClient(credential, subscription_id).storage_accounts.list())

        vm_regions = list(set([vm.location for vm in vms]))
        storage_regions = list(set([sa.location for sa in storage_accounts]))
        all_regions = list(set(vm_regions + storage_regions))

        return create_check_result(
            "Article 30",
            "Regions of Processing",
            "Identifies Azure regions where personal data is processed",
            "PASS",
            "LOW",
            {
                "regions_in_use": all_regions,
                "vm_regions": vm_regions,
                "storage_regions": storage_regions,
                "region_count": len(all_regions)
            },
            "Document these regions in your Record of Processing Activities (RoPA) as required by GDPR Article 30."
        )
    except Exception as e:
        return create_check_result(
            "Article 30",
            "Regions of Processing",
            "Identifies Azure regions where personal data is processed",
            "WARNING",
            "LOW",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.Compute/virtualMachines/read, Microsoft.Storage/storageAccounts/read"
        )

def check_resource_tagging(subscription_id, credential):
    """Article 30 - Resource tagging for data inventory"""
    try:
        resource_client = ResourceManagementClient(credential, subscription_id)
        resource_groups = list(resource_client.resource_groups.list())

        untagged_rgs = []
        for rg in resource_groups:
            if not hasattr(rg, 'tags') or not rg.tags or not rg.tags.get("DataClassification"):
                untagged_rgs.append(rg.name)

        return create_check_result(
            "Article 30",
            "Data Classification Tagging",
            "Ensures resources are tagged for data inventory and RoPA maintenance",
            "PASS" if not untagged_rgs else "WARNING",
            "MEDIUM",
            {
                "total_resource_groups": len(resource_groups),
                "untagged_resource_groups": untagged_rgs
            },
            None if not untagged_rgs else f"Tag {len(untagged_rgs)} resource group(s) with 'DataClassification' to maintain data inventory for GDPR RoPA"
        )
    except Exception as e:
        return create_check_result(
            "Article 30",
            "Data Classification Tagging",
            "Ensures resources are tagged for data inventory and RoPA maintenance",
            "WARNING",
            "MEDIUM",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.Resources/subscriptions/resourceGroups/read"
        )

# ===================== ARTICLE 32 - SECURITY OF PROCESSING =====================

def check_defender_for_cloud(subscription_id, credential):
    """Article 32 - Threat detection capability"""
    try:
        security_client = SecurityCenter(credential, subscription_id, asc_location="centralus")
        pricings = list(security_client.pricings.list())

        enabled_services = [p.name for p in pricings if p.pricing_tier == "Standard"]

        return create_check_result(
            "Article 32",
            "Threat Detection - Defender for Cloud",
            "Ensures capability to detect security incidents affecting personal data",
            "PASS" if enabled_services else "FAIL",
            "CRITICAL",
            {
                "defender_enabled": bool(enabled_services),
                "enabled_services_count": len(enabled_services),
                "enabled_services": enabled_services
            },
            None if enabled_services else "Enable Microsoft Defender for Cloud (Standard tier) for threat detection. Go to Microsoft Defender for Cloud > Environment settings"
        )
    except Exception as e:
        return create_check_result(
            "Article 32",
            "Threat Detection - Defender for Cloud",
            "Ensures capability to detect security incidents affecting personal data",
            "WARNING",
            "CRITICAL",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.Security/pricings/read"
        )

def check_sql_advanced_threat_protection(subscription_id, credential, cache=None):
    """Article 32 - Database threat detection"""
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        sql_servers = cache.get_sql_servers() if cache else list(sql_client.servers.list())

        servers_without_atp = []
        for server in sql_servers:
            resource_group = server.id.split("/")[4]
            try:
                # Check if Advanced Threat Protection is enabled
                # Note: This requires checking server security alert policies
                security_alert_policy = sql_client.server_security_alert_policies.get(
                    resource_group, server.name, "Default"
                )
                if security_alert_policy.state != "Enabled":
                    servers_without_atp.append(server.name)
            except Exception:
                servers_without_atp.append(server.name)

        return create_check_result(
            "Article 32",
            "SQL Advanced Threat Protection",
            "Ability to detect threats to databases containing personal data",
            "PASS" if not servers_without_atp else "WARNING",
            "MEDIUM",
            {
                "total_sql_servers": len(sql_servers),
                "servers_without_atp": servers_without_atp
            },
            None if not servers_without_atp else f"Enable Advanced Threat Protection for {len(servers_without_atp)} SQL server(s). Go to SQL Server > Security > Microsoft Defender for SQL"
        )
    except Exception as e:
        return create_check_result(
            "Article 32",
            "SQL Advanced Threat Protection",
            "Ability to detect threats to databases containing personal data",
            "WARNING",
            "MEDIUM",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.Sql/servers/securityAlertPolicies/read"
        )

def check_key_vault_for_secrets(subscription_id, credential):
    """Article 32 - Secure key management"""
    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient
        keyvault_client = KeyVaultManagementClient(credential, subscription_id)
        vaults = list(keyvault_client.vaults.list())

        return create_check_result(
            "Article 32",
            "Key Vault Usage",
            "Ensures secure key and secret management for data protection",
            "PASS" if vaults else "WARNING",
            "MEDIUM",
            {
                "key_vaults_count": len(vaults),
                "key_vaults": [v.name for v in vaults]
            },
            None if vaults else "Consider using Azure Key Vault to securely manage keys, secrets, and certificates for protecting personal data"
        )
    except Exception as e:
        return create_check_result(
            "Article 32",
            "Key Vault Usage",
            "Ensures secure key and secret management for data protection",
            "WARNING",
            "MEDIUM",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.KeyVault/vaults/read"
        )

# ===================== ARTICLE 33/34 - BREACH MANAGEMENT =====================

def check_security_alerts_configuration(subscription_id, credential):
    """Article 33/34 - Breach detection and notification capability"""
    try:
        security_client = SecurityCenter(credential, subscription_id, asc_location="centralus")

        # Try to get security contacts
        try:
            # List security contacts (requires specific API)
            contacts = list(security_client.security_contacts.list())
            has_contacts = len(contacts) > 0
        except Exception:
            has_contacts = False

        return create_check_result(
            "Article 33 / 34",
            "Breach Detection and Notification",
            "Ability to detect breaches and notify within 72 hours as required by GDPR",
            "PASS" if has_contacts else "WARNING",
            "HIGH",
            {
                "security_contacts_configured": has_contacts,
                "contact_count": len(contacts) if has_contacts else 0
            },
            None if has_contacts else "Configure security contacts in Microsoft Defender for Cloud to receive breach notifications. Go to Defender for Cloud > Environment settings > Email notifications"
        )
    except Exception as e:
        return create_check_result(
            "Article 33 / 34",
            "Breach Detection and Notification",
            "Ability to detect breaches and notify within 72 hours as required by GDPR",
            "WARNING",
            "HIGH",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.Security/securityContacts/read"
        )

def check_alert_rules(subscription_id, credential):
    """Article 33/34 - Alert rules for incident detection"""
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)

        # Get activity log alerts
        alert_rules = list(monitor_client.activity_log_alerts.list_by_subscription_id())

        return create_check_result(
            "Article 33 / 34",
            "Activity Log Alert Rules",
            "Ensures alert rules are configured for detecting security events",
            "PASS" if alert_rules else "WARNING",
            "MEDIUM",
            {
                "alert_rules_count": len(alert_rules),
                "alert_rules": [ar.name for ar in alert_rules]
            },
            None if alert_rules else "Configure Activity Log alert rules to detect security events. Go to Azure Monitor > Alerts > Alert rules"
        )
    except Exception as e:
        return create_check_result(
            "Article 33 / 34",
            "Activity Log Alert Rules",
            "Ensures alert rules are configured for detecting security events",
            "WARNING",
            "MEDIUM",
            {"error": str(e)},
            "Grant necessary permissions: Microsoft.Insights/ActivityLogAlerts/read"
        )

# ===================== EXECUTIVE SUMMARY =====================

def generate_executive_summary(result):
    """Generate a markdown-formatted executive summary of the GDPR audit results"""
    summary = result["metadata"]["summary"]
    subscription_id = result["metadata"].get("subscription_id", "Unknown")

    total_checks = summary["total_checks"]
    passed = summary["passed"]
    failed = summary["failed"]
    warnings = summary["warnings"]
    permission_errors = summary.get("permission_errors", 0)
    checks_completed = summary.get("checks_completed", total_checks)

    # Calculate compliance score based on completed checks only
    compliance_score = int((passed / checks_completed * 100)) if checks_completed > 0 else 0

    # Build markdown summary
    md_lines = []

    # Title
    md_lines.append("# GDPR Compliance Executive Summary")
    md_lines.append("")

    # Overall compliance status
    md_lines.append("## Overall Compliance Status")
    md_lines.append("")
    if compliance_score >= 90:
        md_lines.append(f"**Azure Subscription {subscription_id}** demonstrates **strong GDPR compliance** with a **{compliance_score}%** pass rate across **{total_checks}** checks.")
    elif compliance_score >= 70:
        md_lines.append(f"**Azure Subscription {subscription_id}** shows **moderate GDPR compliance** with a **{compliance_score}%** pass rate across **{total_checks}** checks, requiring targeted improvements.")
    else:
        md_lines.append(f"**Azure Subscription {subscription_id}** requires **significant improvements** with a **{compliance_score}%** pass rate across **{total_checks}** checks.")
    md_lines.append("")

    # Key Findings
    md_lines.append("## Key Findings")
    md_lines.append("")

    # Collect all checks
    all_checks = []
    for section in result.values():
        if isinstance(section, dict) and "checks" in section:
            all_checks.extend(section["checks"])

    critical_failures = [c for c in all_checks if c["status"] == "FAIL" and c["severity"] == "CRITICAL"]
    high_failures = [c for c in all_checks if c["status"] == "FAIL" and c["severity"] == "HIGH"]

    if critical_failures or high_failures:
        severity_text = []
        if critical_failures:
            severity_text.append(f"**{len(critical_failures)} critical**")
        if high_failures:
            severity_text.append(f"**{len(high_failures)} high-severity**")
        md_lines.append(f"The audit identified **{failed} failed check(s)** including {' and '.join(severity_text)} issue(s) that require **immediate attention**.")
    elif failed > 0:
        md_lines.append(f"The audit identified **{failed} failed check(s)** with lower severity levels.")
    else:
        md_lines.append("The audit found **no failed checks**, indicating excellent GDPR compliance.")
    md_lines.append("")

    # GDPR Articles Status
    md_lines.append("## GDPR Articles Status")
    md_lines.append("")

    article_sections = {
        "Article 5 - Integrity & Confidentiality": result.get("article_5_integrity_confidentiality", {}).get("checks", []),
        "Article 25 - Privacy by Design": result.get("article_25_privacy_by_design", {}).get("checks", []),
        "Article 30 - Records of Processing": result.get("article_30_records_of_processing", {}).get("checks", []),
        "Article 32 - Security of Processing": result.get("article_32_security_of_processing", {}).get("checks", []),
        "Article 33/34 - Breach Management": result.get("article_33_34_breach_management", {}).get("checks", [])
    }

    for article_name, checks in article_sections.items():
        if checks:
            failed_count = sum(1 for c in checks if c["status"] == "FAIL")
            if failed_count > 0:
                md_lines.append(f"- **{article_name}**: {failed_count} check(s) failed")

    if not any(sum(1 for c in checks if c["status"] == "FAIL") > 0 for checks in article_sections.values()):
        md_lines.append("All GDPR articles have passing checks.")

    md_lines.append("")

    # Priority Areas
    md_lines.append("## Priority Remediation Areas")
    md_lines.append("")

    if critical_failures or high_failures:
        priority_checks = critical_failures[:3] + high_failures[:3]
        md_lines.append("**Critical and high-severity findings:**")
        md_lines.append("")
        for check in priority_checks[:5]:
            md_lines.append(f"- **{check['check_name']}** ({check['gdpr_article']})")
    else:
        md_lines.append("No critical or high-severity issues identified.")

    md_lines.append("")

    # Additional Observations
    md_lines.append("## Additional Observations")
    md_lines.append("")

    # Add permission error note if any
    if permission_errors > 0:
        md_lines.append(f"**Note:** {permission_errors} check(s) could not be completed due to insufficient Azure RBAC permissions. Grant necessary permissions for a complete audit.")
        md_lines.append("")

    if warnings > 0:
        warnings_without_permission = warnings - permission_errors
        if warnings_without_permission > 0:
            md_lines.append(f"Additionally, **{warnings_without_permission} warning(s)** were identified that should be reviewed.")
    else:
        if permission_errors == 0:
            md_lines.append("No warnings were identified.")
    md_lines.append("")

    # Recommendation
    md_lines.append("## Recommendation")
    md_lines.append("")
    if compliance_score >= 90:
        md_lines.append("**Action:** Address minor findings and maintain GDPR compliance through regular audits.")
    elif compliance_score >= 70:
        md_lines.append("**Action:** Focus on critical and high-severity findings before processing EU personal data.")
    else:
        md_lines.append("**Action:** Implement comprehensive security improvements before processing EU personal data.")

    return "\n".join(md_lines)

# ===================== RUN AUDIT =====================

def run_gdpr_audit(subscription_id: str, credential):
    """Run GDPR audit for a given subscription ID."""
    try:
        RESULT["metadata"]["subscription_id"] = subscription_id

        # Initialize cache for shared resources
        cache = AzureResourceCache(subscription_id, credential)

        # Define all checks with their categories
        check_tasks = [
            # Article 5 - Integrity & Confidentiality
            ("article_5_integrity_confidentiality", lambda: check_activity_log_enabled(subscription_id, credential)),
            ("article_5_integrity_confidentiality", lambda: check_storage_public_access(subscription_id, credential, cache)),
            ("article_5_integrity_confidentiality", lambda: check_diagnostic_logging(subscription_id, credential)),

            # Article 25 - Privacy by Design
            ("article_25_privacy_by_design", lambda: check_storage_encryption(subscription_id, credential, cache)),
            ("article_25_privacy_by_design", lambda: check_sql_tde_encryption(subscription_id, credential, cache)),
            ("article_25_privacy_by_design", lambda: check_network_security_defaults(subscription_id, credential)),

            # Article 30 - Records of Processing
            ("article_30_records_of_processing", lambda: check_regions_of_processing(subscription_id, credential, cache)),
            ("article_30_records_of_processing", lambda: check_resource_tagging(subscription_id, credential)),

            # Article 32 - Security of Processing
            ("article_32_security_of_processing", lambda: check_defender_for_cloud(subscription_id, credential)),
            ("article_32_security_of_processing", lambda: check_sql_advanced_threat_protection(subscription_id, credential, cache)),
            ("article_32_security_of_processing", lambda: check_key_vault_for_secrets(subscription_id, credential)),

            # Article 33/34 - Breach Management
            ("article_33_34_breach_management", lambda: check_security_alerts_configuration(subscription_id, credential)),
            ("article_33_34_breach_management", lambda: check_alert_rules(subscription_id, credential))
        ]

        # Run checks in parallel with ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all tasks
            future_to_check = {executor.submit(check_func): (category, check_func) for category, check_func in check_tasks}

            # Collect results as they complete
            for future in as_completed(future_to_check):
                category, check_func = future_to_check[future]
                try:
                    result = future.result()
                    RESULT[category]["checks"].append(result)
                except Exception as e:
                    # Handle different types of errors
                    error_type = type(e).__name__
                    error_message = str(e)

                    # Check if it's a permission/access error
                    is_permission_error = (
                        "AuthorizationFailed" in error_message or
                        "Forbidden" in error_message or
                        "Authorization" in error_message or
                        error_type in ["ClientAuthenticationError", "HttpResponseError"]
                    )

                    # Extract check name
                    check_name = "Unknown Check"
                    try:
                        check_name = check_func.__name__ if hasattr(check_func, '__name__') else str(check_func)
                    except Exception:
                        pass

                    if is_permission_error:
                        error_result = create_check_result(
                            "PERM-ERROR",
                            f"Permission Error: {check_name}",
                            "Unable to perform this check due to insufficient permissions",
                            "WARNING",
                            "LOW",
                            {
                                "error_type": error_type,
                                "error_message": error_message,
                                "category": category,
                                "reason": "Azure RBAC permissions may be missing for this service/action"
                            },
                            "Grant necessary Azure RBAC permissions to perform this GDPR check."
                        )
                    else:
                        error_result = create_check_result(
                            "CHECK-ERROR",
                            f"Check Failed: {check_name}",
                            f"Check encountered an unexpected error: {error_message}",
                            "WARNING",
                            "LOW",
                            {
                                "error_type": error_type,
                                "error_message": error_message,
                                "category": category
                            },
                            "Review error details and ensure Azure resources are accessible."
                        )

                    RESULT[category]["checks"].append(error_result)

        # Add summary statistics
        all_checks = []
        for section in RESULT.values():
            if isinstance(section, dict) and "checks" in section:
                all_checks.extend(section["checks"])

        # Count permission errors separately
        permission_errors = sum(1 for c in all_checks if c["status"] == "WARNING" and "Permission Error" in c.get("check_name", ""))

        RESULT["metadata"]["summary"] = {
            "total_checks": len(all_checks),
            "passed": sum(1 for c in all_checks if c["status"] == "PASS"),
            "failed": sum(1 for c in all_checks if c["status"] == "FAIL"),
            "warnings": sum(1 for c in all_checks if c["status"] == "WARNING"),
            "critical_failures": sum(1 for c in all_checks if c["status"] == "FAIL" and c["severity"] == "CRITICAL"),
            "high_failures": sum(1 for c in all_checks if c["status"] == "FAIL" and c["severity"] == "HIGH"),
            "permission_errors": permission_errors,
            "checks_completed": len(all_checks) - permission_errors
        }

        # Generate executive summary
        RESULT["metadata"]["executive_summary"] = generate_executive_summary(RESULT)

        return RESULT

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

def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Azure GDPR Compliance Audit Script - Generate GDPR compliance reports.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate GDPR audit report for default subscription
  python3 azure_gdpr.py

  # Generate GDPR audit report for a specific subscription by name
  python3 azure_gdpr.py --subscription-name "Tessell QA BYOA"

  # Generate GDPR audit report for a specific subscription by ID
  python3 azure_gdpr.py --subscription-id "12345678-1234-1234-1234-123456789abc"
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
        help="Azure subscription ID to audit (uses default subscription if not specified)",
        default=None
    )
    parser.add_argument("--verbose", action="store_true", help="Print progress messages to stderr")

    args = parser.parse_args()

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
            print(f"Running GDPR audit for subscription: {subscription_id}", file=sys.stderr)
        raw_report = run_gdpr_audit(subscription_id=subscription_id, credential=credential)

        # Return flat format with categories containing checks directly
        report = {
            "metadata": raw_report["metadata"],
            "article_5_integrity_confidentiality": raw_report["article_5_integrity_confidentiality"],
            "article_25_privacy_by_design": raw_report["article_25_privacy_by_design"],
            "article_30_records_of_processing": raw_report["article_30_records_of_processing"],
            "article_32_security_of_processing": raw_report["article_32_security_of_processing"],
            "article_33_34_breach_management": raw_report["article_33_34_breach_management"]
        }

        return report
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    result = main()
    print(json.dumps(result, indent=2))

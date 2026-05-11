from azure.identity import DefaultAzureCredential, AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.storage.blob import BlobServiceClient
import argparse
from datetime import datetime, timezone, timedelta
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import subprocess
from typing import Optional, List, Dict

def _make_result():
    """Create a fresh result structure for each audit run — avoids stale state across multiple calls."""
    return {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "security": {
            "category_description": "Security controls ensure system protection from unauthorized access",
            "checks": []
        },
        "availability": {
            "category_description": "Availability controls ensure system uptime and reliability",
            "checks": []
        },
        "confidentiality": {
            "category_description": "Confidentiality controls ensure data is protected from unauthorized disclosure",
            "checks": []
        },
        "processing_integrity": {
            "category_description": "Processing integrity controls ensure system processing is complete, valid, accurate, and authorized",
            "checks": []
        },
        "privacy": {
            "category_description": "Privacy controls ensure personal information is collected, used, retained, and disclosed appropriately",
            "checks": []
        }
    }

def create_check_result(name, description, status, severity, details, recommendation=None):
    """Create a standardized check result with descriptive information"""
    result = {
        "check_name": name,
        "description": description,
        "status": status,  # PASS, FAIL, WARNING
        "severity": severity,  # CRITICAL, HIGH, MEDIUM, LOW
        "details": details
    }
    if recommendation:
        result["recommendation"] = recommendation
    return result

# ---------- CACHING HELPERS ----------

class AzureResourceCache:
    """
    Pre-fetched shared Azure resources — all data is loaded eagerly in the main thread
    before the ThreadPoolExecutor starts, so worker threads only read (never write).
    This eliminates lazy-init race conditions entirely.
    """
    def __init__(self, subscription_id, credential):
        self.subscription_id = subscription_id
        self.credential = credential
        self.vms = self._fetch_vms()
        self.disks = self._fetch_disks()
        self.storage_accounts = self._fetch_storage_accounts()
        self.sql_servers = self._fetch_sql_servers()
        self.network_security_groups = self._fetch_nsgs()
        self.resource_groups = self._fetch_resource_groups()
        self.public_ips = self._fetch_public_ips()

    def _fetch_vms(self):
        try:
            return list(ComputeManagementClient(self.credential, self.subscription_id).virtual_machines.list_all())
        except Exception:
            return []

    def _fetch_disks(self):
        try:
            return list(ComputeManagementClient(self.credential, self.subscription_id).disks.list())
        except Exception:
            return []

    def _fetch_storage_accounts(self):
        try:
            return list(StorageManagementClient(self.credential, self.subscription_id).storage_accounts.list())
        except Exception:
            return []

    def _fetch_sql_servers(self):
        try:
            return list(SqlManagementClient(self.credential, self.subscription_id).servers.list())
        except Exception:
            return []

    def _fetch_nsgs(self):
        try:
            return list(NetworkManagementClient(self.credential, self.subscription_id).network_security_groups.list_all())
        except Exception:
            return []

    def _fetch_resource_groups(self):
        try:
            return list(ResourceManagementClient(self.credential, self.subscription_id).resource_groups.list())
        except Exception:
            return []

    def _fetch_public_ips(self):
        try:
            return list(NetworkManagementClient(self.credential, self.subscription_id).public_ip_addresses.list_all())
        except Exception:
            return []

    # Accessor methods for backward compatibility — return pre-fetched data
    def get_vms(self): return self.vms
    def get_disks(self): return self.disks
    def get_storage_accounts(self): return self.storage_accounts
    def get_sql_servers(self): return self.sql_servers
    def get_network_security_groups(self): return self.network_security_groups
    def get_resource_groups(self): return self.resource_groups
    def get_public_ips(self): return self.public_ips

# ---------- SECURITY CONTROLS ----------

def check_mfa_enabled(subscription_id, credential):
    """Check if MFA is enforced via Conditional Access policies"""
    try:
        # Note: Checking MFA requires Microsoft Graph API access
        # This is a simplified check - in production, you'd use Graph API
        return create_check_result(
            name="Multi-Factor Authentication",
            description="Verifies that Multi-Factor Authentication (MFA) is enforced for users",
            status="WARNING",
            severity="HIGH",
            details={
                "explanation": "MFA status requires Microsoft Graph API access to query Conditional Access policies",
                "recommendation_note": "Use Azure Portal to verify MFA is enabled via Conditional Access policies"
            },
            recommendation="Enable MFA for all users via Azure AD Conditional Access policies. Go to Azure AD > Security > Conditional Access > New Policy"
        )
    except Exception as e:
        return create_check_result(
            name="Multi-Factor Authentication",
            description="Verifies that Multi-Factor Authentication (MFA) is enforced for users",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check MFA status due to permission error or API failure"
            },
            recommendation="Grant necessary permissions to query Azure AD and Conditional Access policies"
        )

def check_disk_encryption(subscription_id, credential, cache=None):
    """Check if VM disks have encryption enabled"""
    try:
        disks = cache.get_disks() if cache else list(ComputeManagementClient(credential, subscription_id).disks.list())

        if not disks:
            return create_check_result(
                name="Disk Encryption",
                description="Verifies that all managed disks have encryption enabled",
                status="WARNING",
                severity="LOW",
                details={
                    "total_disks": 0,
                    "explanation": "No managed disks found or unable to access disk list"
                },
                recommendation="Ensure necessary permissions to view Azure compute resources"
            )

        unencrypted_disks = []
        for disk in disks:
            # Check if encryption is enabled (Azure Disk Encryption or encryption at rest)
            encryption_enabled = (
                hasattr(disk, 'encryption_settings_collection') and
                disk.encryption_settings_collection and
                disk.encryption_settings_collection.enabled
            ) or (
                hasattr(disk, 'encryption') and
                disk.encryption and
                disk.encryption.type != 'EncryptionAtRestWithPlatformKey'
            )

            if not encryption_enabled:
                unencrypted_disks.append({
                    "disk_name": disk.name,
                    "disk_id": disk.id,
                    "size_gb": disk.disk_size_gb
                })

        return create_check_result(
            name="Disk Encryption",
            description="Verifies that all managed disks have encryption enabled",
            status="PASS" if len(unencrypted_disks) == 0 else "FAIL",
            severity="HIGH",
            details={
                "total_disks": len(disks),
                "unencrypted_disks_count": len(unencrypted_disks),
                "unencrypted_disks": unencrypted_disks[:10],
                "explanation": f"Found {len(unencrypted_disks)} unencrypted disk(s)" if unencrypted_disks else "All disks have encryption enabled"
            },
            recommendation=None if len(unencrypted_disks) == 0 else f"Enable Azure Disk Encryption for {len(unencrypted_disks)} disk(s). Use Azure Portal > Disks > Select disk > Encryption > Enable"
        )
    except Exception as e:
        return create_check_result(
            name="Disk Encryption",
            description="Verifies that all managed disks have encryption enabled",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check disk encryption status due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Compute/disks/read"
        )

def check_nsg_rules(subscription_id, credential, cache=None):
    """Check for overly permissive Network Security Group rules"""
    try:
        network_client = NetworkManagementClient(credential, subscription_id)
        nsgs = cache.get_network_security_groups() if cache else list(network_client.network_security_groups.list_all())

        if not nsgs:
            return create_check_result(
                name="Network Security Group Rules",
                description="Identifies Network Security Groups with unrestricted access on sensitive ports",
                status="WARNING",
                severity="LOW",
                details={
                    "total_nsgs": 0,
                    "explanation": "No NSGs found or unable to access NSG list"
                },
                recommendation="Ensure necessary permissions to view network security groups"
            )

        risky_rules = []
        sensitive_ports = [22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 5601]

        for nsg in nsgs:
            if hasattr(nsg, 'security_rules'):
                for rule in nsg.security_rules:
                    if rule.direction == "Inbound" and rule.access == "Allow":
                        # Check if source is open to internet
                        source_open = (
                            rule.source_address_prefix in ["*", "Internet", "0.0.0.0/0"] or
                            (hasattr(rule, 'source_address_prefixes') and
                             rule.source_address_prefixes and
                             any(prefix in ["*", "Internet", "0.0.0.0/0"] for prefix in rule.source_address_prefixes))
                        )

                        if source_open:
                            # Check if it's a sensitive port
                            port_range = rule.destination_port_range if hasattr(rule, 'destination_port_range') else "*"

                            is_sensitive = (
                                port_range == "*" or
                                any(str(port) in str(port_range) for port in sensitive_ports)
                            )

                            if is_sensitive:
                                risky_rules.append({
                                    "nsg_name": nsg.name,
                                    "rule_name": rule.name,
                                    "port": port_range,
                                    "protocol": rule.protocol,
                                    "source": rule.source_address_prefix
                                })

        return create_check_result(
            name="Network Security Group Rules",
            description="Identifies Network Security Groups with unrestricted access on sensitive ports",
            status="PASS" if len(risky_rules) == 0 else "FAIL",
            severity="HIGH",
            details={
                "total_nsgs": len(nsgs),
                "risky_rules_count": len(risky_rules),
                "risky_rules": risky_rules[:20],
                "sensitive_ports_checked": sensitive_ports,
                "explanation": f"Found {len(risky_rules)} overly permissive NSG rule(s)" if risky_rules else "No NSGs with unrestricted access on sensitive ports"
            },
            recommendation=None if len(risky_rules) == 0 else f"Restrict {len(risky_rules)} NSG rule(s). Remove wildcard access and limit to specific IP ranges. Use Azure Bastion instead of exposing SSH/RDP to the internet."
        )
    except Exception as e:
        return create_check_result(
            name="Network Security Group Rules",
            description="Identifies Network Security Groups with unrestricted access on sensitive ports",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check NSG rules due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Network/networkSecurityGroups/read"
        )

def check_security_center_enabled(subscription_id, credential):
    """Check if Azure Security Center (Defender for Cloud) is enabled"""
    try:
        security_client = SecurityCenter(credential, subscription_id, asc_location="centralus")

        # Try to get security center settings
        pricings = list(security_client.pricings.list())

        enabled_services = []
        disabled_services = []

        for pricing in pricings:
            if pricing.pricing_tier == "Standard":
                enabled_services.append(pricing.name)
            else:
                disabled_services.append(pricing.name)

        return create_check_result(
            name="Azure Security Center",
            description="Verifies that Azure Security Center (Defender for Cloud) is enabled for security monitoring",
            status="PASS" if len(enabled_services) > 0 else "FAIL",
            severity="HIGH",
            details={
                "enabled_services_count": len(enabled_services),
                "enabled_services": enabled_services,
                "disabled_services_count": len(disabled_services),
                "disabled_services": disabled_services,
                "explanation": f"{len(enabled_services)} Defender plan(s) enabled" if enabled_services else "Azure Security Center is not enabled with Standard tier"
            },
            recommendation=None if len(enabled_services) > 0 else "Enable Azure Security Center Standard tier for comprehensive security monitoring. Go to Azure Security Center > Pricing & settings"
        )
    except Exception as e:
        return create_check_result(
            name="Azure Security Center",
            description="Verifies that Azure Security Center (Defender for Cloud) is enabled for security monitoring",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check Security Center status due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Security/pricings/read"
        )

def check_activity_log_retention(subscription_id, credential):
    """Check if Activity Log has adequate retention"""
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)

        # Get log profiles
        log_profiles = list(monitor_client.log_profiles.list())

        if not log_profiles:
            return create_check_result(
                name="Activity Log Retention",
                description="Verifies that Azure Activity Log has adequate retention configured",
                status="FAIL",
                severity="HIGH",
                details={
                    "log_profiles_count": 0,
                    "explanation": "No Activity Log export profiles configured - activity logs are only retained for 90 days by default"
                },
                recommendation="Configure Activity Log export to Storage Account or Log Analytics workspace for long-term retention. Go to Azure Monitor > Activity Log > Export Activity Logs"
            )

        insufficient_retention = []
        adequate_retention = []

        for profile in log_profiles:
            retention_days = profile.retention_policy.days if hasattr(profile, 'retention_policy') and profile.retention_policy else 0

            if retention_days < 365:
                insufficient_retention.append({
                    "profile_name": profile.name,
                    "retention_days": retention_days
                })
            else:
                adequate_retention.append(profile.name)

        return create_check_result(
            name="Activity Log Retention",
            description="Verifies that Azure Activity Log has adequate retention configured (365+ days)",
            status="PASS" if len(insufficient_retention) == 0 else "WARNING",
            severity="MEDIUM",
            details={
                "total_profiles": len(log_profiles),
                "adequate_retention_count": len(adequate_retention),
                "insufficient_retention_count": len(insufficient_retention),
                "insufficient_retention_profiles": insufficient_retention,
                "explanation": f"{len(insufficient_retention)} profile(s) with retention less than 365 days" if insufficient_retention else "All log profiles meet 365-day retention requirement"
            },
            recommendation=None if len(insufficient_retention) == 0 else f"Increase retention to at least 365 days for {len(insufficient_retention)} profile(s). Update Activity Log export settings."
        )
    except Exception as e:
        return create_check_result(
            name="Activity Log Retention",
            description="Verifies that Azure Activity Log has adequate retention configured",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check Activity Log retention due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Insights/logProfiles/read"
        )

def check_vm_backup_enabled(subscription_id, credential, cache=None):
    """Check if VMs have backup enabled"""
    try:
        vms = cache.get_vms() if cache else list(ComputeManagementClient(credential, subscription_id).virtual_machines.list_all())

        if not vms:
            return create_check_result(
                name="VM Backup Configuration",
                description="Verifies that Virtual Machines have Azure Backup enabled",
                status="WARNING",
                severity="LOW",
                details={
                    "total_vms": 0,
                    "explanation": "No VMs found or unable to access VM list"
                },
                recommendation="Ensure necessary permissions to view virtual machines"
            )

        # Note: Checking backup status requires Azure Backup vault API access
        # This is a simplified check
        return create_check_result(
            name="VM Backup Configuration",
            description="Verifies that Virtual Machines have Azure Backup enabled",
            status="WARNING",
            severity="MEDIUM",
            details={
                "total_vms": len(vms),
                "explanation": "VM backup status requires Azure Backup vault API access to verify backup configuration",
                "recommendation_note": "Use Azure Portal to verify VMs are backed up via Azure Backup"
            },
            recommendation=f"Verify that all {len(vms)} VM(s) have Azure Backup enabled. Go to Azure Backup > Backup Items > Azure Virtual Machine"
        )
    except Exception as e:
        return create_check_result(
            name="VM Backup Configuration",
            description="Verifies that Virtual Machines have Azure Backup enabled",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check VM backup status due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Compute/virtualMachines/read"
        )

# ---------- CONFIDENTIALITY ----------

def check_storage_encryption(subscription_id, credential, cache=None):
    """Check if Storage Accounts have encryption enabled"""
    try:
        storage_accounts = cache.get_storage_accounts() if cache else list(StorageManagementClient(credential, subscription_id).storage_accounts.list())

        if not storage_accounts:
            return create_check_result(
                name="Storage Account Encryption",
                description="Verifies that all Storage Accounts have encryption at rest enabled",
                status="WARNING",
                severity="LOW",
                details={
                    "total_storage_accounts": 0,
                    "explanation": "No Storage Accounts found or unable to access Storage Account list"
                },
                recommendation="Ensure necessary permissions to view Storage Accounts"
            )

        unencrypted = []

        for account in storage_accounts:
            # Azure Storage Accounts have encryption enabled by default
            # Check if customer-managed keys are used or if encryption is properly configured
            encryption_enabled = (
                hasattr(account, 'encryption') and
                account.encryption and
                hasattr(account.encryption, 'services') and
                account.encryption.services
            )

            if not encryption_enabled:
                unencrypted.append(account.name)

        return create_check_result(
            name="Storage Account Encryption",
            description="Verifies that all Storage Accounts have encryption at rest enabled",
            status="PASS" if len(unencrypted) == 0 else "FAIL",
            severity="HIGH",
            details={
                "total_storage_accounts": len(storage_accounts),
                "encrypted_accounts": len(storage_accounts) - len(unencrypted),
                "unencrypted_accounts_count": len(unencrypted),
                "unencrypted_accounts": unencrypted,
                "explanation": f"{len(unencrypted)} of {len(storage_accounts)} Storage Account(s) lack encryption" if unencrypted else "All Storage Accounts have encryption enabled"
            },
            recommendation=None if len(unencrypted) == 0 else f"Enable encryption for {len(unencrypted)} Storage Account(s). Encryption is enabled by default - verify configuration."
        )
    except Exception as e:
        return create_check_result(
            name="Storage Account Encryption",
            description="Verifies that all Storage Accounts have encryption at rest enabled",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check Storage Account encryption due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Storage/storageAccounts/read"
        )

def check_storage_public_access(subscription_id, credential, cache=None):
    """Check if Storage Accounts have public access disabled"""
    try:
        storage_accounts = cache.get_storage_accounts() if cache else list(StorageManagementClient(credential, subscription_id).storage_accounts.list())

        if not storage_accounts:
            return create_check_result(
                name="Storage Account Public Access",
                description="Identifies Storage Accounts that allow public blob access",
                status="WARNING",
                severity="LOW",
                details={
                    "total_storage_accounts": 0,
                    "explanation": "No Storage Accounts found or unable to access Storage Account list"
                },
                recommendation="Ensure necessary permissions to view Storage Accounts"
            )

        public_access_accounts = []

        for account in storage_accounts:
            # Check if public network access is allowed
            allow_blob_public_access = (
                hasattr(account, 'allow_blob_public_access') and
                account.allow_blob_public_access
            )

            if allow_blob_public_access:
                public_access_accounts.append(account.name)

        return create_check_result(
            name="Storage Account Public Access",
            description="Identifies Storage Accounts that allow public blob access",
            status="PASS" if len(public_access_accounts) == 0 else "FAIL",
            severity="CRITICAL",
            details={
                "total_storage_accounts": len(storage_accounts),
                "public_access_accounts_count": len(public_access_accounts),
                "public_access_accounts": public_access_accounts,
                "explanation": f"{len(public_access_accounts)} of {len(storage_accounts)} Storage Account(s) allow public blob access" if public_access_accounts else "All Storage Accounts have public blob access disabled"
            },
            recommendation=None if len(public_access_accounts) == 0 else f"Disable public blob access for {len(public_access_accounts)} Storage Account(s). Go to Storage Account > Configuration > Allow Blob public access > Disabled"
        )
    except Exception as e:
        return create_check_result(
            name="Storage Account Public Access",
            description="Identifies Storage Accounts that allow public blob access",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check Storage Account public access due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Storage/storageAccounts/read"
        )

def check_sql_encryption(subscription_id, credential, cache=None):
    """Check if SQL databases have Transparent Data Encryption (TDE) enabled"""
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        sql_servers = cache.get_sql_servers() if cache else list(sql_client.servers.list())

        if not sql_servers:
            return create_check_result(
                name="SQL Database Encryption",
                description="Verifies that all SQL databases have Transparent Data Encryption (TDE) enabled",
                status="WARNING",
                severity="LOW",
                details={
                    "total_sql_servers": 0,
                    "explanation": "No SQL servers found or unable to access SQL server list"
                },
                recommendation="Ensure necessary permissions to view SQL servers"
            )

        unencrypted_databases = []

        for server in sql_servers:
            resource_group = server.id.split("/")[4]
            try:
                databases = list(sql_client.databases.list_by_server(resource_group, server.name))

                for db in databases:
                    if db.name != "master":  # Skip master database
                        try:
                            # Check TDE status
                            tde = sql_client.transparent_data_encryptions.get(
                                resource_group,
                                server.name,
                                db.name,
                                "current"
                            )

                            if tde.state != "Enabled":
                                unencrypted_databases.append({
                                    "server": server.name,
                                    "database": db.name,
                                    "resource_group": resource_group
                                })
                        except Exception:
                            # If we can't check TDE, assume it might be unencrypted
                            unencrypted_databases.append({
                                "server": server.name,
                                "database": db.name,
                                "resource_group": resource_group,
                                "note": "Unable to verify TDE status"
                            })
            except Exception:
                continue

        return create_check_result(
            name="SQL Database Encryption",
            description="Verifies that all SQL databases have Transparent Data Encryption (TDE) enabled",
            status="PASS" if len(unencrypted_databases) == 0 else "FAIL",
            severity="CRITICAL",
            details={
                "total_sql_servers": len(sql_servers),
                "unencrypted_databases_count": len(unencrypted_databases),
                "unencrypted_databases": unencrypted_databases[:10],
                "explanation": f"Found {len(unencrypted_databases)} database(s) without TDE enabled" if unencrypted_databases else "All SQL databases have TDE enabled"
            },
            recommendation=None if len(unencrypted_databases) == 0 else f"Enable Transparent Data Encryption for {len(unencrypted_databases)} database(s). Go to SQL Database > Security > Transparent data encryption > Enable"
        )
    except Exception as e:
        return create_check_result(
            name="SQL Database Encryption",
            description="Verifies that all SQL databases have Transparent Data Encryption (TDE) enabled",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check SQL database encryption due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Sql/servers/read, Microsoft.Sql/servers/databases/read"
        )

def check_sql_firewall(subscription_id, credential, cache=None):
    """Check if SQL servers have overly permissive firewall rules"""
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        sql_servers = cache.get_sql_servers() if cache else list(sql_client.servers.list())

        if not sql_servers:
            return create_check_result(
                name="SQL Server Firewall Rules",
                description="Identifies SQL servers with overly permissive firewall rules",
                status="WARNING",
                severity="LOW",
                details={
                    "total_sql_servers": 0,
                    "explanation": "No SQL servers found or unable to access SQL server list"
                },
                recommendation="Ensure necessary permissions to view SQL servers"
            )

        risky_servers = []

        for server in sql_servers:
            resource_group = server.id.split("/")[4]
            try:
                firewall_rules = list(sql_client.firewall_rules.list_by_server(resource_group, server.name))

                for rule in firewall_rules:
                    # Check for 0.0.0.0 to 255.255.255.255 (allow all)
                    if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "255.255.255.255":
                        risky_servers.append({
                            "server": server.name,
                            "rule_name": rule.name,
                            "start_ip": rule.start_ip_address,
                            "end_ip": rule.end_ip_address
                        })
            except Exception:
                continue

        return create_check_result(
            name="SQL Server Firewall Rules",
            description="Identifies SQL servers with overly permissive firewall rules",
            status="PASS" if len(risky_servers) == 0 else "FAIL",
            severity="HIGH",
            details={
                "total_sql_servers": len(sql_servers),
                "risky_servers_count": len(risky_servers),
                "risky_servers": risky_servers,
                "explanation": f"Found {len(risky_servers)} SQL server(s) with firewall rules allowing all IPs" if risky_servers else "No SQL servers with overly permissive firewall rules"
            },
            recommendation=None if len(risky_servers) == 0 else f"Restrict firewall rules for {len(risky_servers)} SQL server(s). Remove 'Allow All' rules and limit to specific IP ranges."
        )
    except Exception as e:
        return create_check_result(
            name="SQL Server Firewall Rules",
            description="Identifies SQL servers with overly permissive firewall rules",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check SQL firewall rules due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Sql/servers/firewallRules/read"
        )

# ---------- AVAILABILITY ----------

def check_vm_availability_sets(subscription_id, credential, cache=None):
    """Check if VMs are configured for high availability"""
    try:
        vms = cache.get_vms() if cache else list(ComputeManagementClient(credential, subscription_id).virtual_machines.list_all())

        if not vms:
            return create_check_result(
                name="VM High Availability Configuration",
                description="Checks if VMs are configured in availability sets or zones for high availability",
                status="WARNING",
                severity="LOW",
                details={
                    "total_vms": 0,
                    "explanation": "No VMs found or unable to access VM list"
                },
                recommendation="Ensure necessary permissions to view virtual machines"
            )

        vms_without_ha = []

        for vm in vms:
            # Check if VM is in availability set or availability zone
            has_availability_set = hasattr(vm, 'availability_set') and vm.availability_set
            has_availability_zone = hasattr(vm, 'zones') and vm.zones

            if not has_availability_set and not has_availability_zone:
                vms_without_ha.append({
                    "vm_name": vm.name,
                    "vm_id": vm.id,
                    "location": vm.location
                })

        return create_check_result(
            name="VM High Availability Configuration",
            description="Checks if VMs are configured in availability sets or zones for high availability",
            status="PASS" if len(vms_without_ha) == 0 else "WARNING",
            severity="MEDIUM",
            details={
                "total_vms": len(vms),
                "vms_without_ha_count": len(vms_without_ha),
                "vms_without_ha": vms_without_ha[:10],
                "explanation": f"Found {len(vms_without_ha)} VM(s) without high availability configuration" if vms_without_ha else "All VMs are configured for high availability"
            },
            recommendation=None if len(vms_without_ha) == 0 else f"Configure high availability for {len(vms_without_ha)} VM(s) using availability sets or availability zones. Note: Requires VM redeployment."
        )
    except Exception as e:
        return create_check_result(
            name="VM High Availability Configuration",
            description="Checks if VMs are configured in availability sets or zones for high availability",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check VM high availability configuration due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Compute/virtualMachines/read"
        )

def check_sql_backup_retention(subscription_id, credential, cache=None):
    """Check if SQL databases have adequate backup retention"""
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        sql_servers = cache.get_sql_servers() if cache else list(sql_client.servers.list())

        if not sql_servers:
            return create_check_result(
                name="SQL Database Backup Retention",
                description="Verifies that SQL databases have adequate backup retention configured",
                status="WARNING",
                severity="LOW",
                details={
                    "total_sql_servers": 0,
                    "explanation": "No SQL servers found or unable to access SQL server list"
                },
                recommendation="Ensure necessary permissions to view SQL servers"
            )

        insufficient_retention = []

        for server in sql_servers:
            resource_group = server.id.split("/")[4]
            try:
                databases = list(sql_client.databases.list_by_server(resource_group, server.name))

                for db in databases:
                    if db.name != "master":
                        try:
                            # Get backup policy
                            backup_policy = sql_client.backup_short_term_retention_policies.get(
                                resource_group,
                                server.name,
                                db.name,
                                "default"
                            )

                            retention_days = backup_policy.retention_days if hasattr(backup_policy, 'retention_days') else 7

                            if retention_days < 7:
                                insufficient_retention.append({
                                    "server": server.name,
                                    "database": db.name,
                                    "retention_days": retention_days
                                })
                        except Exception:
                            continue
            except Exception:
                continue

        return create_check_result(
            name="SQL Database Backup Retention",
            description="Verifies that SQL databases have adequate backup retention (7+ days)",
            status="PASS" if len(insufficient_retention) == 0 else "WARNING",
            severity="MEDIUM",
            details={
                "insufficient_retention_count": len(insufficient_retention),
                "databases_with_insufficient_retention": insufficient_retention,
                "explanation": f"Found {len(insufficient_retention)} database(s) with backup retention less than 7 days" if insufficient_retention else "All SQL databases meet backup retention requirements"
            },
            recommendation=None if len(insufficient_retention) == 0 else f"Increase backup retention to at least 7 days for {len(insufficient_retention)} database(s)."
        )
    except Exception as e:
        return create_check_result(
            name="SQL Database Backup Retention",
            description="Verifies that SQL databases have adequate backup retention configured",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check SQL backup retention due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies/read"
        )

# ---------- PROCESSING INTEGRITY ----------

def check_diagnostic_settings(subscription_id, credential):
    """Check if diagnostic settings are configured for monitoring"""
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)

        # Get all resources
        resources = list(resource_client.resources.list())

        if not resources:
            return create_check_result(
                name="Diagnostic Settings",
                description="Verifies that resources have diagnostic settings configured for logging",
                status="WARNING",
                severity="LOW",
                details={
                    "total_resources": 0,
                    "explanation": "No resources found or unable to access resource list"
                },
                recommendation="Ensure necessary permissions to view resources"
            )

        # Sample a few important resources to check diagnostic settings
        # Checking all resources would be too expensive
        important_resource_types = [
            "Microsoft.KeyVault/vaults",
            "Microsoft.Sql/servers/databases",
            "Microsoft.Storage/storageAccounts",
            "Microsoft.Network/networkSecurityGroups"
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
            name="Diagnostic Settings",
            description="Verifies that resources have diagnostic settings configured for logging",
            status="PASS" if len(resources_without_diagnostics) == 0 else "WARNING",
            severity="MEDIUM",
            details={
                "checked_resources": checked_count,
                "resources_without_diagnostics_count": len(resources_without_diagnostics),
                "resources_without_diagnostics": resources_without_diagnostics,
                "explanation": f"Found {len(resources_without_diagnostics)} of {checked_count} checked resource(s) without diagnostic settings" if resources_without_diagnostics else f"All {checked_count} checked resources have diagnostic settings configured"
            },
            recommendation=None if len(resources_without_diagnostics) == 0 else f"Configure diagnostic settings for {len(resources_without_diagnostics)} resource(s) to enable logging and monitoring."
        )
    except Exception as e:
        return create_check_result(
            name="Diagnostic Settings",
            description="Verifies that resources have diagnostic settings configured for logging",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check diagnostic settings due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Insights/diagnosticSettings/read"
        )

def check_resource_locks(subscription_id, credential):
    """Check if critical resources have resource locks"""
    try:
        resource_client = ResourceManagementClient(credential, subscription_id)

        # Get resource groups
        resource_groups = list(resource_client.resource_groups.list())

        if not resource_groups:
            return create_check_result(
                name="Resource Locks",
                description="Checks if critical resources have locks to prevent accidental deletion",
                status="WARNING",
                severity="LOW",
                details={
                    "total_resource_groups": 0,
                    "explanation": "No resource groups found or unable to access resource group list"
                },
                recommendation="Ensure necessary permissions to view resource groups"
            )

        # Check for production resource groups without locks
        production_rgs_without_locks = []

        for rg in resource_groups:
            # Check if resource group has production tag or prod in name
            is_production = (
                "prod" in rg.name.lower() or
                "production" in rg.name.lower() or
                (hasattr(rg, 'tags') and rg.tags and rg.tags.get("Environment", "").lower() in ["prod", "production"])
            )

            if is_production:
                try:
                    locks = list(resource_client.management_locks.list_at_resource_group_level(rg.name))

                    if not locks:
                        production_rgs_without_locks.append({
                            "resource_group": rg.name,
                            "location": rg.location
                        })
                except Exception:
                    continue

        return create_check_result(
            name="Resource Locks",
            description="Checks if production resources have locks to prevent accidental deletion",
            status="PASS" if len(production_rgs_without_locks) == 0 else "WARNING",
            severity="MEDIUM",
            details={
                "total_resource_groups": len(resource_groups),
                "production_rgs_without_locks_count": len(production_rgs_without_locks),
                "production_rgs_without_locks": production_rgs_without_locks,
                "explanation": f"Found {len(production_rgs_without_locks)} production resource group(s) without locks" if production_rgs_without_locks else "All production resource groups have locks configured"
            },
            recommendation=None if len(production_rgs_without_locks) == 0 else f"Apply resource locks to {len(production_rgs_without_locks)} production resource group(s) to prevent accidental deletion."
        )
    except Exception as e:
        return create_check_result(
            name="Resource Locks",
            description="Checks if production resources have locks to prevent accidental deletion",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check resource locks due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Authorization/locks/read"
        )

# ---------- PRIVACY ----------

def check_storage_soft_delete(subscription_id, credential, cache=None):
    """Check if Storage Accounts have soft delete enabled for blobs"""
    try:
        storage_accounts = cache.get_storage_accounts() if cache else list(StorageManagementClient(credential, subscription_id).storage_accounts.list())

        if not storage_accounts:
            return create_check_result(
                name="Storage Blob Soft Delete",
                description="Verifies that Storage Accounts have soft delete enabled for data protection",
                status="WARNING",
                severity="LOW",
                details={
                    "total_storage_accounts": 0,
                    "explanation": "No Storage Accounts found or unable to access Storage Account list"
                },
                recommendation="Ensure necessary permissions to view Storage Accounts"
            )

        # Note: Checking soft delete requires accessing blob service properties
        # This would require storage account keys or additional permissions
        return create_check_result(
            name="Storage Blob Soft Delete",
            description="Verifies that Storage Accounts have soft delete enabled for data protection",
            status="WARNING",
            severity="MEDIUM",
            details={
                "total_storage_accounts": len(storage_accounts),
                "explanation": "Soft delete status requires storage account access keys to query blob service properties",
                "recommendation_note": "Use Azure Portal to verify soft delete is enabled for blobs"
            },
            recommendation=f"Verify that all {len(storage_accounts)} Storage Account(s) have soft delete enabled. Go to Storage Account > Data management > Data protection > Enable soft delete for blobs"
        )
    except Exception as e:
        return create_check_result(
            name="Storage Blob Soft Delete",
            description="Verifies that Storage Accounts have soft delete enabled for data protection",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check soft delete status due to permission error"
            },
            recommendation="Grant necessary permissions: Microsoft.Storage/storageAccounts/read"
        )

def check_vm_tagging(subscription_id, credential, cache=None):
    """Check if VMs have required tags for governance and accountability"""
    try:
        vms = cache.get_vms() if cache else list(ComputeManagementClient(credential, subscription_id).virtual_machines.list_all())
        required_tags = ["Owner", "Environment", "Name"]

        if not vms:
            return create_check_result(
                name="VM Resource Tagging",
                description="Verifies that Virtual Machines have required tags for governance",
                status="WARNING",
                severity="LOW",
                details={"total_vms": 0, "explanation": "No VMs found or unable to access VM list"},
                recommendation="Ensure necessary permissions to view virtual machines"
            )

        improperly_tagged = []
        for vm in vms:
            vm_tags = vm.tags or {}
            missing_tags = [tag for tag in required_tags if tag not in vm_tags]
            if missing_tags:
                improperly_tagged.append({
                    "vm_name": vm.name,
                    "location": vm.location,
                    "missing_tags": missing_tags,
                    "current_tags": list(vm_tags.keys())
                })

        return create_check_result(
            name="VM Resource Tagging",
            description=f"Verifies that Virtual Machines have required tags: {', '.join(required_tags)}",
            status="PASS" if not improperly_tagged else "FAIL",
            severity="MEDIUM",
            details={
                "total_vms": len(vms),
                "required_tags": required_tags,
                "improperly_tagged_count": len(improperly_tagged),
                "improperly_tagged": improperly_tagged[:10],
                "explanation": f"Found {len(improperly_tagged)} VM(s) missing required tags" if improperly_tagged else "All VMs have required tags"
            },
            recommendation=None if not improperly_tagged else (
                f"Add missing tags to {len(improperly_tagged)} VM(s). "
                f"Required tags: {', '.join(required_tags)}. "
                "Use Azure Policy to enforce tagging at scale."
            )
        )
    except Exception as e:
        return create_check_result(
            name="VM Resource Tagging",
            description="Verifies that Virtual Machines have required tags for governance",
            status="WARNING",
            severity="LOW",
            details={"error": str(e), "explanation": "Unable to check VM tags due to permission error"},
            recommendation="Grant necessary permissions: Microsoft.Compute/virtualMachines/read"
        )


def check_vm_public_ip(subscription_id, credential, cache=None):
    """Check if VMs have direct public IP addresses assigned"""
    try:
        public_ips = cache.get_public_ips() if cache else list(
            NetworkManagementClient(credential, subscription_id).public_ip_addresses.list_all()
        )

        # Only flag IPs attached to network interfaces (i.e. directly on VMs),
        # not IPs on load balancers or application gateways
        vm_public_ips = []
        for pip in public_ips:
            if hasattr(pip, 'ip_configuration') and pip.ip_configuration:
                ip_config_id = pip.ip_configuration.id or ""
                if "/networkInterfaces/" in ip_config_id:
                    vm_public_ips.append({
                        "public_ip_name": pip.name,
                        "ip_address": pip.ip_address,
                        "location": pip.location,
                        "nic_id": ip_config_id
                    })

        return create_check_result(
            name="VM Direct Public IP",
            description="Identifies Virtual Machines with direct public IP addresses assigned",
            status="PASS" if not vm_public_ips else "WARNING",
            severity="MEDIUM",
            details={
                "total_public_ips": len(public_ips),
                "vm_public_ips_count": len(vm_public_ips),
                "vm_public_ips": vm_public_ips[:10],
                "explanation": f"Found {len(vm_public_ips)} VM(s) with direct public IPs" if vm_public_ips else "No VMs have direct public IP addresses"
            },
            recommendation=None if not vm_public_ips else (
                f"Review {len(vm_public_ips)} VM(s) with direct public IPs. "
                "Use Azure Bastion, load balancers, or NAT gateway instead of exposing VMs directly to the internet."
            )
        )
    except Exception as e:
        return create_check_result(
            name="VM Direct Public IP",
            description="Identifies Virtual Machines with direct public IP addresses assigned",
            status="WARNING",
            severity="LOW",
            details={"error": str(e), "explanation": "Unable to check VM public IPs due to permission error"},
            recommendation="Grant necessary permissions: Microsoft.Network/publicIPAddresses/read"
        )


def check_rbac_overly_permissive(subscription_id, credential):
    """Check for Owner role assignments at subscription scope"""
    try:
        auth_client = AuthorizationManagementClient(credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"

        assignments = list(auth_client.role_assignments.list_for_scope(scope))

        # Owner role definition GUID (well-known, same across all tenants)
        OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

        owner_assignments = []
        for assignment in assignments:
            if not hasattr(assignment, 'role_definition_id') or not assignment.role_definition_id:
                continue
            role_id = assignment.role_definition_id.split("/")[-1]
            if role_id == OWNER_ROLE_ID and assignment.scope == scope:
                owner_assignments.append({
                    "principal_id": assignment.principal_id,
                    "principal_type": getattr(assignment, 'principal_type', "Unknown"),
                    "scope": assignment.scope
                })

        return create_check_result(
            name="RBAC Overly Permissive Roles",
            description="Identifies Owner role assignments at subscription scope",
            status="PASS" if not owner_assignments else "FAIL",
            severity="HIGH",
            details={
                "total_role_assignments": len(assignments),
                "owner_at_subscription_scope_count": len(owner_assignments),
                "owner_at_subscription_scope": owner_assignments,
                "explanation": f"Found {len(owner_assignments)} Owner role assignment(s) at subscription scope" if owner_assignments else "No Owner role assignments at subscription scope"
            },
            recommendation=None if not owner_assignments else (
                f"Review and minimize {len(owner_assignments)} Owner role assignment(s) at subscription scope. "
                "Apply principle of least privilege — use more specific roles or limit scope to resource groups."
            )
        )
    except Exception as e:
        return create_check_result(
            name="RBAC Overly Permissive Roles",
            description="Identifies Owner role assignments at subscription scope",
            status="WARNING",
            severity="LOW",
            details={"error": str(e), "explanation": "Unable to check RBAC role assignments due to permission error"},
            recommendation="Grant necessary permissions: Microsoft.Authorization/roleAssignments/read"
        )


def check_azure_monitor_alerts(subscription_id, credential):
    """Check if Azure Monitor metric alerts are configured for monitoring"""
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        alert_rules = list(monitor_client.metric_alerts.list_by_subscription())
        alert_count = len(alert_rules)

        return create_check_result(
            name="Azure Monitor Alerts",
            description="Checks if Azure Monitor metric alerts are configured for monitoring system health",
            status="PASS" if alert_count > 0 else "WARNING",
            severity="MEDIUM",
            details={
                "alert_count": alert_count,
                "alert_names": [a.name for a in alert_rules[:10]],
                "explanation": f"{alert_count} Azure Monitor alert(s) configured" if alert_count > 0 else "No Azure Monitor alerts found — proactive monitoring is not configured"
            },
            recommendation=None if alert_count > 0 else (
                "Configure Azure Monitor metric alerts for critical metrics (CPU, memory, disk, error rates). "
                "Enable action groups for alert notifications."
            )
        )
    except Exception as e:
        return create_check_result(
            name="Azure Monitor Alerts",
            description="Checks if Azure Monitor metric alerts are configured for monitoring system health",
            status="WARNING",
            severity="LOW",
            details={"error": str(e), "explanation": "Unable to check Azure Monitor alerts due to permission error"},
            recommendation="Grant necessary permissions: Microsoft.Insights/metricAlerts/read"
        )


def check_sql_deletion_protection(subscription_id, credential, cache=None):
    """Check if SQL servers have resource locks to prevent accidental deletion"""
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)
        sql_servers = cache.get_sql_servers() if cache else list(sql_client.servers.list())

        if not sql_servers:
            return create_check_result(
                name="SQL Server Deletion Protection",
                description="Verifies that SQL servers have resource locks to prevent accidental deletion",
                status="WARNING",
                severity="LOW",
                details={"total_sql_servers": 0, "explanation": "No SQL servers found or unable to access SQL server list"},
                recommendation="Ensure necessary permissions to view SQL servers"
            )

        unprotected_servers = []
        for server in sql_servers:
            resource_group = server.id.split("/")[4]
            try:
                locks = list(resource_client.management_locks.list_at_resource_level(
                    resource_group,
                    "Microsoft.Sql",
                    "",
                    "servers",
                    server.name
                ))
                if not locks:
                    unprotected_servers.append({
                        "server": server.name,
                        "resource_group": resource_group,
                        "location": server.location
                    })
            except Exception:
                continue

        return create_check_result(
            name="SQL Server Deletion Protection",
            description="Verifies that SQL servers have resource locks to prevent accidental deletion",
            status="PASS" if not unprotected_servers else "WARNING",
            severity="MEDIUM",
            details={
                "total_sql_servers": len(sql_servers),
                "unprotected_servers_count": len(unprotected_servers),
                "unprotected_servers": unprotected_servers,
                "explanation": f"Found {len(unprotected_servers)} SQL server(s) without deletion protection locks" if unprotected_servers else "All SQL servers have deletion protection locks"
            },
            recommendation=None if not unprotected_servers else (
                f"Apply CanNotDelete locks to {len(unprotected_servers)} SQL server(s). "
                "Go to SQL Server > Locks > Add lock > Lock type: Delete."
            )
        )
    except Exception as e:
        return create_check_result(
            name="SQL Server Deletion Protection",
            description="Verifies that SQL servers have resource locks to prevent accidental deletion",
            status="WARNING",
            severity="LOW",
            details={"error": str(e), "explanation": "Unable to check SQL server deletion protection due to permission error"},
            recommendation="Grant necessary permissions: Microsoft.Sql/servers/read, Microsoft.Authorization/locks/read"
        )


def check_storage_https_only(subscription_id, credential, cache=None):
    """Check if Storage Accounts enforce HTTPS-only connections"""
    try:
        storage_accounts = cache.get_storage_accounts() if cache else list(
            StorageManagementClient(credential, subscription_id).storage_accounts.list()
        )

        if not storage_accounts:
            return create_check_result(
                name="Storage HTTPS Only",
                description="Verifies that Storage Accounts enforce HTTPS-only connections",
                status="WARNING",
                severity="LOW",
                details={"total_storage_accounts": 0, "explanation": "No Storage Accounts found or unable to access Storage Account list"},
                recommendation="Ensure necessary permissions to view Storage Accounts"
            )

        non_https_accounts = [
            account.name for account in storage_accounts
            if not (hasattr(account, 'enable_https_traffic_only') and account.enable_https_traffic_only)
        ]

        return create_check_result(
            name="Storage HTTPS Only",
            description="Verifies that Storage Accounts enforce HTTPS-only connections",
            status="PASS" if not non_https_accounts else "FAIL",
            severity="HIGH",
            details={
                "total_storage_accounts": len(storage_accounts),
                "non_https_accounts_count": len(non_https_accounts),
                "non_https_accounts": non_https_accounts,
                "explanation": f"Found {len(non_https_accounts)} Storage Account(s) not enforcing HTTPS-only" if non_https_accounts else "All Storage Accounts enforce HTTPS-only connections"
            },
            recommendation=None if not non_https_accounts else (
                f"Enable HTTPS-only for {len(non_https_accounts)} Storage Account(s). "
                "Go to Storage Account > Configuration > Secure transfer required > Enabled."
            )
        )
    except Exception as e:
        return create_check_result(
            name="Storage HTTPS Only",
            description="Verifies that Storage Accounts enforce HTTPS-only connections",
            status="WARNING",
            severity="LOW",
            details={"error": str(e), "explanation": "Unable to check Storage Account HTTPS enforcement due to permission error"},
            recommendation="Grant necessary permissions: Microsoft.Storage/storageAccounts/read"
        )


def check_storage_versioning(subscription_id, credential, cache=None):
    """Check if Storage Accounts have blob versioning enabled"""
    try:
        storage_client = StorageManagementClient(credential, subscription_id)
        storage_accounts = cache.get_storage_accounts() if cache else list(storage_client.storage_accounts.list())

        if not storage_accounts:
            return create_check_result(
                name="Storage Blob Versioning",
                description="Verifies that Storage Accounts have blob versioning enabled for data protection",
                status="WARNING",
                severity="LOW",
                details={"total_storage_accounts": 0, "explanation": "No Storage Accounts found or unable to access Storage Account list"},
                recommendation="Ensure necessary permissions to view Storage Accounts"
            )

        versioning_disabled = []
        for account in storage_accounts:
            resource_group = account.id.split("/")[4]
            try:
                props = storage_client.blob_services.get_service_properties(resource_group, account.name)
                if not (hasattr(props, 'is_versioning_enabled') and props.is_versioning_enabled):
                    versioning_disabled.append(account.name)
            except Exception:
                continue

        return create_check_result(
            name="Storage Blob Versioning",
            description="Verifies that Storage Accounts have blob versioning enabled for data protection",
            status="PASS" if not versioning_disabled else "WARNING",
            severity="MEDIUM",
            details={
                "total_storage_accounts": len(storage_accounts),
                "versioning_disabled_count": len(versioning_disabled),
                "versioning_disabled_accounts": versioning_disabled,
                "explanation": f"Found {len(versioning_disabled)} Storage Account(s) without blob versioning" if versioning_disabled else "All Storage Accounts have blob versioning enabled"
            },
            recommendation=None if not versioning_disabled else (
                f"Enable blob versioning for {len(versioning_disabled)} Storage Account(s). "
                "Go to Storage Account > Data management > Data protection > Enable versioning for blobs."
            )
        )
    except Exception as e:
        return create_check_result(
            name="Storage Blob Versioning",
            description="Verifies that Storage Accounts have blob versioning enabled for data protection",
            status="WARNING",
            severity="LOW",
            details={"error": str(e), "explanation": "Unable to check blob versioning due to permission error"},
            recommendation="Grant necessary permissions: Microsoft.Storage/storageAccounts/blobServices/read"
        )


def check_key_vault_rotation(subscription_id, credential):
    """Check if Key Vaults exist and report on rotation policy verification requirement"""
    try:
        kv_client = KeyVaultManagementClient(credential, subscription_id)
        vaults = list(kv_client.vaults.list())

        if not vaults:
            return create_check_result(
                name="Key Vault Rotation Policy",
                description="Verifies that Key Vault keys and secrets have rotation policies configured",
                status="WARNING",
                severity="LOW",
                details={"total_vaults": 0, "explanation": "No Key Vaults found or unable to access Key Vault list"},
                recommendation="Ensure necessary permissions to view Key Vaults: Microsoft.KeyVault/vaults/read"
            )

        vault_names = [v.name for v in vaults]

        # Full rotation-policy verification requires Key Vault Data Plane access
        # (azure-keyvault-keys / azure-keyvault-secrets). Management Plane can only
        # confirm vaults exist — flag for manual review.
        return create_check_result(
            name="Key Vault Rotation Policy",
            description="Verifies that Key Vault keys and secrets have rotation policies configured",
            status="WARNING",
            severity="MEDIUM",
            details={
                "total_vaults": len(vaults),
                "vault_names": vault_names,
                "explanation": (
                    "Key Vault rotation policies require Data Plane access to verify. "
                    f"Found {len(vaults)} vault(s) — review each manually."
                )
            },
            recommendation=(
                f"Review key rotation policies for {len(vaults)} Key Vault(s): {', '.join(vault_names)}. "
                "Enable automatic rotation for all keys and set expiry dates on all secrets. "
                "Go to Key Vault > Keys/Secrets > select item > Rotation policy."
            )
        )
    except Exception as e:
        return create_check_result(
            name="Key Vault Rotation Policy",
            description="Verifies that Key Vault keys and secrets have rotation policies configured",
            status="WARNING",
            severity="LOW",
            details={"error": str(e), "explanation": "Unable to check Key Vault rotation policies due to permission error"},
            recommendation="Grant necessary permissions: Microsoft.KeyVault/vaults/read"
        )


def check_nsg_flow_logs(subscription_id, credential, cache=None):
    """Check if Network Security Groups have flow logs enabled"""
    try:
        network_client = NetworkManagementClient(credential, subscription_id)
        nsgs = cache.get_network_security_groups() if cache else list(network_client.network_security_groups.list_all())

        if not nsgs:
            return create_check_result(
                name="NSG Flow Logs",
                description="Verifies that Network Security Groups have flow logs enabled for traffic analysis",
                status="WARNING",
                severity="LOW",
                details={"total_nsgs": 0, "explanation": "No NSGs found or unable to access NSG list"},
                recommendation="Ensure necessary permissions to view network security groups"
            )

        # Collect NSG IDs that have flow logs enabled via Network Watchers
        nsg_ids_with_flow_logs = set()
        try:
            watchers = list(network_client.network_watchers.list_all())
            for watcher in watchers:
                rg = watcher.id.split("/")[4]
                try:
                    for fl in network_client.flow_logs.list(rg, watcher.name):
                        if fl.enabled and hasattr(fl, 'target_resource_id') and fl.target_resource_id:
                            nsg_ids_with_flow_logs.add(fl.target_resource_id.lower())
                except Exception:
                    continue
        except Exception:
            pass

        nsgs_without_flow_logs = [
            {"nsg_name": nsg.name, "location": nsg.location}
            for nsg in nsgs
            if nsg.id.lower() not in nsg_ids_with_flow_logs
        ]

        return create_check_result(
            name="NSG Flow Logs",
            description="Verifies that Network Security Groups have flow logs enabled for traffic analysis",
            status="PASS" if not nsgs_without_flow_logs else "WARNING",
            severity="MEDIUM",
            details={
                "total_nsgs": len(nsgs),
                "nsgs_without_flow_logs_count": len(nsgs_without_flow_logs),
                "nsgs_without_flow_logs": nsgs_without_flow_logs[:10],
                "explanation": f"Found {len(nsgs_without_flow_logs)} NSG(s) without flow logs enabled" if nsgs_without_flow_logs else "All NSGs have flow logs enabled"
            },
            recommendation=None if not nsgs_without_flow_logs else (
                f"Enable Network Watcher flow logs for {len(nsgs_without_flow_logs)} NSG(s). "
                "Go to Azure Monitor > Network Insights > Flow logs."
            )
        )
    except Exception as e:
        return create_check_result(
            name="NSG Flow Logs",
            description="Verifies that Network Security Groups have flow logs enabled for traffic analysis",
            status="WARNING",
            severity="LOW",
            details={"error": str(e), "explanation": "Unable to check NSG flow logs due to permission error"},
            recommendation="Grant necessary permissions: Microsoft.Network/networkWatchers/flowLogs/read"
        )


def check_activity_log_alerts(subscription_id, credential):
    """Check if Azure Monitor activity log alerts are configured for critical admin operations"""
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        activity_alerts = list(monitor_client.activity_log_alerts.list_by_subscription_id())

        critical_operations = [
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.Authorization/policyAssignments/write",
            "Microsoft.Network/networkSecurityGroups/write",
            "Microsoft.Security/policies/write",
        ]

        monitored_operations = set()
        for alert in activity_alerts:
            if hasattr(alert, 'condition') and alert.condition:
                for condition in (alert.condition.all_of or []):
                    if hasattr(condition, 'equals') and condition.equals:
                        monitored_operations.add(condition.equals.lower())

        unmonitored_ops = [op for op in critical_operations if op.lower() not in monitored_operations]

        return create_check_result(
            name="Activity Log Alerts",
            description="Checks if Azure Monitor activity log alerts are configured for critical admin operations",
            status="PASS" if not unmonitored_ops else "WARNING",
            severity="MEDIUM",
            details={
                "total_activity_alerts": len(activity_alerts),
                "critical_operations_checked": critical_operations,
                "unmonitored_operations_count": len(unmonitored_ops),
                "unmonitored_operations": unmonitored_ops,
                "explanation": f"{len(unmonitored_ops)} critical admin operation(s) have no activity log alert" if unmonitored_ops else "All critical admin operations have activity log alerts configured"
            },
            recommendation=None if not unmonitored_ops else (
                f"Configure activity log alerts for: {', '.join(unmonitored_ops)}. "
                "Go to Azure Monitor > Alerts > Create > Activity Log signal."
            )
        )
    except Exception as e:
        return create_check_result(
            name="Activity Log Alerts",
            description="Checks if Azure Monitor activity log alerts are configured for critical admin operations",
            status="WARNING",
            severity="LOW",
            details={"error": str(e), "explanation": "Unable to check activity log alerts due to permission error"},
            recommendation="Grant necessary permissions: Microsoft.Insights/activityLogAlerts/read"
        )


def check_entra_password_policy(subscription_id, credential):
    """Check if Entra ID has a strong password policy configured"""
    # Full verification requires Microsoft Graph API access which is outside the
    # scope of Azure management-plane credentials — flag for manual review.
    return create_check_result(
        name="Entra ID Password Policy",
        description="Verifies that Entra ID has a strong password policy with complexity requirements",
        status="WARNING",
        severity="MEDIUM",
        details={
            "explanation": "Password policy verification requires Microsoft Graph API access to query Entra ID tenant settings",
            "recommendation_note": "Use Azure Portal: Entra ID > Users > Password reset > Authentication methods"
        },
        recommendation=(
            "Review Entra ID password policy settings. Ensure: minimum 12 characters, complexity required, "
            "90-day maximum password age. Go to Microsoft Entra ID > Security > Authentication methods > Password protection."
        )
    )


# ---------- EXECUTIVE SUMMARY ----------

def generate_executive_summary(result):
    """Generate a markdown-formatted executive summary of the SOC2 audit results"""
    summary = result["metadata"]["summary"]
    subscription_id = result["metadata"].get("subscription_id", "Unknown")

    total_checks = summary["total_checks"]
    passed = summary["passed"]
    failed = summary["failed"]
    warnings = summary["warnings"]
    critical_failures = summary["critical_failures"]
    high_failures = summary["high_failures"]
    permission_errors = summary.get("permission_errors", 0)
    checks_completed = summary.get("checks_completed", total_checks)

    # Calculate compliance score based on completed checks only
    compliance_score = int((passed / checks_completed * 100)) if checks_completed > 0 else 0

    # Build markdown summary
    md_lines = []

    # Title
    md_lines.append("# Executive Summary")
    md_lines.append("")

    # Overall compliance status
    md_lines.append("## Overall Compliance Status")
    md_lines.append("")
    if compliance_score >= 90:
        md_lines.append(f"**Azure Subscription {subscription_id}** demonstrates **strong SOC2 compliance** with a **{compliance_score}%** pass rate across **{total_checks}** security controls.")
    elif compliance_score >= 70:
        md_lines.append(f"**Azure Subscription {subscription_id}** shows **moderate SOC2 compliance** with a **{compliance_score}%** pass rate across **{total_checks}** security controls, requiring targeted improvements.")
    else:
        md_lines.append(f"**Azure Subscription {subscription_id}** requires **significant security improvements** with a **{compliance_score}%** pass rate across **{total_checks}** security controls.")
    md_lines.append("")

    # Critical and high severity issues
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

    # Add permission error note if any
    if permission_errors > 0:
        md_lines.append("## Additional Observations")
        md_lines.append("")
        md_lines.append(f"**Note:** {permission_errors} check(s) could not be completed due to insufficient permissions. Grant necessary permissions for a complete audit.")
        md_lines.append("")

    # Overall recommendation
    md_lines.append("## Recommendation")
    md_lines.append("")
    if compliance_score >= 90:
        md_lines.append("**Action:** Address minor findings and proceed with SOC2 Type I certification preparation.")
    elif compliance_score >= 70:
        md_lines.append("**Action:** Focus on critical and high-severity findings before pursuing formal SOC2 certification.")
    else:
        md_lines.append("**Action:** Implement comprehensive security improvements across all categories before initiating SOC2 certification process.")

    return "\n".join(md_lines)

# ---------- RUN AUDIT ----------

def run_soc2_audit(subscription_id: str, credential):
    """Run SOC2 audit for a given subscription ID."""
    result = _make_result()
    result["metadata"]["subscription_id"] = subscription_id

    # Pre-fetch all shared resources in the main thread before workers start
    cache = AzureResourceCache(subscription_id, credential)

    # Define all checks to run with their categories
    check_tasks = [
        # Security checks
        ("security", lambda: check_mfa_enabled(subscription_id, credential)),
        ("security", lambda: check_disk_encryption(subscription_id, credential, cache)),
        ("security", lambda: check_nsg_rules(subscription_id, credential, cache)),
        ("security", lambda: check_security_center_enabled(subscription_id, credential)),
        ("security", lambda: check_activity_log_retention(subscription_id, credential)),
        ("security", lambda: check_vm_tagging(subscription_id, credential, cache)),
        ("security", lambda: check_vm_public_ip(subscription_id, credential, cache)),
        ("security", lambda: check_rbac_overly_permissive(subscription_id, credential)),
        ("security", lambda: check_key_vault_rotation(subscription_id, credential)),

        # Availability checks
        ("availability", lambda: check_vm_backup_enabled(subscription_id, credential, cache)),
        ("availability", lambda: check_vm_availability_sets(subscription_id, credential, cache)),
        ("availability", lambda: check_sql_backup_retention(subscription_id, credential, cache)),
        ("availability", lambda: check_azure_monitor_alerts(subscription_id, credential)),
        ("availability", lambda: check_sql_deletion_protection(subscription_id, credential, cache)),

        # Confidentiality checks
        ("confidentiality", lambda: check_storage_encryption(subscription_id, credential, cache)),
        ("confidentiality", lambda: check_storage_public_access(subscription_id, credential, cache)),
        ("confidentiality", lambda: check_sql_encryption(subscription_id, credential, cache)),
        ("confidentiality", lambda: check_sql_firewall(subscription_id, credential, cache)),
        ("confidentiality", lambda: check_storage_https_only(subscription_id, credential, cache)),
        ("confidentiality", lambda: check_storage_versioning(subscription_id, credential, cache)),

        # Processing integrity checks
        ("processing_integrity", lambda: check_diagnostic_settings(subscription_id, credential)),
        ("processing_integrity", lambda: check_resource_locks(subscription_id, credential)),
        ("processing_integrity", lambda: check_nsg_flow_logs(subscription_id, credential, cache)),
        ("processing_integrity", lambda: check_activity_log_alerts(subscription_id, credential)),

        # Privacy checks
        ("privacy", lambda: check_storage_soft_delete(subscription_id, credential, cache)),
        ("privacy", lambda: check_entra_password_policy(subscription_id, credential))
    ]

    # Run checks in parallel with ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all tasks
        future_to_check = {executor.submit(check_func): (category, check_func) for category, check_func in check_tasks}

        # Collect results as they complete
        for future in as_completed(future_to_check):
            category, check_func = future_to_check[future]
            try:
                check_result = future.result()
                result[category]["checks"].append(check_result)
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

                # Extract check name from the lambda function if possible
                check_name = "Unknown Check"
                try:
                    check_name = check_func.__name__ if hasattr(check_func, '__name__') else str(check_func)
                except Exception:
                    pass

                if is_permission_error:
                    error_result = create_check_result(
                        name=f"Permission Error: {check_name}",
                        description="Unable to perform this check due to insufficient permissions",
                        status="WARNING",
                        severity="LOW",
                        details={
                            "error_type": error_type,
                            "error_message": error_message,
                            "category": category,
                            "reason": "Azure RBAC permissions may be missing for this service/action"
                        },
                        recommendation="Grant necessary Azure RBAC permissions to perform this security check."
                    )
                else:
                    error_result = create_check_result(
                        name=f"Check Failed: {check_name}",
                        description=f"Check encountered an unexpected error: {error_message}",
                        status="WARNING",
                        severity="LOW",
                        details={
                            "error_type": error_type,
                            "error_message": error_message,
                            "category": category
                        },
                        recommendation="Review error details and ensure Azure resources are accessible and properly configured."
                    )

                result[category]["checks"].append(error_result)

    # Add summary statistics
    all_checks = (
        result["security"]["checks"] +
        result["availability"]["checks"] +
        result["confidentiality"]["checks"] +
        result["processing_integrity"]["checks"] +
        result["privacy"]["checks"]
    )

    # Count permission errors separately
    permission_errors = sum(1 for c in all_checks if c["status"] == "WARNING" and "Permission Error" in c.get("check_name", ""))

    result["metadata"]["summary"] = {
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
    result["metadata"]["executive_summary"] = generate_executive_summary(result)

    return result

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
        description='Azure SOC2 Audit Script - Generate security compliance reports.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate audit report for default subscription
  python3 azure_audit.py

  # Generate audit report for a specific subscription by name
  python3 azure_audit.py --subscription-name "Tessell QA BYOA"

  # Generate audit report for a specific subscription by ID
  python3 azure_audit.py --subscription-id "12345678-1234-1234-1234-123456789abc"
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
            print(f"Running SOC2 audit for subscription: {subscription_id}", file=sys.stderr)
        raw_report = run_soc2_audit(subscription_id=subscription_id, credential=credential)

        # Return flat format with categories containing checks directly
        report = {
            "metadata": raw_report["metadata"],
            "security": raw_report["security"],
            "availability": raw_report["availability"],
            "confidentiality": raw_report["confidentiality"],
            "processing_integrity": raw_report["processing_integrity"],
            "privacy": raw_report["privacy"]
        }

        return report
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    result = main()
    print(json.dumps(result, indent=2))

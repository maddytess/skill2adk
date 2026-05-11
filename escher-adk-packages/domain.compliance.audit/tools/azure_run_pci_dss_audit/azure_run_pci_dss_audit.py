import argparse
import json
import re
import sys
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict, Any

from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.web import WebSiteManagementClient

# These submodules were removed in azure-mgmt-resource >= 20.x; handle gracefully
try:
    from azure.mgmt.resource.policy import PolicyClient
except ImportError:
    PolicyClient = None  # type: ignore[assignment,misc]

try:
    from azure.mgmt.resource.locks import ManagementLockClient
except ImportError:
    ManagementLockClient = None  # type: ignore[assignment,misc]

try:
    from azure.mgmt.loganalytics import LogAnalyticsManagementClient
except ImportError:
    LogAnalyticsManagementClient = None  # type: ignore[assignment,misc]

try:
    from azure.mgmt.operationsmanagement import OperationsManagementClient
except ImportError:
    OperationsManagementClient = None  # type: ignore[assignment,misc]

from azure.mgmt.redis import RedisManagementClient
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
from azure.mgmt.subscription import SubscriptionClient
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.keys import KeyClient

# ===================== CONSTANTS =====================

_SENSITIVE_PORTS = [22, 3389, 3306, 5432, 1433, 1521, 27017, 6379, 5439]
_UNRESTRICTED_CIDRS = {"0.0.0.0/0", "::/0"}
_CERT_EXPIRY_DAYS = 30
_FLOW_LOG_RETENTION_DAYS = 90
_LOG_RETENTION_DAYS = 365
_SQL_AUDIT_RETENTION_DAYS = 90
_SQL_BACKUP_MIN_DAYS = 7
_OWNER_COUNT_THRESHOLD = 3
_CRED_SECRET_PATTERNS = re.compile(
    r"(password|passwd|secret|api[_\-]?key|access[_\-]?key|token|conn[_\-]?str|connectionstring|private[_\-]?key)",
    re.IGNORECASE,
)

# PCI-DSS v4.0 built-in RBAC role IDs (Owner and Contributor)
_OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
_CONTRIBUTOR_ROLE_ID = "b24988ac-6180-42a0-ab88-20f7382dd24c"
_PRIVILEGED_ROLE_IDS = {_OWNER_ROLE_ID, _CONTRIBUTOR_ROLE_ID}

# EOL runtimes — last updated April 2026
# Python: 3.9 EOL; 3.10+ still supported
# Java: 11 LTS still has vendor support in many distributions — not flagged
# Node: 16 EOL; 18+ still supported
_EOL_LINUX_RUNTIMES = {
    "python|2.", "python|3.6", "python|3.7", "python|3.8", "python|3.9",
    "node|10", "node|12", "node|14", "node|16",
    "dotnetcore|1.", "dotnetcore|2.", "dotnetcore|3.0",
    "java|8",
    "php|5.", "php|7.",
    "ruby|2.",
}
_EOL_FUNCTIONS_VERSIONS = {"~1", "~2", "~3"}

# ===================== RESULT STRUCTURE =====================


def _make_result() -> dict:
    """Create a fresh result structure for each audit run."""
    return {
        "metadata": {
            "framework": "PCI-DSS v4.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "network_security": {
            "category_description": (
                "Network security controls ensure segmentation and protection of the "
                "Cardholder Data Environment (PCI-DSS Requirements 1 & 2)"
            ),
            "checks": [],
        },
        "data_protection": {
            "category_description": (
                "Data protection controls ensure cardholder data is encrypted at rest "
                "and in transit (PCI-DSS Requirements 3 & 4)"
            ),
            "checks": [],
        },
        "access_control": {
            "category_description": (
                "Access control measures restrict access to cardholder data by business need "
                "and enforce strong authentication (PCI-DSS Requirements 7 & 8)"
            ),
            "checks": [],
        },
        "logging_monitoring": {
            "category_description": (
                "Logging and monitoring controls ensure all access to system components "
                "and cardholder data is tracked and reviewed (PCI-DSS Requirements 10 & 11)"
            ),
            "checks": [],
        },
        "vulnerability_management": {
            "category_description": (
                "Vulnerability management controls protect systems against malware and ensure "
                "secure development practices (PCI-DSS Requirements 5 & 6)"
            ),
            "checks": [],
        },
        "data_retention_recovery": {
            "category_description": (
                "Data retention and recovery controls support information security policies "
                "and business continuity (PCI-DSS Requirements 9 & 12)"
            ),
            "checks": [],
        },
    }


# ===================== HELPERS =====================


def create_control_result(requirement, name, description, status, severity, details, recommendation=None):
    result = {
        "pci_requirement": requirement,
        "control_name": name,
        "description": description,
        "status": status,       # PASS / FAIL / WARNING
        "severity": severity,   # CRITICAL / HIGH / MEDIUM / LOW
        "details": details,
    }
    if recommendation:
        result["recommendation"] = recommendation
    return result


def _warning(requirement, name, description, severity, e):
    """Return a WARNING result for a check that failed due to an exception."""
    error_type = type(e).__name__
    return create_control_result(
        requirement, name, description,
        "WARNING", severity,
        {"error": error_type, "message": str(e)},
        f"Ensure the auditing identity has permission to perform this check (error: {error_type}).",
    )


def _rg_from_id(resource_id: str) -> str:
    """Extract resource group name from a full Azure resource ID."""
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""


def _name_from_id(resource_id: str) -> str:
    """Extract resource name (last segment) from a full Azure resource ID."""
    return resource_id.rstrip("/").split("/")[-1]


# ===================== RESOURCE CACHE =====================


class AzureResourceCache:
    """Cache for commonly accessed Azure resources to avoid redundant API calls.

    All resource lists are fetched in parallel during __init__ so the object is
    fully populated before any check runs. get_*() methods are read-only after
    construction — no lazy init, no locks needed.
    """

    def __init__(self, subscription_id: str, credential):
        self.subscription_id = subscription_id
        self._scope = f"/subscriptions/{subscription_id}"
        # Shared SDK clients — created once, reused across all get_*() calls
        self._net_client = NetworkManagementClient(credential, subscription_id)
        self._compute_client = ComputeManagementClient(credential, subscription_id)
        self._storage_client = StorageManagementClient(credential, subscription_id)
        self._sql_client = SqlManagementClient(credential, subscription_id)
        self._kv_client = KeyVaultManagementClient(credential, subscription_id)
        self._auth_client = AuthorizationManagementClient(credential, subscription_id)
        self._web_client = WebSiteManagementClient(credential, subscription_id)
        self._security_client = SecurityCenter(credential, subscription_id)
        # Fetch all resource lists in parallel; object is immutable after __init__ returns
        _fetchers = [
            ("_vnets",            lambda: list(self._net_client.virtual_networks.list_all())),
            ("_nsgs",             lambda: list(self._net_client.network_security_groups.list_all())),
            ("_vms",              lambda: list(self._compute_client.virtual_machines.list_all())),
            ("_disks",            lambda: list(self._compute_client.disks.list())),
            ("_storage_accounts", lambda: list(self._storage_client.storage_accounts.list())),
            ("_sql_servers",      lambda: list(self._sql_client.servers.list())),
            ("_key_vaults",       lambda: list(self._kv_client.vaults.list())),
            ("_role_assignments",  lambda: list(self._auth_client.role_assignments.list_for_scope(self._scope))),
            ("_role_definitions",  lambda: list(self._auth_client.role_definitions.list(self._scope, filter="type eq 'CustomRole'"))),
            ("_web_apps",         lambda: list(self._web_client.web_apps.list())),
            ("_defender_pricings", lambda: list(self._security_client.pricings.list())),
        ]
        self._fetch_errors: dict = {}
        with ThreadPoolExecutor(max_workers=len(_fetchers)) as executor:
            futures = {attr: executor.submit(fn) for attr, fn in _fetchers}
            for attr, future in futures.items():
                try:
                    setattr(self, attr, future.result())
                except Exception as exc:
                    setattr(self, attr, [])
                    self._fetch_errors[attr] = exc

    def _raise_if_fetch_failed(self, attr: str) -> None:
        """Re-raise the exception from __init__ if this resource type failed to load.

        This prevents checks from seeing an empty list (which looks like "no resources →
        PASS") when the real cause was an authentication or permission failure.  The
        check's outer ``except Exception`` handler will catch the re-raised error and
        return WARNING with the original error message.
        """
        if attr in self._fetch_errors:
            raise RuntimeError(
                f"Cache fetch failed for {attr!r} during initialisation — "
                f"{type(self._fetch_errors[attr]).__name__}: {self._fetch_errors[attr]}"
            ) from self._fetch_errors[attr]

    def get_vnets(self) -> list:
        self._raise_if_fetch_failed("_vnets")
        return self._vnets

    def get_nsgs(self) -> list:
        self._raise_if_fetch_failed("_nsgs")
        return self._nsgs

    def get_vms(self) -> list:
        self._raise_if_fetch_failed("_vms")
        return self._vms

    def get_disks(self) -> list:
        self._raise_if_fetch_failed("_disks")
        return self._disks

    def get_storage_accounts(self) -> list:
        self._raise_if_fetch_failed("_storage_accounts")
        return self._storage_accounts

    def get_sql_servers(self) -> list:
        self._raise_if_fetch_failed("_sql_servers")
        return self._sql_servers

    def get_key_vaults(self) -> list:
        self._raise_if_fetch_failed("_key_vaults")
        return self._key_vaults

    def get_role_assignments(self) -> list:
        self._raise_if_fetch_failed("_role_assignments")
        return self._role_assignments

    def get_role_definitions(self) -> list:
        self._raise_if_fetch_failed("_role_definitions")
        return self._role_definitions

    def get_web_apps(self) -> list:
        self._raise_if_fetch_failed("_web_apps")
        return self._web_apps

    def get_defender_pricings(self) -> list:
        self._raise_if_fetch_failed("_defender_pricings")
        return self._defender_pricings


# ===================== NETWORK SECURITY (Req 1 & 2) =====================


def check_nsg_unrestricted_inbound(subscription_id, credential, cache):
    """Req 1.3 — No NSG allows inbound traffic from 0.0.0.0/0 on sensitive ports."""
    req, name, desc, sev = (
        "1.3",
        "NSG Unrestricted Inbound on Sensitive Ports",
        "Verifies no NSG rules allow inbound traffic from 0.0.0.0/0 or ::/0 on sensitive ports "
        "(SSH/22, RDP/3389, SQL/1433, MySQL/3306, PostgreSQL/5432, and other database ports)",
        "CRITICAL",
    )
    try:
        nsgs = cache.get_nsgs()
        violations = []
        for nsg in nsgs:
            for rule in (nsg.security_rules or []):
                if rule.direction != "Inbound":
                    continue
                if rule.access != "Allow":
                    continue
                # A rule may use the singular field OR the plural list — check both.
                # source_address_prefix is a single string; source_address_prefixes is a list.
                if rule.source_address_prefix:
                    sources = [rule.source_address_prefix]
                elif rule.source_address_prefixes:
                    sources = list(rule.source_address_prefixes)
                else:
                    continue
                if not any(s in _UNRESTRICTED_CIDRS for s in sources):
                    continue
                src = next((s for s in sources if s in _UNRESTRICTED_CIDRS), sources[0])
                # Check destination port ranges
                ports = []
                if rule.destination_port_range:
                    ports = [rule.destination_port_range]
                elif rule.destination_port_ranges:
                    ports = list(rule.destination_port_ranges)

                exposed = []
                for port_range in ports:
                    if port_range == "*":
                        exposed = _SENSITIVE_PORTS
                        break
                    for sp in _SENSITIVE_PORTS:
                        if "-" in port_range:
                            lo, hi = port_range.split("-", 1)
                            if lo.isdigit() and hi.isdigit() and int(lo) <= sp <= int(hi):
                                exposed.append(sp)
                        elif port_range.isdigit() and int(port_range) == sp:
                            exposed.append(sp)
                if exposed:
                    violations.append({
                        "nsg": nsg.name,
                        "resource_group": _rg_from_id(nsg.id),
                        "rule": rule.name,
                        "source": src,
                        "exposed_ports": list(set(exposed)),
                    })

        if violations:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"violation_count": len(violations), "violations": violations[:20]},
                "Remove or restrict inbound NSG rules that allow traffic from 0.0.0.0/0 on sensitive "
                "ports. Restrict source to specific IP ranges or use Azure Bastion for SSH/RDP access.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_nsgs": len(nsgs)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_subnets_without_nsg(subscription_id, credential, cache):
    """Req 1.2 — All subnets have an NSG attached."""
    req, name, desc, sev = (
        "1.2",
        "Subnets Without NSG",
        "Verifies all VNet subnets have a Network Security Group attached to filter traffic",
        "HIGH",
    )
    try:
        client = NetworkManagementClient(credential, subscription_id)
        vnets = cache.get_vnets()
        unprotected = []
        total_subnets = 0
        for vnet in vnets:
            rg = _rg_from_id(vnet.id)
            subnets = list(client.subnets.list(rg, vnet.name))
            for subnet in subnets:
                # Skip gateway subnets — they cannot have NSGs
                if subnet.name.lower() in ("gatewaysubnet", "azurebastionsubnet",
                                           "azurefirewallsubnet", "azurefirewallmanagementsubnet"):
                    continue
                total_subnets += 1
                if not subnet.network_security_group:
                    unprotected.append({
                        "vnet": vnet.name,
                        "subnet": subnet.name,
                        "resource_group": rg,
                    })

        if unprotected:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"unprotected_count": len(unprotected), "total_subnets": total_subnets,
                 "unprotected_subnets": unprotected[:20]},
                "Attach an NSG to every subnet in your CDE VNets. Create or assign an NSG via: "
                "az network vnet subnet update --nsg <nsg-name> ...",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_subnets": total_subnets})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_vms_public_ip_no_nsg(subscription_id, credential, cache):
    """Req 1.3 — No VMs have a public IP on a NIC without an NSG."""
    req, name, desc, sev = (
        "1.3",
        "VMs With Public IP and No NSG",
        "Verifies no Virtual Machines have a public IP address on a NIC that has no NSG protecting it",
        "HIGH",
    )
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        vms = cache.get_vms()
        exposed = []
        for vm in vms:
            if not vm.network_profile:
                continue
            for nic_ref in (vm.network_profile.network_interfaces or []):
                nic_id = nic_ref.id
                nic_name = _name_from_id(nic_id)
                nic_rg = _rg_from_id(nic_id)
                try:
                    nic = net_client.network_interfaces.get(nic_rg, nic_name)
                except Exception:
                    continue
                has_public_ip = any(
                    ip_cfg.public_ip_address is not None
                    for ip_cfg in (nic.ip_configurations or [])
                )
                if has_public_ip and not nic.network_security_group:
                    exposed.append({
                        "vm": vm.name,
                        "nic": nic_name,
                        "resource_group": _rg_from_id(vm.id),
                    })

        if exposed:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"exposed_count": len(exposed), "exposed_vms": exposed[:20]},
                "Attach an NSG to the NIC or subnet of each exposed VM. "
                "Consider removing public IPs and using Azure Bastion for management access.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_vms": len(vms)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_network_watcher_flow_logs(subscription_id, credential, cache):
    """Req 10.2 — Network Watcher flow logs enabled per watcher region."""
    req, name, desc, sev = (
        "10.2",
        "Network Watcher Flow Logs Enabled",
        "Verifies Network Watcher flow logs are enabled for VNet regions to capture traffic for CDE analysis",
        "HIGH",
    )
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        vnets = cache.get_vnets()
        vnet_regions = {vnet.location for vnet in vnets}
        if not vnet_regions:
            return create_control_result(req, name, desc, "PASS", sev,
                                         {"message": "No VNets found in subscription."})

        # Get all network watchers
        watchers = list(net_client.network_watchers.list_all())
        watcher_by_region = {w.location: w for w in watchers}

        regions_without_flow_logs = []
        for region in vnet_regions:
            watcher = watcher_by_region.get(region)
            if not watcher:
                regions_without_flow_logs.append({"region": region, "issue": "No Network Watcher"})
                continue
            watcher_rg = _rg_from_id(watcher.id)
            try:
                flow_logs = list(net_client.flow_logs.list(watcher_rg, watcher.name))
                enabled = [fl for fl in flow_logs if fl.enabled]
                if not enabled:
                    regions_without_flow_logs.append({"region": region, "issue": "No flow logs enabled"})
            except Exception:
                regions_without_flow_logs.append({"region": region, "issue": "Could not enumerate flow logs"})

        if regions_without_flow_logs:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"regions_missing_flow_logs": regions_without_flow_logs,
                 "vnet_regions": sorted(vnet_regions)},
                "Enable Network Watcher flow logs in all regions containing VNets. "
                "Navigate to Monitor > Network Watcher > Flow logs and create a flow log for each VNet.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_vnet_regions": sorted(vnet_regions)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_flow_log_retention(subscription_id, credential, cache):
    """Req 10.7 — Flow log retention >= 90 days."""
    req, name, desc, sev = (
        "10.7",
        "Network Watcher Flow Log Retention",
        f"Verifies Network Watcher flow log storage retention is at least {_FLOW_LOG_RETENTION_DAYS} days",
        "HIGH",
    )
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        watchers = list(net_client.network_watchers.list_all())
        short_retention = []
        skipped_watchers = []
        total_flow_logs = 0
        for watcher in watchers:
            watcher_rg = _rg_from_id(watcher.id)
            try:
                flow_logs = list(net_client.flow_logs.list(watcher_rg, watcher.name))
                for fl in flow_logs:
                    if not fl.enabled:
                        continue
                    total_flow_logs += 1
                    # retention_policy.enabled=False means unlimited retention → compliant.
                    # Only flag when retention is explicitly enabled with an insufficient day count.
                    # (Matches the same pattern used by check_activity_log_retention and
                    # check_sql_audit_retention: "days > 0 AND days < threshold".)
                    if fl.retention_policy and fl.retention_policy.enabled:
                        days = fl.retention_policy.days or 0
                        if days > 0 and days < _FLOW_LOG_RETENTION_DAYS:
                            short_retention.append({
                                "flow_log": fl.name,
                                "watcher_region": watcher.location,
                                "retention_days": days,
                            })
            except Exception as e:
                skipped_watchers.append({"watcher": watcher.name, "region": watcher.location, "error": str(e)})

        if total_flow_logs == 0:
            return create_control_result(req, name, desc, "WARNING", sev,
                                         {"message": "No enabled flow logs found to check retention.",
                                          "skipped_watchers": skipped_watchers})
        if short_retention:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"short_retention_count": len(short_retention),
                 "flow_logs": short_retention,
                 "skipped_watchers": skipped_watchers},
                f"Set flow log retention to at least {_FLOW_LOG_RETENTION_DAYS} days. "
                "Navigate to Monitor > Network Watcher > Flow logs and update the retention setting.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_flow_logs": total_flow_logs,
                                      "skipped_watchers": skipped_watchers})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_azure_firewall_or_nva(subscription_id, credential, cache):
    """Req 1.1 — At least one Azure Firewall or NVA is deployed."""
    req, name, desc, sev = (
        "1.1",
        "Azure Firewall or NVA Present",
        "Verifies at least one Azure Firewall or Network Virtual Appliance is deployed for perimeter protection",
        "MEDIUM",
    )
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        firewalls = list(net_client.azure_firewalls.list_all())
        if firewalls:
            return create_control_result(
                req, name, desc, "PASS", sev,
                {"azure_firewall_count": len(firewalls),
                 "firewalls": [{"name": f.name, "location": f.location} for f in firewalls]},
            )
        return create_control_result(
            req, name, desc, "FAIL", sev,
            {"azure_firewall_count": 0,
             "message": "No Azure Firewalls found. If using a third-party NVA, this finding may be a false positive."},
            "Deploy Azure Firewall or a certified Network Virtual Appliance (NVA) to provide "
            "centralised perimeter protection and traffic inspection for the CDE.",
        )
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_ddos_protection(subscription_id, credential, cache):
    """Req 1.1 — DDoS Protection Standard enabled on VNets."""
    req, name, desc, sev = (
        "1.1",
        "DDoS Protection Standard Enabled",
        "Verifies VNets have Azure DDoS Protection Standard enabled for adaptive attack mitigation",
        "MEDIUM",
    )
    try:
        vnets = cache.get_vnets()
        if not vnets:
            return create_control_result(req, name, desc, "PASS", sev,
                                         {"message": "No VNets found."})
        unprotected = [
            {"vnet": v.name, "location": v.location, "resource_group": _rg_from_id(v.id)}
            for v in vnets
            if not (v.enable_ddos_protection or (
                v.ddos_protection_plan is not None
            ))
        ]
        if unprotected:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"unprotected_count": len(unprotected), "total_vnets": len(vnets),
                 "unprotected_vnets": unprotected},
                "Enable Azure DDoS Protection Standard on VNets hosting CDE workloads. "
                "Navigate to the VNet > DDoS protection and select Standard.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_vnets": len(vnets)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_private_endpoints(subscription_id, credential, cache):
    """Req 1.3 — Private endpoints used for PaaS services."""
    req, name, desc, sev = (
        "1.3",
        "Private Endpoints for PaaS Services",
        "Verifies Storage Accounts, SQL Servers, and Key Vaults use Azure Private Endpoints "
        "to eliminate public internet exposure of PaaS data plane endpoints",
        "MEDIUM",
    )
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        private_endpoints = list(net_client.private_endpoints.list_by_subscription())
        # Extract which resources have private endpoints
        pe_resource_ids = set()
        for pe in private_endpoints:
            if pe.private_link_service_connections:
                for conn in pe.private_link_service_connections:
                    if conn.private_link_service_id:
                        pe_resource_ids.add(conn.private_link_service_id.lower())
            if pe.manual_private_link_service_connections:
                for conn in pe.manual_private_link_service_connections:
                    if conn.private_link_service_id:
                        pe_resource_ids.add(conn.private_link_service_id.lower())

        missing = []
        for sa in cache.get_storage_accounts():
            if sa.id.lower() not in pe_resource_ids:
                missing.append({"type": "Storage Account", "name": sa.name,
                                 "resource_group": _rg_from_id(sa.id)})
        for srv in cache.get_sql_servers():
            if srv.id.lower() not in pe_resource_ids:
                missing.append({"type": "SQL Server", "name": srv.name,
                                 "resource_group": _rg_from_id(srv.id)})
        for kv in cache.get_key_vaults():
            if kv.id.lower() not in pe_resource_ids:
                missing.append({"type": "Key Vault", "name": kv.name,
                                 "resource_group": _rg_from_id(kv.id)})

        if missing:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"resources_without_private_endpoint": len(missing),
                 "private_endpoint_count": len(private_endpoints),
                 "missing": missing[:30]},
                "Create Azure Private Endpoints for Storage Accounts, SQL Servers, and Key Vaults "
                "to remove their public endpoints from the internet. Also disable public network access "
                "on each resource after the private endpoint is configured.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"private_endpoints_found": len(private_endpoints)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


# ===================== DATA PROTECTION (Req 3 & 4) =====================


def check_storage_public_access(subscription_id, credential, cache):
    """Req 3.4 — Storage Accounts have public blob access disabled."""
    req, name, desc, sev = (
        "3.4",
        "Storage Account Public Blob Access Disabled",
        "Verifies all Storage Accounts have allowBlobPublicAccess set to false",
        "CRITICAL",
    )
    try:
        accounts = cache.get_storage_accounts()
        public_accounts = [
            {"name": sa.name, "resource_group": _rg_from_id(sa.id), "location": sa.location}
            for sa in accounts
            if sa.allow_blob_public_access is not False
        ]
        if public_accounts:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"public_access_count": len(public_accounts),
                 "total_accounts": len(accounts),
                 "accounts": public_accounts},
                "Disable public blob access on all Storage Accounts: "
                "az storage account update --allow-blob-public-access false "
                "--name <account> --resource-group <rg>",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_storage_accounts": len(accounts)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_storage_https_only(subscription_id, credential, cache):
    """Req 4.2 — Storage Accounts enforce HTTPS-only transfer."""
    req, name, desc, sev = (
        "4.2",
        "Storage Account HTTPS-Only Transfer",
        "Verifies all Storage Accounts enforce HTTPS-only traffic — HTTP connections are rejected",
        "HIGH",
    )
    try:
        accounts = cache.get_storage_accounts()
        http_allowed = [
            {"name": sa.name, "resource_group": _rg_from_id(sa.id)}
            for sa in accounts
            if not sa.enable_https_traffic_only
        ]
        if http_allowed:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"http_allowed_count": len(http_allowed), "total_accounts": len(accounts),
                 "accounts": http_allowed},
                "Enable HTTPS-only on all Storage Accounts: "
                "az storage account update --https-only true --name <account> --resource-group <rg>",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_storage_accounts": len(accounts)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_sql_tde(subscription_id, credential, cache):
    """Req 3.5 — All Azure SQL Databases have TDE enabled."""
    req, name, desc, sev = (
        "3.5",
        "SQL Database TDE Enabled",
        "Verifies all Azure SQL Databases have Transparent Data Encryption enabled",
        "CRITICAL",
    )
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        servers = cache.get_sql_servers()
        unencrypted = []
        total_dbs = 0
        for server in servers:
            rg = _rg_from_id(server.id)
            dbs = list(sql_client.databases.list_by_server(rg, server.name))
            for db in dbs:
                if db.name == "master":
                    continue
                total_dbs += 1
                try:
                    tde = sql_client.transparent_data_encryptions.get(rg, server.name, db.name, "current")
                    if tde.state != "Enabled":
                        unencrypted.append({
                            "server": server.name,
                            "database": db.name,
                            "resource_group": rg,
                        })
                except Exception:
                    unencrypted.append({
                        "server": server.name,
                        "database": db.name,
                        "resource_group": rg,
                        "note": "Could not retrieve TDE status",
                    })

        if unencrypted:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"unencrypted_count": len(unencrypted), "total_databases": total_dbs,
                 "unencrypted_databases": unencrypted},
                "Enable TDE on all Azure SQL Databases: "
                "az sql db tde set --status Enabled --resource-group <rg> --server <server> --database <db>",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_databases": total_dbs})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_sql_tls_version(subscription_id, credential, cache):
    """Req 4.2 — SQL Servers enforce minimum TLS 1.2."""
    req, name, desc, sev = (
        "4.2",
        "SQL Server Minimum TLS Version",
        "Verifies all Azure SQL Servers enforce a minimum TLS version of 1.2",
        "HIGH",
    )
    try:
        servers = cache.get_sql_servers()
        weak_tls = [
            {"server": s.name, "resource_group": _rg_from_id(s.id),
             "min_tls": s.minimal_tls_version or "Not set"}
            for s in servers
            if s.minimal_tls_version not in ("1.2", "1.3")
        ]
        if weak_tls:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"weak_tls_count": len(weak_tls), "total_servers": len(servers),
                 "servers": weak_tls},
                "Set minimum TLS to 1.2 on all SQL Servers: "
                "az sql server update --minimal-tls-version 1.2 --name <server> --resource-group <rg>",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_servers": len(servers)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_vm_disk_encryption(subscription_id, credential, cache):
    """Req 3.5 — VM managed disks encrypted at rest."""
    req, name, desc, sev = (
        "3.5",
        "VM Managed Disk Encryption",
        "Verifies all managed disks attached to Virtual Machines are encrypted at rest",
        "HIGH",
    )
    try:
        disks = cache.get_disks()
        # Only check data and OS disks (not unattached disks for CDE focus, but include all)
        unencrypted = []
        for disk in disks:
            enc = disk.encryption
            # EncryptionAtRestWithPlatformKey = PMK (platform-managed, acceptable)
            # EncryptionAtRestWithCustomerKey = CMK (customer-managed, preferred)
            # None / unknown = flag
            if enc is None or enc.type is None:
                unencrypted.append({
                    "disk": disk.name,
                    "resource_group": _rg_from_id(disk.id),
                    "encryption_type": "None",
                })
        if unencrypted:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"unencrypted_count": len(unencrypted), "total_disks": len(disks),
                 "disks": unencrypted[:20]},
                "Enable encryption on unencrypted managed disks. New disks are encrypted by default "
                "with platform-managed keys since 2017; this finding indicates very old or improperly "
                "created disks. Consider migrating to customer-managed key encryption for CDE disks.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_disks": len(disks)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_keyvault_soft_delete(subscription_id, credential, cache):
    """Req 3.1 — Key Vaults have soft delete and purge protection enabled."""
    req, name, desc, sev = (
        "3.1",
        "Key Vault Soft Delete and Purge Protection",
        "Verifies all Key Vaults have soft delete and purge protection enabled to prevent permanent key loss",
        "HIGH",
    )
    try:
        kv_client = KeyVaultManagementClient(credential, subscription_id)
        vaults_raw = cache.get_key_vaults()
        missing_protection = []
        for vault_ref in vaults_raw:
            rg = _rg_from_id(vault_ref.id)
            try:
                vault = kv_client.vaults.get(rg, vault_ref.name)
                props = vault.properties
                issues = []
                if not props.enable_soft_delete:
                    issues.append("soft delete disabled")
                if not props.enable_purge_protection:
                    issues.append("purge protection disabled")
                if issues:
                    missing_protection.append({
                        "vault": vault.name,
                        "resource_group": rg,
                        "issues": issues,
                    })
            except Exception:
                continue

        if missing_protection:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"unprotected_count": len(missing_protection),
                 "vaults": missing_protection},
                "Enable soft delete (min 7 days retention) and purge protection on all Key Vaults. "
                "Note: purge protection cannot be disabled once enabled. "
                "az keyvault update --enable-soft-delete true --enable-purge-protection true "
                "--name <vault> --resource-group <rg>",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_vaults": len(vaults_raw)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_keyvault_key_rotation(subscription_id, credential, cache):
    """Req 3.7 — Key Vault keys have a rotation policy configured."""
    req, name, desc, sev = (
        "3.7",
        "Key Vault Key Rotation Policy",
        "Verifies all keys in Key Vault have an automatic rotation policy configured",
        "HIGH",
    )
    try:
        kv_client = KeyVaultManagementClient(credential, subscription_id)
        vaults_raw = cache.get_key_vaults()
        keys_without_rotation = []
        total_keys = 0
        for vault_ref in vaults_raw:
            rg = _rg_from_id(vault_ref.id)
            try:
                vault = kv_client.vaults.get(rg, vault_ref.name)
                vault_uri = vault.properties.vault_uri
                key_client = KeyClient(vault_url=vault_uri, credential=credential)
                for key_props in key_client.list_properties_of_keys():
                    total_keys += 1
                    try:
                        rotation_policy = key_client.get_key_rotation_policy(key_props.name)
                        # A policy exists; check if it has a lifetime action
                        has_action = bool(
                            rotation_policy.lifetime_actions and len(rotation_policy.lifetime_actions) > 0
                        )
                        if not has_action:
                            keys_without_rotation.append({
                                "vault": vault.name,
                                "key": key_props.name,
                                "issue": "Rotation policy has no lifetime actions",
                            })
                    except Exception:
                        keys_without_rotation.append({
                            "vault": vault.name,
                            "key": key_props.name,
                            "issue": "No rotation policy configured or could not be read",
                        })
            except Exception:
                continue

        if keys_without_rotation:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"keys_without_rotation": len(keys_without_rotation), "total_keys": total_keys,
                 "keys": keys_without_rotation[:20]},
                "Configure automatic rotation policies on all Key Vault keys used in the CDE. "
                "Navigate to Key Vault > Keys > <key> > Rotation policy and set a rotation interval.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_keys": total_keys})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_app_service_https_tls(subscription_id, credential, cache):
    """Req 4.2 — App Services enforce HTTPS-only and TLS 1.2."""
    req, name, desc, sev = (
        "4.2",
        "App Service HTTPS-Only and TLS 1.2",
        "Verifies all App Service web apps enforce HTTPS-only traffic and require minimum TLS 1.2",
        "HIGH",
    )
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)
        apps = cache.get_web_apps()
        violations = []
        for app in apps:
            rg = _rg_from_id(app.id)
            issues = []
            if not app.https_only:
                issues.append("HTTPS-only disabled")
            try:
                config = web_client.web_apps.get_configuration(rg, app.name)
                tls = config.min_tls_version
                if tls and tls not in ("1.2", "1.3"):
                    issues.append(f"TLS version: {tls}")
                elif not tls:
                    issues.append("TLS version not set")
            except Exception:
                pass
            if issues:
                violations.append({"app": app.name, "resource_group": rg, "issues": issues})

        if violations:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"violation_count": len(violations), "total_apps": len(apps),
                 "apps": violations[:20]},
                "Enable HTTPS-only and set minimum TLS to 1.2 on all App Services: "
                "az webapp update --https-only true --name <app> --resource-group <rg> && "
                "az webapp config set --min-tls-version 1.2 --name <app> --resource-group <rg>",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_apps": len(apps)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_redis_ssl_only(subscription_id, credential, cache):
    """Req 4.2 — Redis Cache non-SSL port disabled."""
    req, name, desc, sev = (
        "4.2",
        "Redis Cache Non-SSL Port Disabled",
        "Verifies all Azure Cache for Redis instances have the unencrypted (non-SSL) port disabled",
        "HIGH",
    )
    try:
        redis_client = RedisManagementClient(credential, subscription_id)
        caches = list(redis_client.redis.list_by_subscription())
        insecure = [
            {"name": r.name, "resource_group": _rg_from_id(r.id), "location": r.location}
            for r in caches
            if r.enable_non_ssl_port
        ]
        if insecure:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"insecure_count": len(insecure), "total_caches": len(caches),
                 "caches": insecure},
                "Disable the non-SSL port on all Redis Cache instances: "
                "az redis update --name <name> --resource-group <rg> --set enableNonSslPort=false",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_caches": len(caches)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_app_settings_plaintext_secrets(subscription_id, credential, cache):
    """Req 3.4 — App Service application settings do not contain plaintext secrets."""
    req, name, desc, sev = (
        "3.4",
        "No Plaintext Secrets in App Service Settings",
        "Scans App Service application setting key names for patterns that suggest stored credentials "
        "rather than Key Vault references",
        "HIGH",
    )
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)
        apps = cache.get_web_apps()
        suspect = []
        for app in apps:
            rg = _rg_from_id(app.id)
            try:
                settings = web_client.web_apps.list_application_settings(rg, app.name)
                if not settings.properties:
                    continue
                flagged_keys = [
                    k for k in settings.properties
                    if _CRED_SECRET_PATTERNS.search(k)
                    and not settings.properties[k].startswith("@Microsoft.KeyVault")
                ]
                if flagged_keys:
                    suspect.append({
                        "app": app.name,
                        "resource_group": rg,
                        "suspicious_setting_keys": flagged_keys[:10],
                    })
            except Exception:
                continue

        if suspect:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"apps_with_suspect_settings": len(suspect), "total_apps": len(apps),
                 "apps": suspect[:20]},
                "Move secrets from App Service application settings to Azure Key Vault and reference "
                "them using Key Vault references: @Microsoft.KeyVault(SecretUri=...)",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_apps": len(apps)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_keyvault_certificate_expiry(subscription_id, credential, cache):
    """Req 4.2 — Key Vault certificates expiring within 30 days."""
    req, name, desc, sev = (
        "4.2",
        "Key Vault Certificate Expiry",
        f"Verifies no certificates in Key Vault are expiring within {_CERT_EXPIRY_DAYS} days",
        "HIGH",
    )
    try:
        kv_client = KeyVaultManagementClient(credential, subscription_id)
        vaults_raw = cache.get_key_vaults()
        expiring = []
        total_certs = 0
        now = datetime.now(timezone.utc)
        threshold = now + timedelta(days=_CERT_EXPIRY_DAYS)
        for vault_ref in vaults_raw:
            rg = _rg_from_id(vault_ref.id)
            try:
                vault = kv_client.vaults.get(rg, vault_ref.name)
                cert_client = CertificateClient(
                    vault_url=vault.properties.vault_uri, credential=credential
                )
                for cert in cert_client.list_properties_of_certificates():
                    total_certs += 1
                    if cert.expires_on and cert.expires_on <= threshold:
                        days_left = (cert.expires_on - now).days
                        expiring.append({
                            "vault": vault.name,
                            "certificate": cert.name,
                            "expires_on": cert.expires_on.isoformat(),
                            "days_until_expiry": days_left,
                        })
            except Exception:
                continue

        if expiring:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"expiring_count": len(expiring), "total_certificates": total_certs,
                 "certificates": expiring},
                "Renew expiring certificates before they expire to prevent TLS failures. "
                "Enable automatic certificate renewal in Key Vault if the CA supports it.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_certificates": total_certs})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_storage_encryption(subscription_id, credential, cache):
    """Req 3.5 — Storage Account encryption at rest using service-managed or customer-managed keys."""
    req, name, desc, sev = (
        "3.5",
        "Storage Account Encryption at Rest",
        "Verifies Storage Account encryption uses service-managed or customer-managed keys",
        "MEDIUM",
    )
    try:
        accounts = cache.get_storage_accounts()
        unencrypted = [
            {"name": sa.name, "resource_group": _rg_from_id(sa.id)}
            for sa in accounts
            if not sa.encryption
        ]
        if unencrypted:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"unencrypted_count": len(unencrypted), "total_accounts": len(accounts),
                 "accounts": unencrypted},
                "Ensure encryption is enabled on all Storage Accounts. "
                "All new Storage Accounts are encrypted by default; this finding indicates "
                "a legacy account that should be investigated.",
            )
        service_managed = [sa.name for sa in accounts
                           if "keyvault" not in (sa.encryption.key_source or "").lower()]
        customer_managed = [sa.name for sa in accounts
                            if "keyvault" in (sa.encryption.key_source or "").lower()]
        return create_control_result(req, name, desc, "PASS", sev, {
            "total_accounts": len(accounts),
            "service_managed_key_count": len(service_managed),
            "customer_managed_key_count": len(customer_managed),
            "note": (
                f"{len(service_managed)} account(s) use service-managed keys; "
                f"{len(customer_managed)} use customer-managed keys (CMK). "
                "Consider CMK for stronger PCI-DSS key management controls."
                if service_managed else
                "All accounts use customer-managed keys (CMK)."
            ),
        })
    except Exception as e:
        return _warning(req, name, desc, sev, e)

# ===================== ACCESS CONTROL (Req 7 & 8) =====================


def check_subscription_owner_count(subscription_id, credential, cache):
    """Req 7.1 — Subscription Owner count <= 3."""
    req, name, desc, sev = (
        "7.1",
        "Subscription Owner Count",
        f"Verifies no more than {_OWNER_COUNT_THRESHOLD} users hold the Owner role at subscription scope",
        "CRITICAL",
    )
    try:
        assignments = cache.get_role_assignments()
        scope = f"/subscriptions/{subscription_id}"
        owner_users = [
            a for a in assignments
            if (a.scope == scope or a.scope == f"/subscriptions/{subscription_id}/")
            and a.role_definition_id
            and a.role_definition_id.split("/")[-1] == _OWNER_ROLE_ID
            and (a.principal_type or "").lower() == "user"
        ]
        count = len(owner_users)
        if count > _OWNER_COUNT_THRESHOLD:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"owner_count": count, "threshold": _OWNER_COUNT_THRESHOLD,
                 "owners": [{"principal_id": a.principal_id,
                              "principal_type": a.principal_type} for a in owner_users]},
                f"Reduce subscription Owner assignments to {_OWNER_COUNT_THRESHOLD} or fewer. "
                "Use time-limited Privileged Identity Management (PIM) assignments for admin access "
                "rather than permanent Owner role assignments.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"owner_count": count})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_privileged_direct_user_assignments(subscription_id, credential, cache):
    """Req 7.1 — Owner/Contributor not directly assigned to individual users."""
    req, name, desc, sev = (
        "7.1",
        "Owner/Contributor Directly Assigned to Users",
        "Verifies Owner and Contributor roles are not directly assigned to individual user accounts "
        "(assignments should target groups for lifecycle management and auditability)",
        "HIGH",
    )
    try:
        assignments = cache.get_role_assignments()
        direct_users = [
            {"principal_id": a.principal_id,
             "role_id": a.role_definition_id.split("/")[-1],
             "scope": a.scope}
            for a in assignments
            if a.role_definition_id
            and a.role_definition_id.split("/")[-1] in _PRIVILEGED_ROLE_IDS
            and (a.principal_type or "").lower() == "user"
        ]
        if direct_users:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"direct_user_count": len(direct_users), "assignments": direct_users[:20]},
                "Replace direct user assignments for Owner/Contributor with group-based assignments. "
                "Use Azure AD security groups and assign roles to groups rather than individuals.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_assignments": len(assignments)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_guest_users_privileged_roles(subscription_id, credential, cache):
    """Req 7.2 — No guest/external users hold privileged roles.

    ARM RBAC exposes principal_type but not UPNs. ForeignGroup (cross-tenant group)
    is detectable here. Guest User objects (principal_type == "User") require
    Microsoft Graph to resolve the UPN and confirm #EXT# status — that is out of
    ARM scope and is not checked here.
    """
    req, name, desc, sev = (
        "7.2",
        "Guest Users With Privileged Roles",
        "Verifies no cross-tenant (ForeignGroup) principals hold Owner or Contributor roles. "
        "Guest User detection requires Microsoft Graph API and is not covered by this check.",
        "HIGH",
    )
    try:
        assignments = cache.get_role_assignments()
        # Only ForeignGroup is reliably detectable via ARM RBAC without Graph API.
        # Guest User objects have principal_type == "User" and their #EXT# UPN is
        # not exposed on the role assignment — Graph API would be needed to resolve them.
        guest_privileged = [
            {"principal_id": a.principal_id,
             "principal_type": a.principal_type,
             "scope": a.scope}
            for a in assignments
            if a.role_definition_id
            and a.role_definition_id.split("/")[-1] in _PRIVILEGED_ROLE_IDS
            and (a.principal_type or "").lower() == "foreigngroup"
        ]
        if guest_privileged:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"guest_privileged_count": len(guest_privileged), "assignments": guest_privileged},
                "Remove Owner and Contributor role assignments from cross-tenant (ForeignGroup) "
                "principals. Grant only the minimum required permissions via a custom RBAC role.",
            )
        return create_control_result(req, name, desc, "PASS", sev, {
            "total_assignments": len(assignments),
            "limitation": (
                "Guest User objects (principal_type=User with #EXT# UPN) cannot be detected "
                "via ARM RBAC alone — use Microsoft Graph API or Azure AD Access Reviews to "
                "audit guest user role assignments."
            ),
        })
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_classic_admins(subscription_id, credential, cache):
    """Req 8.2 — No classic co-administrators present."""
    req, name, desc, sev = (
        "8.2",
        "Classic Co-Administrators Present",
        "Verifies no Azure classic co-administrators exist on the subscription",
        "HIGH",
    )
    try:
        auth_client = AuthorizationManagementClient(credential, subscription_id)
        classic_admins = list(auth_client.classic_administrators.list())
        # Filter out the account admin (always present, legacy artifact)
        co_admins = [
            {"email": ca.email_address, "role": ca.role}
            for ca in classic_admins
            if (ca.role or "").lower() not in ("accountadministrator",)
        ]
        if co_admins:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"classic_admin_count": len(co_admins), "admins": co_admins},
                "Remove classic co-administrator assignments. Navigate to the Azure Portal > "
                "Subscriptions > Access control (IAM) > Classic administrators and remove co-admins.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"classic_admins_found": 0})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_stale_role_assignments(subscription_id, credential, cache):
    """Req 7.2 — No stale role assignments pointing to deleted AAD objects."""
    req, name, desc, sev = (
        "7.2",
        "Stale Role Assignments",
        "Verifies no role assignments reference deleted Azure AD objects (principal type 'Unknown')",
        "MEDIUM",
    )
    try:
        assignments = cache.get_role_assignments()
        stale = [
            {"principal_id": a.principal_id, "scope": a.scope,
             "role_id": a.role_definition_id.split("/")[-1] if a.role_definition_id else ""}
            for a in assignments
            if (a.principal_type or "").lower() == "unknown"
        ]
        if stale:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"stale_count": len(stale), "stale_assignments": stale[:20]},
                "Remove stale role assignments via: "
                "az role assignment delete --assignee <principal_id> --role <role> --scope <scope>",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_assignments": len(assignments)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_custom_role_wildcards(subscription_id, credential, cache):
    """Req 7.2 — No wildcard actions in custom RBAC role definitions."""
    req, name, desc, sev = (
        "7.2",
        "No Wildcard Actions in Custom RBAC Roles",
        "Verifies no custom RBAC role definitions include wildcard (*) actions",
        "HIGH",
    )
    try:
        custom_roles = cache.get_role_definitions()
        wildcard_roles = []
        for role in custom_roles:
            wild_perms = []
            for perm in (role.permissions or []):
                if "*" in (perm.actions or []):
                    wild_perms.append("actions: *")
                if "*" in (perm.data_actions or []):
                    wild_perms.append("data_actions: *")
            if wild_perms:
                wildcard_roles.append({
                    "role_name": role.role_name,
                    "wildcard_permissions": wild_perms,
                })
        if wildcard_roles:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"wildcard_role_count": len(wildcard_roles), "roles": wildcard_roles},
                "Replace wildcard (*) actions in custom RBAC roles with explicit, least-privilege "
                "action lists. Review each role and grant only the specific operations required.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_custom_roles": len(custom_roles)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_managed_identity_usage(subscription_id, credential, cache):
    """Req 8.2 — VMs and App Services use managed identity."""
    req, name, desc, sev = (
        "8.2",
        "VMs and App Services Use Managed Identity",
        "Verifies Virtual Machines and App Services use managed identities rather than embedded credentials",
        "MEDIUM",
    )
    try:
        vms = cache.get_vms()
        apps = cache.get_web_apps()
        vms_without_identity = [
            {"vm": vm.name, "resource_group": _rg_from_id(vm.id)}
            for vm in vms
            if not vm.identity or vm.identity.type is None
        ]
        apps_without_identity = [
            {"app": app.name, "resource_group": _rg_from_id(app.id)}
            for app in apps
            if not app.identity or app.identity.type is None
        ]
        all_missing = (
            [{"type": "VM", **r} for r in vms_without_identity] +
            [{"type": "App Service", **r} for r in apps_without_identity]
        )
        if all_missing:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"resources_without_identity": len(all_missing),
                 "vms_missing": len(vms_without_identity),
                 "apps_missing": len(apps_without_identity),
                 "resources": all_missing[:20]},
                "Enable system-assigned or user-assigned managed identity on VMs and App Services. "
                "This allows them to authenticate to Azure services without storing credentials.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_vms": len(vms), "total_apps": len(apps)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_service_principal_credential_expiry(subscription_id, credential, cache):
    """Req 8.3 — Service principals have credential expiry date set."""
    req, name, desc, sev = (
        "8.3",
        "Service Principals Have Credential Expiry",
        "Verifies service principal password and certificate credentials have an expiry date configured",
        "HIGH",
    )
    # This check requires Microsoft Graph API access which is not in standard Azure RM SDK.
    # Return informational WARNING with guidance.
    return create_control_result(
        req, name, desc, "WARNING", sev,
        {
            "reason": (
                "Checking service principal credential expiry requires Microsoft Graph API access "
                "(Application.Read.All permission), which is outside the Azure Resource Manager SDK "
                "used by this script."
            ),
            "manual_check": (
                "Navigate to Azure AD > App registrations > All applications. For each app, "
                "go to Certificates & secrets and verify all credentials have an expiry date set. "
                "Alternatively, use: az ad app credential list --id <app_id>"
            ),
        },
        "Set expiry dates on all service principal password and certificate credentials. "
        "Credentials without expiry violate PCI-DSS Req 8.3 key rotation requirements.",
    )


def check_mfa_enforcement(subscription_id, credential, cache):
    """Req 8.4 — MFA enforced via Security Defaults or Conditional Access."""
    req, name, desc, sev = (
        "8.4",
        "MFA Enforced via Security Defaults or Conditional Access",
        "Verifies Azure AD Security Defaults are enabled or a Conditional Access MFA policy is present",
        "CRITICAL",
    )
    # Conditional Access and Security Defaults require Microsoft Graph API.
    # Attempt to check via Defender for Cloud security contacts as a proxy indicator.
    return create_control_result(
        req, name, desc, "WARNING", sev,
        {
            "reason": (
                "Verifying MFA enforcement requires Microsoft Graph API access "
                "(Policy.Read.All permission), which is outside the Azure Resource Manager SDK. "
                "This check returns WARNING so the finding is surfaced for manual verification."
            ),
            "manual_check": (
                "1. Navigate to Azure AD > Properties > Manage security defaults — verify enabled. "
                "2. Or navigate to Azure AD > Security > Conditional Access > Policies — verify "
                "an MFA-enforcing policy targeting all users is in Enabled state."
            ),
        },
        "Enable Security Defaults or create a Conditional Access policy requiring MFA for all users "
        "accessing cloud applications. Security Defaults is free; Conditional Access requires Azure AD P1.",
    )


def check_sp_owner_role(subscription_id, credential, cache):
    """Req 7.1 — No service principal holds Owner role at subscription scope."""
    req, name, desc, sev = (
        "7.1",
        "No Service Principal With Subscription Owner Role",
        "Verifies no service principal holds the Owner role at subscription scope",
        "HIGH",
    )
    try:
        assignments = cache.get_role_assignments()
        scope = f"/subscriptions/{subscription_id}"
        sp_owners = [
            {"principal_id": a.principal_id, "scope": a.scope}
            for a in assignments
            if a.role_definition_id
            and a.role_definition_id.split("/")[-1] == _OWNER_ROLE_ID
            and (a.principal_type or "").lower() == "serviceprincipal"
            and (a.scope or "").rstrip("/") == scope.rstrip("/")
        ]
        if sp_owners:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"sp_owner_count": len(sp_owners), "assignments": sp_owners},
                "Replace subscription-level Owner role assignments for service principals with "
                "least-privilege custom RBAC roles scoped to the specific resource groups needed.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_assignments": len(assignments)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


# ===================== LOGGING & MONITORING (Req 10 & 11) =====================


def check_activity_log_diagnostic_settings(subscription_id, credential, cache):
    """Req 10.2 — Activity Log exported via diagnostic settings."""
    req, name, desc, sev = (
        "10.2",
        "Activity Log Diagnostic Settings",
        "Verifies the Azure Activity Log has a diagnostic setting exporting to Storage or Log Analytics",
        "CRITICAL",
    )
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"
        settings = list(monitor_client.diagnostic_settings.list(scope))
        if not settings:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"diagnostic_settings_count": 0,
                 "explanation": "No diagnostic settings found — Activity Log is not being exported."},
                "Create a diagnostic setting to export the Activity Log to a Log Analytics workspace "
                "or Storage Account. Navigate to Monitor > Activity log > Export Activity Logs.",
            )
        # A setting with zero enabled log categories is a no-op — logs are not actually exported.
        active_settings = [
            s for s in settings
            if any(getattr(log, "enabled", False) for log in (s.logs or []))
        ]
        if not active_settings:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"diagnostic_settings_count": len(settings),
                 "active_settings_count": 0,
                 "explanation": (
                     f"{len(settings)} diagnostic setting(s) exist but none have any log "
                     "categories enabled — Activity Log data is not being captured."
                 )},
                "Edit each diagnostic setting and enable at least the Administrative, Security, "
                "Policy, and Alert log categories.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"diagnostic_settings_count": len(settings),
                                      "active_settings_count": len(active_settings),
                                      "settings": [s.name for s in active_settings]})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_activity_log_retention(subscription_id, credential, cache):
    """Req 10.7 — Activity Log retained >= 365 days."""
    req, name, desc, sev = (
        "10.7",
        "Activity Log Retention",
        f"Verifies Activity Log data is retained for at least {_LOG_RETENTION_DAYS} days",
        "HIGH",
    )
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"
        settings = list(monitor_client.diagnostic_settings.list(scope))
        if not settings:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"message": "No diagnostic settings found — retention cannot be verified."},
                f"Configure Activity Log diagnostic settings with at least {_LOG_RETENTION_DAYS}-day retention.",
            )
        inadequate = []
        for s in settings:
            if s.retention_policy and s.retention_policy.enabled:
                days = s.retention_policy.days or 0
                if days > 0 and days < _LOG_RETENTION_DAYS:
                    inadequate.append({"setting": s.name, "retention_days": days})
        if inadequate:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"inadequate_retention": inadequate},
                f"Set Activity Log diagnostic setting retention to at least {_LOG_RETENTION_DAYS} days, "
                "or set retention to 0 (unlimited) and manage retention at the Log Analytics workspace level.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_diagnostic_settings": len(settings)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_log_analytics_retention(subscription_id, credential, cache):
    """Req 10.7 — Log Analytics workspaces retain logs >= 365 days."""
    req, name, desc, sev = (
        "10.7",
        "Log Analytics Workspace Retention",
        f"Verifies all Log Analytics workspaces have retention set to at least {_LOG_RETENTION_DAYS} days",
        "HIGH",
    )
    try:
        if LogAnalyticsManagementClient is None:
            raise ImportError("LogAnalyticsManagementClient not available")
        la_client = LogAnalyticsManagementClient(credential, subscription_id)
        workspaces = list(la_client.workspaces.list())
        if not workspaces:
            return create_control_result(req, name, desc, "WARNING", sev,
                                         {"message": "No Log Analytics workspaces found."})
        short_retention = [
            {"workspace": ws.name, "resource_group": _rg_from_id(ws.id),
             "retention_days": ws.retention_in_days}
            for ws in workspaces
            if (ws.retention_in_days or 0) < _LOG_RETENTION_DAYS
        ]
        if short_retention:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"short_retention_count": len(short_retention), "total_workspaces": len(workspaces),
                 "workspaces": short_retention},
                f"Set Log Analytics workspace retention to at least {_LOG_RETENTION_DAYS} days. "
                "Navigate to the workspace > Usage and estimated costs > Data retention.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_workspaces": len(workspaces)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_sql_auditing(subscription_id, credential, cache):
    """Req 10.2 — SQL Server auditing enabled."""
    req, name, desc, sev = (
        "10.2",
        "SQL Server Auditing Enabled",
        "Verifies all Azure SQL Servers have server-level auditing enabled",
        "HIGH",
    )
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        servers = cache.get_sql_servers()
        not_audited = []
        for server in servers:
            rg = _rg_from_id(server.id)
            try:
                policy = sql_client.server_blob_auditing_policies.get(rg, server.name)
                if policy.state != "Enabled":
                    not_audited.append({"server": server.name, "resource_group": rg,
                                        "state": policy.state})
            except Exception:
                not_audited.append({"server": server.name, "resource_group": rg,
                                    "note": "Could not retrieve auditing policy"})

        if not_audited:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"unaudited_count": len(not_audited), "total_servers": len(servers),
                 "servers": not_audited},
                "Enable auditing on all SQL Servers: Navigate to the SQL Server > Auditing and "
                "enable auditing to Log Analytics, Event Hub, or Storage Account.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_servers": len(servers)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_sql_audit_retention(subscription_id, credential, cache):
    """Req 10.7 — SQL Server audit log retention >= 90 days."""
    req, name, desc, sev = (
        "10.7",
        "SQL Server Audit Log Retention",
        f"Verifies SQL Server audit log storage retention is at least {_SQL_AUDIT_RETENTION_DAYS} days",
        "MEDIUM",
    )
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        servers = cache.get_sql_servers()
        short_retention = []
        for server in servers:
            rg = _rg_from_id(server.id)
            try:
                policy = sql_client.server_blob_auditing_policies.get(rg, server.name)
                if policy.state == "Enabled":
                    days = policy.retention_days or 0
                    if days > 0 and days < _SQL_AUDIT_RETENTION_DAYS:
                        short_retention.append({"server": server.name, "resource_group": rg,
                                                "retention_days": days})
            except Exception:
                continue

        if short_retention:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"short_retention_count": len(short_retention), "servers": short_retention},
                f"Set SQL Server audit log retention to at least {_SQL_AUDIT_RETENTION_DAYS} days.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_servers": len(servers)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_keyvault_diagnostic_logging(subscription_id, credential, cache):
    """Req 10.2 — Key Vaults have diagnostic logging enabled."""
    req, name, desc, sev = (
        "10.2",
        "Key Vault Diagnostic Logging",
        "Verifies all Key Vaults have diagnostic settings configured to capture AuditEvent logs",
        "HIGH",
    )
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        vaults = cache.get_key_vaults()
        not_logging = []
        for vault in vaults:
            try:
                settings = list(monitor_client.diagnostic_settings.list(vault.id))
                has_audit = any(
                    any((log.category or "").lower() in ("auditevent", "alllogs")
                        and log.enabled
                        for log in (s.logs or []))
                    for s in settings
                )
                if not settings or not has_audit:
                    not_logging.append({"vault": vault.name,
                                        "resource_group": _rg_from_id(vault.id)})
            except Exception:
                not_logging.append({"vault": vault.name,
                                     "resource_group": _rg_from_id(vault.id),
                                     "note": "Could not check diagnostic settings"})

        if not_logging:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"unlogged_count": len(not_logging), "total_vaults": len(vaults),
                 "vaults": not_logging},
                "Enable diagnostic settings on each Key Vault to capture AuditEvent logs. "
                "Navigate to the Key Vault > Diagnostic settings > Add diagnostic setting.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_vaults": len(vaults)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_storage_account_logging(subscription_id, credential, cache):
    """Req 10.2 — Storage Account blob logging enabled."""
    req, name, desc, sev = (
        "10.2",
        "Storage Account Logging",
        "Verifies all Storage Accounts have blob service logging enabled for read, write, and delete operations",
        "MEDIUM",
    )
    try:
        storage_client = StorageManagementClient(credential, subscription_id)
        accounts = cache.get_storage_accounts()
        not_logging = []
        for sa in accounts:
            rg = _rg_from_id(sa.id)
            try:
                blob_props = storage_client.blob_services.get_service_properties(rg, sa.name)
                logging_props = blob_props.logging if blob_props else None
                if not logging_props or not (
                    logging_props.read and logging_props.write and logging_props.delete
                ):
                    not_logging.append({"account": sa.name, "resource_group": rg})
            except Exception:
                continue

        if not_logging:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"unlogged_count": len(not_logging), "total_accounts": len(accounts),
                 "accounts": not_logging[:20]},
                "Enable Storage Analytics logging on all Storage Accounts for read, write, and delete "
                "operations. Navigate to Storage Account > Monitoring > Diagnostic settings.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_accounts": len(accounts)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_defender_for_cloud_plans(subscription_id, credential, cache):
    """Req 10.6 — Defender for Cloud Standard plans enabled for VMs, SQL, Storage."""
    req, name, desc, sev = (
        "10.6",
        "Defender for Cloud Standard Tier Enabled",
        "Verifies Microsoft Defender for Cloud Standard plans are enabled for Virtual Machines, SQL, and Storage",
        "HIGH",
    )
    try:
        pricings = cache.get_defender_pricings()
        pricing_map = {p.name: p.pricing_tier for p in pricings}
        required_plans = ["VirtualMachines", "SqlServers", "StorageAccounts"]
        not_standard = [
            {"plan": plan, "current_tier": pricing_map.get(plan, "Not found")}
            for plan in required_plans
            if pricing_map.get(plan, "").lower() != "standard"
        ]
        if not_standard:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"plans_not_standard": not_standard, "all_plans": pricing_map},
                "Enable Defender for Cloud Standard tier for VirtualMachines, SqlServers, and StorageAccounts. "
                "Navigate to Defender for Cloud > Environment settings > Subscription > Defender plans.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"standard_plans_enabled": required_plans})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_defender_security_contacts(subscription_id, credential, cache):
    """Req 10.6 — Defender for Cloud security contacts configured."""
    req, name, desc, sev = (
        "10.6",
        "Defender for Cloud Security Contacts",
        "Verifies at least one security notification contact is configured with email alerts enabled",
        "MEDIUM",
    )
    try:
        security_client = SecurityCenter(credential, subscription_id)
        contacts = list(security_client.security_contacts.list())
        def _alerts_enabled(contact) -> bool:
            """alert_notifications is a plain "On"/"Off" string in older SDK versions
            and a SecurityContactPropertiesAlertNotifications object in newer ones."""
            v = contact.alert_notifications
            if v is None:
                return False
            if isinstance(v, str):
                return v.lower() == "on"
            # Object form: check .state attribute (newer azure-mgmt-security)
            state = getattr(v, "state", None)
            return (state or "").lower() == "on"

        valid_contacts = [c for c in contacts if c.email and _alerts_enabled(c)]
        if not valid_contacts:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"contacts_found": len(contacts), "valid_contacts": 0},
                "Configure security contacts in Defender for Cloud with email notifications enabled. "
                "Navigate to Defender for Cloud > Environment settings > Email notifications.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"valid_contacts": len(valid_contacts)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_defender_auto_provisioning(subscription_id, credential, cache):
    """Req 10.2 — Defender for Cloud auto-provisioning agents enabled.

    MMA (Log Analytics agent) is being sunset in favour of AMA (Azure Monitor Agent).
    A subscription is compliant if either agent has auto-provisioning enabled.
    """
    req, name, desc, sev = (
        "10.2",
        "Defender for Cloud Auto-Provisioning",
        "Verifies Defender for Cloud auto-provisioning is enabled for the Log Analytics agent (MMA) "
        "or the newer Azure Monitor Agent (AMA)",
        "HIGH",
    )
    try:
        security_client = SecurityCenter(credential, subscription_id)
        settings = list(security_client.auto_provisioning_settings.list())
        setting_map = {s.name: s.auto_provision for s in settings}
        # MMA keys (legacy): "mma-agent" or "MicrosoftMonitoringAgent"
        # AMA key (current):  "AzureMonitoringAgent"
        mma_on = setting_map.get("mma-agent", setting_map.get("MicrosoftMonitoringAgent", "Off")) == "On"
        ama_on = setting_map.get("AzureMonitoringAgent", "Off") == "On"
        if not mma_on and not ama_on:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"all_settings": setting_map},
                "Enable auto-provisioning for the Azure Monitor Agent (AMA) in Defender for Cloud. "
                "Navigate to Defender for Cloud > Environment settings > Auto provisioning. "
                "MMA is being retired — prefer AMA for new deployments.",
            )
        return create_control_result(req, name, desc, "PASS", sev, {
            "auto_provision_settings": setting_map,
            "mma_enabled": mma_on,
            "ama_enabled": ama_on,
        })
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_activity_log_alerts(subscription_id, credential, cache):
    """Req 10.6 — Activity Log alerts configured for critical security operations."""
    req, name, desc, sev = (
        "10.6",
        "Activity Log Alerts for Critical Operations",
        "Verifies Azure Monitor Activity Log alerts cover critical security events such as "
        "Key Vault deletion, policy assignment deletion, and NSG rule modification",
        "HIGH",
    )
    _CRITICAL_OPERATIONS = {
        "microsoft.keyvault/vaults/delete",
        "microsoft.authorization/policyassignments/delete",
        "microsoft.network/networksecuritygroups/delete",
        "microsoft.network/networksecuritygroups/securityrules/delete",
        "microsoft.network/networksecuritygroups/write",
        "microsoft.security/securitycontacts/delete",
    }
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        alerts = list(monitor_client.activity_log_alerts.list_by_subscription_id())
        covered_ops = set()
        for alert in alerts:
            if not alert.enabled:
                continue
            for condition in (alert.condition.all_of or []):
                if condition.field == "operationName" and condition.equals:
                    covered_ops.add(condition.equals.lower())
        missing_ops = _CRITICAL_OPERATIONS - covered_ops
        if missing_ops:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"alert_count": len(alerts), "covered_operations": sorted(covered_ops),
                 "missing_operations": sorted(missing_ops)},
                "Create Activity Log alerts for critical security operations. "
                "Navigate to Monitor > Alerts > Create > Activity Log signal.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"alerts_checked": len(alerts),
                                      "covered_operations": sorted(covered_ops)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_monitor_metric_alerts(subscription_id, credential, cache):
    """Req 10.6 — Azure Monitor metric alerts configured."""
    req, name, desc, sev = (
        "10.6",
        "Azure Monitor Metric Alerts",
        "Verifies at least one Azure Monitor metric alert is configured for the subscription",
        "MEDIUM",
    )
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        alerts = list(monitor_client.metric_alerts.list_by_subscription())
        enabled_alerts = [a for a in alerts if a.enabled]
        if not enabled_alerts:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"total_metric_alerts": len(alerts), "enabled_alerts": 0},
                "Configure Azure Monitor metric alerts for key resources (VM CPU, database DTU, "
                "storage failures). Navigate to Monitor > Alerts > Create.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"enabled_metric_alerts": len(enabled_alerts)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_sentinel_workspace(subscription_id, credential, cache):
    """Req 10.6 — Microsoft Sentinel workspace present."""
    req, name, desc, sev = (
        "10.6",
        "Microsoft Sentinel Workspace",
        "Verifies Microsoft Sentinel (SecurityInsights solution) is deployed in a Log Analytics workspace",
        "HIGH",
    )
    try:
        if LogAnalyticsManagementClient is None or OperationsManagementClient is None:
            raise ImportError("LogAnalyticsManagementClient or OperationsManagementClient not available")
        la_client = LogAnalyticsManagementClient(credential, subscription_id)
        om_client = OperationsManagementClient(credential, subscription_id)
        workspaces = list(la_client.workspaces.list())
        sentinel_found = False
        for ws in workspaces:
            rg = _rg_from_id(ws.id)
            try:
                solutions = list(om_client.solutions.list_by_resource_group(rg))
                if any("securityinsights" in (s.name or "").lower() for s in solutions):
                    sentinel_found = True
                    break
            except Exception:
                continue

        if not sentinel_found:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"total_workspaces": len(workspaces),
                 "message": "No Microsoft Sentinel workspace found"},
                "Deploy Microsoft Sentinel for centralised SIEM and SOAR capabilities. "
                "Navigate to Microsoft Sentinel in the Azure Portal and add a workspace.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"sentinel_found": True,
                                      "total_workspaces": len(workspaces)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_network_watcher_enabled(subscription_id, credential, cache):
    """Req 10.2 — Network Watcher enabled in all regions with VNets."""
    req, name, desc, sev = (
        "10.2",
        "Network Watcher Enabled in All VNet Regions",
        "Verifies Azure Network Watcher is enabled in every region that contains Virtual Networks",
        "MEDIUM",
    )
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        vnets = cache.get_vnets()
        vnet_regions = {vnet.location for vnet in vnets}
        if not vnet_regions:
            return create_control_result(req, name, desc, "PASS", sev,
                                         {"message": "No VNets found."})
        watchers = list(net_client.network_watchers.list_all())
        watcher_regions = {w.location for w in watchers}
        missing = vnet_regions - watcher_regions
        if missing:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"regions_without_watcher": sorted(missing),
                 "vnet_regions": sorted(vnet_regions)},
                "Enable Network Watcher in all regions containing VNets. "
                "Navigate to Monitor > Network Watcher and click 'Enable' for missing regions.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_regions": sorted(vnet_regions)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


# ===================== VULNERABILITY MANAGEMENT (Req 5 & 6) =====================


def check_defender_for_servers(subscription_id, credential, cache):
    """Req 6.3 — Defender for Servers enabled."""
    req, name, desc, sev = (
        "6.3",
        "Defender for Servers Enabled",
        "Verifies Microsoft Defender for Servers (Standard plan) is enabled for vulnerability assessment and threat detection",
        "HIGH",
    )
    try:
        pricings = cache.get_defender_pricings()
        vm_plan = next((p for p in pricings if p.name == "VirtualMachines"), None)
        if not vm_plan or vm_plan.pricing_tier != "Standard":
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"current_tier": vm_plan.pricing_tier if vm_plan else "Not configured"},
                "Enable Defender for Servers (Standard) in Defender for Cloud. "
                "Navigate to Defender for Cloud > Environment settings > Defender plans > Servers.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"pricing_tier": vm_plan.pricing_tier})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_defender_for_sql(subscription_id, credential, cache):
    """Req 6.3 — Defender for SQL enabled."""
    req, name, desc, sev = (
        "6.3",
        "Defender for SQL Enabled",
        "Verifies Microsoft Defender for SQL is enabled for vulnerability assessments and Advanced Threat Protection",
        "HIGH",
    )
    try:
        pricings = cache.get_defender_pricings()
        sql_plan = next((p for p in pricings if p.name == "SqlServers"), None)
        if not sql_plan or sql_plan.pricing_tier != "Standard":
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"current_tier": sql_plan.pricing_tier if sql_plan else "Not configured"},
                "Enable Defender for SQL in Defender for Cloud. "
                "Navigate to Defender for Cloud > Environment settings > Defender plans > Databases.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"pricing_tier": sql_plan.pricing_tier})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_defender_for_storage(subscription_id, credential, cache):
    """Req 5.2 — Defender for Storage enabled."""
    req, name, desc, sev = (
        "5.2",
        "Defender for Storage Enabled",
        "Verifies Microsoft Defender for Storage is enabled to detect malware uploads and suspicious access patterns",
        "HIGH",
    )
    try:
        pricings = cache.get_defender_pricings()
        storage_plan = next((p for p in pricings if p.name == "StorageAccounts"), None)
        if not storage_plan or storage_plan.pricing_tier != "Standard":
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"current_tier": storage_plan.pricing_tier if storage_plan else "Not configured"},
                "Enable Defender for Storage in Defender for Cloud. "
                "Navigate to Defender for Cloud > Environment settings > Defender plans > Storage.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"pricing_tier": storage_plan.pricing_tier})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_vm_auto_patching(subscription_id, credential, cache):
    """Req 6.3 — VM automatic OS patching enabled."""
    req, name, desc, sev = (
        "6.3",
        "VM Automatic OS Patching",
        "Verifies Virtual Machines have automatic OS patching or Update Management enabled",
        "MEDIUM",
    )
    try:
        vms = cache.get_vms()
        unpatched = []
        for vm in vms:
            os_profile = vm.os_profile
            if not os_profile:
                continue
            patching_enabled = False
            # Windows
            if os_profile.windows_configuration:
                wc = os_profile.windows_configuration
                patch_mode = (wc.patch_settings.patch_mode
                              if wc.patch_settings else None)
                if patch_mode in ("AutomaticByPlatform", "AutomaticByOS"):
                    patching_enabled = True
                elif wc.enable_automatic_updates:
                    patching_enabled = True
            # Linux
            if os_profile.linux_configuration:
                lc = os_profile.linux_configuration
                patch_mode = (lc.patch_settings.patch_mode
                              if hasattr(lc, "patch_settings") and lc.patch_settings else None)
                if patch_mode in ("AutomaticByPlatform", "ImageDefault"):
                    patching_enabled = True
            if not patching_enabled:
                unpatched.append({"vm": vm.name, "resource_group": _rg_from_id(vm.id),
                                   "location": vm.location})

        if unpatched:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"unpatched_count": len(unpatched), "total_vms": len(vms),
                 "vms": unpatched[:20]},
                "Enable automatic OS patching or enrol VMs in Azure Update Manager. "
                "For Windows VMs: set patch mode to AutomaticByPlatform. "
                "For Linux VMs: configure patch mode via the Azure Guest Configuration extension.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_vms": len(vms)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_app_service_runtime_eol(subscription_id, credential, cache):
    """Req 6.3 — App Service runtime versions not EOL."""
    req, name, desc, sev = (
        "6.3",
        "App Service Runtime Not EOL",
        "Verifies App Service web apps are not using end-of-life runtime versions",
        "MEDIUM",
    )
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)
        apps = cache.get_web_apps()
        eol_apps = []
        for app in apps:
            rg = _rg_from_id(app.id)
            try:
                config = web_client.web_apps.get_configuration(rg, app.name)
                runtime = config.linux_fx_version or config.windows_fx_version or ""
                runtime_lower = runtime.lower()
                for eol_pattern in _EOL_LINUX_RUNTIMES:
                    if runtime_lower.startswith(eol_pattern):
                        eol_apps.append({"app": app.name, "resource_group": rg,
                                         "runtime": runtime})
                        break
            except Exception:
                continue

        if eol_apps:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"eol_count": len(eol_apps), "total_apps": len(apps), "apps": eol_apps[:20]},
                "Upgrade App Service applications to supported runtime versions. "
                "Navigate to App Service > Configuration > General settings > Stack settings.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_apps": len(apps)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_function_runtime_eol(subscription_id, credential, cache):
    """Req 6.3 — Azure Functions runtime not EOL."""
    req, name, desc, sev = (
        "6.3",
        "Azure Functions Runtime Not EOL",
        "Verifies Function Apps are not pinned to end-of-life major runtime versions (~1, ~2, ~3)",
        "MEDIUM",
    )
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)
        apps = cache.get_web_apps()
        # Filter to function apps
        function_apps = [a for a in apps if a.kind and "functionapp" in a.kind.lower()]
        eol_functions = []
        for app in function_apps:
            rg = _rg_from_id(app.id)
            try:
                settings = web_client.web_apps.list_application_settings(rg, app.name)
                version = (settings.properties or {}).get("FUNCTIONS_EXTENSION_VERSION", "")
                if version in _EOL_FUNCTIONS_VERSIONS:
                    eol_functions.append({"app": app.name, "resource_group": rg,
                                          "functions_version": version})
            except Exception:
                continue

        if eol_functions:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"eol_count": len(eol_functions), "total_function_apps": len(function_apps),
                 "apps": eol_functions},
                "Upgrade Function Apps to ~4 (current LTS). "
                "Update the FUNCTIONS_EXTENSION_VERSION app setting to ~4.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_function_apps": len(function_apps)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_waf_prevention_mode(subscription_id, credential, cache):
    """Req 6.4 — WAF in Prevention mode on Application Gateways.

    Note: Front Door WAF policies require azure.mgmt.frontdoor which is not
    included in this script's dependencies. Only Application Gateway WAF is checked.
    """
    req, name, desc, sev = (
        "6.4",
        "WAF in Prevention Mode",
        "Verifies Azure WAF on Application Gateways is configured in Prevention mode "
        "(Front Door WAF requires azure.mgmt.frontdoor and is not covered by this check)",
        "HIGH",
    )
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        app_gateways = list(net_client.application_gateways.list_all())
        detection_mode = []
        no_waf = []
        for ag in app_gateways:
            waf_config = ag.web_application_firewall_configuration
            if not waf_config:
                sku = ag.sku.name if ag.sku else ""
                if "waf" in (sku or "").lower():
                    no_waf.append({"resource": ag.name, "type": "Application Gateway",
                                   "issue": "WAF SKU but no WAF config"})
                continue
            if not waf_config.enabled:
                detection_mode.append({"resource": ag.name, "type": "Application Gateway",
                                        "mode": "Disabled"})
            elif waf_config.firewall_mode != "Prevention":
                detection_mode.append({"resource": ag.name, "type": "Application Gateway",
                                        "mode": waf_config.firewall_mode})

        all_issues = detection_mode + no_waf
        if all_issues:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"waf_issues_count": len(all_issues),
                 "total_app_gateways": len(app_gateways),
                 "issues": all_issues},
                "Switch WAF from Detection to Prevention mode on all Application Gateways. "
                "Navigate to Application Gateway > Web application firewall > Firewall mode.",
            )
        return create_control_result(req, name, desc, "PASS", sev, {
            "total_app_gateways": len(app_gateways),
            "limitation": "Front Door WAF policies are not checked (requires azure.mgmt.frontdoor)",
        })
    except Exception as e:
        return _warning(req, name, desc, sev, e)


# ===================== DATA RETENTION & RECOVERY (Req 9 & 12) =====================


def check_sql_backup_retention(subscription_id, credential, cache):
    """Req 12.3 — SQL Database short-term backup retention >= 7 days."""
    req, name, desc, sev = (
        "12.3",
        "SQL Database Short-Term Backup Retention",
        f"Verifies all Azure SQL Databases have short-term backup retention set to at least {_SQL_BACKUP_MIN_DAYS} days",
        "HIGH",
    )
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        servers = cache.get_sql_servers()
        short_retention = []
        total_dbs = 0
        for server in servers:
            rg = _rg_from_id(server.id)
            dbs = list(sql_client.databases.list_by_server(rg, server.name))
            for db in dbs:
                if db.name == "master":
                    continue
                total_dbs += 1
                try:
                    policy = sql_client.backup_short_term_retention_policies.get(
                        rg, server.name, db.name, "default"
                    )
                    if (policy.retention_days or 0) < _SQL_BACKUP_MIN_DAYS:
                        short_retention.append({
                            "server": server.name, "database": db.name,
                            "resource_group": rg, "retention_days": policy.retention_days,
                        })
                except Exception:
                    continue

        if short_retention:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"short_retention_count": len(short_retention), "total_databases": total_dbs,
                 "databases": short_retention},
                f"Set SQL Database backup retention to at least {_SQL_BACKUP_MIN_DAYS} days. "
                "Navigate to SQL Database > Backups > Configure retention.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_databases": total_dbs})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_sql_geo_redundant_backup(subscription_id, credential, cache):
    """Req 12.3 — SQL Server uses geo-redundant backup storage."""
    req, name, desc, sev = (
        "12.3",
        "SQL Database Geo-Redundant Backup",
        "Verifies Azure SQL Server backup storage is geo-redundant for regional disaster recovery",
        "HIGH",
    )
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        servers = cache.get_sql_servers()
        locally_redundant = []
        for server in servers:
            rg = _rg_from_id(server.id)
            try:
                dbs = list(sql_client.databases.list_by_server(rg, server.name))
                for db in dbs:
                    if db.name == "master":
                        continue
                    redundancy = db.current_backup_storage_redundancy or db.requested_backup_storage_redundancy
                    if redundancy and redundancy.lower() == "local":
                        locally_redundant.append({
                            "server": server.name, "database": db.name,
                            "resource_group": rg, "redundancy": redundancy,
                        })
            except Exception:
                continue

        if locally_redundant:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"local_redundant_count": len(locally_redundant),
                 "databases": locally_redundant[:20]},
                "Configure geo-redundant backup storage for SQL Databases. "
                "Navigate to SQL Database > Compute + storage > Backup storage redundancy and select Geo.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_servers": len(servers)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_vm_backup(subscription_id, credential, cache):
    """Req 12.3 — VMs backed up via Azure Backup."""
    req, name, desc, sev = (
        "12.3",
        "VM Backup via Azure Backup",
        "Verifies all Virtual Machines are enrolled in an Azure Backup vault",
        "MEDIUM",
    )
    try:
        recovery_client = RecoveryServicesClient(credential, subscription_id)
        backup_client = RecoveryServicesBackupClient(credential, subscription_id)
        vaults = list(recovery_client.vaults.list_by_subscription_id())
        protected_vm_ids = set()
        for vault in vaults:
            rg = _rg_from_id(vault.id)
            try:
                items = list(backup_client.backup_protected_items.list(vault.name, rg))
                for item in items:
                    if item.properties and hasattr(item.properties, "virtual_machine_id"):
                        vm_id = item.properties.virtual_machine_id
                        if vm_id:
                            protected_vm_ids.add(vm_id.lower())
            except Exception:
                continue

        vms = cache.get_vms()
        unprotected = [
            {"vm": vm.name, "resource_group": _rg_from_id(vm.id)}
            for vm in vms
            if vm.id.lower() not in protected_vm_ids
        ]
        if unprotected:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"unprotected_count": len(unprotected), "total_vms": len(vms),
                 "vms": unprotected[:20]},
                "Enrol unprotected VMs in Azure Backup. Navigate to Backup center > Backup > "
                "Azure Virtual machines and configure a backup policy.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_vms": len(vms), "total_vaults": len(vaults)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_storage_blob_soft_delete(subscription_id, credential, cache):
    """Req 12.3 — Storage Account blob soft delete enabled."""
    req, name, desc, sev = (
        "12.3",
        "Storage Account Blob Soft Delete",
        "Verifies all Storage Accounts have blob soft delete enabled to protect against accidental deletion",
        "MEDIUM",
    )
    try:
        storage_client = StorageManagementClient(credential, subscription_id)
        accounts = cache.get_storage_accounts()
        no_soft_delete = []
        for sa in accounts:
            rg = _rg_from_id(sa.id)
            try:
                blob_props = storage_client.blob_services.get_service_properties(rg, sa.name)
                delete_policy = blob_props.delete_retention_policy if blob_props else None
                if not delete_policy or not delete_policy.enabled:
                    no_soft_delete.append({"account": sa.name, "resource_group": rg})
            except Exception:
                continue

        if no_soft_delete:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"no_soft_delete_count": len(no_soft_delete), "total_accounts": len(accounts),
                 "accounts": no_soft_delete[:20]},
                "Enable blob soft delete on all Storage Accounts: "
                "az storage account blob-service-properties update "
                "--enable-delete-retention true --delete-retention-days 7 "
                "--account-name <account> --resource-group <rg>",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"total_accounts": len(accounts)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_resource_locks(subscription_id, credential, cache):
    """Req 12.3 — Resource Delete locks on critical resource groups."""
    req, name, desc, sev = (
        "12.3",
        "Resource Delete Locks on Resource Groups",
        "Verifies at least one resource group has a CanNotDelete resource lock to protect CDE infrastructure",
        "MEDIUM",
    )
    try:
        if ManagementLockClient is None:
            raise ImportError("ManagementLockClient not available (azure.mgmt.resource.locks missing)")
        lock_client = ManagementLockClient(credential, subscription_id)
        locks = list(lock_client.management_locks.list_at_subscription_level())
        delete_locks = [
            l for l in locks
            if (l.level or "").lower() in ("cannotdelete", "readonly")
        ]
        rg_locks = []
        if not delete_locks:
            # Also check resource group level
            rm_client = ResourceManagementClient(credential, subscription_id)
            resource_groups = list(rm_client.resource_groups.list())
            for rg in resource_groups:
                rg_level_locks = list(lock_client.management_locks.list_at_resource_group_level(rg.name))
                rg_locks.extend(
                    l for l in rg_level_locks
                    if (l.level or "").lower() in ("cannotdelete", "readonly")
                )
            if not rg_locks:
                return create_control_result(
                    req, name, desc, "FAIL", sev,
                    {"delete_locks_found": 0,
                     "message": "No CanNotDelete or ReadOnly locks found at subscription or resource group scope"},
                    "Add resource locks to critical resource groups containing CDE infrastructure: "
                    "az lock create --name CDE-Lock --lock-type CanNotDelete "
                    "--resource-group <rg>",
                )
        total_locks_found = len(delete_locks) + len(rg_locks)
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"delete_locks_found": total_locks_found,
                                      "subscription_level": len(delete_locks),
                                      "resource_group_level": len(rg_locks)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


def check_azure_policy_assignments(subscription_id, credential, cache):
    """Req 12.1 — Azure Policy assignments present for compliance governance."""
    req, name, desc, sev = (
        "12.1",
        "Azure Policy Compliance Assignments",
        "Verifies at least one Azure Policy assignment exists for compliance governance",
        "MEDIUM",
    )
    try:
        if PolicyClient is None:
            raise ImportError("PolicyClient not available (azure.mgmt.resource.policy missing)")
        policy_client = PolicyClient(credential, subscription_id)
        assignments = list(policy_client.policy_assignments.list())
        # Filter out Microsoft-managed built-in assignments to find customer-managed ones.
        # These prefixes identify assignments auto-created by Azure services (Defender for Cloud,
        # Azure Policy built-in initiatives, etc.) that are not customer governance controls.
        _MSFT_PREFIXES = (
            "ASC Default",          # Defender for Cloud legacy
            "[Preview]:",           # Microsoft preview initiatives
            "Configure ",           # Azure Policy auto-remediation assignments
            "Deploy ",              # Azure Policy deploy-if-not-exists assignments
            "Enable ",              # Azure Policy enable-* assignments
            # NOTE: "Audit " intentionally omitted — customers commonly name their own
            # policies "Audit <something>" and filtering on this prefix would cause false FAILs.
        )
        meaningful = [
            a for a in assignments
            if not any((a.display_name or "").startswith(p) for p in _MSFT_PREFIXES)
        ]
        if not meaningful:
            return create_control_result(
                req, name, desc, "FAIL", sev,
                {"total_assignments": len(assignments), "meaningful_assignments": 0,
                 "message": "No customer-managed policy assignments found"},
                "Create Azure Policy assignments to enforce and audit compliance controls. "
                "Consider assigning the 'PCI v3.2.1:2018' or 'Azure Security Benchmark' built-in initiative.",
            )
        return create_control_result(req, name, desc, "PASS", sev,
                                     {"meaningful_assignments": len(meaningful),
                                      "total_assignments": len(assignments)})
    except Exception as e:
        return _warning(req, name, desc, sev, e)


# ===================== EXECUTIVE SUMMARY =====================


def generate_executive_summary(result: dict) -> str:
    """Generate a markdown executive summary from the audit result."""
    meta = result["metadata"]
    summary = meta.get("summary", {})
    total = summary.get("total_checks", 0)
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)
    warnings = summary.get("warnings", 0)
    critical = summary.get("critical_failures", 0)
    high = summary.get("high_failures", 0)
    completed = summary.get("checks_completed", total)

    score = round(passed / completed * 100, 1) if completed > 0 else 0
    if score >= 90:
        status_text = "strong PCI-DSS posture"
    elif score >= 70:
        status_text = "moderate PCI-DSS posture with areas requiring attention"
    else:
        status_text = "significant PCI-DSS gaps requiring immediate remediation"

    lines = [
        f"## PCI-DSS v4.0 Azure Compliance Summary",
        f"",
        f"**Compliance Score:** {score}% ({passed}/{completed} checks passed)",
        f"**Overall Status:** {status_text}",
        f"",
        f"| Category | Total | Passed | Failed | Warnings |",
        f"|----------|-------|--------|--------|---------- |",
    ]
    categories = [
        ("network_security", "Network Security"),
        ("data_protection", "Data Protection"),
        ("access_control", "Access Control"),
        ("logging_monitoring", "Logging & Monitoring"),
        ("vulnerability_management", "Vulnerability Management"),
        ("data_retention_recovery", "Data Retention & Recovery"),
    ]
    for key, label in categories:
        checks = result.get(key, {}).get("checks", [])
        cat_total = len(checks)
        cat_pass = sum(1 for c in checks if c["status"] == "PASS")
        cat_fail = sum(1 for c in checks if c["status"] == "FAIL")
        cat_warn = sum(1 for c in checks if c["status"] == "WARNING")
        lines.append(f"| {label} | {cat_total} | {cat_pass} | {cat_fail} | {cat_warn} |")

    lines += [
        f"",
        f"**Critical Failures:** {critical}  **High Failures:** {high}  "
        f"**Warnings (permission/API errors):** {warnings}",
    ]
    if critical > 0 or high > 0:
        lines += ["", "### Priority Remediation Items", ""]
        for key, _ in categories:
            for check in result.get(key, {}).get("checks", []):
                if check["status"] == "FAIL" and check["severity"] in ("CRITICAL", "HIGH"):
                    lines.append(
                        f"- **[{check['severity']}]** {check['control_name']} "
                        f"(PCI Req {check['pci_requirement']})"
                    )
    return "\n".join(lines)


# ===================== MAIN AUDIT RUNNER =====================


def run_pci_dss_audit(subscription_id: str, credential=None) -> dict:
    """Run all PCI-DSS v4.0 checks against the Azure subscription and return a structured report."""
    if credential is None:
        credential = DefaultAzureCredential()
    result = _make_result()

    # Pre-populate subscription metadata
    try:
        sub_client = SubscriptionClient(credential)
        sub = sub_client.subscriptions.get(subscription_id)
        result["metadata"]["subscription_id"] = subscription_id
        result["metadata"]["subscription_name"] = sub.display_name
    except Exception:
        result["metadata"]["subscription_id"] = subscription_id

    # Resource cache fetches all lists in parallel during construction.
    cache = AzureResourceCache(subscription_id, credential)

    # Define all tasks: (category_key, check_function)
    tasks = [
        # Network Security
        ("network_security",  check_nsg_unrestricted_inbound),
        ("network_security",  check_subnets_without_nsg),
        ("network_security",  check_vms_public_ip_no_nsg),
        ("network_security",  check_network_watcher_flow_logs),
        ("network_security",  check_flow_log_retention),
        ("network_security",  check_azure_firewall_or_nva),
        ("network_security",  check_ddos_protection),
        ("network_security",  check_private_endpoints),
        # Data Protection
        ("data_protection",   check_storage_public_access),
        ("data_protection",   check_storage_https_only),
        ("data_protection",   check_sql_tde),
        ("data_protection",   check_sql_tls_version),
        ("data_protection",   check_vm_disk_encryption),
        ("data_protection",   check_keyvault_soft_delete),
        ("data_protection",   check_keyvault_key_rotation),
        ("data_protection",   check_app_service_https_tls),
        ("data_protection",   check_redis_ssl_only),
        ("data_protection",   check_app_settings_plaintext_secrets),
        ("data_protection",   check_keyvault_certificate_expiry),
        ("data_protection",   check_storage_encryption),
        # Access Control
        ("access_control",    check_subscription_owner_count),
        ("access_control",    check_privileged_direct_user_assignments),
        ("access_control",    check_guest_users_privileged_roles),
        ("access_control",    check_classic_admins),
        ("access_control",    check_stale_role_assignments),
        ("access_control",    check_custom_role_wildcards),
        ("access_control",    check_managed_identity_usage),
        ("access_control",    check_service_principal_credential_expiry),
        ("access_control",    check_mfa_enforcement),
        ("access_control",    check_sp_owner_role),
        # Logging & Monitoring
        ("logging_monitoring", check_activity_log_diagnostic_settings),
        ("logging_monitoring", check_activity_log_retention),
        ("logging_monitoring", check_log_analytics_retention),
        ("logging_monitoring", check_sql_auditing),
        ("logging_monitoring", check_sql_audit_retention),
        ("logging_monitoring", check_keyvault_diagnostic_logging),
        ("logging_monitoring", check_storage_account_logging),
        ("logging_monitoring", check_defender_for_cloud_plans),
        ("logging_monitoring", check_defender_security_contacts),
        ("logging_monitoring", check_defender_auto_provisioning),
        ("logging_monitoring", check_activity_log_alerts),
        ("logging_monitoring", check_monitor_metric_alerts),
        ("logging_monitoring", check_sentinel_workspace),
        ("logging_monitoring", check_network_watcher_enabled),
        # Vulnerability Management
        ("vulnerability_management", check_defender_for_servers),
        ("vulnerability_management", check_defender_for_sql),
        ("vulnerability_management", check_defender_for_storage),
        ("vulnerability_management", check_vm_auto_patching),
        ("vulnerability_management", check_app_service_runtime_eol),
        ("vulnerability_management", check_function_runtime_eol),
        ("vulnerability_management", check_waf_prevention_mode),
        # Data Retention & Recovery
        ("data_retention_recovery", check_sql_backup_retention),
        ("data_retention_recovery", check_sql_geo_redundant_backup),
        ("data_retention_recovery", check_vm_backup),
        ("data_retention_recovery", check_storage_blob_soft_delete),
        ("data_retention_recovery", check_resource_locks),
        ("data_retention_recovery", check_azure_policy_assignments),
    ]

    # Execute all checks in parallel
    with ThreadPoolExecutor(max_workers=25) as executor:
        future_to_category = {
            executor.submit(fn, subscription_id, credential, cache): category
            for category, fn in tasks
        }
        for future in as_completed(future_to_category):
            category = future_to_category[future]
            try:
                check_result = future.result()
            except Exception as exc:
                check_result = {
                    "pci_requirement": "Unknown",
                    "control_name": "Unknown",
                    "description": "Check failed with an unhandled exception",
                    "status": "WARNING",
                    "severity": "MEDIUM",
                    "details": {"error": type(exc).__name__, "message": str(exc)},
                }
            result[category]["checks"].append(check_result)

    # Sort checks within each category by pci_requirement for deterministic output
    for cat_data in result.values():
        if isinstance(cat_data, dict) and "checks" in cat_data:
            cat_data["checks"].sort(key=lambda c: c.get("pci_requirement", ""))

    # Calculate summary
    all_checks = [
        c for cat in [
            "network_security", "data_protection", "access_control",
            "logging_monitoring", "vulnerability_management", "data_retention_recovery"
        ]
        for c in result[cat]["checks"]
    ]
    total = len(all_checks)
    passed = sum(1 for c in all_checks if c["status"] == "PASS")
    failed = sum(1 for c in all_checks if c["status"] == "FAIL")
    warnings = sum(1 for c in all_checks if c["status"] == "WARNING")
    critical_failures = sum(1 for c in all_checks if c["status"] == "FAIL" and c["severity"] == "CRITICAL")
    high_failures = sum(1 for c in all_checks if c["status"] == "FAIL" and c["severity"] == "HIGH")
    _AUTH_KEYWORDS = ("AuthorizationFailed", "Forbidden", "does not have authorization",
                      "ClientAuthenticationError", "CredentialUnavailableError")
    permission_errors = sum(
        1 for c in all_checks
        if c["status"] == "WARNING"
        and any(kw in (c.get("details", {}).get("message", "") or "") for kw in _AUTH_KEYWORDS)
    )
    # Intentional WARNINGs (Graph API checks) are still "completed" — only unhandled
    # exception WARNINGs (control_name == "Unknown") indicate an incomplete check.
    _INTENTIONAL_WARNING_NAMES = {
        "Service Principals Have Credential Expiry",
        "MFA Enforced via Security Defaults or Conditional Access",
    }
    checks_completed = sum(
        1 for c in all_checks
        if c["status"] != "WARNING" or c.get("control_name") in _INTENTIONAL_WARNING_NAMES
    )

    result["metadata"]["summary"] = {
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "warnings": warnings,
        "critical_failures": critical_failures,
        "high_failures": high_failures,
        "permission_errors": permission_errors,
        "checks_completed": checks_completed,
    }
    result["metadata"]["executive_summary"] = generate_executive_summary(result)
    return result


def get_azure_subscriptions() -> List[Dict[str, Any]]:
    """Return all accessible Azure subscriptions as a list of dicts with 'subscription_id' and 'name'."""
    from azure.identity import AzureCliCredential
    credential = AzureCliCredential()
    sub_client = SubscriptionClient(credential)
    return [
        {"subscription_id": s.subscription_id, "name": s.display_name}
        for s in sub_client.subscriptions.list()
    ]


def resolve_subscription_name_to_id(name: str, subscriptions: List[Dict[str, Any]]) -> Optional[str]:
    """Resolve a subscription display name (case-insensitive) to its ID. Returns None if not found."""
    match = next((s for s in subscriptions if s["name"].lower() == name.lower()), None)
    return match["subscription_id"] if match else None


def _resolve_subscription(credential, name: Optional[str], sub_id: Optional[str]) -> str:
    """Resolve subscription name to ID, or return sub_id directly."""
    sub_client = SubscriptionClient(credential)
    available = [
        {"subscription_id": s.subscription_id, "name": s.display_name}
        for s in sub_client.subscriptions.list()
    ]
    if name:
        match = next(
            (s for s in available if s["name"].lower() == name.lower()), None
        )
        if not match:
            raise SystemExit(f"Error: Subscription '{name}' not found. "
                             f"Available: {[s['name'] for s in available]}")
        resolved = match["subscription_id"]
        return resolved
    if sub_id:
        return sub_id
    raise SystemExit(
        "Error: specify --subscription-id or --subscription-name. "
        f"Available subscriptions: {[s['name'] for s in available]}"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Azure PCI-DSS v4.0 Compliance Audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            '  python3 azure_pci_dss_checker.py --subscription-name "Tessell R&D"\n'
            "  python3 azure_pci_dss_checker.py --subscription-id 958ef0fb-...\n"
            "  python3 azure_pci_dss_checker.py --subscription-id <id> --output report.json"
        ),
    )
    parser.add_argument(
        "--subscription-id", "-s",
        default=None,
        help="Azure subscription ID to audit",
    )
    parser.add_argument(
        "--subscription-name",
        default=None,
        help="Subscription name (case-insensitive); resolved to ID automatically",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write JSON output to a file instead of stdout",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print progress messages to stderr",
    )
    args = parser.parse_args()

    try:
        credential = DefaultAzureCredential()
        subscription_id = _resolve_subscription(credential, args.subscription_name, args.subscription_id)
        if args.verbose:
            print(f"Running PCI-DSS audit for subscription: {subscription_id}", file=sys.stderr)
        report = run_pci_dss_audit(subscription_id, credential=credential)
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

from azure.identity import DefaultAzureCredential, AzureCliCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.subscription import SubscriptionClient
import argparse
from datetime import datetime, timezone
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict
import sys


# ===================== RESULT HELPERS =====================

def create_check_result(name, description, status, severity, details, recommendation=None):
    """Create a standardised check result dict. Status: PASS | FAIL | WARNING. Severity: CRITICAL | HIGH | MEDIUM | LOW."""
    result = {
        "check_name": name,
        "description": description,
        "status": status,
        "severity": severity,
        "details": details,
    }
    if recommendation:
        result["recommendation"] = recommendation
    return result


def _warning(name: str, description: str, severity: str, exc: Exception) -> dict:
    """Return a WARNING result for a check that raised an exception."""
    error_type = type(exc).__name__
    return create_check_result(
        name, description, "WARNING", severity,
        {"error": error_type, "message": str(exc)},
        f"Ensure the auditing role has permission to perform this check (error: {error_type}).",
    )


def _make_result(subscription_id: str) -> dict:
    """Return a fresh, empty result structure for a single audit run."""
    return {
        "metadata": {
            "subscription_id": subscription_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {},
        },
        "checks": [],
    }


# ===================== CONSTANTS =====================

# Built-in role definition UUIDs — stable across all Azure tenants.
_OWNER_ROLE_ID                  = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
_CONTRIBUTOR_ROLE_ID            = "b24988ac-6180-42a0-ab88-20f7382dd24c"
_USER_ACCESS_ADMIN_ROLE_ID      = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"

# Roles considered "overly broad" for broad subscription-scope assignment.
_BROAD_BUILTIN_ROLE_IDS = {
    _OWNER_ROLE_ID,
    _CONTRIBUTOR_ROLE_ID,
    _USER_ACCESS_ADMIN_ROLE_ID,
}

# Key Vault permission sets considered "full access" — any principal holding all
# permissions in any single category (keys, secrets, or certificates) is flagged.
_ALL_KEY_PERMISSIONS = {
    "backup", "create", "decrypt", "delete", "encrypt", "get", "import",
    "list", "purge", "recover", "restore", "sign", "unwrapkey", "update",
    "verify", "wrapkey", "release", "rotate", "getrotationpolicy",
    "setrotationpolicy",
}
_ALL_SECRET_PERMISSIONS = {
    "backup", "delete", "get", "list", "purge", "recover", "restore", "set",
}
_ALL_CERT_PERMISSIONS = {
    "backup", "create", "delete", "deleteissuers", "get", "getissuers",
    "import", "list", "listissuers", "managecontacts", "manageissuers",
    "purge", "recover", "restore", "setissuers", "update",
}

# Minimum threshold: flagged if granted ≥ this fraction of permissions in any category.
_FULL_ACCESS_THRESHOLD = 0.8


# ===================== RESOURCE CACHE =====================

class AzureIAMResourceCache:
    """Pre-fetches Azure resources once and shares them across all parallel checks."""

    def __init__(self, subscription_id: str, credential):
        self.subscription_id = subscription_id
        self.credential = credential
        self._scope = f"/subscriptions/{subscription_id}"

        self.role_assignments: List = self._fetch_role_assignments()
        self.role_definitions: List = self._fetch_role_definitions()
        self.classic_admins: List = self._fetch_classic_admins()
        self.key_vaults: List = self._fetch_key_vaults()
        self.vms: List = self._fetch_vms()
        self.app_services: List = self._fetch_app_services()
        self.function_apps: List = self._fetch_function_apps()

    def _fetch_role_assignments(self) -> List:
        try:
            client = AuthorizationManagementClient(self.credential, self.subscription_id)
            return list(client.role_assignments.list_for_scope(self._scope, filter="atScope()"))
        except Exception:
            return []

    def _fetch_role_definitions(self) -> List:
        try:
            client = AuthorizationManagementClient(self.credential, self.subscription_id)
            return list(client.role_definitions.list(self._scope))
        except Exception:
            return []

    def _fetch_classic_admins(self) -> List:
        try:
            client = AuthorizationManagementClient(self.credential, self.subscription_id)
            return list(client.classic_administrators.list())
        except Exception:
            return []

    def _fetch_key_vaults(self) -> List:
        try:
            client = KeyVaultManagementClient(self.credential, self.subscription_id)
            return list(client.vaults.list())
        except Exception:
            return []

    def _fetch_vms(self) -> List:
        try:
            client = ComputeManagementClient(self.credential, self.subscription_id)
            return list(client.virtual_machines.list_all())
        except Exception:
            return []

    def _fetch_app_services(self) -> List:
        try:
            client = WebSiteManagementClient(self.credential, self.subscription_id)
            return [s for s in client.web_apps.list() if s.kind and "functionapp" not in s.kind.lower()]
        except Exception:
            return []

    def _fetch_function_apps(self) -> List:
        try:
            client = WebSiteManagementClient(self.credential, self.subscription_id)
            return [s for s in client.web_apps.list() if s.kind and "functionapp" in s.kind.lower()]
        except Exception:
            return []


# ===================== RBAC CHECKS =====================

def check_subscription_owner_count(subscription_id: str, credential, role_assignments: List) -> dict:
    """Subscription has more than 3 Owner role assignments — CIS Azure benchmark 1.22."""
    name = "Subscription Owner Count"
    description = "Subscription should have no more than 3 Owner role assignments"
    severity = "CRITICAL"
    try:
        owners = [
            a for a in role_assignments
            if (a.role_definition_id or "").split("/")[-1].lower() == _OWNER_ROLE_ID
        ]
        owner_count = len(owners)
        owner_list = [
            {
                "principal_id": a.principal_id,
                "principal_type": getattr(a, "principal_type", "Unknown"),
            }
            for a in owners
        ]
        status = "PASS" if owner_count <= 3 else "FAIL"
        return create_check_result(
            name, description, status, severity,
            {"owner_count": owner_count, "owners": owner_list},
            None if status == "PASS" else (
                f"Reduce Owner assignments from {owner_count} to 3 or fewer. "
                "Use Azure PIM for just-in-time access rather than permanent Owner assignments."
            ),
        )
    except Exception as e:
        return _warning(name, description, severity, e)


def check_service_principal_with_owner_role(subscription_id: str, credential, role_assignments: List) -> dict:
    """Service principals assigned Owner at subscription scope — automation should not hold Owner."""
    name = "Service Principal Owner Role"
    description = "No service principal should be permanently assigned Owner at subscription scope"
    severity = "CRITICAL"
    try:
        sp_owners = [
            a for a in role_assignments
            if (a.role_definition_id or "").split("/")[-1].lower() == _OWNER_ROLE_ID
            and getattr(a, "principal_type", "") == "ServicePrincipal"
        ]
        risky = [
            {"principal_id": a.principal_id, "principal_type": "ServicePrincipal"}
            for a in sp_owners
        ]
        status = "PASS" if not risky else "FAIL"
        return create_check_result(
            name, description, status, severity,
            {"risky_service_principals_count": len(risky), "risky_service_principals": risky},
            None if status == "PASS" else (
                f"{len(risky)} service principal(s) hold Owner at subscription scope. "
                "Replace with scoped Contributor on specific resource groups, or use managed identities. "
                "Use Azure PIM for time-bound elevation when Owner is genuinely needed."
            ),
        )
    except Exception as e:
        return _warning(name, description, severity, e)


def check_overly_broad_builtin_roles(subscription_id: str, credential, role_assignments: List) -> dict:
    """Count of unique principals with Owner, Contributor, or User Access Administrator at subscription scope."""
    name = "Overly Broad Built-in Role Assignments"
    description = (
        "Tracks unique principals holding Owner, Contributor, or User Access Administrator "
        "at subscription scope — these grant broad control and should be minimised"
    )
    severity = "HIGH"
    try:
        _ROLE_NAMES = {
            _OWNER_ROLE_ID: "Owner",
            _CONTRIBUTOR_ROLE_ID: "Contributor",
            _USER_ACCESS_ADMIN_ROLE_ID: "User Access Administrator",
        }
        broad = []
        for a in role_assignments:
            role_uuid = (a.role_definition_id or "").split("/")[-1].lower()
            role_name = _ROLE_NAMES.get(role_uuid)
            if role_name:
                broad.append({
                    "principal_id": a.principal_id,
                    "principal_type": getattr(a, "principal_type", "Unknown"),
                    "role": role_name,
                })
        # FAIL if any Contributor or UAA present, or Owner count already caught above
        status = "PASS" if not broad else "FAIL"
        return create_check_result(
            name, description, status, severity,
            {"broad_assignments_count": len(broad), "broad_assignments": broad},
            None if status == "PASS" else (
                f"{len(broad)} broad role assignment(s) at subscription scope. "
                "Scope permissions to resource groups or individual resources instead. "
                "Replace standing access with Azure PIM eligible assignments."
            ),
        )
    except Exception as e:
        return _warning(name, description, severity, e)


def check_cross_tenant_access(subscription_id: str, credential, role_assignments: List) -> dict:
    """External (cross-tenant) principals with privileged role assignments."""
    name = "Cross-Tenant Role Access"
    description = (
        "External or cross-tenant principals (ForeignGroup, guests) should not hold "
        "privileged roles at subscription scope"
    )
    severity = "HIGH"
    try:
        # ForeignGroup principal_type indicates a group from another tenant.
        # Guest users surface as principal_type "User" but are identifiable only via Graph;
        # we flag ForeignGroup as a definitive signal.
        external = [
            a for a in role_assignments
            if getattr(a, "principal_type", "") == "ForeignGroup"
        ]
        risky = [
            {
                "principal_id": a.principal_id,
                "principal_type": "ForeignGroup",
                "role_definition_id": a.role_definition_id,
            }
            for a in external
        ]
        status = "PASS" if not risky else "FAIL"
        return create_check_result(
            name, description, status, severity,
            {"cross_tenant_assignments_count": len(risky), "cross_tenant_assignments": risky},
            None if status == "PASS" else (
                f"{len(risky)} cross-tenant principal(s) have role assignments at subscription scope. "
                "Review each assignment and remove any that are not explicitly required. "
                "Prefer Azure Lighthouse for managed cross-tenant access with audit trails."
            ),
        )
    except Exception as e:
        return _warning(name, description, severity, e)


def check_custom_roles_wildcard_actions(subscription_id: str, credential, role_definitions: List) -> dict:
    """Custom role definitions containing wildcard (*) actions."""
    name = "Custom Roles with Wildcard Actions"
    description = "Custom role definitions should not use wildcard (*) in Actions — use specific action strings"
    severity = "HIGH"
    try:
        risky = []
        for rd in role_definitions:
            # Skip built-in roles — only audit customer-defined custom roles.
            if getattr(rd, "role_type", "") == "BuiltInRole":
                continue
            permissions = getattr(rd, "permissions", []) or []
            wildcard_actions = []
            for perm in permissions:
                actions = getattr(perm, "actions", []) or []
                wildcard_actions.extend(a for a in actions if "*" in a)
            if wildcard_actions:
                risky.append({
                    "role_name": rd.role_name,
                    "role_id": rd.id,
                    "wildcard_actions": wildcard_actions,
                })
        status = "PASS" if not risky else "FAIL"
        return create_check_result(
            name, description, status, severity,
            {"risky_custom_roles_count": len(risky), "risky_custom_roles": risky},
            None if status == "PASS" else (
                f"{len(risky)} custom role(s) contain wildcard actions. "
                "Replace wildcard actions with the specific Azure resource provider actions required. "
                "Use the Azure RBAC built-in roles as a reference for scoped permission sets."
            ),
        )
    except Exception as e:
        return _warning(name, description, severity, e)


def check_custom_roles_notactions(subscription_id: str, credential, role_definitions: List) -> dict:
    """Custom roles that combine a wildcard Action with NotActions to restrict access."""
    name = "Custom Roles Using NotActions"
    description = (
        "Custom roles that grant wildcard Actions and use NotActions to restrict them — "
        "this pattern is fragile and often grants more than intended as new actions are added"
    )
    severity = "MEDIUM"
    try:
        risky = []
        for rd in role_definitions:
            if getattr(rd, "role_type", "") == "BuiltInRole":
                continue
            permissions = getattr(rd, "permissions", []) or []
            for perm in permissions:
                actions = getattr(perm, "actions", []) or []
                not_actions = getattr(perm, "not_actions", []) or []
                has_wildcard = any("*" in a for a in actions)
                if has_wildcard and not_actions:
                    risky.append({
                        "role_name": rd.role_name,
                        "role_id": rd.id,
                        "wildcard_actions": [a for a in actions if "*" in a],
                        "not_actions": not_actions,
                    })
                    break
        status = "PASS" if not risky else "FAIL"
        return create_check_result(
            name, description, status, severity,
            {"risky_custom_roles_count": len(risky), "risky_custom_roles": risky},
            None if status == "PASS" else (
                f"{len(risky)} custom role(s) use NotActions to restrict wildcard grants. "
                "Replace with explicit allowed action lists. NotActions do not prevent new "
                "resource provider actions added in future Azure updates."
            ),
        )
    except Exception as e:
        return _warning(name, description, severity, e)


def check_classic_administrators(subscription_id: str, credential, classic_admins: List) -> dict:
    """Legacy Classic Administrator / Co-Administrator assignments still configured."""
    name = "Classic Administrators"
    description = (
        "Legacy Classic Administrator and Co-Administrator roles should be removed — "
        "they predate Azure RBAC and cannot be scoped to resource groups"
    )
    severity = "MEDIUM"
    try:
        # Service Administrator is always present (the subscription owner); flag Co-Admins only.
        co_admins = [
            a for a in classic_admins
            if "coadministrator" in (getattr(a, "role", "") or "").lower()
        ]
        flagged = [
            {
                "email_address": getattr(a, "email_address", "Unknown"),
                "role": getattr(a, "role", "Unknown"),
            }
            for a in co_admins
        ]
        status = "PASS" if not flagged else "FAIL"
        return create_check_result(
            name, description, status, severity,
            {"classic_admin_count": len(flagged), "classic_admins": flagged},
            None if status == "PASS" else (
                f"{len(flagged)} Co-Administrator assignment(s) found. "
                "Remove legacy Classic Administrator roles and replace with equivalent Azure RBAC roles. "
                "Go to Azure Portal > Subscriptions > Access control (IAM) > Classic administrators."
            ),
        )
    except Exception as e:
        return _warning(name, description, severity, e)


# ===================== KEY VAULT ACCESS CHECKS =====================

def check_key_vault_full_access_policies(subscription_id: str, credential, key_vaults: List) -> dict:
    """Key Vault access policies granting near-full permissions to any principal."""
    name = "Key Vault Full Access Policies"
    description = (
        "Key Vault access policies should follow least privilege — "
        "principals with full key, secret, or certificate permissions are flagged"
    )
    severity = "HIGH"
    try:
        if not key_vaults:
            return create_check_result(
                name, description, "PASS", severity,
                {"total_vaults": 0, "overpermissioned_principals_count": 0},
            )

        kv_client = KeyVaultManagementClient(credential, subscription_id)
        risky = []

        for vault in key_vaults:
            rg = vault.id.split("/")[4]
            try:
                detail = kv_client.vaults.get(rg, vault.name)
            except Exception:
                continue

            # If vault uses RBAC authorization, access policies are not active.
            if getattr(detail.properties, "enable_rbac_authorization", False):
                continue

            policies = getattr(detail.properties, "access_policies", []) or []
            for policy in policies:
                perms = getattr(policy, "permissions", None)
                if perms is None:
                    continue
                key_perms = {p.lower() for p in (getattr(perms, "keys", []) or [])}
                secret_perms = {p.lower() for p in (getattr(perms, "secrets", []) or [])}
                cert_perms = {p.lower() for p in (getattr(perms, "certificates", []) or [])}

                key_ratio = len(key_perms & _ALL_KEY_PERMISSIONS) / max(len(_ALL_KEY_PERMISSIONS), 1)
                secret_ratio = len(secret_perms & _ALL_SECRET_PERMISSIONS) / max(len(_ALL_SECRET_PERMISSIONS), 1)
                cert_ratio = len(cert_perms & _ALL_CERT_PERMISSIONS) / max(len(_ALL_CERT_PERMISSIONS), 1)

                if any(r >= _FULL_ACCESS_THRESHOLD for r in (key_ratio, secret_ratio, cert_ratio)):
                    risky.append({
                        "vault_name": vault.name,
                        "object_id": policy.object_id,
                        "key_permissions_count": len(key_perms),
                        "secret_permissions_count": len(secret_perms),
                        "certificate_permissions_count": len(cert_perms),
                    })

        status = "PASS" if not risky else "FAIL"
        return create_check_result(
            name, description, status, severity,
            {"total_vaults": len(key_vaults), "overpermissioned_principals_count": len(risky), "overpermissioned_principals": risky},
            None if status == "PASS" else (
                f"{len(risky)} principal(s) have near-full Key Vault permissions. "
                "Apply least privilege — grant only the specific key/secret operations each application needs. "
                "Migrate to Azure RBAC authorization to use fine-grained built-in roles."
            ),
        )
    except Exception as e:
        return _warning(name, description, severity, e)


def check_key_vault_rbac_authorization(subscription_id: str, credential, key_vaults: List) -> dict:
    """Key Vaults using legacy access policy model instead of Azure RBAC."""
    name = "Key Vault RBAC Authorization"
    description = (
        "Key Vaults should use Azure RBAC authorization rather than legacy vault access policies "
        "for consistent, auditable permission management"
    )
    severity = "MEDIUM"
    try:
        if not key_vaults:
            return create_check_result(
                name, description, "PASS", severity,
                {"total_vaults": 0, "legacy_policy_vaults_count": 0},
            )

        kv_client = KeyVaultManagementClient(credential, subscription_id)
        legacy = []

        for vault in key_vaults:
            rg = vault.id.split("/")[4]
            try:
                detail = kv_client.vaults.get(rg, vault.name)
            except Exception:
                continue
            if not getattr(detail.properties, "enable_rbac_authorization", False):
                legacy.append({"vault_name": vault.name, "resource_group": rg})

        status = "PASS" if not legacy else "FAIL"
        return create_check_result(
            name, description, status, severity,
            {"total_vaults": len(key_vaults), "legacy_policy_vaults_count": len(legacy), "legacy_policy_vaults": legacy},
            None if status == "PASS" else (
                f"{len(legacy)} Key Vault(s) use legacy access policies. "
                "Enable RBAC authorization: az keyvault update --name <vault> --enable-rbac-authorization true. "
                "Migrate existing access policies to Azure RBAC built-in roles (Key Vault Secrets Officer, etc.)."
            ),
        )
    except Exception as e:
        return _warning(name, description, severity, e)


# ===================== MANAGED IDENTITY CHECKS =====================

def check_vm_managed_identity(subscription_id: str, credential, vms: List) -> dict:
    """VMs not assigned a system-assigned or user-assigned managed identity."""
    name = "VM Managed Identity"
    description = (
        "Virtual machines should use managed identities to authenticate to Azure services "
        "rather than storing credentials or service principal secrets"
    )
    severity = "MEDIUM"
    try:
        if not vms:
            return create_check_result(
                name, description, "PASS", severity,
                {"total_vms": 0, "vms_without_identity_count": 0},
            )
        no_identity = []
        for vm in vms:
            identity = getattr(vm, "identity", None)
            if not identity or getattr(identity, "type", None) in (None, "None"):
                no_identity.append({"vm_name": vm.name, "location": vm.location})

        status = "PASS" if not no_identity else "FAIL"
        return create_check_result(
            name, description, status, severity,
            {"total_vms": len(vms), "vms_without_identity_count": len(no_identity), "vms_without_identity": no_identity},
            None if status == "PASS" else (
                f"{len(no_identity)} VM(s) have no managed identity. "
                "Enable system-assigned managed identity: az vm identity assign --name <vm> --resource-group <rg>. "
                "Update application code to use DefaultAzureCredential instead of stored credentials."
            ),
        )
    except Exception as e:
        return _warning(name, description, severity, e)


def check_app_service_managed_identity(subscription_id: str, credential, app_services: List) -> dict:
    """App Services not using a managed identity."""
    name = "App Service Managed Identity"
    description = (
        "App Services should use managed identities to authenticate to Azure services "
        "rather than connection strings or service principal secrets"
    )
    severity = "MEDIUM"
    try:
        if not app_services:
            return create_check_result(
                name, description, "PASS", severity,
                {"total_app_services": 0, "apps_without_identity_count": 0},
            )
        no_identity = []
        for app in app_services:
            identity = getattr(app, "identity", None)
            if not identity or getattr(identity, "type", None) in (None, "None"):
                no_identity.append({"app_name": app.name, "location": app.location})

        status = "PASS" if not no_identity else "FAIL"
        return create_check_result(
            name, description, status, severity,
            {"total_app_services": len(app_services), "apps_without_identity_count": len(no_identity), "apps_without_identity": no_identity},
            None if status == "PASS" else (
                f"{len(no_identity)} App Service(s) have no managed identity. "
                "Enable system-assigned identity: az webapp identity assign --name <app> --resource-group <rg>. "
                "Update connection strings to use managed identity authentication."
            ),
        )
    except Exception as e:
        return _warning(name, description, severity, e)


def check_function_app_managed_identity(subscription_id: str, credential, function_apps: List) -> dict:
    """Function Apps not using a managed identity."""
    name = "Function App Managed Identity"
    description = (
        "Function Apps should use managed identities to authenticate to Azure services "
        "rather than storing credentials or service principal secrets"
    )
    severity = "MEDIUM"
    try:
        if not function_apps:
            return create_check_result(
                name, description, "PASS", severity,
                {"total_function_apps": 0, "function_apps_without_identity_count": 0},
            )
        no_identity = []
        for app in function_apps:
            identity = getattr(app, "identity", None)
            if not identity or getattr(identity, "type", None) in (None, "None"):
                no_identity.append({"app_name": app.name, "location": app.location})

        status = "PASS" if not no_identity else "FAIL"
        return create_check_result(
            name, description, status, severity,
            {"total_function_apps": len(function_apps), "function_apps_without_identity_count": len(no_identity), "function_apps_without_identity": no_identity},
            None if status == "PASS" else (
                f"{len(no_identity)} Function App(s) have no managed identity. "
                "Enable system-assigned identity: az functionapp identity assign --name <app> --resource-group <rg>. "
                "Use DefaultAzureCredential in function code to consume the managed identity."
            ),
        )
    except Exception as e:
        return _warning(name, description, severity, e)


# ===================== INFORMATIONAL CHECKS (always WARNING) =====================

def check_mfa_enforcement(subscription_id: str, credential) -> dict:
    """MFA enforcement via Conditional Access — informational only, requires Graph API."""
    return create_check_result(
        "MFA Enforcement",
        "Verifies MFA is enforced for all users via Conditional Access policies",
        "WARNING",
        "CRITICAL",
        {
            "informational": True,
            "explanation": (
                "Verifying MFA enforcement and Conditional Access policies requires the "
                "Microsoft Graph API, which is outside Azure Resource Manager scope. "
                "Verify manually in Entra ID > Security > Conditional Access."
            ),
        },
        "Configure a Conditional Access policy requiring MFA for all users. "
        "Go to Entra ID > Security > Conditional Access > New policy.",
    )


def check_entra_id_password_policy(subscription_id: str, credential) -> dict:
    """Entra ID password policy strength — informational only, requires Graph API."""
    return create_check_result(
        "Entra ID Password Policy",
        "Verifies Entra ID enforces a strong password policy",
        "WARNING",
        "HIGH",
        {
            "informational": True,
            "explanation": (
                "Reading Entra ID password policy requires the Microsoft Graph API "
                "(directorySettings endpoint), which is outside Azure Resource Manager scope. "
                "Verify manually in Entra ID > Security > Authentication methods > Password protection."
            ),
        },
        "Enable Entra ID Password Protection with a custom banned-password list and "
        "set the lockout threshold to 10 or fewer attempts. "
        "Consider enabling Smart Lockout for cloud-only accounts.",
    )


# ===================== EXECUTIVE SUMMARY =====================

def generate_executive_summary(result: dict) -> str:
    """Generate a markdown-formatted executive summary of the IAM audit results."""
    summary = result["metadata"]["summary"]
    subscription_id = result["metadata"].get("subscription_id", "Unknown")
    audit_date = result["metadata"].get("generated_at", "")[:10]

    total = summary.get("total_checks", 0)
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)
    warnings = summary.get("warnings", 0)
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)

    compliance_score = int(passed / total * 100) if total > 0 else 0

    md = []
    md.append("# Azure IAM Security Audit — Executive Summary")
    md.append("")
    md.append(
        f"**Subscription:** {subscription_id}  |  **Date:** {audit_date}  |  "
        f"**Score:** {compliance_score}% ({passed}/{total} checks passed)"
    )
    md.append("")

    if compliance_score >= 90:
        md.append(
            f"**Subscription {subscription_id}** demonstrates **strong IAM security** with a "
            f"{compliance_score}% pass rate. Minor gaps remain."
        )
    elif compliance_score >= 70:
        md.append(
            f"**Subscription {subscription_id}** shows **moderate IAM security** with a "
            f"{compliance_score}% pass rate. Several issues require attention."
        )
    else:
        md.append(
            f"**Subscription {subscription_id}** requires **significant IAM remediation** with a "
            f"{compliance_score}% pass rate. Critical and high-severity findings should be addressed immediately."
        )
    md.append("")

    if critical > 0 or high > 0:
        md.append("## Key Findings")
        md.append("")
        if critical > 0:
            md.append(f"- **{critical} CRITICAL** finding(s) — immediate action required")
        if high > 0:
            md.append(f"- **{high} HIGH** finding(s) — address within 30 days")
        md.append(f"- {warnings} check(s) returned WARNING (informational — require Graph API)")
        md.append("")

    md.append("## Results by Severity")
    md.append("")
    md.append("| Severity | Failed |")
    md.append("|---|---|")
    md.append(f"| Critical | {critical} |")
    md.append(f"| High | {high} |")
    md.append(f"| Medium | {summary.get('medium', 0)} |")
    md.append(f"| Low | {summary.get('low', 0)} |")
    md.append("")

    failed_checks = [c for c in result["checks"] if c["status"] == "FAIL"]
    critical_checks = [c for c in failed_checks if c["severity"] == "CRITICAL"]
    if critical_checks:
        md.append("## Priority Remediation")
        md.append("")
        for c in critical_checks[:5]:
            md.append(f"- **{c['check_name']}**: {c.get('recommendation', '')[:120]}")
        md.append("")

    md.append("## Recommendation")
    md.append("")
    if compliance_score >= 90:
        md.append("**Action:** Address remaining findings to achieve full IAM least-privilege compliance.")
    elif compliance_score >= 70:
        md.append("**Action:** Focus on critical and high-severity findings as the immediate priority.")
    else:
        md.append(
            "**Action:** Implement a structured IAM remediation programme. "
            "Start with subscription Owner count and service principal privilege reduction."
        )

    return "\n".join(md)


# ===================== ORCHESTRATOR =====================

def run_iam_audit(subscription_id: str, credential) -> dict:
    """Run all 14 IAM checks against the given Azure subscription and return structured results."""
    result = _make_result(subscription_id)

    cache = AzureIAMResourceCache(subscription_id, credential)

    check_tasks = [
        # RBAC / Subscription Access (7 checks)
        lambda: check_subscription_owner_count(subscription_id, credential, cache.role_assignments),
        lambda: check_service_principal_with_owner_role(subscription_id, credential, cache.role_assignments),
        lambda: check_overly_broad_builtin_roles(subscription_id, credential, cache.role_assignments),
        lambda: check_cross_tenant_access(subscription_id, credential, cache.role_assignments),
        lambda: check_custom_roles_wildcard_actions(subscription_id, credential, cache.role_definitions),
        lambda: check_custom_roles_notactions(subscription_id, credential, cache.role_definitions),
        lambda: check_classic_administrators(subscription_id, credential, cache.classic_admins),
        # Key Vault Access (2 checks)
        lambda: check_key_vault_full_access_policies(subscription_id, credential, cache.key_vaults),
        lambda: check_key_vault_rbac_authorization(subscription_id, credential, cache.key_vaults),
        # Managed Identity (3 checks)
        lambda: check_vm_managed_identity(subscription_id, credential, cache.vms),
        lambda: check_app_service_managed_identity(subscription_id, credential, cache.app_services),
        lambda: check_function_app_managed_identity(subscription_id, credential, cache.function_apps),
        # Informational — always WARNING (2 checks)
        lambda: check_mfa_enforcement(subscription_id, credential),
        lambda: check_entra_id_password_policy(subscription_id, credential),
    ]

    with ThreadPoolExecutor(max_workers=14) as executor:
        futures = {executor.submit(fn): fn for fn in check_tasks}
        for future in as_completed(futures):
            try:
                result["checks"].append(future.result())
            except Exception as e:
                error_type = type(e).__name__
                error_message = str(e)
                is_auth_error = any(kw in error_message for kw in (
                    "AuthorizationFailed", "Forbidden", "does not have authorization",
                    "ClientAuthenticationError", "CredentialUnavailableError",
                ))
                result["checks"].append(create_check_result(
                    name=f"{'Permission Error' if is_auth_error else 'Check Failed'}: {error_type}",
                    description="Check could not complete",
                    status="WARNING",
                    severity="LOW",
                    details={"error_type": error_type, "error_message": error_message},
                    recommendation="Review the error and ensure the auditing identity has the required RBAC permissions listed in README-IAM-AZURE.md.",
                ))

    all_checks = result["checks"]
    failed_checks = [c for c in all_checks if c["status"] == "FAIL"]
    result["metadata"]["summary"] = {
        "total_checks": len(all_checks),
        "passed": sum(1 for c in all_checks if c["status"] == "PASS"),
        "failed": len(failed_checks),
        "warnings": sum(1 for c in all_checks if c["status"] == "WARNING"),
        "critical": sum(1 for c in failed_checks if c["severity"] == "CRITICAL"),
        "high": sum(1 for c in failed_checks if c["severity"] == "HIGH"),
        "medium": sum(1 for c in failed_checks if c["severity"] == "MEDIUM"),
        "low": sum(1 for c in failed_checks if c["severity"] == "LOW"),
    }
    result["metadata"]["executive_summary"] = generate_executive_summary(result)

    return result


# ===================== SUBSCRIPTION DISCOVERY =====================

def get_azure_subscriptions() -> List[Dict[str, str]]:
    """Return all accessible Azure subscriptions using the current credential."""
    try:
        credential = DefaultAzureCredential()
        client = SubscriptionClient(credential)
        subscriptions = []
        for sub in client.subscriptions.list():
            tenant_id = getattr(sub, "tenant_id", None) or getattr(sub, "home_tenant_id", "") or ""
            state = str(sub.state) if getattr(sub, "state", None) else "Enabled"
            subscriptions.append({
                "name": sub.display_name,
                "subscription_id": sub.subscription_id,
                "tenant_id": tenant_id,
                "state": state,
            })
        return subscriptions
    except Exception as e:
        print(f"Error listing subscriptions: {e}", file=sys.stderr)
        return []


def resolve_subscription_name_to_id(name: str, subscriptions: List[Dict[str, str]]) -> Optional[str]:
    """Case-insensitive match of a subscription display name to its ID."""
    for sub in subscriptions:
        if sub["name"].lower() == name.lower():
            return sub["subscription_id"]
    return None


# ===================== MAIN =====================

def main():
    parser = argparse.ArgumentParser(
        description="Azure IAM Security Analyser — audit RBAC, managed identities, and Key Vault access.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 azure_audit_iam.py --subscription-id <subscription_id>
  python3 azure_audit_iam.py --subscription-name "My Subscription"
  python3 azure_audit_iam.py --subscription-id <subscription_id> --output report.json
  python3 azure_audit_iam.py --subscription-id <subscription_id> --format presentation
  python3 azure_audit_iam.py   # uses default subscription from az login
        """,
    )
    parser.add_argument("--subscription-id", "-s", help="Azure subscription ID to audit")
    parser.add_argument("--subscription-name", help="Subscription display name (case-insensitive)")
    parser.add_argument("--output", "-o", help="Write JSON output to a file instead of stdout")
    parser.add_argument(
        "--format", "-f",
        choices=["raw", "presentation"],
        default="raw",
        help="Output format: raw (JSON, default) or presentation (markdown executive summary)",
    )
    parser.add_argument("--verbose", action="store_true", help="Print progress messages to stderr")
    args = parser.parse_args()

    if args.verbose:
        print("Detecting Azure subscriptions...", file=sys.stderr)
    available = get_azure_subscriptions()
    if not available:
        print("Error: No Azure subscriptions found. Run: az login", file=sys.stderr)
        sys.exit(1)

    subscription_id = args.subscription_id
    if args.subscription_name:
        subscription_id = resolve_subscription_name_to_id(args.subscription_name, available)
        if not subscription_id:
            print(f"Error: Subscription '{args.subscription_name}' not found.", file=sys.stderr)
            print("Available:", file=sys.stderr)
            for s in available:
                print(f"  - {s['name']}", file=sys.stderr)
            sys.exit(1)
        if args.verbose:
            print(f"Resolved '{args.subscription_name}' → {subscription_id}", file=sys.stderr)

    if not subscription_id:
        subscription_id = available[0]["subscription_id"]
        if args.verbose:
            print(f"Using default subscription: {available[0]['name']} ({subscription_id})", file=sys.stderr)

    try:
        credential = AzureCliCredential()
    except Exception:
        credential = DefaultAzureCredential()

    try:
        if args.verbose:
            print(f"Running IAM audit for subscription: {subscription_id}", file=sys.stderr)
        report = run_iam_audit(subscription_id=subscription_id, credential=credential)

        if args.format == "presentation":
            output = report["metadata"]["executive_summary"]
        else:
            output = json.dumps(report, indent=2)

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

import boto3
import argparse
import csv
import io
import json
import sys
import time
from datetime import datetime, timezone
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed


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


# ---------- CONSTANTS ----------

# AWS-managed policies considered overly broad for general attachment.
_ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}

_OVERLY_BROAD_AWS_MANAGED_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
}

# Actions considered sensitive for check_wildcard_resources_managed_policies.
# Mirrors the set used in aws_audit.py check_overly_permissive_policies, extended with
# IAM/STS write actions that are uniquely relevant to IAM-specific auditing.
_SENSITIVE_ACTIONS = {
    "s3:*", "s3:getobject", "s3:putobject", "s3:deleteobject", "s3:deletebucket",
    "ec2:*", "ec2:runinstances", "ec2:terminateinstances",
    "rds:*", "rds:deletedbinstance",
    "iam:*", "iam:createuser", "iam:attachuserpolicy", "iam:passrole", "iam:createaccesskey",
    "sts:*", "sts:assumerole",
    "lambda:*",
    "dynamodb:*",
    "secretsmanager:*",
    "kms:*",
    "cloudtrail:*",
}


# ---------- POLICY DOCUMENT HELPERS ----------

def _normalise_list(value):
    """Coerce a string or list to a list. Returns [] for falsy input."""
    if isinstance(value, str):
        return [value]
    return value or []


def _allow_statements(document):
    """Yield each Allow-effect statement from a policy document."""
    if not document:
        return
    for stmt in document.get("Statement", []):
        if stmt.get("Effect") == "Allow":
            yield stmt


def _has_wildcard_action(stmt):
    """Return True if any action in the statement is '*' or ends with ':*' (e.g. 's3:*')."""
    for action in _normalise_list(stmt.get("Action", [])):
        if action == "*" or action.endswith(":*"):
            return True
    return False


def _has_wildcard_resource(stmt):
    """Return True if '*' appears in the Resource list."""
    return "*" in _normalise_list(stmt.get("Resource", []))


def _has_sensitive_action(stmt):
    """Return True if any action in the statement is in _SENSITIVE_ACTIONS (case-insensitive)."""
    actions = {a.lower() for a in _normalise_list(stmt.get("Action", []))}
    return bool(actions & _SENSITIVE_ACTIONS)


def _document_has_notaction(document):
    """Return True if the document contains any Allow statement that uses NotAction."""
    if not document:
        return False
    for stmt in document.get("Statement", []):
        if stmt.get("Effect") == "Allow" and "NotAction" in stmt:
            return True
    return False


def _document_has_sts_assumerole_star(document):
    """Return True if any Allow statement grants sts:AssumeRole on Resource: '*'."""
    for stmt in _allow_statements(document):
        actions = {a.lower() for a in _normalise_list(stmt.get("Action", []))}
        resources = _normalise_list(stmt.get("Resource", []))
        if "sts:assumerole" in actions and "*" in resources:
            return True
    return False


# ---------- CACHE ----------

class AWSIAMResourceCache:
    """
    Pre-fetches all IAM resources eagerly in the main thread before the
    ThreadPoolExecutor starts. Worker threads only read cached data — never
    write — eliminating lazy-init race conditions entirely.

    Per-entity enrichment (keys, policies, groups) is parallelised within
    each fetch method using its own inner ThreadPoolExecutor.
    """

    def __init__(self, session, stale_days=90):  # noqa: ARG002 — stale_days reserved for future use
        iam = session.client("iam", region_name="us-east-1")

        self.account_summary = self._fetch_account_summary(iam)
        self.credential_report = self._fetch_credential_report(iam)
        self.password_policy = self._fetch_password_policy(iam)
        self.users = self._fetch_users(iam)
        self.roles = self._fetch_roles(iam)
        self.managed_policies = self._fetch_managed_policies(iam)
        self.groups = self._fetch_groups(iam)

    @staticmethod
    def _fetch_account_summary(iam):
        try:
            return iam.get_account_summary()["SummaryMap"]
        except Exception:
            return {}

    @staticmethod
    def _fetch_credential_report(iam):
        """
        Generates the IAM credential report and blocks until it is COMPLETE.

        Polls up to 10 times with 2-second intervals. Returns a list of row
        dicts (one per IAM user / root account, as parsed from CSV), or an
        empty list if the report cannot be retrieved.
        """
        try:
            iam.generate_credential_report()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ReportInProgress":
                return []
        except Exception:
            return []

        for _ in range(10):
            try:
                resp = iam.get_credential_report()
                reader = csv.DictReader(io.StringIO(resp["Content"].decode("utf-8")))
                return list(reader)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("ReportNotPresent", "ReportInProgress"):
                    time.sleep(2)
                else:
                    return []
            except Exception:
                return []

        return []

    @staticmethod
    def _fetch_password_policy(iam):
        try:
            return iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] in ("NoSuchEntity", "NoSuchEntityException"):
                return None
            return None
        except Exception:
            return None

    @staticmethod
    def _fetch_users(iam):
        """
        Fetches all IAM users from list_users, then enriches each user in
        parallel with their access keys, last-used dates, login profile
        presence, attached policies, inline policy documents, and group
        memberships.
        """
        try:
            paginator = iam.get_paginator("list_users")
            users = []
            for page in paginator.paginate():
                users.extend(page["Users"])
        except Exception:
            return []

        def _enrich(user):
            name = user["UserName"]

            # Access keys
            try:
                keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
            except Exception:
                keys = []
            user["_access_keys"] = keys

            # Per-key last-used dates (datetime or None)
            key_last_used = {}
            for key in keys:
                try:
                    info = iam.get_access_key_last_used(
                        AccessKeyId=key["AccessKeyId"]
                    )["AccessKeyLastUsed"]
                    key_last_used[key["AccessKeyId"]] = info.get("LastUsedDate")
                except Exception:
                    key_last_used[key["AccessKeyId"]] = None
            user["_access_key_last_used"] = key_last_used

            # Console login profile
            try:
                iam.get_login_profile(UserName=name)
                user["_has_login_profile"] = True
            except ClientError as e:
                user["_has_login_profile"] = (
                    e.response["Error"]["Code"] not in ("NoSuchEntity", "NoSuchEntityException")
                )
            except Exception:
                user["_has_login_profile"] = False

            # Directly attached managed policies
            try:
                pag = iam.get_paginator("list_attached_user_policies")
                attached = []
                for page in pag.paginate(UserName=name):
                    attached.extend(page["AttachedPolicies"])
                user["_attached_policies"] = attached
            except Exception:
                user["_attached_policies"] = []

            # Inline policies (full documents)
            try:
                pag = iam.get_paginator("list_user_policies")
                policy_names = []
                for page in pag.paginate(UserName=name):
                    policy_names.extend(page["PolicyNames"])
            except Exception:
                policy_names = []

            inline = []
            for pname in policy_names:
                try:
                    doc = iam.get_user_policy(UserName=name, PolicyName=pname)["PolicyDocument"]
                    inline.append({"PolicyName": pname, "Document": doc})
                except Exception:
                    pass
            user["_inline_policies"] = inline

            # Group memberships
            try:
                pag = iam.get_paginator("list_groups_for_user")
                groups = []
                for page in pag.paginate(UserName=name):
                    groups.extend(page["Groups"])
                user["_groups"] = groups
            except Exception:
                user["_groups"] = []

            return user

        with ThreadPoolExecutor(max_workers=10) as executor:
            return list(executor.map(_enrich, users))

    @staticmethod
    def _fetch_roles(iam):
        """
        Fetches all IAM roles from list_roles (which includes AssumeRolePolicyDocument
        and RoleLastUsed), then enriches each role in parallel with attached policies
        and inline policy documents.
        """
        try:
            paginator = iam.get_paginator("list_roles")
            roles = []
            for page in paginator.paginate():
                roles.extend(page["Roles"])
        except Exception:
            return []

        def _enrich(role):
            name = role["RoleName"]

            # Attached managed policies
            try:
                pag = iam.get_paginator("list_attached_role_policies")
                attached = []
                for page in pag.paginate(RoleName=name):
                    attached.extend(page["AttachedPolicies"])
                role["_attached_policies"] = attached
            except Exception:
                role["_attached_policies"] = []

            # Inline policies (full documents)
            try:
                pag = iam.get_paginator("list_role_policies")
                policy_names = []
                for page in pag.paginate(RoleName=name):
                    policy_names.extend(page["PolicyNames"])
            except Exception:
                policy_names = []

            inline = []
            for pname in policy_names:
                try:
                    doc = iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"]
                    inline.append({"PolicyName": pname, "Document": doc})
                except Exception:
                    pass
            role["_inline_policies"] = inline

            return role

        with ThreadPoolExecutor(max_workers=10) as executor:
            return list(executor.map(_enrich, roles))

    @staticmethod
    def _fetch_managed_policies(iam):
        """
        Fetches all customer-managed policies (Scope=Local) and retrieves
        the policy document for each in parallel.
        """
        try:
            paginator = iam.get_paginator("list_policies")
            policies = []
            for page in paginator.paginate(Scope="Local"):
                policies.extend(page["Policies"])
        except Exception:
            return []

        def _enrich(policy):
            try:
                version = iam.get_policy_version(
                    PolicyArn=policy["Arn"],
                    VersionId=policy["DefaultVersionId"],
                )
                policy["_document"] = version["PolicyVersion"]["Document"]
            except Exception:
                policy["_document"] = None
            return policy

        with ThreadPoolExecutor(max_workers=10) as executor:
            return list(executor.map(_enrich, policies))

    @staticmethod
    def _fetch_groups(iam):
        """
        Fetches all IAM groups and enriches each in parallel with attached
        policies and inline policy documents.
        """
        try:
            paginator = iam.get_paginator("list_groups")
            groups = []
            for page in paginator.paginate():
                groups.extend(page["Groups"])
        except Exception:
            return []

        def _enrich(group):
            name = group["GroupName"]

            try:
                pag = iam.get_paginator("list_attached_group_policies")
                attached = []
                for page in pag.paginate(GroupName=name):
                    attached.extend(page["AttachedPolicies"])
                group["_attached_policies"] = attached
            except Exception:
                group["_attached_policies"] = []

            try:
                pag = iam.get_paginator("list_group_policies")
                policy_names = []
                for page in pag.paginate(GroupName=name):
                    policy_names.extend(page["PolicyNames"])
            except Exception:
                policy_names = []

            inline = []
            for pname in policy_names:
                try:
                    doc = iam.get_group_policy(GroupName=name, PolicyName=pname)["PolicyDocument"]
                    inline.append({"PolicyName": pname, "Document": doc})
                except Exception:
                    pass
            group["_inline_policies"] = inline

            return group

        with ThreadPoolExecutor(max_workers=10) as executor:
            return list(executor.map(_enrich, groups))


# ---------- USERS ----------

def check_root_mfa(account_summary):
    mfa_enabled = account_summary.get("AccountMFAEnabled", 0) == 1
    return create_check_result(
        name="Root Account MFA",
        description="Verifies that Multi-Factor Authentication (MFA) is enabled for the root account",
        status="PASS" if mfa_enabled else "FAIL",
        severity="CRITICAL",
        details={
            "mfa_enabled": mfa_enabled,
            "explanation": (
                "Root account is protected with MFA"
                if mfa_enabled
                else "Root account has unrestricted access to all AWS resources and is not protected by MFA"
            ),
        },
        recommendation=None if mfa_enabled else (
            "Enable MFA for the root account immediately. Go to IAM Console > Dashboard > "
            "Security Status > Activate MFA on your root account. "
            "Use a hardware MFA device for maximum security."
        ),
    )


def check_root_access_keys(account_summary):
    keys_present = account_summary.get("AccountAccessKeysPresent", 0)
    return create_check_result(
        name="Root Account Access Keys",
        description="Verifies no active access keys exist for the root account",
        status="PASS" if keys_present == 0 else "FAIL",
        severity="CRITICAL",
        details={
            "root_access_keys_present": keys_present,
            "explanation": (
                "No root access keys found"
                if keys_present == 0
                else (
                    f"{keys_present} active root access key(s) found — "
                    "the root account should never use programmatic credentials"
                )
            ),
        },
        recommendation=None if keys_present == 0 else (
            "Delete all root account access keys immediately. "
            "Use IAM roles with least-privilege policies for programmatic access instead. "
            "Go to IAM Console > Security Credentials (root) > Access Keys > Delete."
        ),
    )


def check_iam_users_mfa(credential_report, users):  # noqa: ARG001 — users kept for signature symmetry
    """Only flags console users (password_enabled=true) who lack MFA. Programmatic-only users are excluded."""
    if not credential_report:
        return create_check_result(
            name="IAM Users MFA",
            description="Checks that all console IAM users have MFA enabled",
            status="WARNING",
            severity="HIGH",
            details={"explanation": "Could not retrieve IAM credential report"},
            recommendation=(
                "Ensure IAM permissions include: iam:GenerateCredentialReport, iam:GetCredentialReport"
            ),
        )

    non_compliant = []
    console_users = 0
    for row in credential_report:
        if row.get("user", "") == "<root_account>":
            continue
        has_password = row.get("password_enabled", "false").lower() == "true"
        mfa_active = row.get("mfa_active", "false").lower() == "true"
        if has_password:
            console_users += 1
            if not mfa_active:
                non_compliant.append(row["user"])

    compliance_rate = (
        f"{((console_users - len(non_compliant)) / console_users * 100):.1f}%"
        if console_users > 0
        else "N/A"
    )
    return create_check_result(
        name="IAM Users MFA",
        description="Checks that all console IAM users have MFA enabled",
        status="PASS" if not non_compliant else "FAIL",
        severity="HIGH",
        details={
            "console_users_checked": console_users,
            "users_without_mfa": len(non_compliant),
            "non_compliant_users": non_compliant,
            "compliance_rate": compliance_rate,
            "note": "Programmatic-only users (no console password) are excluded from this check",
        },
        recommendation=None if not non_compliant else (
            f"Enable MFA for {len(non_compliant)} console user(s): {', '.join(non_compliant)}. "
            "Configure a virtual MFA device or hardware token in IAM Console."
        ),
    )


def check_stale_access_keys(users, stale_days):
    stale = []
    for user in users:
        for key in user.get("_access_keys", []):
            if key.get("Status") != "Active":
                continue
            age = (datetime.now(timezone.utc) - key["CreateDate"]).days
            if age > stale_days:
                stale.append({
                    "user": user["UserName"],
                    "access_key_id": key["AccessKeyId"],
                    "age_days": age,
                })
    return create_check_result(
        name="Stale Access Keys",
        description=f"Identifies active access keys not rotated within {stale_days} days",
        status="PASS" if not stale else "FAIL",
        severity="HIGH",
        details={
            "threshold_days": stale_days,
            "stale_keys_count": len(stale),
            "stale_keys": stale,
            "explanation": (
                f"Found {len(stale)} active key(s) exceeding the {stale_days}-day rotation threshold"
                if stale
                else f"All active access keys are within the {stale_days}-day rotation policy"
            ),
        },
        recommendation=None if not stale else (
            f"Rotate {len(stale)} stale access key(s). "
            "Best practice: disable the old key first, verify nothing breaks, then delete it. "
            "Consider using IAM roles instead of long-lived access keys where possible."
        ),
    )


def check_unused_access_keys(users):
    unused = []
    for user in users:
        for key in user.get("_access_keys", []):
            if key.get("Status") != "Active":
                continue
            last_used = user.get("_access_key_last_used", {}).get(key["AccessKeyId"])
            if last_used is None:
                age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                unused.append({
                    "user": user["UserName"],
                    "access_key_id": key["AccessKeyId"],
                    "age_days": age,
                })
    return create_check_result(
        name="Unused Access Keys",
        description="Identifies active access keys that have been created but never used",
        status="PASS" if not unused else "FAIL",
        severity="MEDIUM",
        details={
            "unused_keys_count": len(unused),
            "unused_keys": unused,
            "explanation": (
                f"Found {len(unused)} active key(s) that have never been used"
                if unused
                else "All active access keys have been used at least once"
            ),
        },
        recommendation=None if not unused else (
            f"Delete or disable {len(unused)} never-used active key(s). "
            "Each dormant credential is an unnecessary attack surface. "
            "Note: last-used data is only available for keys created after April 2015."
        ),
    )


def check_inactive_iam_users(users, stale_days):
    inactive = []
    now = datetime.now(timezone.utc)

    for user in users:
        last_activity = None

        if "PasswordLastUsed" in user:
            last_activity = user["PasswordLastUsed"]

        for key in user.get("_access_keys", []):
            lu = user.get("_access_key_last_used", {}).get(key["AccessKeyId"])
            if lu and (last_activity is None or lu > last_activity):
                last_activity = lu

        if last_activity is not None:
            days_inactive = (now - last_activity).days
            if days_inactive > stale_days:
                inactive.append({
                    "username": user["UserName"],
                    "days_inactive": days_inactive,
                    "last_activity": last_activity.isoformat(),
                })
        else:
            days_since_created = (now - user["CreateDate"]).days
            if days_since_created > stale_days:
                inactive.append({
                    "username": user["UserName"],
                    "days_inactive": "never_used",
                    "created": user["CreateDate"].isoformat(),
                })

    return create_check_result(
        name="Inactive IAM Users",
        description=f"Identifies IAM users with no console login or API activity within the last {stale_days} days",
        status="PASS" if not inactive else "FAIL",
        severity="MEDIUM",
        details={
            "threshold_days": stale_days,
            "inactive_users_count": len(inactive),
            "inactive_users": inactive,
            "explanation": (
                f"Found {len(inactive)} user(s) with no activity in {stale_days}+ days"
                if inactive
                else f"All users have had activity within the last {stale_days} days"
            ),
        },
        recommendation=None if not inactive else (
            f"Review and disable or remove {len(inactive)} inactive user(s). "
            "Unused accounts are an attack surface — stolen credentials for dormant accounts "
            "may go undetected if no one is actively monitoring them."
        ),
    )


def check_multiple_active_access_keys(users):
    multi_key_users = []
    for user in users:
        active = [k for k in user.get("_access_keys", []) if k.get("Status") == "Active"]
        if len(active) > 1:
            multi_key_users.append({
                "username": user["UserName"],
                "active_key_count": len(active),
                "access_key_ids": [k["AccessKeyId"] for k in active],
            })
    return create_check_result(
        name="Multiple Active Access Keys",
        description="Identifies IAM users with more than one active access key simultaneously",
        status="PASS" if not multi_key_users else "FAIL",
        severity="MEDIUM",
        details={
            "count": len(multi_key_users),
            "users_with_multiple_keys": multi_key_users,
            "explanation": (
                f"Found {len(multi_key_users)} user(s) with multiple active keys"
                if multi_key_users
                else "No users have more than one active access key"
            ),
        },
        recommendation=None if not multi_key_users else (
            f"Reduce to a single active key per user for {len(multi_key_users)} user(s). "
            "Multiple active keys typically indicate an incomplete key rotation. "
            "Disable and delete the older key once the newer key is confirmed working."
        ),
    )


# ---------- ROLES ----------

def check_unused_iam_roles(roles, stale_days):
    unused = []
    now = datetime.now(timezone.utc)

    for role in roles:
        last_used_date = role.get("RoleLastUsed", {}).get("LastUsedDate")
        if last_used_date is None:
            days_since_created = (now - role["CreateDate"]).days
            if days_since_created > stale_days:
                unused.append({
                    "role_name": role["RoleName"],
                    "role_arn": role["Arn"],
                    "status": "never_used",
                    "created_days_ago": days_since_created,
                })
        else:
            days_inactive = (now - last_used_date).days
            if days_inactive > stale_days:
                unused.append({
                    "role_name": role["RoleName"],
                    "role_arn": role["Arn"],
                    "status": "stale",
                    "days_since_last_used": days_inactive,
                    "last_used": last_used_date.isoformat(),
                })

    return create_check_result(
        name="Unused IAM Roles",
        description=f"Identifies roles with no activity within the last {stale_days} days, or never used",
        status="PASS" if not unused else "FAIL",
        severity="MEDIUM",
        details={
            "threshold_days": stale_days,
            "unused_roles_count": len(unused),
            "unused_roles": unused[:20],
            "explanation": (
                f"Found {len(unused)} unused or stale role(s)"
                if unused
                else f"All roles have had activity within the last {stale_days} days"
            ),
        },
        recommendation=None if not unused else (
            f"Review and remove {len(unused)} unused role(s). "
            "Verify no active workloads depend on these roles before deletion."
        ),
    )


def check_roles_with_admin_access(roles):
    admin_roles = []
    for role in roles:
        matching = [
            p["PolicyArn"]
            for p in role.get("_attached_policies", [])
            if p.get("PolicyArn") in _ADMIN_POLICY_ARNS
        ]
        if matching:
            admin_roles.append({
                "role_name": role["RoleName"],
                "role_arn": role["Arn"],
                "admin_policies": matching,
            })
    return create_check_result(
        name="Roles with AdministratorAccess",
        description="Identifies roles that have AdministratorAccess or PowerUserAccess attached",
        status="PASS" if not admin_roles else "FAIL",
        severity="HIGH",
        details={
            "admin_roles_count": len(admin_roles),
            "admin_roles": admin_roles,
            "explanation": (
                f"Found {len(admin_roles)} role(s) with broad administrative access"
                if admin_roles
                else "No roles have AdministratorAccess or PowerUserAccess attached"
            ),
        },
        recommendation=None if not admin_roles else (
            f"Replace AdministratorAccess/PowerUserAccess on {len(admin_roles)} role(s) with "
            "least-privilege policies scoped to the specific actions and resources each role requires. "
            "Use IAM Access Analyzer to generate least-privilege policies from CloudTrail activity."
        ),
    )


def check_overly_broad_trust_policies(roles):
    risky = []
    for role in roles:
        doc = role.get("AssumeRolePolicyDocument", {})
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            # Principal: "*" or Principal: {"AWS": "*"} — both are critical
            is_wildcard = principal == "*" or (
                isinstance(principal, dict) and "*" in _normalise_list(principal.get("AWS", []))
            )
            if is_wildcard:
                risky.append({
                    "role_name": role["RoleName"],
                    "role_arn": role["Arn"],
                    "reason": "Trust policy allows any principal ('*') to assume this role",
                })
                break
    return create_check_result(
        name="Overly Broad Role Trust Policies",
        description="Identifies roles whose trust policies allow any principal ('*') to assume them",
        status="PASS" if not risky else "FAIL",
        severity="CRITICAL",
        details={
            "risky_roles_count": len(risky),
            "risky_roles": risky,
            "explanation": (
                f"Found {len(risky)} role(s) that any AWS principal can assume"
                if risky
                else "No roles with wildcard trust policies found"
            ),
        },
        recommendation=None if not risky else (
            f"Restrict the trust policy of {len(risky)} role(s) to specific, named principals. "
            "Principal: '*' allows any entity in any AWS account to assume the role, which is "
            "almost never intentional and represents a critical privilege escalation risk."
        ),
    )


def check_cross_account_role_assumptions(roles, account_id):
    cross_account = []
    for role in roles:
        doc = role.get("AssumeRolePolicyDocument", {})
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if isinstance(principal, str):
                aws_principals = [principal]
            elif isinstance(principal, dict):
                aws_principals = _normalise_list(principal.get("AWS", []))
            else:
                aws_principals = []

            external = [
                p for p in aws_principals
                if isinstance(p, str) and p != "*" and account_id not in p
            ]
            if external:
                cross_account.append({
                    "role_name": role["RoleName"],
                    "role_arn": role["Arn"],
                    "external_principals": external,
                })
                break
    return create_check_result(
        name="Cross-Account Role Assumptions",
        description="Enumerates roles that can be assumed by principals from external AWS accounts",
        status="PASS" if not cross_account else "WARNING",
        severity="HIGH",
        details={
            "cross_account_roles_count": len(cross_account),
            "cross_account_roles": cross_account,
            "explanation": (
                f"Found {len(cross_account)} role(s) accessible from external AWS accounts"
                if cross_account
                else "No cross-account role assumptions detected"
            ),
        },
        recommendation=None if not cross_account else (
            f"Review {len(cross_account)} role(s) with cross-account trust relationships. "
            "Confirm each external account is intentionally trusted, that permissions granted are "
            "appropriately scoped, and that an ExternalId condition is used where applicable."
        ),
    )


def check_service_roles_wildcard_permissions(roles, managed_policies):
    """
    Flags roles used by AWS services (Lambda, EC2, etc.) that have wildcard
    actions or wildcard resources paired with sensitive actions in any of
    their policies (inline or customer-managed attached).

    AWS-managed attached policies are covered by check_overly_broad_aws_managed_policies.
    """
    # Build a lookup of customer-managed policy documents keyed by ARN
    managed_docs = {
        p["Arn"]: p.get("_document")
        for p in managed_policies
        if p.get("_document")
    }

    risky = []
    for role in roles:
        doc = role.get("AssumeRolePolicyDocument", {})
        is_service_role = any(
            isinstance(stmt.get("Principal"), dict) and "Service" in stmt["Principal"]
            for stmt in doc.get("Statement", [])
            if stmt.get("Effect") == "Allow"
        )
        if not is_service_role:
            continue

        wildcard_policies = []

        # Check inline policies
        for policy in role.get("_inline_policies", []):
            for stmt in _allow_statements(policy.get("Document")):
                if _has_wildcard_action(stmt) or (
                    _has_wildcard_resource(stmt) and _has_sensitive_action(stmt)
                ):
                    wildcard_policies.append(policy["PolicyName"])
                    break

        # Check customer-managed attached policies (AWS-managed checked separately)
        for attached in role.get("_attached_policies", []):
            arn = attached.get("PolicyArn", "")
            if arn not in managed_docs:
                continue
            for stmt in _allow_statements(managed_docs[arn]):
                if _has_wildcard_action(stmt) or (
                    _has_wildcard_resource(stmt) and _has_sensitive_action(stmt)
                ):
                    wildcard_policies.append(attached["PolicyName"])
                    break

        if wildcard_policies:
            risky.append({
                "role_name": role["RoleName"],
                "role_arn": role["Arn"],
                "wildcard_policies": wildcard_policies,
            })

    return create_check_result(
        name="Service Roles with Wildcard Permissions",
        description=(
            "Identifies roles used by AWS services (Lambda, EC2, etc.) "
            "with wildcard actions or resources in their policies"
        ),
        status="PASS" if not risky else "FAIL",
        severity="HIGH",
        details={
            "risky_service_roles_count": len(risky),
            "risky_service_roles": risky[:20],
            "explanation": (
                f"Found {len(risky)} service role(s) with overly broad permissions"
                if risky
                else "No service roles with wildcard permissions detected"
            ),
        },
        recommendation=None if not risky else (
            f"Restrict permissions for {len(risky)} service role(s) to the specific actions and "
            "resources their workload requires. Use IAM Access Analyzer to generate least-privilege "
            "policies from observed CloudTrail activity."
        ),
    )


# ---------- POLICIES ----------
# Note: check_disabled_keys_not_deleted is grouped here per the README's
# "Policies" section. Conceptually it concerns access key hygiene, but it
# is placed here to match the documented check grouping.

def check_wildcard_actions_managed_policies(managed_policies):
    risky = []
    for policy in managed_policies:
        for stmt in _allow_statements(policy.get("_document")):
            if _has_wildcard_action(stmt):
                risky.append({
                    "policy_name": policy["PolicyName"],
                    "policy_arn": policy["Arn"],
                    "reason": "Action contains wildcard ('*' or 'service:*') in an Allow statement",
                })
                break
    return create_check_result(
        name="Wildcard Actions in Managed Policies",
        description="Identifies customer-managed policies with Action: '*' or Action: 'service:*' in any statement",
        status="PASS" if not risky else "FAIL",
        severity="HIGH",
        details={
            "risky_policies_count": len(risky),
            "risky_policies": risky[:20],
            "explanation": (
                f"Found {len(risky)} customer-managed policy/policies with wildcard actions"
                if risky
                else "No customer-managed policies with wildcard actions detected"
            ),
        },
        recommendation=None if not risky else (
            f"Replace wildcard actions in {len(risky)} policy/policies with the specific actions "
            "your workload requires. Use IAM Access Analyzer policy generation to produce "
            "least-privilege policies from CloudTrail activity."
        ),
    )


def check_wildcard_resources_managed_policies(managed_policies):
    """Flags customer-managed policies with Resource: '*' paired with sensitive actions."""
    risky = []
    for policy in managed_policies:
        for stmt in _allow_statements(policy.get("_document")):
            if _has_wildcard_resource(stmt) and _has_sensitive_action(stmt):
                risky.append({
                    "policy_name": policy["PolicyName"],
                    "policy_arn": policy["Arn"],
                    "reason": "Resource: '*' paired with sensitive action(s)",
                })
                break
    return create_check_result(
        name="Wildcard Resources in Managed Policies",
        description=(
            "Identifies customer-managed policies with Resource: '*' paired with sensitive actions "
            "(S3, EC2, RDS, IAM, STS, Lambda, DynamoDB, Secrets Manager, KMS, CloudTrail)"
        ),
        status="PASS" if not risky else "FAIL",
        severity="HIGH",
        details={
            "risky_policies_count": len(risky),
            "risky_policies": risky[:20],
            "explanation": (
                f"Found {len(risky)} policy/policies granting sensitive actions on all resources"
                if risky
                else "No customer-managed policies with wildcard resources on sensitive actions detected"
            ),
        },
        recommendation=None if not risky else (
            f"Scope Resource to specific ARNs in {len(risky)} policy/policies. "
            "Replace Resource: '*' with the specific S3 buckets, RDS instances, KMS keys, "
            "or other resources the workload needs to access."
        ),
    )


def check_inline_policy_wildcards(users, roles, groups):
    risky = []

    def _check_entity(entity_type, entity_name, entity_arn, inline_policies):
        for policy in inline_policies:
            for stmt in _allow_statements(policy.get("Document")):
                if _has_wildcard_action(stmt) or (
                    _has_wildcard_resource(stmt) and _has_sensitive_action(stmt)
                ):
                    risky.append({
                        "entity_type": entity_type,
                        "entity_name": entity_name,
                        "entity_arn": entity_arn,
                        "policy_name": policy["PolicyName"],
                        "reason": (
                            "Inline policy contains wildcard action or "
                            "Resource: '*' with sensitive action"
                        ),
                    })
                    break

    for user in users:
        _check_entity("user", user["UserName"], user["Arn"], user.get("_inline_policies", []))
    for role in roles:
        _check_entity("role", role["RoleName"], role["Arn"], role.get("_inline_policies", []))
    for group in groups:
        _check_entity("group", group["GroupName"], group["Arn"], group.get("_inline_policies", []))

    return create_check_result(
        name="Inline Policies with Wildcard Permissions",
        description="Identifies inline policies on users, roles, or groups containing wildcard actions or resources",
        status="PASS" if not risky else "FAIL",
        severity="HIGH",
        details={
            "risky_inline_policies_count": len(risky),
            "risky_inline_policies": risky[:20],
            "explanation": (
                f"Found {len(risky)} inline policy/policies with wildcard permissions"
                if risky
                else "No inline policies with wildcard permissions detected"
            ),
        },
        recommendation=None if not risky else (
            f"Replace {len(risky)} inline policy/policies with scoped customer-managed policies. "
            "Inline policies are embedded in a single entity, cannot be reused, and are harder "
            "to audit consistently. Consolidate permissions into versioned, managed policies."
        ),
    )


def check_notaction_policies(users, roles, groups, managed_policies):
    """Identifies policies using NotAction — grants everything except the listed actions."""
    risky = []

    def _check(entity_type, entity_name, policy_name, doc):
        if _document_has_notaction(doc):
            risky.append({
                "entity_type": entity_type,
                "entity_name": entity_name,
                "policy_name": policy_name,
                "reason": "Policy uses NotAction — grants all actions except those explicitly listed",
            })

    for user in users:
        for p in user.get("_inline_policies", []):
            _check("user", user["UserName"], p["PolicyName"], p.get("Document"))
    for role in roles:
        for p in role.get("_inline_policies", []):
            _check("role", role["RoleName"], p["PolicyName"], p.get("Document"))
    for group in groups:
        for p in group.get("_inline_policies", []):
            _check("group", group["GroupName"], p["PolicyName"], p.get("Document"))
    for policy in managed_policies:
        _check("managed_policy", policy["PolicyName"], policy["PolicyName"], policy.get("_document"))

    return create_check_result(
        name="NotAction Policies",
        description="Identifies policies using NotAction, which grants all actions except those listed",
        status="PASS" if not risky else "FAIL",
        severity="MEDIUM",
        details={
            "risky_policies_count": len(risky),
            "risky_policies": risky[:20],
            "explanation": (
                f"Found {len(risky)} policy/policies using NotAction"
                if risky
                else "No policies using NotAction detected"
            ),
        },
        recommendation=None if not risky else (
            f"Replace NotAction with explicit Action lists in {len(risky)} policy/policies. "
            "NotAction is almost always unintentionally over-permissive: "
            "NotAction: ['iam:*'] grants access to every AWS service except IAM management."
        ),
    )


def check_overly_broad_aws_managed_policies(users, roles, groups):
    risky = []

    def _check_entity(entity_type, entity_name, entity_arn, attached_policies):
        broad = [
            p["PolicyArn"]
            for p in attached_policies
            if p.get("PolicyArn") in _OVERLY_BROAD_AWS_MANAGED_POLICY_ARNS
        ]
        if broad:
            risky.append({
                "entity_type": entity_type,
                "entity_name": entity_name,
                "entity_arn": entity_arn,
                "broad_policies": broad,
            })

    for user in users:
        _check_entity("user", user["UserName"], user["Arn"], user.get("_attached_policies", []))
    for role in roles:
        _check_entity("role", role["RoleName"], role["Arn"], role.get("_attached_policies", []))
    for group in groups:
        _check_entity("group", group["GroupName"], group["Arn"], group.get("_attached_policies", []))

    return create_check_result(
        name="Overly Broad AWS-Managed Policy Attachments",
        description=(
            "Identifies principals with AWS-managed policies such as AdministratorAccess, "
            "PowerUserAccess, IAMFullAccess, or AmazonS3FullAccess attached"
        ),
        status="PASS" if not risky else "FAIL",
        severity="HIGH",
        details={
            "risky_principals_count": len(risky),
            "risky_principals": risky[:20],
            "policies_checked": sorted(_OVERLY_BROAD_AWS_MANAGED_POLICY_ARNS),
            "explanation": (
                f"Found {len(risky)} principal(s) with overly broad AWS-managed policies"
                if risky
                else "No principals with overly broad AWS-managed policies detected"
            ),
        },
        recommendation=None if not risky else (
            f"Replace broad AWS-managed policies on {len(risky)} principal(s) with scoped "
            "customer-managed policies. Use IAM Access Analyzer to identify the minimum "
            "permissions actually needed by each principal."
        ),
    )


def check_sts_assumerole_star(users, roles, groups, managed_policies):
    """Flags policies that allow sts:AssumeRole on Resource: '*', enabling lateral movement."""
    risky = []

    def _check(entity_type, entity_name, policy_name, doc):
        if _document_has_sts_assumerole_star(doc):
            risky.append({
                "entity_type": entity_type,
                "entity_name": entity_name,
                "policy_name": policy_name,
                "reason": (
                    "Policy allows sts:AssumeRole on Resource: '*' — "
                    "holder can assume any role in the account"
                ),
            })

    for user in users:
        for p in user.get("_inline_policies", []):
            _check("user", user["UserName"], p["PolicyName"], p.get("Document"))
    for role in roles:
        for p in role.get("_inline_policies", []):
            _check("role", role["RoleName"], p["PolicyName"], p.get("Document"))
    for group in groups:
        for p in group.get("_inline_policies", []):
            _check("group", group["GroupName"], p["PolicyName"], p.get("Document"))
    for policy in managed_policies:
        _check("managed_policy", policy["PolicyName"], policy["PolicyName"], policy.get("_document"))

    return create_check_result(
        name="Policies Allowing sts:AssumeRole *",
        description=(
            "Identifies policies that allow sts:AssumeRole on Resource: '*', "
            "enabling lateral movement to any role in the account"
        ),
        status="PASS" if not risky else "FAIL",
        severity="HIGH",
        details={
            "risky_policies_count": len(risky),
            "risky_policies": risky[:20],
            "explanation": (
                f"Found {len(risky)} policy/policies allowing sts:AssumeRole on any resource"
                if risky
                else "No policies allowing unrestricted sts:AssumeRole detected"
            ),
        },
        recommendation=None if not risky else (
            f"Restrict sts:AssumeRole to specific role ARNs in {len(risky)} policy/policies. "
            "Allowing sts:AssumeRole on Resource: '*' lets the holder assume any role in the "
            "account, enabling lateral movement to roles with higher or different permissions."
        ),
    )


def check_disabled_keys_not_deleted(users, grace_days=14):
    lingering = []
    for user in users:
        for key in user.get("_access_keys", []):
            if key.get("Status") == "Inactive":
                age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                if age > grace_days:
                    lingering.append({
                        "user": user["UserName"],
                        "access_key_id": key["AccessKeyId"],
                        "age_days": age,
                    })
    return create_check_result(
        name="Disabled Access Keys Not Deleted",
        description=(
            f"Identifies disabled access keys not deleted within {grace_days} days, "
            "contributing to credential sprawl"
        ),
        status="PASS" if not lingering else "FAIL",
        severity="LOW",
        details={
            "grace_days": grace_days,
            "lingering_keys_count": len(lingering),
            "lingering_keys": lingering,
            "explanation": (
                f"Found {len(lingering)} disabled key(s) not deleted after {grace_days} days"
                if lingering
                else f"No disabled access keys older than {grace_days} days — no credential sprawl detected"
            ),
        },
        recommendation=None if not lingering else (
            f"Delete {len(lingering)} disabled access key(s) older than {grace_days} days. "
            "Once a key is confirmed unused and disabled, it should be deleted to reduce the "
            "credential footprint of the account."
        ),
    )


# ---------- USER & GROUP STRUCTURE ----------

def check_users_direct_attached_policies(users):
    direct_policy_users = []
    for user in users:
        attached = user.get("_attached_policies", [])
        if attached:
            direct_policy_users.append({
                "username": user["UserName"],
                "user_arn": user["Arn"],
                "attached_policies": [p["PolicyName"] for p in attached],
                "policy_count": len(attached),
            })
    return create_check_result(
        name="Users with Direct Attached Policies",
        description="Identifies IAM users with policies attached directly rather than through groups",
        status="PASS" if not direct_policy_users else "FAIL",
        severity="MEDIUM",
        details={
            "affected_users_count": len(direct_policy_users),
            "affected_users": direct_policy_users,
            "explanation": (
                f"Found {len(direct_policy_users)} user(s) with directly attached policies"
                if direct_policy_users
                else "All policies are attached through IAM groups — no direct policy attachments"
            ),
        },
        recommendation=None if not direct_policy_users else (
            f"Move permissions for {len(direct_policy_users)} user(s) to IAM groups. "
            "Direct policy attachments make permission audits harder and risk inconsistent access "
            "across users with the same role. Managing permissions through groups ensures "
            "consistent access and simplifies revocation."
        ),
    )


def check_users_no_group_membership(users):
    no_group = []
    for user in users:
        if not user.get("_groups"):
            no_group.append({
                "username": user["UserName"],
                "user_arn": user["Arn"],
            })
    return create_check_result(
        name="Users with No Group Membership",
        description="Identifies IAM users who are not a member of any IAM group",
        status="PASS" if not no_group else "FAIL",
        severity="LOW",
        details={
            "affected_users_count": len(no_group),
            "affected_users": no_group,
            "explanation": (
                f"Found {len(no_group)} user(s) not assigned to any IAM group"
                if no_group
                else "All IAM users are members of at least one group"
            ),
        },
        recommendation=None if not no_group else (
            f"Assign {len(no_group)} user(s) to appropriate IAM groups. "
            "Permissions should be managed through groups so that all users with the same "
            "role have consistent access and revocation is a single group operation."
        ),
    )


def check_password_policy_strength(password_policy):
    if password_policy is None:
        return create_check_result(
            name="Password Policy Strength",
            description=(
                "Verifies the account password policy enforces minimum length, complexity, and expiry"
            ),
            status="FAIL",
            severity="MEDIUM",
            details={
                "policy_configured": False,
                "explanation": (
                    "No account password policy is configured — "
                    "AWS defaults apply, which are very permissive"
                ),
            },
            recommendation=(
                "Configure an account password policy. Require: minimum 14 characters, "
                "uppercase, lowercase, numbers, symbols, and password expiry (90 days or less). "
                "Go to IAM Console > Account settings > Password policy."
            ),
        )

    issues = []
    if password_policy.get("MinimumPasswordLength", 0) < 14:
        issues.append(
            f"Minimum length is {password_policy.get('MinimumPasswordLength', 0)} (required: 14+)"
        )
    if not password_policy.get("RequireUppercaseCharacters", False):
        issues.append("Uppercase characters not required")
    if not password_policy.get("RequireLowercaseCharacters", False):
        issues.append("Lowercase characters not required")
    if not password_policy.get("RequireNumbers", False):
        issues.append("Numbers not required")
    if not password_policy.get("RequireSymbols", False):
        issues.append("Symbols not required")
    if not password_policy.get("ExpirePasswords", False):
        issues.append("Password expiry not enabled")
    elif password_policy.get("MaxPasswordAge", 0) > 90:
        issues.append(
            f"Password expiry is {password_policy['MaxPasswordAge']} days (required: 90 or fewer)"
        )

    return create_check_result(
        name="Password Policy Strength",
        description=(
            "Verifies the account password policy enforces minimum length, complexity, and expiry"
        ),
        status="PASS" if not issues else "FAIL",
        severity="MEDIUM",
        details={
            "policy_configured": True,
            "minimum_length": password_policy.get("MinimumPasswordLength"),
            "requires_uppercase": password_policy.get("RequireUppercaseCharacters", False),
            "requires_lowercase": password_policy.get("RequireLowercaseCharacters", False),
            "requires_numbers": password_policy.get("RequireNumbers", False),
            "requires_symbols": password_policy.get("RequireSymbols", False),
            "expire_passwords": password_policy.get("ExpirePasswords", False),
            "max_password_age": password_policy.get("MaxPasswordAge"),
            "issues": issues,
            "explanation": (
                "Password policy meets minimum security requirements"
                if not issues
                else f"Password policy has {len(issues)} weakness(es): {'; '.join(issues)}"
            ),
        },
        recommendation=None if not issues else (
            f"Strengthen the password policy to address {len(issues)} gap(s): {'; '.join(issues)}. "
            "Go to IAM Console > Account settings > Password policy."
        ),
    )


# ---------- EXECUTIVE SUMMARY ----------

def generate_executive_summary(result):
    """Generate a markdown-formatted executive summary of the IAM audit results."""
    summary = result["metadata"]["summary"]
    account_id = result["metadata"].get("aws_account_id", "Unknown")
    audit_date = result["metadata"].get("generated_at", "")[:10]

    total = summary.get("total_checks", 0)
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)
    warnings = summary.get("warnings", 0)
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)

    compliance_score = int((passed / total * 100)) if total > 0 else 0

    md = []
    md.append("# IAM Security Audit — Executive Summary")
    md.append("")
    md.append(f"**AWS Account:** {account_id}  |  **Date:** {audit_date}  |  "
              f"**Checks:** {total}  |  **Score:** {compliance_score}%")
    md.append("")

    md.append("## Overall Security Posture")
    md.append("")
    if compliance_score >= 90:
        md.append(
            f"**Account {account_id}** demonstrates **strong IAM security** with a "
            f"**{compliance_score}%** pass rate across {total} checks."
        )
    elif compliance_score >= 70:
        md.append(
            f"**Account {account_id}** shows **moderate IAM security** with a "
            f"**{compliance_score}%** pass rate across {total} checks — targeted improvements required."
        )
    else:
        md.append(
            f"**Account {account_id}** requires **significant IAM remediation** with a "
            f"**{compliance_score}%** pass rate across {total} checks."
        )
    md.append("")

    md.append("## Key Findings")
    md.append("")
    if critical > 0 or high > 0:
        parts = []
        if critical > 0:
            parts.append(f"**{critical} critical**")
        if high > 0:
            parts.append(f"**{high} high-severity**")
        md.append(
            f"The audit identified **{failed} failed check(s)** including "
            f"{' and '.join(parts)} issue(s) requiring **immediate remediation**."
        )
    elif failed > 0:
        md.append(
            f"The audit identified **{failed} failed check(s)** with medium or low severity "
            "that should be addressed to improve security posture."
        )
    else:
        md.append(
            "The audit found **no failed checks** — excellent IAM hygiene across all evaluated areas."
        )
    md.append("")

    if warnings > 0:
        md.append(
            f"**{warnings} warning(s)** were recorded (typically permission errors that prevented "
            "a check from running). Grant the required IAM permissions for a complete audit."
        )
        md.append("")

    md.append("## Severity Breakdown")
    md.append("")
    md.append("| Severity | Failed |")
    md.append("|---|---|")
    md.append(f"| Critical | {summary.get('critical', 0)} |")
    md.append(f"| High | {summary.get('high', 0)} |")
    md.append(f"| Medium | {summary.get('medium', 0)} |")
    md.append(f"| Low | {summary.get('low', 0)} |")
    md.append("")

    md.append("## Priority Areas")
    md.append("")
    checks = result.get("checks", [])
    top_failures = [
        c for c in checks
        if c["status"] == "FAIL" and c["severity"] in ("CRITICAL", "HIGH")
    ]
    if top_failures:
        md.append("**Priority remediation areas:**")
        md.append("")
        for c in top_failures[:5]:
            md.append(f"- {c['check_name']} ({c['severity']})")
    else:
        strengths = [c for c in checks if c["status"] == "PASS"]
        if strengths:
            md.append("**Key security strengths demonstrated:**")
            md.append("")
            for c in strengths[:5]:
                md.append(f"- {c['check_name']}")
    md.append("")

    md.append("## Recommendation")
    md.append("")
    if compliance_score >= 90:
        md.append("**Action:** Address minor findings to achieve full IAM least-privilege compliance.")
    elif compliance_score >= 70:
        md.append(
            "**Action:** Focus on critical and high-severity findings as the immediate priority."
        )
    else:
        md.append(
            "**Action:** Implement a structured IAM remediation programme across all identified categories."
        )

    return "\n".join(md)


# ---------- ORCHESTRATOR ----------

def run_iam_audit(profile_name=None, stale_days=90):
    region = "us-east-1"
    session = (
        boto3.Session(profile_name=profile_name, region_name=region)
        if profile_name
        else boto3.Session(region_name=region)
    )

    account_id = session.client("sts", region_name=region).get_caller_identity()["Account"]

    result = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "aws_profile": profile_name or "default",
            "aws_account_id": account_id,
            "stale_days_threshold": stale_days,
            "summary": {},
        },
        "checks": [],
    }

    cache = AWSIAMResourceCache(session, stale_days=stale_days)

    check_tasks = [
        # Users (7 checks)
        lambda: check_root_mfa(cache.account_summary),
        lambda: check_root_access_keys(cache.account_summary),
        lambda: check_iam_users_mfa(cache.credential_report, cache.users),
        lambda: check_stale_access_keys(cache.users, stale_days),
        lambda: check_unused_access_keys(cache.users),
        lambda: check_inactive_iam_users(cache.users, stale_days),
        lambda: check_multiple_active_access_keys(cache.users),
        # Roles (5 checks)
        lambda: check_unused_iam_roles(cache.roles, stale_days),
        lambda: check_roles_with_admin_access(cache.roles),
        lambda: check_overly_broad_trust_policies(cache.roles),
        lambda: check_cross_account_role_assumptions(cache.roles, account_id),
        lambda: check_service_roles_wildcard_permissions(cache.roles, cache.managed_policies),
        # Policies (7 checks)
        lambda: check_wildcard_actions_managed_policies(cache.managed_policies),
        lambda: check_wildcard_resources_managed_policies(cache.managed_policies),
        lambda: check_inline_policy_wildcards(cache.users, cache.roles, cache.groups),
        lambda: check_notaction_policies(
            cache.users, cache.roles, cache.groups, cache.managed_policies
        ),
        lambda: check_overly_broad_aws_managed_policies(cache.users, cache.roles, cache.groups),
        lambda: check_sts_assumerole_star(
            cache.users, cache.roles, cache.groups, cache.managed_policies
        ),
        lambda: check_disabled_keys_not_deleted(cache.users),
        # User & Group Structure (3 checks)
        lambda: check_users_direct_attached_policies(cache.users),
        lambda: check_users_no_group_membership(cache.users),
        lambda: check_password_policy_strength(cache.password_policy),
    ]

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_name = {}
        for check_func in check_tasks:
            future = executor.submit(check_func)
            check_name = "Unknown Check"
            try:
                if hasattr(check_func, "__code__"):
                    for const in check_func.__code__.co_consts:
                        if callable(const) and hasattr(const, "__name__"):
                            check_name = const.__name__
                            break
            except Exception:
                pass
            future_to_name[future] = check_name

        for future in as_completed(future_to_name):
            check_name = future_to_name[future]
            try:
                result["checks"].append(future.result())
            except Exception as e:
                error_type = type(e).__name__
                error_message = str(e)
                is_region_error = (
                    error_type == "NoRegionError"
                    or "You must specify a region" in error_message
                )
                is_permission_error = (
                    "AccessDenied" in error_message
                    or "UnauthorizedOperation" in error_message
                    or "AccessDeniedException" in error_message
                    or "Forbidden" in error_message
                    or error_type in ("ClientError", "NoCredentialsError", "CredentialRetrievalError")
                )
                friendly_name = check_name.replace("check_", "").replace("_", " ").title()
                profile = profile_name or "default"

                if is_region_error:
                    profile_example = (
                        f"[profile {profile}]" if profile != "default" else "[default]"
                    )
                    result["checks"].append(create_check_result(
                        name=f"Configuration Required: {friendly_name}",
                        description="This check requires a default AWS region to be configured",
                        status="WARNING",
                        severity="LOW",
                        details={
                            "error_type": error_type,
                            "error_message": error_message,
                            "check_name": check_name,
                        },
                        recommendation=(
                            f"Add 'region = us-east-1' to the '{profile}' profile in ~/.aws/config:\n\n"
                            f"{profile_example}\nregion = us-east-1"
                        ),
                    ))
                elif is_permission_error:
                    result["checks"].append(create_check_result(
                        name=f"Permission Error: {friendly_name}",
                        description="Unable to perform this check due to insufficient IAM permissions",
                        status="WARNING",
                        severity="LOW",
                        details={
                            "error_type": error_type,
                            "error_message": error_message,
                            "check_name": check_name,
                        },
                        recommendation=(
                            "Grant the IAM permissions listed in the Required IAM Permissions "
                            "section of README-IAM-AWS.md."
                        ),
                    ))
                else:
                    result["checks"].append(create_check_result(
                        name=f"Check Failed: {friendly_name}",
                        description="Check encountered an unexpected error",
                        status="WARNING",
                        severity="LOW",
                        details={
                            "error_type": error_type,
                            "error_message": error_message,
                            "check_name": check_name,
                        },
                        recommendation=(
                            "Review the error details and ensure AWS resources are accessible."
                        ),
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


# ---------- ENTRY POINT ----------

def main():
    parser = argparse.ArgumentParser(
        description="Run an IAM security audit on an AWS account",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--profile", "-p",
        type=str,
        default=None,
        help="AWS CLI profile name to audit (from ~/.aws/credentials or ~/.aws/config)",
    )
    parser.add_argument(
        "--format",
        type=str,
        default="raw",
        choices=["raw", "presentation"],
        help="Output format: raw (JSON, default) or presentation (markdown executive summary)",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Write output to a file instead of stdout",
    )
    parser.add_argument(
        "--stale-days",
        type=int,
        default=90,
        help="Days threshold for inactivity and key rotation checks (default: 90)",
    )
    args = parser.parse_args()

    try:
        raw_report = run_iam_audit(profile_name=args.profile, stale_days=args.stale_days)

        if args.format == "presentation":
            output = generate_executive_summary(raw_report)
        else:
            output = json.dumps(raw_report, indent=2, default=str)

        if args.output:
            with open(args.output, "w") as fh:
                fh.write(output)
        else:
            print(output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

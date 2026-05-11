import boto3
import argparse
import fnmatch
import json
import logging
import sys
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional
from botocore.exceptions import ClientError
from botocore.config import Config

logger = logging.getLogger(__name__)


# ---------- RESULT FACTORY ----------

def _make_result() -> dict[str, Any]:
    """Create a fresh result structure for each analysis run — avoids stale state across multiple calls."""
    return {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "privilege_escalation": {
            "category_description": "Trust chain paths where a role with limited permissions can reach a role with significantly higher permissions",
            "findings": []
        },
        "cross_account_access": {
            "category_description": "Trust relationships where roles can be assumed by principals in other AWS accounts without sufficient condition constraints",
            "findings": []
        },
        "role_hygiene": {
            "category_description": "Permission hygiene issues on individual roles that increase blast radius or indicate misconfiguration",
            "findings": []
        },
        "user_hygiene": {
            "category_description": "IAM user-level security issues including MFA, access key rotation, and permission scope",
            "findings": []
        }
    }


# ---------- FINDING FACTORY ----------

def create_finding(finding_id: str, description: str, status: str, severity: str, details: dict, path: Optional[list] = None, permissions_gained: Optional[list] = None, recommendation: Optional[str] = None) -> dict[str, Any]:
    """Create a standardized finding with IAM-specific fields."""
    result = {
        "finding_id": finding_id,
        "description": description,
        "status": status,           # PASS, FAIL, WARNING
        "severity": severity,       # CRITICAL, HIGH, MEDIUM, LOW
        "path": path or [],
        "permissions_gained": permissions_gained or [],
        "details": details
    }
    if recommendation:
        result["recommendation"] = recommendation
    return result


# ---------- IAM ROLE CACHE ----------

class IAMRoleCache:
    """
    Pre-fetches all IAM role data eagerly in the main thread before any ThreadPoolExecutor starts.
    Worker threads only read — no lazy init, no race conditions.
    """

    def __init__(self, session):
        _retry_config = Config(max_pool_connections=25, retries={"max_attempts": 8, "mode": "adaptive"})
        iam = session.client("iam", config=_retry_config)

        # Phase 1: Fetch roles (needed by everything else)
        self.roles = self._fetch_all_roles(iam)
        self.trust_policies = self._parse_trust_policies(self.roles)

        # Phase 2: Fetch role permissions + users + role_last_used + org_accounts in parallel
        # (role_permissions needs roles; users/last_used/org are independent of each other)
        with ThreadPoolExecutor(max_workers=4) as pool:
            f_perms = pool.submit(self._fetch_role_permissions, iam, self.roles)
            f_last_used = pool.submit(self._fetch_role_last_used, iam, self.roles)
            f_org = pool.submit(self._fetch_org_accounts, session)
            f_users = pool.submit(self._fetch_all_users, iam)

            self.role_permissions, self.inline_policies, self.role_is_admin, self.inaccessible_roles, self.role_denied_actions, self.role_action_resources = f_perms.result()
            self.role_last_used = f_last_used.result()
            self.org_accounts = f_org.result()
            self.users = f_users.result()

        self.trust_graph, self.reverse_graph, self.edge_conditions = self._build_trust_graph(self.roles, self.trust_policies)

        # Phase 3: Fetch user details (needs users list)
        if self.users:
            with ThreadPoolExecutor(max_workers=2) as pool:
                f_user_perms = pool.submit(self._fetch_user_permissions, iam, self.users)
                f_user_details = pool.submit(self._fetch_user_details, iam, self.users)
                self.user_permissions, self.user_is_admin = f_user_perms.result()
                self.user_access_keys, self.user_has_mfa, self.user_has_console = f_user_details.result()
        else:
            self.user_permissions = {}
            self.user_is_admin = {}
            self.user_access_keys = {}
            self.user_has_mfa = {}
            self.user_has_console = {}

    @staticmethod
    def _fetch_all_roles(iam):
        """Paginated list of all IAM roles — trust policy documents are embedded in list_roles response."""
        _ACCESS_DENIED = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation")
        roles = []
        logger.info("Fetching all IAM roles...")
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                roles.extend(page["Roles"])
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in _ACCESS_DENIED:
                raise PermissionError(
                    f"AccessDenied on iam:ListRoles — analysis cannot proceed without role listing permission. "
                    f"(AWS error: {code})"
                ) from e
            raise
        logger.info("Fetched %d IAM roles", len(roles))
        return roles

    @staticmethod
    def _parse_trust_policies(roles):
        """Extract trust policy document per role ARN — already present in list_roles payload, no extra API call."""
        return {role["Arn"]: role.get("AssumeRolePolicyDocument", {}) for role in roles}

    @staticmethod
    def _fetch_role_permissions(iam, roles):
        """
        Fetch attached managed policies + inline policies for every role in parallel.
        Returns:
          role_permissions: dict[role_arn -> set of allowed action strings]
          inline_policies:  dict[role_arn -> list of policy documents]
        """
        logger.info("Fetching permissions for %d roles...", len(roles))
        role_attached = {}      # role_arn -> [policy_arn, ...]
        role_inline_docs = defaultdict(list)
        inaccessible_roles = []
        _ACCESS_DENIED = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation")

        def fetch_role_policies(role):
            arn = role["Arn"]
            name = role["RoleName"]
            attached = []
            inline_docs = []
            access_denied = False
            try:
                for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=name):
                    attached.extend([p["PolicyArn"] for p in page["AttachedPolicies"]])
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in _ACCESS_DENIED:
                    access_denied = True
                elif code != "NoSuchEntity":
                    raise
            try:
                for page in iam.get_paginator("list_role_policies").paginate(RoleName=name):
                    for policy_name in page["PolicyNames"]:
                        try:
                            doc = iam.get_role_policy(RoleName=name, PolicyName=policy_name)
                            inline_docs.append(doc["PolicyDocument"])
                        except ClientError as e:
                            code = e.response["Error"]["Code"]
                            if code in _ACCESS_DENIED:
                                access_denied = True
                            elif code != "NoSuchEntity":
                                raise
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in _ACCESS_DENIED:
                    access_denied = True
                elif code != "NoSuchEntity":
                    raise
            return arn, attached, inline_docs, access_denied

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(fetch_role_policies, r): r for r in roles}
            for future in as_completed(futures):
                arn, attached, inline_docs, access_denied = future.result()
                role_attached[arn] = attached
                role_inline_docs[arn] = inline_docs
                if access_denied:
                    inaccessible_roles.append(arn)

        # Fetch each unique managed policy document once — cache by ARN to avoid duplicate API calls
        unique_policy_arns = {arn for arns in role_attached.values() for arn in arns}
        logger.info("Fetching %d unique managed policy documents...", len(unique_policy_arns))

        def fetch_policy_doc(policy_arn):
            try:
                policy = iam.get_policy(PolicyArn=policy_arn)
                version_id = policy["Policy"]["DefaultVersionId"]
                version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                doc = version["PolicyVersion"]["Document"]
                return policy_arn, doc
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in _ACCESS_DENIED or code == "NoSuchEntity":
                    return policy_arn, {}
                raise
            except Exception as e:
                logger.warning("Unexpected error fetching policy %s: %s: %s", policy_arn, type(e).__name__, e)
                return policy_arn, {}

        policy_action_cache = {}   # policy_arn -> (allowed_set, denied_set)
        policy_pairs_cache = {}    # policy_arn -> list of (action, resource) tuples
        policy_is_admin = {}       # policy_arn -> bool (Action:* on Resource:*)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(fetch_policy_doc, arn): arn for arn in unique_policy_arns}
            for future in as_completed(futures):
                policy_arn, doc = future.result()
                policy_action_cache[policy_arn] = IAMRoleCache._extract_actions(doc)
                policy_pairs_cache[policy_arn] = IAMRoleCache._extract_action_resource_pairs(doc)
                policy_is_admin[policy_arn] = _has_admin_statement(doc)

        # Fetch permission boundary policy documents (may overlap with attached policies)
        boundary_arns = set()
        for role in roles:
            b = role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            if b:
                boundary_arns.add(b)
        # Only fetch boundaries not already cached from attached-policy fetch
        missing_boundary_arns = boundary_arns - set(policy_action_cache.keys())
        if missing_boundary_arns:
            logger.info("Fetching %d permission boundary policy documents...", len(missing_boundary_arns))
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(fetch_policy_doc, arn): arn for arn in missing_boundary_arns}
                for future in as_completed(futures):
                    policy_arn, doc = future.result()
                    policy_action_cache[policy_arn] = IAMRoleCache._extract_actions(doc)

        # Aggregate permissions and admin status per role
        role_permissions = {}
        role_denied_actions = {}
        role_action_resources = {}
        role_is_admin = {}
        for role in roles:
            arn = role["Arn"]
            all_allowed = set()
            all_denied = set()
            all_pairs = []
            for policy_arn in role_attached.get(arn, []):
                allowed, denied = policy_action_cache.get(policy_arn, (set(), set()))
                all_allowed.update(allowed)
                all_denied.update(denied)
                all_pairs.extend(policy_pairs_cache.get(policy_arn, []))
            for doc in role_inline_docs.get(arn, []):
                allowed, denied = IAMRoleCache._extract_actions(doc)
                all_allowed.update(allowed)
                all_denied.update(denied)
                all_pairs.extend(IAMRoleCache._extract_action_resource_pairs(doc))
            # Apply deny subtraction for effective permissions
            effective = IAMRoleCache._apply_deny(all_allowed, all_denied)

            # Apply permission boundary intersection: effective = policy_perms ∩ boundary_perms
            boundary_arn = role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            if boundary_arn:
                boundary_allowed, _ = policy_action_cache.get(boundary_arn, (set(), set()))
                if boundary_allowed:
                    effective = IAMRoleCache._intersect_with_boundary(effective, boundary_allowed)

            role_permissions[arn] = effective
            role_denied_actions[arn] = all_denied
            role_action_resources[arn] = all_pairs

            # Admin = effective permissions still contain admin-level actions after boundary
            is_admin = _has_admin_statement_from_actions(effective)
            role_is_admin[arn] = is_admin

        return role_permissions, dict(role_inline_docs), role_is_admin, inaccessible_roles, role_denied_actions, role_action_resources

    @staticmethod
    def _extract_actions(policy_doc):
        """
        Extract Allow and Deny action strings from a policy document.

        Returns (allowed, denied) tuple of sets.

        NotAction with Resource: * is treated as a wildcard grant ("*") because
        NotAction: ["s3:GetObject"] on Resource: * allows every action except
        the listed one — effectively broader than most explicit grants.
        """
        allowed = set()
        denied = set()
        if not isinstance(policy_doc, dict):
            return allowed, denied
        for stmt in policy_doc.get("Statement", []):
            effect = stmt.get("Effect")
            if effect == "Allow":
                # NotAction + Resource:* is effectively a wildcard grant
                if "NotAction" in stmt:
                    resources = stmt.get("Resource", [])
                    if isinstance(resources, str):
                        resources = [resources]
                    if "*" in resources:
                        allowed.add("*")
                    continue
                raw = stmt.get("Action", [])
                if isinstance(raw, str):
                    raw = [raw]
                allowed.update(raw)
            elif effect == "Deny":
                # NotAction in Deny = deny everything except listed = effectively deny all
                if "NotAction" in stmt:
                    denied.add("*")
                    continue
                raw = stmt.get("Action", [])
                if isinstance(raw, str):
                    raw = [raw]
                denied.update(raw)
        return allowed, denied

    @staticmethod
    def _apply_deny(allowed: set, denied: set) -> set:
        """Subtract denied actions from allowed. Wildcard deny clears everything."""
        if not denied:
            return allowed
        if "*" in denied:
            return set()
        result = set()
        for action in allowed:
            if action in denied:
                continue
            # Service-wildcard deny: "iam:*" in denied removes "iam:CreateRole"
            if ":" in action:
                service_wildcard = action.split(":")[0] + ":*"
                if service_wildcard in denied:
                    continue
            result.add(action)
        return result

    @staticmethod
    def _intersect_with_boundary(effective: set, boundary_allowed: set) -> set:
        """
        Compute effective permissions as policy_perms ∩ boundary_perms.

        If boundary grants '*', it's permissive — all effective permissions pass through.
        If effective has '*' but boundary is scoped, the effective set is narrowed to the boundary.
        Otherwise, keep only actions present in both sets (with service-wildcard expansion).
        """
        if "*" in boundary_allowed:
            return effective  # boundary is permissive
        if "*" in effective:
            # Policy grants everything, but boundary restricts — effective becomes boundary
            return set(boundary_allowed)
        # For each effective action, check if boundary allows it
        result = set()
        for action in effective:
            if action in boundary_allowed:
                result.add(action)
                continue
            # Check if boundary has a service wildcard that covers this action
            if ":" in action:
                service = action.split(":")[0]
                if f"{service}:*" in boundary_allowed:
                    result.add(action)
        return result

    @staticmethod
    def _extract_action_resource_pairs(policy_doc):
        """Extract (action, resource) tuples from Allow statements for resource-scoped checks."""
        pairs = []
        if not isinstance(policy_doc, dict):
            return pairs
        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            # NotAction + Resource:* treated conservatively as wildcard
            if "NotAction" in stmt:
                actions = ["*"]
            for a in actions:
                for r in resources:
                    pairs.append((a, r))
        return pairs

    @staticmethod
    def _build_trust_graph(roles, trust_policies):
        """
        Build directed trust graph from IAM trust policies.

        trust_graph[role_arn]       = list of principals that can assume this role
        reverse_graph[principal]    = list of role ARNs that this principal can assume
        edge_conditions[(p, role)]  = {has_external_id, has_org_id, is_cross_account}
        """
        trust_graph = defaultdict(list)
        reverse_graph = defaultdict(list)
        edge_conditions = {}

        for role in roles:
            role_arn = role["Arn"]
            role_account = role_arn.split(":")[4]
            doc = trust_policies.get(role_arn, {})

            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                _STS_ASSUME_ACTIONS = (
                    "sts:AssumeRole", "sts:AssumeRoleWithWebIdentity",
                    "sts:AssumeRoleWithSAML", "sts:*", "*",
                )
                if not any(a in _STS_ASSUME_ACTIONS for a in actions):
                    continue

                # NotPrincipal means "everyone except the listed principals" — treat as wildcard (worst case)
                if "NotPrincipal" in stmt:
                    principals = ["*"]
                    federated_principals = set()
                else:
                    principal = stmt.get("Principal", {})
                    principals = []
                    federated_principals = set()
                    if principal == "*":
                        principals = ["*"]
                    elif isinstance(principal, str):
                        principals = [principal]
                    elif isinstance(principal, dict):
                        for key in ("AWS", "Service", "Federated"):
                            val = principal.get(key, [])
                            if isinstance(val, str):
                                val = [val]
                            principals.extend(val)
                            if key == "Federated":
                                federated_principals.update(val)

                conds = stmt.get("Condition", {})
                # Check all common condition operators that can legitimately restrict ExternalId/OrgID
                _all_cond_keys = set()
                for op_block in conds.values():
                    if isinstance(op_block, dict):
                        _all_cond_keys.update(op_block.keys())
                has_external_id = "sts:ExternalId" in _all_cond_keys
                has_org_id = "aws:PrincipalOrgID" in _all_cond_keys

                for p in principals:
                    trust_graph[role_arn].append(p)
                    reverse_graph[p].append(role_arn)
                    p_account = p.split(":")[4] if p.count(":") >= 5 else None
                    is_federated = (
                        p in federated_principals
                        or ":saml-provider/" in p
                        or ":oidc-provider/" in p
                    )
                    is_cross_account = (
                        p_account is not None
                        and p_account != role_account
                        and not p.endswith(".amazonaws.com")
                        and not is_federated
                    )
                    edge_conditions[(p, role_arn)] = {
                        "has_external_id": has_external_id,
                        "has_org_id": has_org_id,
                        "is_cross_account": is_cross_account,
                        "is_federated": is_federated,
                    }

        return dict(trust_graph), dict(reverse_graph), edge_conditions

    @staticmethod
    def _fetch_role_last_used(iam, roles):
        """Fetch RoleLastUsed data for each role — get_role() is required as list_roles does not include this field."""
        logger.info("Fetching last-used data for %d roles...", len(roles))
        last_used = {}

        def fetch_one(role):
            try:
                detail = iam.get_role(RoleName=role["RoleName"])["Role"]
                used = detail.get("RoleLastUsed", {}).get("LastUsedDate")
                return role["Arn"], used
            except ClientError as e:
                logger.warning("Could not fetch last-used for role %s: %s", role["RoleName"], e)
                return role["Arn"], None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(fetch_one, r): r for r in roles}
            for future in as_completed(futures):
                arn, used = future.result()
                last_used[arn] = used

        return last_used

    @staticmethod
    def _fetch_org_accounts(session):
        """Fetch all account IDs in the organisation. Returns empty set gracefully if not accessible."""
        logger.info("Fetching organization accounts...")
        try:
            _org_config = Config(retries={"max_attempts": 5, "mode": "adaptive"})
            org = session.client("organizations", config=_org_config)
            accounts = set()
            for page in org.get_paginator("list_accounts").paginate():
                for acct in page["Accounts"]:
                    accounts.add(acct["Id"])
            logger.info("Fetched %d organization accounts", len(accounts))
            return accounts
        except ClientError as e:
            logger.info("Could not fetch organization accounts: %s — treating as non-org account", e)
            return set()


    @staticmethod
    def _fetch_all_users(iam):
        """Paginated list of all IAM users."""
        _ACCESS_DENIED = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation")
        users = []
        logger.info("Fetching all IAM users...")
        try:
            for page in iam.get_paginator("list_users").paginate():
                users.extend(page["Users"])
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in _ACCESS_DENIED:
                logger.warning("AccessDenied on iam:ListUsers — user scanning skipped")
                return []
            raise
        logger.info("Fetched %d IAM users", len(users))
        return users

    @staticmethod
    def _fetch_user_permissions(iam, users):
        """
        Fetch permissions for each IAM user including attached, inline, and group policies.
        Returns (user_permissions, user_is_admin).
        """
        _ACCESS_DENIED = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation")
        logger.info("Fetching permissions for %d users...", len(users))

        # Pre-fetch group policies once per group to avoid duplicate API calls
        # when multiple users share the same group.
        group_permissions_cache = {}  # group_name -> (allowed_set, denied_set)

        def _fetch_group_permissions(gname):
            """Fetch and cache all permissions for a single IAM group."""
            if gname in group_permissions_cache:
                return group_permissions_cache[gname]
            g_allowed, g_denied = set(), set()
            # Attached managed policies
            try:
                for page in iam.get_paginator("list_attached_group_policies").paginate(GroupName=gname):
                    for p in page["AttachedPolicies"]:
                        try:
                            policy = iam.get_policy(PolicyArn=p["PolicyArn"])
                            version_id = policy["Policy"]["DefaultVersionId"]
                            version = iam.get_policy_version(PolicyArn=p["PolicyArn"], VersionId=version_id)
                            doc = version["PolicyVersion"]["Document"]
                            allowed, denied = IAMRoleCache._extract_actions(doc)
                            g_allowed.update(allowed)
                            g_denied.update(denied)
                        except ClientError as e:
                            if e.response["Error"]["Code"] not in _ACCESS_DENIED and e.response["Error"]["Code"] != "NoSuchEntity":
                                raise
            except ClientError as e:
                if e.response["Error"]["Code"] not in _ACCESS_DENIED and e.response["Error"]["Code"] != "NoSuchEntity":
                    raise
            # Inline policies
            try:
                for page in iam.get_paginator("list_group_policies").paginate(GroupName=gname):
                    for policy_name in page["PolicyNames"]:
                        try:
                            doc = iam.get_group_policy(GroupName=gname, PolicyName=policy_name)["PolicyDocument"]
                            allowed, denied = IAMRoleCache._extract_actions(doc)
                            g_allowed.update(allowed)
                            g_denied.update(denied)
                        except ClientError as e:
                            if e.response["Error"]["Code"] not in _ACCESS_DENIED and e.response["Error"]["Code"] != "NoSuchEntity":
                                raise
            except ClientError as e:
                if e.response["Error"]["Code"] not in _ACCESS_DENIED and e.response["Error"]["Code"] != "NoSuchEntity":
                    raise
            group_permissions_cache[gname] = (g_allowed, g_denied)
            return g_allowed, g_denied

        # Pre-fetch user-to-group mappings and group permissions in parallel
        user_groups_cache = {}  # username -> [group_name, ...]
        all_group_names = set()
        for user in users:
            try:
                groups = iam.list_groups_for_user(UserName=user["UserName"]).get("Groups", [])
                gnames = [g["GroupName"] for g in groups]
                user_groups_cache[user["UserName"]] = gnames
                all_group_names.update(gnames)
            except ClientError:
                user_groups_cache[user["UserName"]] = []

        with ThreadPoolExecutor(max_workers=max(1, len(all_group_names))) as pool:
            list(pool.map(_fetch_group_permissions, all_group_names))
        logger.info("Cached permissions for %d unique groups", len(group_permissions_cache))

        def fetch_one_user(user):
            name = user["UserName"]
            arn = user["Arn"]
            all_allowed = set()
            all_denied = set()
            access_denied = False

            # Attached managed policies
            try:
                for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=name):
                    for p in page["AttachedPolicies"]:
                        try:
                            policy = iam.get_policy(PolicyArn=p["PolicyArn"])
                            version_id = policy["Policy"]["DefaultVersionId"]
                            version = iam.get_policy_version(PolicyArn=p["PolicyArn"], VersionId=version_id)
                            doc = version["PolicyVersion"]["Document"]
                            allowed, denied = IAMRoleCache._extract_actions(doc)
                            all_allowed.update(allowed)
                            all_denied.update(denied)
                        except ClientError as e:
                            if e.response["Error"]["Code"] in _ACCESS_DENIED:
                                access_denied = True
                            elif e.response["Error"]["Code"] != "NoSuchEntity":
                                raise
            except ClientError as e:
                if e.response["Error"]["Code"] in _ACCESS_DENIED:
                    access_denied = True
                elif e.response["Error"]["Code"] != "NoSuchEntity":
                    raise

            # Inline policies
            try:
                for page in iam.get_paginator("list_user_policies").paginate(UserName=name):
                    for policy_name in page["PolicyNames"]:
                        try:
                            doc = iam.get_user_policy(UserName=name, PolicyName=policy_name)["PolicyDocument"]
                            allowed, denied = IAMRoleCache._extract_actions(doc)
                            all_allowed.update(allowed)
                            all_denied.update(denied)
                        except ClientError as e:
                            if e.response["Error"]["Code"] in _ACCESS_DENIED:
                                access_denied = True
                            elif e.response["Error"]["Code"] != "NoSuchEntity":
                                raise
            except ClientError as e:
                if e.response["Error"]["Code"] in _ACCESS_DENIED:
                    access_denied = True
                elif e.response["Error"]["Code"] != "NoSuchEntity":
                    raise

            # Group policies (from pre-fetched caches — no extra API call)
            for gname in user_groups_cache.get(name, []):
                g_allowed, g_denied = group_permissions_cache.get(gname, (set(), set()))
                all_allowed.update(g_allowed)
                all_denied.update(g_denied)

            effective = IAMRoleCache._apply_deny(all_allowed, all_denied)
            is_admin = "*" in effective or "*:*" in effective or "iam:*" in effective
            return arn, effective, is_admin, access_denied

        user_permissions = {}
        user_is_admin = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(fetch_one_user, u): u for u in users}
            for future in as_completed(futures):
                arn, perms, is_admin, _ = future.result()
                user_permissions[arn] = perms
                user_is_admin[arn] = is_admin

        return user_permissions, user_is_admin

    @staticmethod
    def _fetch_user_details(iam, users):
        """
        Fetch access keys, MFA devices, and console login status for each user.
        Returns (user_access_keys, user_has_mfa, user_has_console).
        """
        _ACCESS_DENIED = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation")
        logger.info("Fetching user details (access keys, MFA, console) for %d users...", len(users))

        def fetch_one(user):
            name = user["UserName"]
            arn = user["Arn"]
            access_keys = []
            has_mfa = False
            has_console = False

            # Access keys
            try:
                for page in iam.get_paginator("list_access_keys").paginate(UserName=name):
                    for key in page["AccessKeyMetadata"]:
                        access_keys.append({
                            "KeyId": key["AccessKeyId"],
                            "CreateDate": key["CreateDate"],
                            "Status": key["Status"],
                        })
            except ClientError as e:
                if e.response["Error"]["Code"] not in _ACCESS_DENIED:
                    raise

            # MFA devices
            try:
                mfa_resp = iam.list_mfa_devices(UserName=name)
                has_mfa = len(mfa_resp.get("MFADevices", [])) > 0
            except ClientError as e:
                if e.response["Error"]["Code"] not in _ACCESS_DENIED:
                    raise

            # Console access (login profile)
            try:
                iam.get_login_profile(UserName=name)
                has_console = True
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "NoSuchEntity":
                    has_console = False
                elif code not in _ACCESS_DENIED:
                    raise

            return arn, access_keys, has_mfa, has_console

        user_access_keys = {}
        user_has_mfa = {}
        user_has_console = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(fetch_one, u): u for u in users}
            for future in as_completed(futures):
                arn, keys, mfa, console = future.result()
                user_access_keys[arn] = keys
                user_has_mfa[arn] = mfa
                user_has_console[arn] = console

        return user_access_keys, user_has_mfa, user_has_console


# ---------- GRAPH TRAVERSAL ----------

def find_all_escalation_paths(start_arn: str, reverse_graph: dict, role_is_admin: dict, role_permissions: dict, max_depth: int) -> list:
    """
    BFS from start_arn following reverse_graph edges (roles that start_arn can assume).
    Returns list of (path, final_role_arn, permissions) for paths reaching high-privilege roles.
    Uses role_is_admin (per-statement Action+Resource check) for accurate admin detection.
    Cycle-safe: visited set prevents revisiting nodes within a traversal.
    """
    results = []
    queue = deque([(start_arn, [start_arn])])
    visited = {start_arn}

    while queue:
        current, path = queue.popleft()
        if len(path) > max_depth + 1:
            continue
        for target_arn in reverse_graph.get(current, []):
            if not target_arn.startswith("arn:aws:iam::"):
                continue
            if target_arn in visited:
                continue
            new_path = path + [target_arn]
            if role_is_admin.get(target_arn, False):
                results.append((new_path, target_arn, role_permissions.get(target_arn, set())))
            visited.add(target_arn)
            queue.append((target_arn, new_path))

    return results


def find_cycles(trust_graph: dict) -> list:
    """
    Detect cycles in the trust graph using iterative DFS. Returns list of cycle paths.

    Each start node gets its own visited set so that nodes shared between multiple
    traversals are not prematurely skipped — e.g. D→B→D is found even if B was
    already visited during an earlier traversal from A.
    """
    cycles = []
    seen_cycles: set[frozenset] = set()

    for start in list(trust_graph.keys()):
        # Per-traversal visited: only skip nodes already processed in THIS traversal
        visited: set[str] = set()
        stack = [(start, [start], {start})]
        while stack:
            node, path, rec_stack = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            for neighbor in trust_graph.get(node, []):
                if not neighbor.startswith("arn:aws:iam::"):
                    continue
                if neighbor in rec_stack:
                    idx = path.index(neighbor) if neighbor in path else 0
                    cycle = path[idx:] + [neighbor]
                    key = frozenset(cycle)
                    if key not in seen_cycles:
                        seen_cycles.add(key)
                        cycles.append(cycle)
                elif neighbor not in visited:
                    stack.append((neighbor, path + [neighbor], rec_stack | {neighbor}))

    return cycles


def _has_admin_statement(policy_doc: dict) -> bool:
    """
    Return True if a policy document contains an Allow statement with both
    a broad action (*, *:*, iam:*) AND a broad resource scope in the same statement.

    Broad resource scope means either Resource: * or NotResource (which applies
    the action to all resources except the listed exclusions — effectively broad).
    Checking action+resource together avoids false positives where iam:* is scoped
    to a specific resource ARN — that is NOT admin access.
    """
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        is_broad_action = "*" in actions or "*:*" in actions or "iam:*" in actions
        # NotResource is a broad resource scope — it grants access to everything except exclusions
        is_broad_resource = "*" in resources or "NotResource" in stmt
        if is_broad_action and is_broad_resource:
            return True
    return False


def _perms_contain(perms: set, action: str) -> bool:
    """
    Check if a permission set grants a specific action, accounting for wildcards.

    Handles: exact match, service-wildcard (iam:*), global wildcard (*),
    and IAM-style glob patterns (iam:Pass*, s3:Get*).
    """
    if action in perms or "*" in perms:
        return True
    # Check service-wildcard: "iam:*" covers "iam:PassRole"
    if ":" in action:
        service = action.split(":")[0]
        if f"{service}:*" in perms:
            return True
    # Check IAM-style glob patterns in the permission set (e.g. "iam:Pass*")
    for perm in perms:
        if "*" in perm or "?" in perm:
            if fnmatch.fnmatch(action.lower(), perm.lower()):
                return True
    return False


def _has_admin_statement_from_actions(effective_perms: set) -> bool:
    """Check if a set of effective permissions (post-deny, post-boundary) is admin-level."""
    return bool({"*", "*:*", "iam:*"} & effective_perms)


def _get_admin_permissions(permission_set):
    """Return the subset of permissions that are considered high-privilege."""
    high_priv = {"*", "*:*", "iam:*", "iam:CreatePolicyVersion",
                 "iam:AttachRolePolicy", "iam:PutRolePolicy",
                 "iam:UpdateAssumeRolePolicy", "iam:PassRole"}
    return sorted(permission_set & high_priv)


# ---------- RESOURCE-SCOPED HELPERS ----------

def _is_wildcard_resource(resource: str) -> bool:
    """Return True if a resource string is effectively a wildcard covering all roles/resources."""
    if resource == "*":
        return True
    # arn:aws:iam::*:role/* covers all roles in all accounts — functionally wildcard
    if resource.endswith(":role/*") and ":*:" in resource:
        return True
    # arn:aws:iam::123456789012:role/* covers all roles in the account
    if resource.endswith(":role/*"):
        return True
    return False


def _has_action_on_wildcard_resource(role_arn: str, action_names: set, cache) -> bool:
    """Check if a role has any of the given actions on a wildcard resource (not scoped to a specific ARN)."""
    for action, resource in cache.role_action_resources.get(role_arn, []):
        if _is_wildcard_resource(resource) and (action in action_names or action == "*"):
            return True
    return False


# ---------- PRIVILEGE ESCALATION CHECKS ----------

def check_direct_admin_access(cache):
    """CRITICAL: Roles that directly hold admin-level permissions."""
    admin_roles = [
        {
            "role_arn": role["Arn"],
            "role_name": role["RoleName"],
            "admin_permissions": _get_admin_permissions(cache.role_permissions.get(role["Arn"], set()))
        }
        for role in cache.roles
        if cache.role_is_admin.get(role["Arn"], False)
    ]

    return create_finding(
        finding_id="DIRECT_ADMIN_ACCESS",
        description="Roles that directly hold administrator-level or IAM-manipulation permissions",
        status="FAIL" if admin_roles else "PASS",
        severity="CRITICAL",
        details={
            "admin_roles_count": len(admin_roles),
            "admin_roles": admin_roles[:20],
            "explanation": (
                f"{len(admin_roles)} role(s) hold direct admin-level permissions" if admin_roles
                else "No roles hold direct admin-level permissions"
            )
        },
        recommendation=None if not admin_roles else (
            "Review admin-level roles and ensure they follow least-privilege. "
            "Use permissions boundaries and restrict who can assume these roles."
        )
    )


def check_single_hop_escalation(cache):
    """CRITICAL: Low-privilege role can assume a high-privilege role in one hop."""
    escalation_paths = []

    for role in cache.roles:
        start_arn = role["Arn"]
        if cache.role_is_admin.get(start_arn, False):
            continue
        for target_arn in cache.reverse_graph.get(start_arn, []):
            if not target_arn.startswith("arn:aws:iam::"):
                continue
            if cache.role_is_admin.get(target_arn, False):
                target_perms = cache.role_permissions.get(target_arn, set())
                escalation_paths.append({
                    "path": [start_arn, target_arn],
                    "permissions_gained": _get_admin_permissions(target_perms),
                    "source_role": start_arn,
                    "target_role": target_arn
                })

    return create_finding(
        finding_id="PRIV_ESC_SINGLE_HOP",
        description="Low-privilege role can assume a high-privilege role in a single sts:AssumeRole hop",
        status="FAIL" if escalation_paths else "PASS",
        severity="CRITICAL",
        path=escalation_paths[0]["path"] if escalation_paths else [],
        permissions_gained=escalation_paths[0]["permissions_gained"] if escalation_paths else [],
        details={
            "escalation_paths_count": len(escalation_paths),
            "escalation_paths": escalation_paths[:10],
            "explanation": (
                f"{len(escalation_paths)} single-hop privilege escalation path(s) found" if escalation_paths
                else "No single-hop privilege escalation paths found"
            )
        },
        recommendation=None if not escalation_paths else (
            f"Remove or restrict sts:AssumeRole permissions for {len(escalation_paths)} path(s). "
            "Add aws:PrincipalTag or aws:RequestedRegion conditions to limit who can assume high-privilege roles."
        )
    )


def check_multi_hop_escalation(cache, max_depth):
    """HIGH: Role can reach a high-privilege role through 2+ assume-role hops."""
    multi_hop_paths = []

    for role in cache.roles:
        start_arn = role["Arn"]
        if cache.role_is_admin.get(start_arn, False):
            continue
        for path, final_arn, final_perms in find_all_escalation_paths(start_arn, cache.reverse_graph, cache.role_is_admin, cache.role_permissions, max_depth):
            if len(path) > 2:
                multi_hop_paths.append({
                    "path": path,
                    "hops": len(path) - 1,
                    "permissions_gained": _get_admin_permissions(final_perms),
                    "source_role": start_arn,
                    "target_role": final_arn
                })

    # Deduplicate by path
    seen = set()
    unique_paths = []
    for p in multi_hop_paths:
        key = tuple(p["path"])
        if key not in seen:
            seen.add(key)
            unique_paths.append(p)

    return create_finding(
        finding_id="PRIV_ESC_MULTI_HOP",
        description="Role can reach a high-privilege role through 2 or more sts:AssumeRole hops",
        status="FAIL" if unique_paths else "PASS",
        severity="HIGH",
        path=unique_paths[0]["path"] if unique_paths else [],
        permissions_gained=unique_paths[0]["permissions_gained"] if unique_paths else [],
        details={
            "multi_hop_paths_count": len(unique_paths),
            "multi_hop_paths": unique_paths[:10],
            "max_depth_used": max_depth,
            "explanation": (
                f"{len(unique_paths)} multi-hop escalation path(s) found (up to {max_depth} hops)" if unique_paths
                else f"No multi-hop escalation paths found (checked up to {max_depth} hops)"
            )
        },
        recommendation=None if not unique_paths else (
            "Audit intermediate roles in each chain — ensure no role can be used as a stepping stone to admin access. "
            "Consider breaking long trust chains and requiring explicit approval for cross-role assumptions."
        )
    )


def check_pass_role_escalation(cache):
    """HIGH: Role has iam:PassRole without resource constraints, enabling service-based privilege escalation."""
    confirmed_roles = []   # inline policy — resource scope known to be *
    warning_roles = []     # managed policy — resource scope unknown, manual review needed

    for role in cache.roles:
        arn = role["Arn"]
        flagged_inline = False
        for doc in cache.inline_policies.get(arn, []):
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                if ("iam:PassRole" in actions or "iam:*" in actions or "*" in actions) and "*" in resources:
                    confirmed_roles.append({
                        "role_arn": arn,
                        "role_name": role["RoleName"],
                        "reason": "Inline policy grants iam:PassRole on all resources (*)"
                    })
                    flagged_inline = True
                    break
            if flagged_inline:
                break

        if not flagged_inline:
            perms = cache.role_permissions.get(arn, set())
            if _perms_contain(perms, "iam:PassRole"):
                # With resource-scoped data, check if PassRole is on wildcard resource
                if _has_action_on_wildcard_resource(arn, {"iam:PassRole", "iam:*", "*"}, cache):
                    confirmed_roles.append({
                        "role_arn": arn,
                        "role_name": role["RoleName"],
                        "reason": "Managed policy grants iam:PassRole on all resources (*)"
                    })
                else:
                    warning_roles.append({
                        "role_arn": arn,
                        "role_name": role["RoleName"],
                        "reason": "iam:PassRole granted via managed policy scoped to specific resources — verify manually"
                    })

    if confirmed_roles:
        status = "FAIL"
        all_roles = confirmed_roles + warning_roles
    elif warning_roles:
        status = "WARNING"
        all_roles = warning_roles
    else:
        status = "PASS"
        all_roles = []

    return create_finding(
        finding_id="PRIV_ESC_PASS_ROLE",
        description="Role has iam:PassRole permission, enabling privilege escalation by attaching a higher-privilege role to a compute service",
        status=status,
        severity="HIGH",
        details={
            "confirmed_count": len(confirmed_roles),
            "needs_review_count": len(warning_roles),
            "risky_roles": all_roles[:20],
            "explanation": (
                f"{len(confirmed_roles)} confirmed (inline wildcard) + {len(warning_roles)} needing manual review"
                if all_roles else "No roles have unconstrained iam:PassRole"
            )
        },
        recommendation=None if not all_roles else (
            "Restrict iam:PassRole to specific role ARNs: "
            "\"Resource\": \"arn:aws:iam::ACCOUNT:role/specific-role\". "
            "Never allow iam:PassRole on Resource: \"*\"."
        )
    )


def check_create_policy_version_escalation(cache):
    """HIGH: Role can create new IAM policy versions, enabling self-elevation."""
    risky_roles = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if not cache.role_is_admin.get(role["Arn"], False)  # already reported by DIRECT_ADMIN_ACCESS
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:CreatePolicyVersion")
    ]

    return create_finding(
        finding_id="PRIV_ESC_CREATE_POLICY_VERSION",
        description="Role can create new IAM policy versions, enabling self-elevation by overwriting an attached policy",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have iam:CreatePolicyVersion" if risky_roles
                else "No roles have iam:CreatePolicyVersion"
            )
        },
        recommendation=None if not risky_roles else (
            "Remove iam:CreatePolicyVersion from roles that do not need to manage IAM policies. "
            "If required, restrict to specific policy ARNs using resource-level constraints."
        )
    )


def check_set_default_policy_version_escalation(cache):
    """HIGH: Role can switch the default version of an attached policy to a previously stored broader version."""
    risky_roles = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if not cache.role_is_admin.get(role["Arn"], False)
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:SetDefaultPolicyVersion")
    ]

    return create_finding(
        finding_id="PRIV_ESC_SET_DEFAULT_POLICY_VERSION",
        description="Role can switch the active version of an IAM policy, potentially activating an older version with broader permissions",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have iam:SetDefaultPolicyVersion" if risky_roles
                else "No roles have iam:SetDefaultPolicyVersion"
            )
        },
        recommendation=None if not risky_roles else (
            "Remove iam:SetDefaultPolicyVersion unless strictly required. "
            "Pair with iam:CreatePolicyVersion restrictions and enable AWS Config rule access-keys-rotated to detect version changes."
        )
    )


def check_attach_role_policy_escalation(cache):
    """HIGH: Role can attach arbitrary managed policies to itself or other roles."""
    risky_roles = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if not cache.role_is_admin.get(role["Arn"], False)  # already reported by DIRECT_ADMIN_ACCESS
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:AttachRolePolicy")
    ]

    return create_finding(
        finding_id="PRIV_ESC_ATTACH_ROLE_POLICY",
        description="Role can attach managed policies to itself or other roles, enabling self-elevation to arbitrary permissions",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have iam:AttachRolePolicy" if risky_roles
                else "No roles have iam:AttachRolePolicy"
            )
        },
        recommendation=None if not risky_roles else (
            "Restrict iam:AttachRolePolicy to specific role ARNs. "
            "Use permissions boundaries to cap what policies can be attached."
        )
    )


def check_create_role_attach_policy_escalation(cache):
    """HIGH: Role can create a new IAM role and attach a managed policy to it, creating a backdoor admin role."""
    risky_roles = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if not cache.role_is_admin.get(role["Arn"], False)
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:CreateRole")
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:AttachRolePolicy")
    ]

    return create_finding(
        finding_id="PRIV_ESC_CREATE_ROLE_ATTACH",
        description="Role can create a new IAM role and attach any managed policy to it (including AdministratorAccess), creating a backdoor escalation path",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have both iam:CreateRole and iam:AttachRolePolicy" if risky_roles
                else "No roles have the iam:CreateRole + iam:AttachRolePolicy combination"
            )
        },
        recommendation=None if not risky_roles else (
            "Separate iam:CreateRole and iam:AttachRolePolicy — require both to escalate. "
            "Restrict iam:AttachRolePolicy to specific policy ARNs using resource conditions. "
            "Use permissions boundaries on new role creation to cap what can be attached."
        )
    )


def check_update_assume_role_policy_escalation(cache):
    """HIGH: Role can modify its own or other roles' trust policies."""
    risky_roles = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if not cache.role_is_admin.get(role["Arn"], False)  # already reported by DIRECT_ADMIN_ACCESS
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:UpdateAssumeRolePolicy")
    ]

    return create_finding(
        finding_id="PRIV_ESC_UPDATE_TRUST_POLICY",
        description="Role can modify trust policies, enabling it to grant itself or others the ability to assume any role",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have iam:UpdateAssumeRolePolicy" if risky_roles
                else "No roles have iam:UpdateAssumeRolePolicy"
            )
        },
        recommendation=None if not risky_roles else (
            "Remove iam:UpdateAssumeRolePolicy from roles that do not require IAM administration. "
            "This permission allows rewriting trust policies and is effectively equivalent to admin access."
        )
    )


def check_put_role_policy_escalation(cache):
    """HIGH: Role can inline a policy into any role, enabling direct privilege escalation."""
    risky_roles = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if not cache.role_is_admin.get(role["Arn"], False)  # already reported by DIRECT_ADMIN_ACCESS
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:PutRolePolicy")
    ]

    return create_finding(
        finding_id="PRIV_ESC_PUT_ROLE_POLICY",
        description="Role can inline arbitrary policies into any IAM role, enabling direct privilege escalation without attaching a managed policy",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have iam:PutRolePolicy" if risky_roles
                else "No roles have iam:PutRolePolicy"
            )
        },
        recommendation=None if not risky_roles else (
            "Remove iam:PutRolePolicy from roles that do not require IAM administration. "
            "This permission allows writing arbitrary inline policies to any role and is equivalent to admin access."
        )
    )


def check_create_user_access_key_escalation(cache):
    """HIGH: Role can create a new IAM user and generate access keys, creating a backdoor identity."""
    risky_roles = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if not cache.role_is_admin.get(role["Arn"], False)
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:CreateUser")
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:CreateAccessKey")
    ]

    return create_finding(
        finding_id="PRIV_ESC_CREATE_USER_KEY",
        description="Role can create a new IAM user and generate access keys, enabling persistent backdoor access",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have both iam:CreateUser and iam:CreateAccessKey" if risky_roles
                else "No roles have the iam:CreateUser + iam:CreateAccessKey combination"
            )
        },
        recommendation=None if not risky_roles else (
            "Separate iam:CreateUser and iam:CreateAccessKey permissions. "
            "Use permissions boundaries on user creation to cap what new users can do."
        )
    )


def check_add_user_to_group_escalation(cache):
    """HIGH: Role can add any user to an admin group, escalating that user's privileges."""
    risky_roles = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if not cache.role_is_admin.get(role["Arn"], False)
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:AddUserToGroup")
    ]

    return create_finding(
        finding_id="PRIV_ESC_ADD_USER_TO_GROUP",
        description="Role can add IAM users to groups, enabling privilege escalation by joining an admin group",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have iam:AddUserToGroup" if risky_roles
                else "No roles have iam:AddUserToGroup"
            )
        },
        recommendation=None if not risky_roles else (
            "Restrict iam:AddUserToGroup to specific group ARNs. "
            "Without resource constraints, this permission allows joining any group including admin groups."
        )
    )


def check_update_login_profile_escalation(cache):
    """HIGH: Role can reset another user's console password, enabling account takeover."""
    risky_roles = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if not cache.role_is_admin.get(role["Arn"], False)
        and (_perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:UpdateLoginProfile")
             or _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:CreateLoginProfile"))
    ]

    return create_finding(
        finding_id="PRIV_ESC_LOGIN_PROFILE",
        description="Role can create or reset IAM user console passwords, enabling account takeover of any user",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have iam:UpdateLoginProfile or iam:CreateLoginProfile" if risky_roles
                else "No roles have login profile manipulation permissions"
            )
        },
        recommendation=None if not risky_roles else (
            "Remove iam:UpdateLoginProfile and iam:CreateLoginProfile from non-admin roles. "
            "These permissions allow resetting any user's console password."
        )
    )


def check_delete_role_boundary_escalation(cache):
    """HIGH: Role can remove permission boundaries from other roles, enabling escalation past guardrails."""
    risky_roles = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if not cache.role_is_admin.get(role["Arn"], False)
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:DeleteRolePermissionsBoundary")
    ]

    return create_finding(
        finding_id="PRIV_ESC_DELETE_BOUNDARY",
        description="Role can delete permission boundaries from other roles, removing guardrails and enabling escalation",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have iam:DeleteRolePermissionsBoundary" if risky_roles
                else "No roles have iam:DeleteRolePermissionsBoundary"
            )
        },
        recommendation=None if not risky_roles else (
            "Remove iam:DeleteRolePermissionsBoundary from non-admin roles. "
            "This permission allows removing the safety net that caps a role's maximum effective permissions."
        )
    )


def check_ssm_send_command_escalation(cache):
    """MEDIUM: Role can run commands on EC2 instances via SSM, inheriting the instance profile's permissions."""
    risky_roles = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if not cache.role_is_admin.get(role["Arn"], False)
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "ssm:SendCommand")
    ]

    return create_finding(
        finding_id="PRIV_ESC_SSM_SEND_COMMAND",
        description="Role can execute commands on EC2 instances via SSM, inheriting the instance profile's permissions",
        status="FAIL" if risky_roles else "PASS",
        severity="MEDIUM",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have ssm:SendCommand" if risky_roles
                else "No roles have ssm:SendCommand"
            )
        },
        recommendation=None if not risky_roles else (
            "Restrict ssm:SendCommand to specific instance IDs or tags. "
            "Without resource constraints, this allows running code on any SSM-managed instance, "
            "inheriting that instance's IAM role permissions."
        )
    )


def check_detach_role_policy_escalation(cache):
    """MEDIUM: Role can detach policies from roles, potentially removing deny policies that block escalation."""
    risky_roles = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if not cache.role_is_admin.get(role["Arn"], False)
        and _perms_contain(cache.role_permissions.get(role["Arn"], set()), "iam:DetachRolePolicy")
    ]

    return create_finding(
        finding_id="PRIV_ESC_DETACH_POLICY",
        description="Role can detach managed policies from roles, potentially removing deny policies that block escalation",
        status="FAIL" if risky_roles else "PASS",
        severity="MEDIUM",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have iam:DetachRolePolicy" if risky_roles
                else "No roles have iam:DetachRolePolicy"
            )
        },
        recommendation=None if not risky_roles else (
            "Restrict iam:DetachRolePolicy to specific role ARNs. "
            "Unrestricted detach allows removing deny policies that may be the only barrier to admin access."
        )
    )


def check_lambda_ec2_service_escalation(cache):
    """MEDIUM: Role can create Lambda/EC2/Glue/CloudFormation/ECS and pass a higher-privilege role."""
    risky_roles = []
    admin_arns = {arn for arn, is_admin in cache.role_is_admin.items() if is_admin}

    for role in cache.roles:
        arn = role["Arn"]
        if cache.role_is_admin.get(arn, False):
            continue
        perms = cache.role_permissions.get(arn, set())
        _create_actions = [
            "lambda:CreateFunction", "ec2:RunInstances", "glue:CreateJob",
            "cloudformation:CreateStack", "ecs:RegisterTaskDefinition",
        ]
        has_create = any(_perms_contain(perms, a) for a in _create_actions)
        has_pass = _perms_contain(perms, "iam:PassRole")
        if not (has_create and has_pass):
            continue
        # Only flag if there are admin roles in the account that could be passed
        if not admin_arns:
            continue
        # Determine which services are implicated
        implicated = []
        if _perms_contain(perms, "lambda:CreateFunction"):
            implicated.append("Lambda")
        if _perms_contain(perms, "ec2:RunInstances"):
            implicated.append("EC2")
        if _perms_contain(perms, "glue:CreateJob"):
            implicated.append("Glue")
        if _perms_contain(perms, "cloudformation:CreateStack"):
            implicated.append("CloudFormation")
        if _perms_contain(perms, "ecs:RegisterTaskDefinition"):
            implicated.append("ECS")
        risky_roles.append({
            "role_arn": arn,
            "role_name": role["RoleName"],
            "services": implicated,
            "passable_admin_roles_count": len(admin_arns),
            "reason": f"Can create {'/'.join(implicated)} resources and pass a role — {len(admin_arns)} admin role(s) in account could be passed"
        })

    return create_finding(
        finding_id="PRIV_ESC_SERVICE_ATTACH",
        description="Role can create compute resources (Lambda/EC2/Glue/CloudFormation/ECS) and pass a higher-privilege role to them, enabling indirect privilege escalation",
        status="FAIL" if risky_roles else "PASS",
        severity="MEDIUM",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) can escalate via service attachment" if risky_roles
                else "No service-attachment escalation paths found"
            )
        },
        recommendation=None if not risky_roles else (
            "Restrict iam:PassRole to specific role ARNs and scope compute creation to least-privilege roles. "
            "Separate permissions to create resources from permissions to assign IAM roles to them."
        )
    )


def check_cyclic_trust_chains(cache):
    """MEDIUM: Roles that mutually trust each other, creating unintended escalation loops."""
    # find_cycles already deduplicates via seen_cycles
    cycles = find_cycles(cache.trust_graph)

    return create_finding(
        finding_id="CYCLIC_TRUST",
        description="Roles mutually trust each other via sts:AssumeRole, creating circular trust chains",
        status="FAIL" if cycles else "PASS",
        severity="MEDIUM",
        details={
            "cyclic_chains_count": len(cycles),
            "cyclic_chains": [{"cycle": c} for c in cycles[:10]],
            "explanation": (
                f"{len(cycles)} cyclic trust chain(s) detected" if cycles
                else "No cyclic trust chains detected"
            )
        },
        recommendation=None if not cycles else (
            "Break circular trust relationships — review whether mutual trust is intentional. "
            "Cyclic chains can be exploited to escalate privileges by traversing the loop."
        )
    )


# ---------- CROSS-ACCOUNT ACCESS CHECKS ----------

def check_unrestricted_cross_account(cache):
    """CRITICAL: Role trust policy allows assumption from an external account with no condition constraints."""
    risky_roles = []

    for role in cache.roles:
        arn = role["Arn"]
        for principal in cache.trust_graph.get(arn, []):
            conds = cache.edge_conditions.get((principal, arn), {})
            if conds.get("is_cross_account") and not conds.get("has_external_id") and not conds.get("has_org_id"):
                risky_roles.append({
                    "role_arn": arn,
                    "role_name": role["RoleName"],
                    "external_principal": principal,
                    "reason": "Cross-account trust with no ExternalId or OrgID condition"
                })

    return create_finding(
        finding_id="CROSS_ACCT_UNRESTRICTED",
        description="Role trust policy allows assumption from an external AWS account without condition constraints",
        status="FAIL" if risky_roles else "PASS",
        severity="CRITICAL",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) allow unrestricted cross-account assumption" if risky_roles
                else "No unrestricted cross-account trust relationships found"
            )
        },
        recommendation=None if not risky_roles else (
            "Add sts:ExternalId and/or aws:PrincipalOrgID conditions to cross-account trust policies. "
            "This prevents confused deputy attacks and restricts assumption to known principals."
        )
    )


def check_missing_external_id(cache):
    """HIGH: Cross-account trust policy lacks sts:ExternalId condition."""
    risky_roles = []

    for role in cache.roles:
        arn = role["Arn"]
        for principal in cache.trust_graph.get(arn, []):
            conds = cache.edge_conditions.get((principal, arn), {})
            if conds.get("is_cross_account") and not conds.get("has_external_id"):
                risky_roles.append({
                    "role_arn": arn,
                    "role_name": role["RoleName"],
                    "external_principal": principal
                })

    return create_finding(
        finding_id="CROSS_ACCT_NO_EXTERNAL_ID",
        description="Cross-account trust policy lacks sts:ExternalId condition, exposing the role to confused deputy attacks",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} cross-account trust(s) missing sts:ExternalId" if risky_roles
                else "All cross-account trusts have sts:ExternalId condition"
            )
        },
        recommendation=None if not risky_roles else (
            "Add a Condition block with sts:ExternalId to all cross-account trust policies. "
            "Coordinate a secret ExternalId value with the trusted account to prevent confused deputy attacks."
        )
    )


def check_missing_org_id(cache):
    """HIGH: Cross-account trust policy lacks aws:PrincipalOrgID condition."""
    risky_roles = []

    for role in cache.roles:
        arn = role["Arn"]
        for principal in cache.trust_graph.get(arn, []):
            conds = cache.edge_conditions.get((principal, arn), {})
            # Skip external vendor trusts (Datadog, Cloudflare, etc.) — they use sts:ExternalId
            # which is the correct mitigation for third-party integrations. PrincipalOrgID only
            # applies to internal cross-account access within your AWS Organisation.
            if conds.get("is_cross_account") and not conds.get("has_org_id") and not conds.get("has_external_id"):
                risky_roles.append({
                    "role_arn": arn,
                    "role_name": role["RoleName"],
                    "external_principal": principal
                })

    return create_finding(
        finding_id="CROSS_ACCT_NO_ORG_ID",
        description="Cross-account trust policy lacks aws:PrincipalOrgID condition, allowing any AWS account (not just org members) to attempt assumption",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} cross-account trust(s) missing aws:PrincipalOrgID" if risky_roles
                else "All cross-account trusts have aws:PrincipalOrgID condition"
            )
        },
        recommendation=None if not risky_roles else (
            "Add aws:PrincipalOrgID condition to cross-account trust policies to restrict assumption "
            "to principals within your AWS Organisation only."
        )
    )


def check_wildcard_principal(cache):
    """CRITICAL: Trust policy uses Principal: '*' allowing any AWS principal to assume the role."""
    risky_roles = [
        {
            "role_arn": role["Arn"],
            "role_name": role["RoleName"],
            "reason": "Trust policy uses Principal: \"*\""
        }
        for role in cache.roles
        if "*" in cache.trust_graph.get(role["Arn"], [])
    ]

    return create_finding(
        finding_id="CROSS_ACCT_WILDCARD_PRINCIPAL",
        description="Role trust policy uses Principal: \"*\", allowing any AWS principal to attempt assumption",
        status="FAIL" if risky_roles else "PASS",
        severity="CRITICAL",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have wildcard Principal in trust policy" if risky_roles
                else "No roles use wildcard Principal in trust policy"
            )
        },
        recommendation=None if not risky_roles else (
            "Replace Principal: \"*\" with specific role or account ARNs. "
            "A wildcard principal allows any entity to attempt role assumption."
        )
    )


def check_broad_service_principal(cache):
    """MEDIUM: High-privilege role has a broad AWS service principal in its trust policy."""
    broad_services = {
        "ec2.amazonaws.com", "lambda.amazonaws.com", "ecs-tasks.amazonaws.com",
        "glue.amazonaws.com", "sagemaker.amazonaws.com", "datapipeline.amazonaws.com"
    }
    risky_roles = []

    for role in cache.roles:
        arn = role["Arn"]
        if not cache.role_is_admin.get(arn, False):
            continue
        for principal in cache.trust_graph.get(arn, []):
            if principal in broad_services:
                risky_roles.append({
                    "role_arn": arn,
                    "role_name": role["RoleName"],
                    "service_principal": principal,
                    "reason": f"High-privilege role assumable by broad service {principal}"
                })

    return create_finding(
        finding_id="CROSS_ACCT_BROAD_SERVICE",
        description="High-privilege role has a broad AWS service principal in its trust policy, allowing any resource of that service type to assume it",
        status="FAIL" if risky_roles else "PASS",
        severity="MEDIUM",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} high-privilege role(s) have broad service principals" if risky_roles
                else "No broad service principal issues found on high-privilege roles"
            )
        },
        recommendation=None if not risky_roles else (
            "Reduce permissions on roles assumed by broad services. "
            "Grant only the specific actions required for that workload — not admin-level access."
        )
    )


def check_stale_cross_account_trusts(cache):
    """MEDIUM: Trust policy references an AWS account ID no longer in the organisation."""
    if not cache.org_accounts:
        return create_finding(
            finding_id="CROSS_ACCT_STALE",
            description="Detects trust policies referencing AWS account IDs no longer in the organisation",
            status="WARNING",
            severity="MEDIUM",
            details={
                "explanation": (
                    "Unable to check stale cross-account trusts — organizations:ListAccounts permission "
                    "not available or this account is not an AWS Organization member"
                )
            },
            recommendation="Grant organizations:ListAccounts permission to the analysis role to enable this check."
        )

    stale_roles = []
    for role in cache.roles:
        arn = role["Arn"]
        for principal in cache.trust_graph.get(arn, []):
            conds = cache.edge_conditions.get((principal, arn), {})
            if not conds.get("is_cross_account"):
                continue
            parts = principal.split(":")
            if len(parts) >= 5:
                principal_account = parts[4]
                if principal_account and principal_account not in cache.org_accounts:
                    stale_roles.append({
                        "role_arn": arn,
                        "role_name": role["RoleName"],
                        "stale_principal": principal,
                        "stale_account_id": principal_account
                    })

    return create_finding(
        finding_id="CROSS_ACCT_STALE",
        description="Trust policies reference AWS account IDs no longer present in the organisation",
        status="FAIL" if stale_roles else "PASS",
        severity="MEDIUM",
        details={
            "stale_trusts_count": len(stale_roles),
            "stale_trusts": stale_roles[:20],
            "explanation": (
                f"{len(stale_roles)} trust(s) reference account IDs not in the organisation" if stale_roles
                else "All cross-account trust principals are active organisation members"
            )
        },
        recommendation=None if not stale_roles else (
            "Remove trust policy statements referencing decommissioned accounts. "
            "If an external account ID was recycled by AWS, this trust could now grant access to an unrelated third party."
        )
    )


# ---------- ROLE HYGIENE CHECKS ----------

def check_unused_high_privilege_roles(cache, days=90):
    """MEDIUM: Roles with admin-level permissions not used in the last N days."""
    unused_roles = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    for role in cache.roles:
        arn = role["Arn"]
        if not cache.role_is_admin.get(arn, False):
            continue
        last_used = cache.role_last_used.get(arn)
        if last_used is None:
            unused_roles.append({
                "role_arn": arn,
                "role_name": role["RoleName"],
                "last_used": None,
                "days_inactive": "Never used"
            })
        else:
            if last_used.tzinfo is None:
                last_used = last_used.replace(tzinfo=timezone.utc)
            if last_used < cutoff:
                unused_roles.append({
                    "role_arn": arn,
                    "role_name": role["RoleName"],
                    "last_used": last_used.isoformat(),
                    "days_inactive": (datetime.now(timezone.utc) - last_used).days
                })

    return create_finding(
        finding_id="HYGIENE_UNUSED_ADMIN",
        description=f"High-privilege roles not used in the last {days} days",
        status="FAIL" if unused_roles else "PASS",
        severity="MEDIUM",
        details={
            "unused_admin_roles_count": len(unused_roles),
            "unused_admin_roles": unused_roles[:20],
            "inactivity_threshold_days": days,
            "explanation": (
                f"{len(unused_roles)} high-privilege role(s) unused for {days}+ days" if unused_roles
                else f"All high-privilege roles used within the last {days} days"
            )
        },
        recommendation=None if not unused_roles else (
            f"Review and consider decommissioning {len(unused_roles)} unused high-privilege role(s). "
            "Unused admin roles increase blast radius — delete or disable roles no longer needed."
        )
    )


def check_inline_wildcard_policies(cache):
    """HIGH: Roles carry inline policies granting * on actions or resources."""
    risky_roles = []

    for role in cache.roles:
        arn = role["Arn"]
        flagged = False
        for doc in cache.inline_policies.get(arn, []):
            if flagged:
                break
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                if "*" in actions or "*:*" in actions or "*" in resources:
                    risky_roles.append({
                        "role_arn": arn,
                        "role_name": role["RoleName"],
                        "reason": "Inline policy grants wildcard actions or resources"
                    })
                    flagged = True
                    break

    return create_finding(
        finding_id="HYGIENE_INLINE_WILDCARD",
        description="Roles have inline policies granting wildcard (*) actions or resources",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have inline wildcard policies" if risky_roles
                else "No inline wildcard policies found"
            )
        },
        recommendation=None if not risky_roles else (
            "Replace wildcard inline policies with scoped managed policies. "
            "Inline policies with * actions bypass least-privilege and are harder to audit."
        )
    )


def check_overpermissive_managed_policies(cache):
    """HIGH: Roles attached to policies granting admin or sensitive service-level full access."""
    # Restricted to high-impact services only — common operational services (sqs:*, sns:*,
    # cloudwatch:*) are deliberately excluded to avoid overwhelming false-positive noise.
    broad_indicators = {"*", "iam:*", "s3:*", "ec2:*", "rds:*", "dynamodb:*", "lambda:*"}
    risky_roles = []

    for role in cache.roles:
        arn = role["Arn"]
        perms = cache.role_permissions.get(arn, set())
        found_broad = perms & broad_indicators
        if found_broad:
            risky_roles.append({
                "role_arn": arn,
                "role_name": role["RoleName"],
                "broad_permissions": sorted(found_broad)[:5]
            })

    return create_finding(
        finding_id="HYGIENE_BROAD_MANAGED_POLICY",
        description="Roles attached to overly broad policies granting full service-level access",
        status="FAIL" if risky_roles else "PASS",
        severity="HIGH",
        details={
            "risky_roles_count": len(risky_roles),
            "risky_roles": risky_roles[:20],
            "explanation": (
                f"{len(risky_roles)} role(s) have overly broad permissions" if risky_roles
                else "No overly broad managed policies found"
            )
        },
        recommendation=None if not risky_roles else (
            "Replace full-access managed policies with scoped customer-managed policies. "
            "Grant only the specific actions required — e.g. s3:GetObject on specific buckets, not s3:*."
        )
    )


def check_roles_without_boundary(cache):
    """LOW: Privileged roles lack a permissions boundary."""
    roles_without_boundary = [
        {"role_arn": role["Arn"], "role_name": role["RoleName"]}
        for role in cache.roles
        if cache.role_is_admin.get(role["Arn"], False)
        and role.get("PermissionsBoundary") is None
    ]

    return create_finding(
        finding_id="HYGIENE_NO_BOUNDARY",
        description="Privileged roles do not have a permissions boundary, removing a guardrail against further escalation",
        status="FAIL" if roles_without_boundary else "PASS",
        severity="LOW",
        details={
            "roles_without_boundary_count": len(roles_without_boundary),
            "roles_without_boundary": roles_without_boundary[:20],
            "explanation": (
                f"{len(roles_without_boundary)} high-privilege role(s) lack a permissions boundary" if roles_without_boundary
                else "All high-privilege roles have permissions boundaries"
            )
        },
        recommendation=None if not roles_without_boundary else (
            "Attach a permissions boundary to privileged roles to cap maximum effective permissions. "
            "Boundaries act as a safety net — even if a policy is misconfigured, the boundary limits impact."
        )
    )


# ---------- USER HYGIENE CHECKS ----------

def check_user_admin_access(cache):
    """CRITICAL: IAM users that directly hold admin-level permissions."""
    admin_users = [
        {
            "user_arn": user["Arn"],
            "user_name": user["UserName"],
            "admin_permissions": sorted(cache.user_permissions.get(user["Arn"], set()) & {"*", "*:*", "iam:*"})
        }
        for user in cache.users
        if cache.user_is_admin.get(user["Arn"], False)
    ]

    return create_finding(
        finding_id="USER_ADMIN_ACCESS",
        description="IAM users with administrator-level permissions",
        status="FAIL" if admin_users else "PASS",
        severity="CRITICAL",
        details={
            "admin_users_count": len(admin_users),
            "admin_users": admin_users[:20],
            "explanation": (
                f"{len(admin_users)} IAM user(s) hold direct admin-level permissions" if admin_users
                else "No IAM users hold direct admin-level permissions"
            )
        },
        recommendation=None if not admin_users else (
            "Replace IAM user admin access with IAM roles using temporary credentials. "
            "IAM users with permanent admin credentials are a high-value target for attackers."
        )
    )


def check_user_no_mfa_console(cache):
    """HIGH: IAM users with console access but no MFA enabled."""
    risky_users = [
        {"user_arn": user["Arn"], "user_name": user["UserName"]}
        for user in cache.users
        if cache.user_has_console.get(user["Arn"], False)
        and not cache.user_has_mfa.get(user["Arn"], False)
    ]

    return create_finding(
        finding_id="USER_NO_MFA_CONSOLE",
        description="IAM users with console access but no MFA device enabled",
        status="FAIL" if risky_users else "PASS",
        severity="HIGH",
        details={
            "risky_users_count": len(risky_users),
            "risky_users": risky_users[:20],
            "explanation": (
                f"{len(risky_users)} user(s) have console access without MFA" if risky_users
                else "All console users have MFA enabled"
            )
        },
        recommendation=None if not risky_users else (
            "Enable MFA for all IAM users with console access. "
            "Console access without MFA is vulnerable to credential phishing and brute-force attacks."
        )
    )


def check_user_stale_access_keys(cache, max_age_days=90):
    """MEDIUM: IAM users with access keys older than the specified threshold."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    stale_users = []

    for user in cache.users:
        arn = user["Arn"]
        for key in cache.user_access_keys.get(arn, []):
            if key["Status"] != "Active":
                continue
            create_date = key["CreateDate"]
            if hasattr(create_date, 'tzinfo') and create_date.tzinfo is None:
                create_date = create_date.replace(tzinfo=timezone.utc)
            if create_date < cutoff:
                stale_users.append({
                    "user_arn": arn,
                    "user_name": user["UserName"],
                    "key_id": key["KeyId"],
                    "key_age_days": (datetime.now(timezone.utc) - create_date).days,
                })

    return create_finding(
        finding_id="USER_STALE_ACCESS_KEYS",
        description=f"IAM users with active access keys older than {max_age_days} days",
        status="FAIL" if stale_users else "PASS",
        severity="MEDIUM",
        details={
            "stale_keys_count": len(stale_users),
            "stale_keys": stale_users[:20],
            "max_age_days": max_age_days,
            "explanation": (
                f"{len(stale_users)} active access key(s) older than {max_age_days} days" if stale_users
                else f"All active access keys are within the {max_age_days}-day rotation window"
            )
        },
        recommendation=None if not stale_users else (
            f"Rotate access keys older than {max_age_days} days. "
            "Long-lived access keys increase the window of exposure if compromised."
        )
    )


def check_user_dual_access_admin(cache):
    """HIGH: IAM users with both console and programmatic access AND admin permissions."""
    risky_users = []

    for user in cache.users:
        arn = user["Arn"]
        if not cache.user_is_admin.get(arn, False):
            continue
        has_console = cache.user_has_console.get(arn, False)
        has_keys = any(k["Status"] == "Active" for k in cache.user_access_keys.get(arn, []))
        if has_console and has_keys:
            risky_users.append({
                "user_arn": arn,
                "user_name": user["UserName"],
                "reason": "Admin user with both console and active access key — maximum attack surface"
            })

    return create_finding(
        finding_id="USER_DUAL_ACCESS_ADMIN",
        description="IAM users with admin permissions and both console + programmatic access",
        status="FAIL" if risky_users else "PASS",
        severity="HIGH",
        details={
            "risky_users_count": len(risky_users),
            "risky_users": risky_users[:20],
            "explanation": (
                f"{len(risky_users)} admin user(s) have both console and programmatic access" if risky_users
                else "No admin users have dual access methods"
            )
        },
        recommendation=None if not risky_users else (
            "Separate console and programmatic access for admin users. "
            "Use IAM roles for programmatic admin tasks and restrict console access to break-glass scenarios."
        )
    )


# ---------- RISK SCORE ----------

def _compute_risk_score(summary: dict) -> int:
    """
    Compute a 0-100 pass rate where 100 = all checks passed.

    Uses passed / (passed + failed) * 100, excluding warnings from the
    denominator. Matches AWS Security Hub and Prowler scoring convention.
    """
    passed = summary["passed"]
    failed = summary["failed"]
    completed = passed + failed
    if completed == 0:
        return 100
    return int((passed / completed) * 100)


# ---------- EXECUTIVE SUMMARY ----------

def generate_executive_summary(result):
    """Generate a markdown-formatted executive summary of the IAM access path analysis."""
    summary = result["metadata"]["summary"]
    account_id = result["metadata"].get("aws_account_id", "Unknown")
    total_roles = result["metadata"].get("total_roles_analysed", 0)

    total_findings = summary["total_findings"]
    failed = summary["failed"]
    critical_findings = summary["critical_findings"]
    high_findings = summary["high_findings"]
    escalation_paths = summary["escalation_paths_found"]
    cross_account_issues = summary["cross_account_issues"]
    user_issues = summary.get("user_issues", 0)

    risk_score = _compute_risk_score(summary)

    md_lines = []
    md_lines.append("# Executive Summary")
    md_lines.append("")
    md_lines.append("## Overall Risk Assessment")
    md_lines.append("")

    if risk_score >= 90:
        md_lines.append(f"**AWS Account {account_id}** demonstrates **low IAM risk** with a **{risk_score}%** pass rate across **{total_findings}** checks over **{total_roles}** roles analysed.")
    elif risk_score >= 70:
        md_lines.append(f"**AWS Account {account_id}** shows **moderate IAM risk** with a **{risk_score}%** pass rate across **{total_findings}** checks. Targeted remediation is required.")
    else:
        md_lines.append(f"**AWS Account {account_id}** has **elevated IAM risk** with a **{risk_score}%** pass rate across **{total_findings}** checks. Immediate action is required.")
    md_lines.append("")

    md_lines.append("## Key Findings")
    md_lines.append("")
    if escalation_paths > 0:
        md_lines.append(f"- **{escalation_paths} privilege escalation path(s)** — roles that can reach admin-level access through trust chain traversal")
    if cross_account_issues > 0:
        md_lines.append(f"- **{cross_account_issues} cross-account access issue(s)** — trust relationships lacking required condition constraints")
    if user_issues > 0:
        md_lines.append(f"- **{user_issues} IAM user issue(s)** — users with admin access, missing MFA, or stale credentials")
    if critical_findings > 0 or high_findings > 0:
        md_lines.append(f"- **{critical_findings} critical** and **{high_findings} high-severity** findings requiring immediate remediation")
    if not (escalation_paths or cross_account_issues or user_issues or failed):
        md_lines.append("No significant IAM trust chain risks detected.")
    md_lines.append("")

    md_lines.append("## Risk Categories")
    md_lines.append("")
    categories_with_issues = []
    if any(f["status"] == "FAIL" for f in result["privilege_escalation"]["findings"]):
        categories_with_issues.append("**Privilege Escalation**")
    if any(f["status"] == "FAIL" for f in result["cross_account_access"]["findings"]):
        categories_with_issues.append("**Cross-Account Access**")
    if any(f["status"] == "FAIL" for f in result["role_hygiene"]["findings"]):
        categories_with_issues.append("**Role Hygiene**")
    if any(f["status"] == "FAIL" for f in result.get("user_hygiene", {}).get("findings", [])):
        categories_with_issues.append("**User Hygiene**")

    if categories_with_issues:
        md_lines.append(f"Categories requiring attention: {', '.join(categories_with_issues)}")
    else:
        md_lines.append("All risk categories (**Privilege Escalation**, **Cross-Account Access**, **Role Hygiene**, **User Hygiene**) pass.")
    md_lines.append("")

    md_lines.append("## Priority Remediation Areas")
    md_lines.append("")
    all_findings = [
        f for key in result
        if isinstance(result[key], dict) and "findings" in result[key]
        for f in result[key]["findings"]
    ]
    critical_high = [f for f in all_findings if f["status"] == "FAIL" and f["severity"] in ("CRITICAL", "HIGH")]
    if critical_high:
        md_lines.append("**Immediate action required:**")
        md_lines.append("")
        for f in critical_high[:3]:
            md_lines.append(f"- {f['description']}")
    else:
        md_lines.append("No critical or high-severity findings requiring immediate action.")
    md_lines.append("")

    md_lines.append("## Recommendation")
    md_lines.append("")
    if risk_score >= 90:
        md_lines.append("**Action:** Address minor hygiene findings and implement permissions boundaries on remaining privileged roles.")
    elif risk_score >= 70:
        md_lines.append("**Action:** Remediate critical and high-severity trust chain risks before the next access review cycle.")
    else:
        md_lines.append("**Action:** Immediate IAM remediation required — engage your security team to break high-risk trust chains and remove wildcard permissions.")

    return "\n".join(md_lines)


# ---------- RUN ANALYSIS ----------

def run_analysis(profile_name=None, max_depth=10):
    return _run_analysis(profile_name=profile_name, max_depth=max_depth)


def _run_analysis(profile_name=None, max_depth=10):
    logger.info("Starting IAM access path analysis (profile=%s, max_depth=%d)", profile_name or "default", max_depth)
    RESULT = _make_result()

    # Use the region from the profile/environment — fall back to us-east-1 only if unset,
    # as STS is a global service but regional endpoints are required for GovCloud/China.
    session = (
        boto3.Session(profile_name=profile_name)
        if profile_name
        else boto3.Session()
    )
    region = session.region_name or "us-east-1"
    session = (
        boto3.Session(profile_name=profile_name, region_name=region)
        if profile_name
        else boto3.Session(region_name=region)
    )

    try:
        _retry_config = Config(retries={"max_attempts": 5, "mode": "adaptive"})
        RESULT["metadata"]["aws_account_id"] = session.client("sts", config=_retry_config).get_caller_identity()["Account"]
    except Exception as e:
        RESULT["metadata"]["aws_account_id"] = "unknown"
        RESULT["metadata"]["account_error"] = str(e)

    RESULT["metadata"]["aws_profile"] = profile_name or "default"
    RESULT["metadata"]["max_depth"] = max_depth

    # Eager prefetch — all IAM data loaded before executor starts
    cache = IAMRoleCache(session)
    RESULT["metadata"]["total_roles_analysed"] = len(cache.roles)
    RESULT["metadata"]["total_users_analysed"] = len(cache.users)
    logger.info("Cache built: %d roles, %d users, running %d checks...", len(cache.roles), len(cache.users), 32)

    check_tasks = [
        # Privilege escalation (12 checks)
        ("privilege_escalation", "check_direct_admin_access", lambda: check_direct_admin_access(cache)),
        ("privilege_escalation", "check_single_hop_escalation", lambda: check_single_hop_escalation(cache)),
        ("privilege_escalation", "check_multi_hop_escalation", lambda: check_multi_hop_escalation(cache, max_depth)),
        ("privilege_escalation", "check_pass_role_escalation", lambda: check_pass_role_escalation(cache)),
        ("privilege_escalation", "check_create_policy_version_escalation", lambda: check_create_policy_version_escalation(cache)),
        ("privilege_escalation", "check_set_default_policy_version_escalation", lambda: check_set_default_policy_version_escalation(cache)),
        ("privilege_escalation", "check_attach_role_policy_escalation", lambda: check_attach_role_policy_escalation(cache)),
        ("privilege_escalation", "check_create_role_attach_policy_escalation", lambda: check_create_role_attach_policy_escalation(cache)),
        ("privilege_escalation", "check_update_assume_role_policy_escalation", lambda: check_update_assume_role_policy_escalation(cache)),
        ("privilege_escalation", "check_put_role_policy_escalation", lambda: check_put_role_policy_escalation(cache)),
        ("privilege_escalation", "check_create_user_access_key_escalation", lambda: check_create_user_access_key_escalation(cache)),
        ("privilege_escalation", "check_add_user_to_group_escalation", lambda: check_add_user_to_group_escalation(cache)),
        ("privilege_escalation", "check_update_login_profile_escalation", lambda: check_update_login_profile_escalation(cache)),
        ("privilege_escalation", "check_delete_role_boundary_escalation", lambda: check_delete_role_boundary_escalation(cache)),
        ("privilege_escalation", "check_ssm_send_command_escalation", lambda: check_ssm_send_command_escalation(cache)),
        ("privilege_escalation", "check_detach_role_policy_escalation", lambda: check_detach_role_policy_escalation(cache)),
        ("privilege_escalation", "check_lambda_ec2_service_escalation", lambda: check_lambda_ec2_service_escalation(cache)),
        ("privilege_escalation", "check_cyclic_trust_chains", lambda: check_cyclic_trust_chains(cache)),

        # Cross-account access (6 checks)
        ("cross_account_access", "check_unrestricted_cross_account", lambda: check_unrestricted_cross_account(cache)),
        ("cross_account_access", "check_missing_external_id", lambda: check_missing_external_id(cache)),
        ("cross_account_access", "check_missing_org_id", lambda: check_missing_org_id(cache)),
        ("cross_account_access", "check_wildcard_principal", lambda: check_wildcard_principal(cache)),
        ("cross_account_access", "check_broad_service_principal", lambda: check_broad_service_principal(cache)),
        ("cross_account_access", "check_stale_cross_account_trusts", lambda: check_stale_cross_account_trusts(cache)),

        # Role hygiene (4 checks)
        ("role_hygiene", "check_unused_high_privilege_roles", lambda: check_unused_high_privilege_roles(cache)),
        ("role_hygiene", "check_inline_wildcard_policies", lambda: check_inline_wildcard_policies(cache)),
        ("role_hygiene", "check_overpermissive_managed_policies", lambda: check_overpermissive_managed_policies(cache)),
        ("role_hygiene", "check_roles_without_boundary", lambda: check_roles_without_boundary(cache)),

        # User hygiene (4 checks)
        ("user_hygiene", "check_user_admin_access", lambda: check_user_admin_access(cache)),
        ("user_hygiene", "check_user_no_mfa_console", lambda: check_user_no_mfa_console(cache)),
        ("user_hygiene", "check_user_stale_access_keys", lambda: check_user_stale_access_keys(cache)),
        ("user_hygiene", "check_user_dual_access_admin", lambda: check_user_dual_access_admin(cache)),
    ]

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_check = {executor.submit(fn): (cat, name, fn) for cat, name, fn in check_tasks}

        # as_completed yields one future at a time in the main thread — all appends
        # below happen serially here, not inside worker threads, so no lock is needed.
        for future in as_completed(future_to_check):
            category, check_name, _ = future_to_check[future]
            try:
                finding = future.result()
                RESULT[category]["findings"].append(finding)
            except Exception as e:
                error_type = type(e).__name__
                error_message = str(e)
                is_permission_error = (
                    "AccessDenied" in error_message or
                    "UnauthorizedOperation" in error_message or
                    "AccessDeniedException" in error_message or
                    "Forbidden" in error_message or
                    error_type in ("ClientError", "NoCredentialsError", "CredentialRetrievalError")
                )
                logger.warning("Check %s failed: %s: %s", check_name, error_type, error_message)
                if is_permission_error:
                    error_finding = create_finding(
                        finding_id="PERMISSION_ERROR",
                        description=f"Unable to perform check due to insufficient permissions: {check_name}",
                        status="WARNING",
                        severity="LOW",
                        details={"error_type": error_type, "error_message": error_message, "category": category},
                        recommendation="Grant necessary IAM read-only permissions to perform this analysis check."
                    )
                else:
                    error_finding = create_finding(
                        finding_id="CHECK_ERROR",
                        description=f"Check encountered an unexpected error: {check_name}",
                        status="WARNING",
                        severity="LOW",
                        details={"error_type": error_type, "error_message": error_message, "category": category},
                        recommendation="Review error details and ensure AWS resources are accessible."
                    )
                RESULT[category]["findings"].append(error_finding)

    # Dynamic section iteration — adding a new category never requires touching this block
    all_findings = [
        f
        for key in RESULT
        if isinstance(RESULT[key], dict) and "findings" in RESULT[key]
        for f in RESULT[key]["findings"]
    ]

    escalation_paths_found = sum(
        1 for f in RESULT["privilege_escalation"]["findings"]
        if f["status"] == "FAIL"
        and f["finding_id"] in ("PRIV_ESC_SINGLE_HOP", "PRIV_ESC_MULTI_HOP")
        and f.get("details", {}).get("escalation_paths_count", 0) > 0
    )

    cross_account_issues = sum(
        1 for f in RESULT["cross_account_access"]["findings"]
        if f["status"] == "FAIL"
    )

    # Permission error detection via details content — catches both executor-level errors
    # and checks that internally return WARNING (e.g. stale trust check without org access)
    permission_errors = sum(
        1 for f in all_findings
        if f["status"] == "WARNING" and any(
            kw in str(f.get("details", {}).get("error", ""))
            for kw in ("AccessDenied", "Unauthorized", "Forbidden")
        )
    ) + len(cache.inaccessible_roles)

    RESULT["metadata"]["summary"] = {
        "total_findings": len(all_findings),
        "passed": sum(1 for f in all_findings if f["status"] == "PASS"),
        "failed": sum(1 for f in all_findings if f["status"] == "FAIL"),
        "warnings": sum(1 for f in all_findings if f["status"] == "WARNING"),
        "critical_findings": sum(1 for f in all_findings if f["status"] == "FAIL" and f["severity"] == "CRITICAL"),
        "high_findings": sum(1 for f in all_findings if f["status"] == "FAIL" and f["severity"] == "HIGH"),
        "escalation_paths_found": escalation_paths_found,
        "cross_account_issues": cross_account_issues,
        "user_issues": sum(1 for f in RESULT.get("user_hygiene", {}).get("findings", []) if f["status"] == "FAIL"),
        "permission_errors": permission_errors
    }

    if cache.inaccessible_roles:
        RESULT["metadata"]["inaccessible_roles"] = cache.inaccessible_roles
        RESULT["metadata"]["inaccessible_roles_count"] = len(cache.inaccessible_roles)
        RESULT["metadata"]["inaccessible_roles_warning"] = (
            f"{len(cache.inaccessible_roles)} role(s) had AccessDenied on policy fetch — "
            "their permissions are unknown and checks may report false negatives for these roles."
        )

    RESULT["metadata"]["executive_summary"] = generate_executive_summary(RESULT)

    logger.info("Analysis complete: %d findings (%d passed, %d failed, %d warnings)",
                RESULT["metadata"]["summary"]["total_findings"],
                RESULT["metadata"]["summary"]["passed"],
                RESULT["metadata"]["summary"]["failed"],
                RESULT["metadata"]["summary"]["warnings"])
    return RESULT


# ---------- MAIN ----------

def main():
    parser = argparse.ArgumentParser(description="Analyse IAM trust chains and assume-role paths across an AWS account")
    parser.add_argument("--profile", "-p", type=str, default=None,
                        help="AWS CLI profile name to analyse")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Write JSON output to a file instead of stdout")
    parser.add_argument("--max-depth", type=int, default=10,
                        help="Maximum role chain depth to traverse (default: 10)")
    parser.add_argument("--verbose", "-v", action="store_true", default=False,
                        help="Enable verbose logging output to stderr")
    args = parser.parse_args()

    log_level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        stream=__import__("sys").stderr,
    )
    # Suppress noisy boto/urllib3 debug logs even in verbose mode
    if args.verbose:
        logging.getLogger("botocore").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("boto3").setLevel(logging.WARNING)

    try:
        raw_result = run_analysis(profile_name=args.profile, max_depth=args.max_depth)
        json_output = json.dumps(raw_result, indent=2, default=str)

        if args.output:
            with open(args.output, "w") as f:
                f.write(json_output)
        else:
            print(json_output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

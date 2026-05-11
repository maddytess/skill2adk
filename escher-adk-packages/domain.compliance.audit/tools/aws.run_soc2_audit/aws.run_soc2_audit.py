import boto3
import argparse
import csv
import io
import sys
import time
from datetime import datetime, timezone
import json
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

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

class AWSResourceCache:
    """
    Pre-fetched shared AWS resources — all data is loaded eagerly in the main thread
    before the ThreadPoolExecutor starts, so worker threads only read (never write).
    This eliminates lazy-init race conditions entirely.
    """
    def __init__(self, session):
        self._regions = self._get_all_regions(session)
        self.iam_users = self._fetch_iam_users(session)
        self.s3_buckets = self._fetch_s3_buckets(session)
        self.ec2_instances = self._fetch_ec2_instances(session, self._regions)
        self.security_groups = self._fetch_security_groups(session, self._regions)
        self.cloudtrail_trails = self._fetch_cloudtrail_trails(session)
        self.rds_instances = self._fetch_rds_instances(session, self._regions)
        self.vpcs = self._fetch_vpcs(session, self._regions)

    @staticmethod
    def _get_all_regions(session):
        try:
            ec2 = session.client("ec2", region_name="us-east-1")
            regions = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False).get("Regions", [])]
            return regions or ["us-east-1"]
        except Exception:
            return ["us-east-1"]

    @staticmethod
    def _fetch_iam_users(session):
        try:
            iam = session.client("iam")
            paginator = iam.get_paginator("list_users")
            users = []
            for page in paginator.paginate():
                users.extend(page["Users"])
            return users
        except Exception:
            return []

    @staticmethod
    def _fetch_s3_buckets(session):
        try:
            return session.client("s3").list_buckets()["Buckets"]
        except Exception:
            return []

    @staticmethod
    def _fetch_ec2_instances(session, regions):
        all_reservations = []
        def fetch_region(region):
            try:
                paginator = session.client("ec2", region_name=region).get_paginator("describe_instances")
                reservations = []
                for page in paginator.paginate():
                    reservations.extend(page["Reservations"])
                for reservation in reservations:
                    reservation["_region"] = region
                return reservations
            except Exception:
                return []
        with ThreadPoolExecutor(max_workers=10) as executor:
            for result in executor.map(fetch_region, regions):
                all_reservations.extend(result)
        return all_reservations

    @staticmethod
    def _fetch_security_groups(session, regions):
        all_sgs = []
        def fetch_region(region):
            try:
                paginator = session.client("ec2", region_name=region).get_paginator("describe_security_groups")
                sgs = []
                for page in paginator.paginate():
                    sgs.extend(page["SecurityGroups"])
                return sgs
            except Exception:
                return []
        with ThreadPoolExecutor(max_workers=10) as executor:
            for result in executor.map(fetch_region, regions):
                all_sgs.extend(result)
        return all_sgs

    @staticmethod
    def _fetch_cloudtrail_trails(session):
        try:
            return session.client("cloudtrail").describe_trails()["trailList"]
        except Exception:
            return []

    @staticmethod
    def _fetch_rds_instances(session, regions):
        all_instances = []
        def fetch_region(region):
            try:
                paginator = session.client("rds", region_name=region).get_paginator("describe_db_instances")
                instances = []
                for page in paginator.paginate():
                    instances.extend(page["DBInstances"])
                return instances
            except Exception:
                return []
        with ThreadPoolExecutor(max_workers=10) as executor:
            for result in executor.map(fetch_region, regions):
                all_instances.extend(result)
        return all_instances

    @staticmethod
    def _fetch_vpcs(session, regions):
        all_vpcs = []
        def fetch_region(region):
            try:
                vpcs = session.client("ec2", region_name=region).describe_vpcs()["Vpcs"]
                for vpc in vpcs:
                    vpc["_region"] = region
                return vpcs
            except Exception:
                return []
        with ThreadPoolExecutor(max_workers=10) as executor:
            for result in executor.map(fetch_region, regions):
                all_vpcs.extend(result)
        return all_vpcs

# ---------- SECURITY CONTROLS ----------

def check_root_mfa(session):
    try:
        iam = session.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1

        return create_check_result(
            name="Root Account MFA",
            description="Verifies that Multi-Factor Authentication (MFA) is enabled for the root account",
            status="PASS" if mfa_enabled else "FAIL",
            severity="CRITICAL",
            details={
                "mfa_enabled": mfa_enabled,
                "explanation": "Root account has unrestricted access to all AWS resources" if not mfa_enabled else "Root account is protected with MFA"
            },
            recommendation=None if mfa_enabled else "Enable MFA for the root account immediately. Go to IAM Console > Dashboard > Security Status > Activate MFA on your root account"
        )
    except Exception as e:
        return create_check_result(
            name="Root Account MFA",
            description="Verifies that Multi-Factor Authentication (MFA) is enabled for the root account",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check root MFA status due to permission error or API failure"
            },
            recommendation="Grant IAM permissions: iam:GetAccountSummary"
        )

def check_iam_users_mfa(session):
    """Only flags console users (password_enabled=true) who lack MFA — programmatic-only users are excluded."""
    try:
        iam = session.client("iam")

        # Use credential report to accurately identify console users
        try:
            iam.generate_credential_report()
        except Exception:
            pass

        rows = []
        for _ in range(5):
            try:
                report = iam.get_credential_report()
                reader = csv.DictReader(io.StringIO(report["Content"].decode("utf-8")))
                rows = list(reader)
                break
            except ClientError as e:
                if e.response["Error"]["Code"] == "ReportNotPresent":
                    time.sleep(2)
                else:
                    raise

        if not rows:
            return create_check_result(
                name="IAM Users MFA",
                description="Checks if all console IAM users have Multi-Factor Authentication (MFA) enabled",
                status="WARNING",
                severity="LOW",
                details={"explanation": "Could not generate or retrieve IAM credential report"},
                recommendation="Ensure IAM permissions include: iam:GenerateCredentialReport, iam:GetCredentialReport"
            )

        non_compliant = []
        console_users = 0
        for row in rows:
            if row.get("user", "") == "<root_account>":
                continue
            has_password = row.get("password_enabled", "false").lower() == "true"
            mfa_active = row.get("mfa_active", "false").lower() == "true"
            if has_password:
                console_users += 1
                if not mfa_active:
                    non_compliant.append(row.get("user", ""))

        return create_check_result(
            name="IAM Users MFA",
            description="Checks if all console IAM users have Multi-Factor Authentication (MFA) enabled",
            status="PASS" if not non_compliant else "FAIL",
            severity="HIGH",
            details={
                "console_users_checked": console_users,
                "users_without_mfa": len(non_compliant),
                "non_compliant_users": non_compliant,
                "note": "Programmatic-only users (no console password) are excluded from this check",
                "compliance_rate": f"{((console_users - len(non_compliant)) / console_users * 100):.1f}%" if console_users > 0 else "N/A"
            },
            recommendation=None if not non_compliant else (
                f"Enable MFA for {len(non_compliant)} console user(s): {', '.join(non_compliant)}. "
                "Configure a virtual MFA device or hardware token in IAM Console."
            )
        )
    except Exception as e:
        return create_check_result(
            name="IAM Users MFA",
            description="Checks if all console IAM users have Multi-Factor Authentication (MFA) enabled",
            status="WARNING",
            severity="LOW",
            details={"error": str(e), "explanation": "Unable to check IAM users MFA status"},
            recommendation="Grant IAM permissions: iam:GenerateCredentialReport, iam:GetCredentialReport"
        )

def check_old_access_keys(session, iam_users, days=90):
    try:
        iam = session.client("iam")
        stale_keys = []

        for user in iam_users:
            try:
                keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
                for key in keys:
                    age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                    if age > days:
                        stale_keys.append({
                            "user": user["UserName"],
                            "access_key": key["AccessKeyId"],
                            "age_days": age
                        })
            except Exception:
                continue

        return create_check_result(
            name="Stale Access Keys",
            description=f"Identifies IAM access keys older than {days} days that should be rotated",
            status="PASS" if len(stale_keys) == 0 else "FAIL",
            severity="HIGH",
            details={
                "threshold_days": days,
                "stale_keys_count": len(stale_keys),
                "stale_keys": stale_keys,
                "explanation": f"Found {len(stale_keys)} access key(s) older than {days} days" if stale_keys else "All access keys are within rotation policy"
            },
            recommendation=None if len(stale_keys) == 0 else f"Rotate {len(stale_keys)} stale access key(s). Best practice: Rotate access keys every 90 days. Disable old keys before deletion to test impact."
        )
    except Exception as e:
        return create_check_result(
            name="Stale Access Keys",
            description=f"Identifies IAM access keys older than {days} days that should be rotated",
            status="WARNING",
            severity="HIGH",
            details={"error": str(e), "explanation": "Unable to check access key ages"},
            recommendation="Grant IAM permissions: iam:ListAccessKeys"
        )

def check_cloudtrail(session, trails):
    ct = session.client("cloudtrail")

    active_trails = []
    inactive_trails = []
    for trail in trails:
        try:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            if status.get("IsLogging"):
                active_trails.append(trail["Name"])
            else:
                inactive_trails.append(trail["Name"])
        except Exception:
            inactive_trails.append(trail["Name"])

    passing = bool(active_trails)
    return create_check_result(
        name="CloudTrail Logging",
        description="Verifies that CloudTrail is enabled and actively logging API calls and user activity",
        status="PASS" if passing else "FAIL",
        severity="CRITICAL",
        details={
            "trails_count": len(trails),
            "active_logging_trails": active_trails,
            "inactive_trails": inactive_trails,
            "explanation": f"{len(active_trails)} trail(s) actively logging" if passing else (
                "No trails are actively logging — API activity is not being recorded" if trails
                else "No CloudTrail trails configured"
            )
        },
        recommendation=None if passing else (
            "Start logging on existing trail(s) or create a new multi-region trail. "
            "Go to CloudTrail Console > Trails > select trail > Enable logging."
        )
    )

def check_overly_permissive_policies(session):
    iam = session.client("iam")
    risky_policies = []

    # Check managed policies
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            try:
                version = iam.get_policy_version(
                    PolicyArn=policy["Arn"],
                    VersionId=policy["DefaultVersionId"]
                )
                doc = version["PolicyVersion"]["Document"]

                # Check for overly permissive statements
                if isinstance(doc.get("Statement"), list):
                    for stmt in doc["Statement"]:
                        if stmt.get("Effect") == "Allow":
                            actions = stmt.get("Action", [])
                            resources = stmt.get("Resource", [])

                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]

                            if "*" in actions or "*" in resources:
                                risky_policies.append({
                                    "policy_name": policy["PolicyName"],
                                    "policy_arn": policy["Arn"],
                                    "reason": "Contains wildcard (*) in actions or resources"
                                })
                                break
            except Exception:
                continue

    return create_check_result(
        name="Overly Permissive IAM Policies",
        description="Identifies IAM policies with wildcard (*) permissions that grant broad access",
        status="PASS" if len(risky_policies) == 0 else "FAIL",
        severity="HIGH",
        details={
            "risky_policies_count": len(risky_policies),
            "risky_policies": risky_policies[:10],
            "explanation": f"Found {len(risky_policies)} policy/policies with overly broad permissions" if risky_policies else "No overly permissive policies detected"
        },
        recommendation=None if len(risky_policies) == 0 else "Review and restrict policies with wildcard permissions. Apply principle of least privilege by granting only necessary permissions."
    )

def check_inactive_users(session, iam_users, days=90):
    iam = session.client("iam")
    users = iam_users
    inactive_users = []

    for user in users:
        try:
            access_keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
            last_used = None

            # Check password last used
            if "PasswordLastUsed" in user:
                last_used = user["PasswordLastUsed"]

            # Check access key last used
            for key in access_keys:
                try:
                    key_last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                    if "LastUsedDate" in key_last_used.get("AccessKeyLastUsed", {}):
                        key_date = key_last_used["AccessKeyLastUsed"]["LastUsedDate"]
                        if last_used is None or key_date > last_used:
                            last_used = key_date
                except Exception:
                    continue

            if last_used:
                days_inactive = (datetime.now(timezone.utc) - last_used).days
                if days_inactive > days:
                    inactive_users.append({
                        "username": user["UserName"],
                        "days_inactive": days_inactive,
                        "last_activity": last_used.isoformat()
                    })
            else:
                # Never used
                days_since_created = (datetime.now(timezone.utc) - user["CreateDate"]).days
                if days_since_created > days:
                    inactive_users.append({
                        "username": user["UserName"],
                        "days_inactive": "Never used",
                        "created": user["CreateDate"].isoformat()
                    })
        except Exception:
            continue

    return create_check_result(
        name="Inactive IAM Users",
        description=f"Identifies IAM users with no activity in the last {days} days",
        status="PASS" if len(inactive_users) == 0 else "WARNING",
        severity="MEDIUM",
        details={
            "threshold_days": days,
            "inactive_users_count": len(inactive_users),
            "inactive_users": inactive_users,
            "explanation": f"Found {len(inactive_users)} inactive user(s)" if inactive_users else "All users have recent activity"
        },
        recommendation=None if len(inactive_users) == 0 else f"Review and disable/remove {len(inactive_users)} inactive user(s). Remove unused accounts to reduce attack surface."
    )

def check_password_rotation(session, iam_users, days=90):
    iam = session.client("iam")

    # First check if password policy requires rotation
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        password_rotation_enabled = policy.get("ExpirePasswords", False)
    except Exception:
        password_rotation_enabled = False

    users = iam_users
    stale_passwords = []

    for user in users:
        # Check if user has console access
        try:
            login_profile = iam.get_login_profile(UserName=user["UserName"])
            password_last_changed = login_profile["LoginProfile"].get("CreateDate")

            if password_last_changed:
                days_old = (datetime.now(timezone.utc) - password_last_changed).days
                if days_old > days:
                    stale_passwords.append({
                        "username": user["UserName"],
                        "password_age_days": days_old,
                        "last_changed": password_last_changed.isoformat()
                    })
        except iam.exceptions.NoSuchEntityException:
            # User doesn't have console access
            continue
        except Exception:
            continue

    return create_check_result(
        name="Password Rotation",
        description=f"Identifies users with console access whose passwords haven't been rotated in {days}+ days",
        status="PASS" if len(stale_passwords) == 0 else "WARNING",
        severity="MEDIUM",
        details={
            "threshold_days": days,
            "password_rotation_policy_enabled": password_rotation_enabled,
            "stale_passwords_count": len(stale_passwords),
            "users_with_stale_passwords": stale_passwords,
            "explanation": f"Found {len(stale_passwords)} user(s) with passwords older than {days} days" if stale_passwords else "All console passwords are within rotation policy"
        },
        recommendation=None if len(stale_passwords) == 0 else f"Require {len(stale_passwords)} user(s) to rotate their passwords. Enable password expiration in account password policy."
    )

# ---------- AVAILABILITY ----------

def check_cloudwatch_alarms(session):
    cw = session.client("cloudwatch")
    alarms = cw.describe_alarms()["MetricAlarms"]
    alarm_count = len(alarms)

    return create_check_result(
        name="CloudWatch Alarms",
        description="Checks if CloudWatch alarms are configured for monitoring system health and availability",
        status="PASS" if alarm_count > 0 else "WARNING",
        severity="MEDIUM",
        details={
            "alarm_count": alarm_count,
            "alarm_names": [a["AlarmName"] for a in alarms[:10]] if alarms else [],
            "explanation": f"{alarm_count} CloudWatch alarm(s) configured for monitoring" if alarm_count > 0 else "No CloudWatch alarms found - proactive monitoring is not configured"
        },
        recommendation=None if alarm_count > 0 else "Configure CloudWatch alarms for critical metrics (CPU, memory, disk, errors). Set up SNS notifications for alarm triggers."
    )

# ---------- EC2 SECURITY ----------

def check_ebs_encryption(session):
    try:
        ec2_global = session.client("ec2", region_name="us-east-1")
        all_regions = [r["RegionName"] for r in ec2_global.describe_regions(AllRegions=False).get("Regions", [])]
    except Exception:
        all_regions = ["us-east-1"]

    unencrypted_volumes = []

    def check_region(region):
        result = []
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page.get("Volumes", []):
                    if not volume.get("Encrypted"):
                        instance_id = None
                        for attachment in volume.get("Attachments", []):
                            instance_id = attachment.get("InstanceId")
                            break
                        result.append({
                            "volume_id": volume["VolumeId"],
                            "instance_id": instance_id,
                            "size_gb": volume.get("Size"),
                            "state": volume.get("State"),
                            "region": region
                        })
        except Exception:
            pass
        return result

    with ThreadPoolExecutor(max_workers=10) as executor:
        for result in executor.map(check_region, all_regions):
            unencrypted_volumes.extend(result)

    return create_check_result(
        name="EBS Encryption",
        description="Verifies that all EBS volumes attached to EC2 instances are encrypted",
        status="PASS" if len(unencrypted_volumes) == 0 else "FAIL",
        severity="HIGH",
        details={
            "unencrypted_volumes_count": len(unencrypted_volumes),
            "unencrypted_volumes": unencrypted_volumes,
            "explanation": f"Found {len(unencrypted_volumes)} unencrypted EBS volume(s)" if unencrypted_volumes else "All EBS volumes are encrypted"
        },
        recommendation=None if len(unencrypted_volumes) == 0 else f"Encrypt {len(unencrypted_volumes)} EBS volume(s). Create encrypted snapshot, then create new encrypted volume from snapshot. Enable EBS encryption by default in account settings."
    )

def check_public_instances(session, ec2_instances):
    instances = ec2_instances
    public_instances = []

    for reservation in instances:
        region = reservation.get("_region", "us-east-1")
        ec2 = session.client("ec2", region_name=region)
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] == "running":
                # Check if instance has public IP
                public_ip = instance.get("PublicIpAddress")
                if public_ip:
                    # Check if it's in a public subnet
                    subnet_id = instance.get("SubnetId")
                    if subnet_id:
                        subnet = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
                        # Check route table for internet gateway
                        if subnet.get("MapPublicIpOnLaunch", False):
                            public_instances.append({
                                "instance_id": instance["InstanceId"],
                                "public_ip": public_ip,
                                "subnet_id": subnet_id,
                                "region": region,
                                "instance_type": instance["InstanceType"]
                            })

    return create_check_result(
        name="Public EC2 Instances",
        description="Identifies EC2 instances with public IPs in public subnets",
        status="PASS" if len(public_instances) == 0 else "WARNING",
        severity="MEDIUM",
        details={
            "public_instances_count": len(public_instances),
            "public_instances": public_instances,
            "explanation": f"Found {len(public_instances)} instance(s) directly accessible from internet" if public_instances else "No instances with public IPs in public subnets"
        },
        recommendation=None if len(public_instances) == 0 else f"Review {len(public_instances)} public instance(s). Use load balancers or NAT gateways instead of directly exposing instances. Place instances in private subnets when possible."
    )

def check_security_group_rules(session, security_groups):
    risky_rules = []

    sensitive_ports = [22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 5601]

    for sg in security_groups:
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", "All")
            to_port = rule.get("ToPort", "All")
            is_sensitive = from_port in sensitive_ports or to_port in sensitive_ports or from_port == "All"

            if not is_sensitive:
                continue

            # Check IPv4 open ranges
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    risky_rules.append({
                        "security_group_id": sg["GroupId"],
                        "security_group_name": sg["GroupName"],
                        "from_port": from_port,
                        "to_port": to_port,
                        "protocol": rule.get("IpProtocol", "All"),
                        "cidr": "0.0.0.0/0"
                    })

            # Check IPv6 open ranges
            for ip_range in rule.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    risky_rules.append({
                        "security_group_id": sg["GroupId"],
                        "security_group_name": sg["GroupName"],
                        "from_port": from_port,
                        "to_port": to_port,
                        "protocol": rule.get("IpProtocol", "All"),
                        "cidr": "::/0"
                    })

    return create_check_result(
        name="Overly Permissive Security Groups",
        description="Identifies security groups with unrestricted (0.0.0.0/0) access on sensitive ports",
        status="PASS" if len(risky_rules) == 0 else "FAIL",
        severity="HIGH",
        details={
            "risky_rules_count": len(risky_rules),
            "risky_rules": risky_rules[:20],
            "sensitive_ports_checked": sensitive_ports,
            "explanation": f"Found {len(risky_rules)} overly permissive security group rule(s)" if risky_rules else "No security groups with unrestricted access on sensitive ports"
        },
        recommendation=None if len(risky_rules) == 0 else f"Restrict {len(risky_rules)} security group rule(s). Remove 0.0.0.0/0 access and limit to specific IP ranges. Use AWS Systems Manager Session Manager instead of opening SSH/RDP to the world."
    )

def check_instance_tagging(session, ec2_instances):
    instances = ec2_instances
    required_tags = ["Owner", "Environment", "Name"]
    improperly_tagged = []

    for reservation in instances:
        region = reservation.get("_region")
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] != "terminated":
                tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
                missing_tags = [tag for tag in required_tags if tag not in tags]

                if missing_tags:
                    entry = {
                        "instance_id": instance["InstanceId"],
                        "missing_tags": missing_tags,
                        "current_tags": list(tags.keys())
                    }
                    if region:
                        entry["region"] = region
                    improperly_tagged.append(entry)

    return create_check_result(
        name="EC2 Instance Tagging",
        description=f"Verifies that EC2 instances have required tags: {', '.join(required_tags)}",
        status="PASS" if len(improperly_tagged) == 0 else "WARNING",
        severity="LOW",
        details={
            "required_tags": required_tags,
            "improperly_tagged_count": len(improperly_tagged),
            "improperly_tagged_instances": improperly_tagged[:20],
            "explanation": f"Found {len(improperly_tagged)} instance(s) with missing required tags" if improperly_tagged else "All instances have required tags"
        },
        recommendation=None if len(improperly_tagged) == 0 else f"Add required tags to {len(improperly_tagged)} instance(s). Proper tagging enables cost allocation, automation, and resource management."
    )

def check_default_security_groups(session, security_groups, ec2_instances):
    instances = ec2_instances

    default_sgs = [sg for sg in security_groups if sg["GroupName"] == "default"]
    default_sg_ids = {sg["GroupId"] for sg in default_sgs}

    instances_using_default = []

    for reservation in instances:
        region = reservation.get("_region")
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] != "terminated":
                instance_sgs = {sg["GroupId"] for sg in instance.get("SecurityGroups", [])}
                if instance_sgs & default_sg_ids:  # Intersection
                    entry = {
                        "instance_id": instance["InstanceId"],
                        "security_groups": [sg["GroupName"] for sg in instance.get("SecurityGroups", [])]
                    }
                    if region:
                        entry["region"] = region
                    instances_using_default.append(entry)

    return create_check_result(
        name="Default Security Groups in Use",
        description="Identifies EC2 instances using default security groups",
        status="PASS" if len(instances_using_default) == 0 else "WARNING",
        severity="MEDIUM",
        details={
            "instances_using_default_count": len(instances_using_default),
            "instances_using_default": instances_using_default[:20],
            "explanation": f"{len(instances_using_default)} instance(s) use default security groups" if instances_using_default else "No instances use default security groups"
        },
        recommendation=None if len(instances_using_default) == 0 else f"Create custom security groups for {len(instances_using_default)} instance(s). Default security groups should not be used per best practices."
    )

# ---------- CONFIDENTIALITY ----------

def check_s3_public_access(session, s3_buckets):
    try:
        s3 = session.client("s3")
        buckets = s3_buckets

        if not buckets:
            return create_check_result(
                name="S3 Public Access",
                description="Identifies S3 buckets that may allow public access",
                status="WARNING",
                severity="LOW",
                details={
                    "total_buckets": 0,
                    "explanation": "No S3 buckets found or unable to access S3 bucket list"
                },
                recommendation="Ensure S3 permissions include: s3:ListAllMyBuckets, s3:GetBucketPublicAccessBlock"
            )

        public_buckets = []

        for bucket in buckets:
            try:
                pab = s3.get_public_access_block(Bucket=bucket["Name"])
                config = pab["PublicAccessBlockConfiguration"]
                if not all(config.values()):
                    public_buckets.append(bucket["Name"])
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDenied", "AllAccessDisabled"):
                    return create_check_result(
                        name="S3 Public Access",
                        description="Identifies S3 buckets that may allow public access",
                        status="WARNING",
                        severity="CRITICAL",
                        details={"error": f"Insufficient permissions to check public access block: {e.response['Error']['Message']}"},
                        recommendation="Grant s3:GetBucketPublicAccessBlock permission to audit S3 public access settings."
                    )
                # NoSuchPublicAccessBlockConfiguration means no block configured → potentially public
                public_buckets.append(bucket["Name"])

        total_buckets = len(buckets)

        return create_check_result(
            name="S3 Public Access",
            description="Identifies S3 buckets that may allow public access",
            status="PASS" if len(public_buckets) == 0 else "FAIL",
            severity="CRITICAL",
            details={
                "total_buckets": total_buckets,
                "public_buckets_count": len(public_buckets),
                "public_buckets": public_buckets,
                "explanation": f"{len(public_buckets)} of {total_buckets} bucket(s) may allow public access" if public_buckets else "All S3 buckets have public access blocked"
            },
            recommendation=None if len(public_buckets) == 0 else f"Review and block public access for {len(public_buckets)} bucket(s): {', '.join(public_buckets[:5])}{'...' if len(public_buckets) > 5 else ''}. Enable 'Block all public access' in S3 bucket settings."
        )
    except Exception as e:
        return create_check_result(
            name="S3 Public Access",
            description="Identifies S3 buckets that may allow public access",
            status="WARNING",
            severity="LOW",
            details={
                "error": str(e),
                "explanation": "Unable to check S3 bucket public access due to permission error"
            },
            recommendation="Grant S3 permissions: s3:ListAllMyBuckets, s3:GetBucketPublicAccessBlock"
        )

def check_s3_encryption(session, s3_buckets):
    s3 = session.client("s3")
    buckets = s3_buckets
    unencrypted = []

    for bucket in buckets:
        try:
            s3.get_bucket_encryption(Bucket=bucket["Name"])
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AllAccessDisabled"):
                return create_check_result(
                    name="S3 Encryption at Rest",
                    description="Verifies that all S3 buckets have default encryption enabled",
                    status="WARNING",
                    severity="HIGH",
                    details={"error": f"Insufficient permissions to check bucket encryption: {e.response['Error']['Message']}"},
                    recommendation="Grant s3:GetEncryptionConfiguration permission to audit S3 encryption."
                )
            # ServerSideEncryptionConfigurationNotFoundError means encryption genuinely not set
            unencrypted.append(bucket["Name"])

    total_buckets = len(buckets)

    return create_check_result(
        name="S3 Encryption at Rest",
        description="Verifies that all S3 buckets have default encryption enabled",
        status="PASS" if len(unencrypted) == 0 else "FAIL",
        severity="HIGH",
        details={
            "total_buckets": total_buckets,
            "encrypted_buckets": total_buckets - len(unencrypted),
            "unencrypted_buckets_count": len(unencrypted),
            "unencrypted_buckets": unencrypted,
            "explanation": f"{len(unencrypted)} of {total_buckets} bucket(s) lack default encryption" if unencrypted else "All S3 buckets have encryption enabled"
        },
        recommendation=None if len(unencrypted) == 0 else f"Enable default encryption for {len(unencrypted)} bucket(s): {', '.join(unencrypted[:5])}{'...' if len(unencrypted) > 5 else ''}. Use S3 Console > Bucket > Properties > Default encryption > Enable with SSE-S3 or SSE-KMS."
    )

def check_rds_encryption(rds_instances):
    instances = rds_instances
    unencrypted = [
        db["DBInstanceIdentifier"]
        for db in instances
        if not db["StorageEncrypted"]
    ]

    total_instances = len(instances)

    return create_check_result(
        name="RDS Encryption at Rest",
        description="Verifies that all RDS database instances have encryption at rest enabled",
        status="PASS" if len(unencrypted) == 0 else "FAIL",
        severity="CRITICAL",
        details={
            "total_instances": total_instances,
            "encrypted_instances": total_instances - len(unencrypted),
            "unencrypted_instances_count": len(unencrypted),
            "unencrypted_instances": unencrypted,
            "explanation": f"{len(unencrypted)} of {total_instances} RDS instance(s) lack encryption" if unencrypted else "All RDS instances have encryption enabled"
        },
        recommendation=None if len(unencrypted) == 0 else f"Enable encryption for {len(unencrypted)} RDS instance(s): {', '.join(unencrypted)}. Note: Encryption cannot be enabled on existing instances - create encrypted snapshot and restore to new encrypted instance."
    )

def check_rds_backups(rds_instances):
    instances = rds_instances
    no_backups = []

    for db in instances:
        if not db.get("BackupRetentionPeriod", 0) > 0:
            no_backups.append({
                "db_identifier": db["DBInstanceIdentifier"],
                "engine": db["Engine"],
                "backup_retention_period": db.get("BackupRetentionPeriod", 0)
            })

    total_instances = len(instances)

    return create_check_result(
        name="RDS Automated Backups",
        description="Verifies that all RDS instances have automated backups enabled",
        status="PASS" if len(no_backups) == 0 else "FAIL",
        severity="CRITICAL",
        details={
            "total_instances": total_instances,
            "instances_with_backups": total_instances - len(no_backups),
            "instances_without_backups_count": len(no_backups),
            "instances_without_backups": no_backups,
            "explanation": f"{len(no_backups)} of {total_instances} instance(s) lack automated backups" if no_backups else "All RDS instances have automated backups enabled"
        },
        recommendation=None if len(no_backups) == 0 else f"Enable automated backups for {len(no_backups)} RDS instance(s). Set backup retention period to at least 7 days."
    )

def check_rds_backup_retention(rds_instances, min_retention_days=7):
    instances = rds_instances
    insufficient_retention = []

    for db in instances:
        retention = db.get("BackupRetentionPeriod", 0)
        if 0 < retention < min_retention_days:
            insufficient_retention.append({
                "db_identifier": db["DBInstanceIdentifier"],
                "engine": db["Engine"],
                "backup_retention_period": retention
            })

    return create_check_result(
        name="RDS Backup Retention",
        description=f"Verifies that RDS backup retention period meets minimum of {min_retention_days} days",
        status="PASS" if len(insufficient_retention) == 0 else "WARNING",
        severity="MEDIUM",
        details={
            "minimum_retention_days": min_retention_days,
            "insufficient_retention_count": len(insufficient_retention),
            "instances_with_insufficient_retention": insufficient_retention,
            "explanation": f"{len(insufficient_retention)} instance(s) have backup retention less than {min_retention_days} days" if insufficient_retention else f"All RDS instances meet {min_retention_days}-day retention requirement"
        },
        recommendation=None if len(insufficient_retention) == 0 else f"Increase backup retention to at least {min_retention_days} days for {len(insufficient_retention)} instance(s)."
    )

def check_rds_public_access(rds_instances):
    instances = rds_instances
    publicly_accessible = []

    for db in instances:
        if db.get("PubliclyAccessible", False):
            publicly_accessible.append({
                "db_identifier": db["DBInstanceIdentifier"],
                "engine": db["Engine"],
                "endpoint": db.get("Endpoint", {}).get("Address", "N/A")
            })

    total_instances = len(instances)

    return create_check_result(
        name="RDS Public Accessibility",
        description="Identifies RDS instances that are publicly accessible from the internet",
        status="PASS" if len(publicly_accessible) == 0 else "FAIL",
        severity="CRITICAL",
        details={
            "total_instances": total_instances,
            "publicly_accessible_count": len(publicly_accessible),
            "publicly_accessible_instances": publicly_accessible,
            "explanation": f"{len(publicly_accessible)} of {total_instances} instance(s) are publicly accessible" if publicly_accessible else "No RDS instances are publicly accessible"
        },
        recommendation=None if len(publicly_accessible) == 0 else f"Disable public accessibility for {len(publicly_accessible)} RDS instance(s). Place databases in private subnets and use VPN/bastion hosts for access."
    )

def check_rds_deletion_protection(rds_instances):
    instances = rds_instances
    no_deletion_protection = []

    for db in instances:
        # Check for production tags or identifiers
        tags = {tag["Key"]: tag["Value"] for tag in db.get("TagList", [])}
        is_production = tags.get("Environment", "").lower() in ["prod", "production"]

        if is_production and not db.get("DeletionProtection", False):
            no_deletion_protection.append({
                "db_identifier": db["DBInstanceIdentifier"],
                "engine": db["Engine"],
                "environment": tags.get("Environment", "N/A")
            })

    return create_check_result(
        name="RDS Deletion Protection",
        description="Verifies that production RDS instances have deletion protection enabled",
        status="PASS" if len(no_deletion_protection) == 0 else "WARNING",
        severity="MEDIUM",
        details={
            "production_instances_without_protection": len(no_deletion_protection),
            "unprotected_instances": no_deletion_protection,
            "explanation": f"{len(no_deletion_protection)} production instance(s) lack deletion protection" if no_deletion_protection else "All production RDS instances have deletion protection enabled"
        },
        recommendation=None if len(no_deletion_protection) == 0 else f"Enable deletion protection for {len(no_deletion_protection)} production instance(s) to prevent accidental deletion."
    )

def check_s3_versioning(session, s3_buckets):
    s3 = session.client("s3")
    buckets = s3_buckets
    without_versioning = []

    for bucket in buckets:
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket["Name"])
            if versioning.get("Status") != "Enabled":
                without_versioning.append(bucket["Name"])
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AllAccessDisabled"):
                return create_check_result(
                    name="S3 Bucket Versioning",
                    description="Verifies that S3 buckets have versioning enabled for data protection",
                    status="WARNING",
                    severity="MEDIUM",
                    details={"error": f"Insufficient permissions to check bucket versioning: {e.response['Error']['Message']}"},
                    recommendation="Grant s3:GetBucketVersioning permission to audit S3 versioning."
                )
            without_versioning.append(bucket["Name"])

    total_buckets = len(buckets)

    return create_check_result(
        name="S3 Bucket Versioning",
        description="Verifies that S3 buckets have versioning enabled for data protection",
        status="PASS" if len(without_versioning) == 0 else "WARNING",
        severity="MEDIUM",
        details={
            "total_buckets": total_buckets,
            "buckets_with_versioning": total_buckets - len(without_versioning),
            "buckets_without_versioning_count": len(without_versioning),
            "buckets_without_versioning": without_versioning,
            "explanation": f"{len(without_versioning)} of {total_buckets} bucket(s) lack versioning" if without_versioning else "All S3 buckets have versioning enabled"
        },
        recommendation=None if len(without_versioning) == 0 else f"Enable versioning for {len(without_versioning)} bucket(s) to protect against accidental deletion and enable point-in-time recovery."
    )

def check_s3_logging(session, s3_buckets):
    s3 = session.client("s3")
    buckets = s3_buckets
    without_logging = []

    for bucket in buckets:
        try:
            logging = s3.get_bucket_logging(Bucket=bucket["Name"])
            if "LoggingEnabled" not in logging:
                without_logging.append(bucket["Name"])
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AllAccessDisabled"):
                return create_check_result(
                    name="S3 Access Logging",
                    description="Verifies that S3 buckets have access logging enabled for audit trails",
                    status="WARNING",
                    severity="MEDIUM",
                    details={"error": f"Insufficient permissions to check bucket logging: {e.response['Error']['Message']}"},
                    recommendation="Grant s3:GetBucketLogging permission to audit S3 access logging."
                )
            without_logging.append(bucket["Name"])

    total_buckets = len(buckets)

    return create_check_result(
        name="S3 Access Logging",
        description="Verifies that S3 buckets have access logging enabled for audit trails",
        status="PASS" if len(without_logging) == 0 else "WARNING",
        severity="MEDIUM",
        details={
            "total_buckets": total_buckets,
            "buckets_with_logging": total_buckets - len(without_logging),
            "buckets_without_logging_count": len(without_logging),
            "buckets_without_logging": without_logging,
            "explanation": f"{len(without_logging)} of {total_buckets} bucket(s) lack access logging" if without_logging else "All S3 buckets have access logging enabled"
        },
        recommendation=None if len(without_logging) == 0 else f"Enable server access logging for {len(without_logging)} bucket(s) to track access requests and detect security incidents."
    )

def check_s3_lifecycle(session, s3_buckets):
    s3 = session.client("s3")
    buckets = s3_buckets
    without_lifecycle = []

    for bucket in buckets:
        try:
            s3.get_bucket_lifecycle_configuration(Bucket=bucket["Name"])
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchLifecycleConfiguration":
                without_lifecycle.append(bucket["Name"])
            elif code in ("AccessDenied", "AllAccessDisabled"):
                return create_check_result(
                    name="S3 Lifecycle Policies",
                    description="Checks if S3 buckets have lifecycle policies configured for cost optimization",
                    status="WARNING",
                    severity="LOW",
                    details={"error": f"Insufficient permissions to check lifecycle configuration: {e.response['Error']['Message']}"},
                    recommendation="Grant s3:GetLifecycleConfiguration permission to audit S3 lifecycle policies."
                )

    total_buckets = len(buckets)

    return create_check_result(
        name="S3 Lifecycle Policies",
        description="Checks if S3 buckets have lifecycle policies configured for cost optimization",
        status="PASS" if len(without_lifecycle) == 0 else "WARNING",
        severity="LOW",
        details={
            "total_buckets": total_buckets,
            "buckets_with_lifecycle": total_buckets - len(without_lifecycle),
            "buckets_without_lifecycle_count": len(without_lifecycle),
            "buckets_without_lifecycle": without_lifecycle,
            "explanation": f"{len(without_lifecycle)} of {total_buckets} bucket(s) lack lifecycle policies" if without_lifecycle else "All S3 buckets have lifecycle policies configured"
        },
        recommendation=None if len(without_lifecycle) == 0 else f"Configure lifecycle policies for {len(without_lifecycle)} bucket(s) to automatically transition or expire objects, reducing storage costs."
    )

# ---------- PROCESSING INTEGRITY ----------

def check_cloudtrail_validation(trails):
    if not trails:
        return create_check_result(
            name="CloudTrail Log File Validation",
            description="Checks if CloudTrail trails have log file integrity validation enabled",
            status="FAIL",
            severity="HIGH",
            details={"total_trails": 0, "explanation": "No CloudTrail trails configured — log file validation cannot be assessed"},
            recommendation="Create a CloudTrail trail with log file validation enabled to ensure audit log integrity."
        )

    without_validation = [
        t["Name"]
        for t in trails
        if not t.get("LogFileValidationEnabled", False)
    ]

    total_trails = len(trails)

    return create_check_result(
        name="CloudTrail Log File Validation",
        description="Checks if CloudTrail trails have log file integrity validation enabled",
        status="PASS" if len(without_validation) == 0 else "FAIL",
        severity="HIGH",
        details={
            "total_trails": total_trails,
            "trails_with_validation": total_trails - len(without_validation),
            "trails_without_validation_count": len(without_validation),
            "trails_without_validation": without_validation,
            "explanation": f"{len(without_validation)} of {total_trails} trail(s) lack log file validation" if without_validation else "All CloudTrail trails have log file validation enabled"
        },
        recommendation=None if len(without_validation) == 0 else f"Enable log file validation for {len(without_validation)} trail(s): {', '.join(without_validation)}. This ensures logs haven't been tampered with after delivery."
    )

def check_aws_config(session):
    """Check AWS Config is enabled and recording in all opted-in regions."""
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        all_regions = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False).get("Regions", [])]
    except Exception:
        all_regions = ["us-east-1"]

    enabled_regions = []
    disabled_regions = []

    def check_region(region):
        try:
            cfg = session.client("config", region_name=region)
            recorders = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
            if not recorders:
                return (region, False)
            statuses = cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
            return (region, any(s.get("recording") for s in statuses))
        except Exception:
            return (region, False)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_region, r): r for r in all_regions}
        for future in as_completed(futures):
            region, recording = future.result()
            (enabled_regions if recording else disabled_regions).append(region)

    passing = not disabled_regions
    return create_check_result(
        name="AWS Config",
        description="Verifies that AWS Config is enabled and recording in all regions",
        status="PASS" if passing else "WARNING",
        severity="MEDIUM",
        details={
            "enabled_regions": sorted(enabled_regions),
            "disabled_regions": sorted(disabled_regions),
            "explanation": (
                "AWS Config recording active in all regions" if passing
                else f"AWS Config not recording in {len(disabled_regions)} region(s): {', '.join(sorted(disabled_regions))}"
            )
        },
        recommendation=None if passing else (
            f"Enable AWS Config recording in {len(disabled_regions)} region(s): {', '.join(sorted(disabled_regions))}."
        )
    )

def check_cloudtrail_multiregion(trails):
    multiregion_trails = [t for t in trails if t.get("IsMultiRegionTrail", False)]

    return create_check_result(
        name="CloudTrail Multi-Region",
        description="Verifies that CloudTrail is enabled across all regions",
        status="PASS" if len(multiregion_trails) > 0 else "FAIL",
        severity="HIGH",
        details={
            "total_trails": len(trails),
            "multiregion_trails_count": len(multiregion_trails),
            "multiregion_trails": [t["Name"] for t in multiregion_trails],
            "explanation": f"{len(multiregion_trails)} multi-region trail(s) configured" if multiregion_trails else "No multi-region trails - some regions may not be logged"
        },
        recommendation=None if len(multiregion_trails) > 0 else "Enable multi-region CloudTrail to ensure all API activity is logged across all regions. Edit existing trail or create new multi-region trail."
    )

def check_cloudtrail_encryption(session, trails):
    if not trails:
        return create_check_result(
            name="CloudTrail Log Encryption",
            description="Verifies that CloudTrail logs are encrypted with KMS",
            status="FAIL",
            severity="MEDIUM",
            details={"total_trails": 0, "explanation": "No CloudTrail trails configured — encryption cannot be assessed"},
            recommendation="Create a CloudTrail trail with KMS encryption enabled."
        )

    ct = session.client("cloudtrail")
    unencrypted_trails = []

    for trail in trails:
        trail_status = ct.get_trail(Name=trail["TrailARN"])["Trail"]
        if not trail_status.get("KmsKeyId"):
            unencrypted_trails.append(trail["Name"])

    return create_check_result(
        name="CloudTrail Log Encryption",
        description="Verifies that CloudTrail logs are encrypted with KMS",
        status="PASS" if len(unencrypted_trails) == 0 else "WARNING",
        severity="MEDIUM",
        details={
            "total_trails": len(trails),
            "encrypted_trails": len(trails) - len(unencrypted_trails),
            "unencrypted_trails_count": len(unencrypted_trails),
            "unencrypted_trails": unencrypted_trails,
            "explanation": f"{len(unencrypted_trails)} trail(s) store logs without KMS encryption" if unencrypted_trails else "All CloudTrail logs are encrypted with KMS"
        },
        recommendation=None if len(unencrypted_trails) == 0 else f"Enable KMS encryption for {len(unencrypted_trails)} CloudTrail trail(s) to protect log data at rest."
    )

def check_vpc_flow_logs(session, vpcs):
    vpcs_without_flow_logs = []

    # Group VPCs by region so we use one regional client per region
    vpcs_by_region = {}
    for vpc in vpcs:
        region = vpc.get("_region", "us-east-1")
        vpcs_by_region.setdefault(region, []).append(vpc)

    for region, region_vpcs in vpcs_by_region.items():
        ec2 = session.client("ec2", region_name=region)
        for vpc in region_vpcs:
            vpc_id = vpc["VpcId"]
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )["FlowLogs"]

            if len(flow_logs) == 0:
                vpcs_without_flow_logs.append({
                    "vpc_id": vpc_id,
                    "region": region,
                    "is_default": vpc.get("IsDefault", False)
                })

    total_vpcs = len(vpcs)

    return create_check_result(
        name="VPC Flow Logs",
        description="Verifies that VPC Flow Logs are enabled for network traffic monitoring",
        status="PASS" if len(vpcs_without_flow_logs) == 0 else "WARNING",
        severity="MEDIUM",
        details={
            "total_vpcs": total_vpcs,
            "vpcs_with_flow_logs": total_vpcs - len(vpcs_without_flow_logs),
            "vpcs_without_flow_logs_count": len(vpcs_without_flow_logs),
            "vpcs_without_flow_logs": vpcs_without_flow_logs,
            "explanation": f"{len(vpcs_without_flow_logs)} VPC(s) lack flow logs" if vpcs_without_flow_logs else "All VPCs have flow logs enabled"
        },
        recommendation=None if len(vpcs_without_flow_logs) == 0 else f"Enable VPC Flow Logs for {len(vpcs_without_flow_logs)} VPC(s) to monitor network traffic and detect security incidents."
    )

def check_cloudtrail_log_retention(session, trails, min_retention_days=90):
    if not trails:
        return create_check_result(
            name="CloudTrail Log Retention",
            description=f"Verifies that CloudTrail logs are retained for at least {min_retention_days} days",
            status="FAIL",
            severity="MEDIUM",
            details={"minimum_retention_days": min_retention_days, "explanation": "No CloudTrail trails configured — log retention cannot be assessed"},
            recommendation=f"Create a CloudTrail trail and configure the S3 bucket lifecycle to retain logs for at least {min_retention_days} days."
        )

    s3 = session.client("s3")
    insufficient_retention = []

    for trail in trails:
        bucket_name = trail.get("S3BucketName")
        if bucket_name:
            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                # Check if any rule has expiration less than min_retention_days
                has_proper_retention = False
                for rule in lifecycle.get("Rules", []):
                    expiration = rule.get("Expiration", {}).get("Days", 0)
                    if expiration >= min_retention_days or expiration == 0:
                        has_proper_retention = True
                        break

                if not has_proper_retention:
                    insufficient_retention.append({
                        "trail_name": trail["Name"],
                        "s3_bucket": bucket_name
                    })
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
                    # No lifecycle policy means logs are retained indefinitely (PASS)
                    pass

    return create_check_result(
        name="CloudTrail Log Retention",
        description=f"Verifies that CloudTrail logs are retained for at least {min_retention_days} days",
        status="PASS" if len(insufficient_retention) == 0 else "WARNING",
        severity="MEDIUM",
        details={
            "minimum_retention_days": min_retention_days,
            "trails_with_insufficient_retention": len(insufficient_retention),
            "insufficient_retention_trails": insufficient_retention,
            "explanation": f"{len(insufficient_retention)} trail(s) may not retain logs for {min_retention_days} days" if insufficient_retention else f"All trails meet {min_retention_days}-day retention requirement"
        },
        recommendation=None if len(insufficient_retention) == 0 else f"Review retention policies for {len(insufficient_retention)} trail(s). Ensure S3 lifecycle policies don't delete logs before {min_retention_days} days."
    )

# ---------- PRIVACY ----------

def check_password_policy(session):
    iam = session.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]

        # Check if policy meets best practices
        weak_points = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            weak_points.append(f"Password length is {policy.get('MinimumPasswordLength', 0)} (recommended: 14+)")
        if not policy.get("RequireUppercaseCharacters", False):
            weak_points.append("Uppercase characters not required")
        if not policy.get("RequireLowercaseCharacters", False):
            weak_points.append("Lowercase characters not required")
        if not policy.get("RequireNumbers", False):
            weak_points.append("Numbers not required")
        if not policy.get("RequireSymbols", False):
            weak_points.append("Symbols not required")
        if not policy.get("ExpirePasswords", False):
            weak_points.append("Password expiration not enabled")

        status = "PASS" if len(weak_points) == 0 else "WARNING"

        return create_check_result(
            name="Password Policy",
            description="Reviews IAM password policy for strength requirements",
            status=status,
            severity="MEDIUM",
            details={
                "policy_configured": True,
                "minimum_length": policy.get("MinimumPasswordLength", 0),
                "require_uppercase": policy.get("RequireUppercaseCharacters", False),
                "require_lowercase": policy.get("RequireLowercaseCharacters", False),
                "require_numbers": policy.get("RequireNumbers", False),
                "require_symbols": policy.get("RequireSymbols", False),
                "expire_passwords": policy.get("ExpirePasswords", False),
                "max_password_age": policy.get("MaxPasswordAge", "N/A") if policy.get("ExpirePasswords", False) else "N/A",
                "weak_points": weak_points,
                "explanation": f"Password policy configured with {len(weak_points)} weakness(es)" if weak_points else "Password policy meets best practice requirements"
            },
            recommendation=None if len(weak_points) == 0 else f"Strengthen password policy: {'; '.join(weak_points)}. Go to IAM Console > Account settings > Password policy."
        )
    except Exception:
        return create_check_result(
            name="Password Policy",
            description="Reviews IAM password policy for strength requirements",
            status="FAIL",
            severity="MEDIUM",
            details={
                "policy_configured": False,
                "explanation": "No custom password policy is configured - using AWS default policy"
            },
            recommendation="Configure a custom password policy with strong requirements: 14+ characters, require uppercase, lowercase, numbers, and symbols. Go to IAM Console > Account settings > Password policy."
        )

# ---------- NEW CHECKS ----------

def check_guardduty_enabled(session):
    """Security: GuardDuty must be enabled in all regions for automated threat detection."""
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        all_regions = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False).get("Regions", [])]
    except Exception:
        all_regions = ["us-east-1"]

    enabled_regions = []
    disabled_regions = []

    def check_region(region):
        try:
            gd = session.client("guardduty", region_name=region)
            detectors = gd.list_detectors()["DetectorIds"]
            if detectors:
                det = gd.get_detector(DetectorId=detectors[0])
                return (region, det.get("Status") == "ENABLED")
            return (region, False)
        except Exception:
            return (region, False)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_region, r): r for r in all_regions}
        for future in as_completed(futures):
            region, enabled = future.result()
            (enabled_regions if enabled else disabled_regions).append(region)

    passing = not disabled_regions
    return create_check_result(
        name="GuardDuty Enabled",
        description="Verifies that GuardDuty threat detection is enabled in all AWS regions",
        status="PASS" if passing else "FAIL",
        severity="HIGH",
        details={
            "enabled_regions": sorted(enabled_regions),
            "disabled_regions": sorted(disabled_regions),
            "explanation": (
                "GuardDuty enabled in all regions" if passing
                else f"GuardDuty disabled in {len(disabled_regions)} region(s): {', '.join(sorted(disabled_regions))}"
            )
        },
        recommendation=None if passing else (
            f"Enable GuardDuty in {len(disabled_regions)} region(s): {', '.join(sorted(disabled_regions))}. "
            "Go to GuardDuty Console > Get started in each region."
        )
    )


def check_iam_access_analyzer(session):
    """Security: IAM Access Analyzer detects resources exposed to unintended external access."""
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        all_regions = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False).get("Regions", [])]
    except Exception:
        all_regions = ["us-east-1"]

    enabled_regions = []
    disabled_regions = []

    def check_region(region):
        try:
            aa = session.client("accessanalyzer", region_name=region)
            analyzers = aa.list_analyzers(type="ACCOUNT")["analyzers"]
            return (region, any(a.get("status") == "ACTIVE" for a in analyzers))
        except Exception:
            return (region, False)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_region, r): r for r in all_regions}
        for future in as_completed(futures):
            region, enabled = future.result()
            (enabled_regions if enabled else disabled_regions).append(region)

    passing = not disabled_regions
    return create_check_result(
        name="IAM Access Analyzer",
        description="Verifies IAM Access Analyzer is active in all regions to detect unintended resource exposure",
        status="PASS" if passing else "FAIL",
        severity="HIGH",
        details={
            "enabled_regions": sorted(enabled_regions),
            "disabled_regions": sorted(disabled_regions),
            "explanation": (
                "IAM Access Analyzer active in all regions" if passing
                else f"IAM Access Analyzer not active in {len(disabled_regions)} region(s)"
            )
        },
        recommendation=None if passing else (
            f"Enable IAM Access Analyzer in {len(disabled_regions)} region(s). "
            "Go to IAM Console > Access Analyzer > Create analyzer."
        )
    )


def check_kms_key_rotation(session):
    """Confidentiality: Customer-managed KMS keys must have annual rotation enabled."""
    keys_without_rotation = []
    access_denied_regions = []

    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        all_regions = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False).get("Regions", [])]
    except Exception:
        all_regions = ["us-east-1"]

    def check_region(region):
        result = []
        access_denied = False
        try:
            kms = session.client("kms", region_name=region)
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for key in page.get("Keys", []):
                    kid = key["KeyId"]
                    try:
                        meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
                        if (meta.get("KeyManager") == "CUSTOMER" and
                                meta.get("KeyState") == "Enabled" and
                                meta.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT"):
                            rotation = kms.get_key_rotation_status(KeyId=kid)
                            if not rotation.get("KeyRotationEnabled"):
                                result.append({"keyId": kid, "region": region})
                    except ClientError as e:
                        if e.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"):
                            access_denied = True
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"):
                access_denied = True
        except Exception:
            pass
        return result, access_denied

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_region, r): r for r in all_regions}
        for future in as_completed(futures):
            keys, ad = future.result()
            keys_without_rotation.extend(keys)
            if ad:
                access_denied_regions.append(futures[future])

    if access_denied_regions:
        return create_check_result(
            name="KMS Key Rotation",
            description="Verifies that customer-managed KMS keys have annual automatic rotation enabled",
            status="WARNING",
            severity="MEDIUM",
            details={"error": f"Insufficient permissions to check KMS key rotation in {len(access_denied_regions)} region(s): {sorted(access_denied_regions)}"},
            recommendation="Grant kms:ListKeys, kms:DescribeKey, and kms:GetKeyRotationStatus permissions to audit KMS key rotation."
        )

    return create_check_result(
        name="KMS Key Rotation",
        description="Verifies that customer-managed KMS keys have annual automatic rotation enabled",
        status="PASS" if not keys_without_rotation else "FAIL",
        severity="MEDIUM",
        details={
            "keys_without_rotation": keys_without_rotation,
            "count": len(keys_without_rotation),
            "explanation": (
                "All customer-managed KMS keys have rotation enabled" if not keys_without_rotation
                else f"{len(keys_without_rotation)} key(s) lack automatic rotation"
            )
        },
        recommendation=None if not keys_without_rotation else (
            f"Enable annual key rotation on {len(keys_without_rotation)} KMS CMK(s). "
            "Use: aws kms enable-key-rotation --key-id <key-id>"
        )
    )


def check_ec2_imdsv2(ec2_instances):
    """Security: Running EC2 instances must require IMDSv2 to prevent SSRF credential theft."""
    instances = ec2_instances

    imdsv1_instances = []
    for reservation in instances:
        region = reservation.get("_region")
        for instance in reservation.get("Instances", []):
            if instance.get("State", {}).get("Name") != "running":
                continue
            meta_opts = instance.get("MetadataOptions", {})
            if meta_opts.get("HttpTokens") != "required":
                entry = {
                    "instance_id": instance["InstanceId"],
                    "http_tokens": meta_opts.get("HttpTokens", "optional")
                }
                if region:
                    entry["region"] = region
                imdsv1_instances.append(entry)

    return create_check_result(
        name="EC2 IMDSv2 Enforcement",
        description="Verifies running EC2 instances require IMDSv2 to prevent SSRF-based credential theft",
        status="PASS" if not imdsv1_instances else "FAIL",
        severity="HIGH",
        details={
            "instances_allowing_imdsv1": imdsv1_instances[:20],
            "count": len(imdsv1_instances),
            "explanation": (
                "All running instances require IMDSv2" if not imdsv1_instances
                else f"{len(imdsv1_instances)} instance(s) allow IMDSv1 (insecure)"
            )
        },
        recommendation=None if not imdsv1_instances else (
            f"Enforce IMDSv2 on {len(imdsv1_instances)} instance(s): "
            "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required"
        )
    )


def check_cloudwatch_log_retention(session):
    """Processing Integrity: CloudWatch log groups must retain logs for at least 365 days."""
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        all_regions = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False).get("Regions", [])]
    except Exception:
        all_regions = ["us-east-1"]

    short_retention = []

    def check_region(region):
        result = []
        try:
            logs = session.client("logs", region_name=region)
            paginator = logs.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                for lg in page.get("logGroups", []):
                    retention = lg.get("retentionInDays")
                    # None = never expires = acceptable; only flag explicit short retention
                    if retention is not None and retention < 365:
                        result.append({
                            "logGroup": lg["logGroupName"],
                            "region": region,
                            "retentionDays": retention
                        })
        except Exception:
            pass
        return result

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_region, r): r for r in all_regions}
        for future in as_completed(futures):
            short_retention.extend(future.result())

    return create_check_result(
        name="CloudWatch Log Retention",
        description="Verifies CloudWatch log groups retain logs for at least 365 days for audit purposes",
        status="PASS" if not short_retention else "WARNING",
        severity="MEDIUM",
        details={
            "log_groups_below_365_days": short_retention[:20],
            "count": len(short_retention),
            "explanation": (
                "All log groups meet 365-day retention requirement" if not short_retention
                else f"{len(short_retention)} log group(s) have retention below 365 days"
            )
        },
        recommendation=None if not short_retention else (
            f"Set retention to at least 365 days on {len(short_retention)} CloudWatch log group(s)."
        )
    )


def check_rds_auto_minor_version(rds_instances):
    """Availability: RDS instances should have auto minor version upgrade enabled for security patches."""
    instances = rds_instances

    no_auto_upgrade = [
        {
            "db_identifier": db["DBInstanceIdentifier"],
            "engine": db["Engine"],
            "engine_version": db.get("EngineVersion")
        }
        for db in instances
        if not db.get("AutoMinorVersionUpgrade", False)
    ]

    return create_check_result(
        name="RDS Auto Minor Version Upgrade",
        description="Verifies RDS instances have auto minor version upgrade enabled for security patching",
        status="PASS" if not no_auto_upgrade else "WARNING",
        severity="LOW",
        details={
            "instances_without_auto_upgrade": no_auto_upgrade,
            "count": len(no_auto_upgrade),
            "explanation": (
                "All RDS instances have auto minor version upgrade enabled" if not no_auto_upgrade
                else f"{len(no_auto_upgrade)} instance(s) lack auto minor version upgrade"
            )
        },
        recommendation=None if not no_auto_upgrade else (
            f"Enable auto minor version upgrade on {len(no_auto_upgrade)} RDS instance(s) "
            "to ensure security patches are applied automatically."
        )
    )


# ---------- PRIVACY CHECKS ----------

def check_macie_enabled(session):
    """Privacy: Amazon Macie should be enabled to detect and classify sensitive/PII data in S3."""
    try:
        macie = session.client("macie2", region_name="us-east-1")
        status = macie.get_macie_session()
        enabled = status.get("status") == "ENABLED"

        return create_check_result(
            name="Amazon Macie — PII Detection",
            description="Verifies Amazon Macie is enabled to automatically discover and classify sensitive data (PII) in S3",
            status="PASS" if enabled else "FAIL",
            severity="HIGH",
            details={
                "macie_enabled": enabled,
                "explanation": (
                    "Macie is enabled and scanning S3 buckets for sensitive data" if enabled
                    else "Macie is not enabled — S3 buckets are not being scanned for PII or sensitive data"
                )
            },
            recommendation=None if enabled else (
                "Enable Amazon Macie to automatically discover, classify, and protect sensitive data. "
                "Go to Macie Console > Get started > Enable Macie."
            )
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "AccessDeniedException":
            return create_check_result(
                name="Amazon Macie — PII Detection",
                description="Verifies Amazon Macie is enabled to automatically discover and classify sensitive data (PII) in S3",
                status="WARNING",
                severity="LOW",
                details={"error": "Permission denied", "explanation": "Unable to check Macie status"},
                recommendation="Grant macie2:GetMacieSession permission to check this control."
            )
        # Macie not enabled returns an exception in some SDK versions
        return create_check_result(
            name="Amazon Macie — PII Detection",
            description="Verifies Amazon Macie is enabled to automatically discover and classify sensitive data (PII) in S3",
            status="FAIL",
            severity="HIGH",
            details={"macie_enabled": False, "explanation": "Macie is not enabled for this account"},
            recommendation="Enable Amazon Macie to discover and classify PII and sensitive data in S3 buckets."
        )
    except Exception as e:
        return create_check_result(
            name="Amazon Macie — PII Detection",
            description="Verifies Amazon Macie is enabled to automatically discover and classify sensitive data (PII) in S3",
            status="WARNING",
            severity="LOW",
            details={"error": str(e)},
            recommendation="Grant macie2:GetMacieSession permission to check this control."
        )


def check_s3_object_ownership(session, s3_buckets):
    """Privacy: S3 buckets should disable ACLs (BucketOwnerEnforced) to prevent unintended data exposure."""
    try:
        s3 = session.client("s3")
        buckets = s3_buckets
        acl_enabled_buckets = []

        for bucket in buckets:
            name = bucket["Name"]
            try:
                ownership = s3.get_bucket_ownership_controls(Bucket=name)
                rules = ownership.get("OwnershipControls", {}).get("Rules", [])
                # BucketOwnerEnforced disables ACLs — anything else allows ACLs
                if not any(r.get("ObjectOwnership") == "BucketOwnerEnforced" for r in rules):
                    acl_enabled_buckets.append(name)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "OwnershipControlsNotFoundError":
                    # No ownership controls set = ACLs are still in effect
                    acl_enabled_buckets.append(name)
                elif code in ("AccessDenied", "AllAccessDisabled"):
                    return create_check_result(
                        name="S3 Object Ownership — ACLs Disabled",
                        description="Verifies S3 buckets use BucketOwnerEnforced ownership to disable ACLs",
                        status="WARNING",
                        severity="MEDIUM",
                        details={"error": f"Insufficient permissions to check bucket ownership controls: {e.response['Error']['Message']}"},
                        recommendation="Grant s3:GetBucketOwnershipControls permission to audit S3 ownership settings."
                    )

        total = len(buckets)
        return create_check_result(
            name="S3 Object Ownership — ACLs Disabled",
            description="Verifies S3 buckets use BucketOwnerEnforced ownership to disable ACLs and prevent unintended data sharing",
            status="PASS" if not acl_enabled_buckets else "WARNING",
            severity="MEDIUM",
            details={
                "total_buckets": total,
                "buckets_with_acls_enabled": acl_enabled_buckets,
                "count": len(acl_enabled_buckets),
                "explanation": (
                    "All buckets have ACLs disabled (BucketOwnerEnforced)" if not acl_enabled_buckets
                    else f"{len(acl_enabled_buckets)} bucket(s) still allow ACLs, which can grant unintended access to data"
                )
            },
            recommendation=None if not acl_enabled_buckets else (
                f"Set ObjectOwnership=BucketOwnerEnforced on {len(acl_enabled_buckets)} bucket(s) to disable ACLs "
                "and enforce that the bucket owner controls all object access via bucket policies only."
            )
        )
    except Exception as e:
        return create_check_result(
            name="S3 Object Ownership — ACLs Disabled",
            description="Verifies S3 buckets use BucketOwnerEnforced ownership to disable ACLs",
            status="WARNING",
            severity="LOW",
            details={"error": str(e)},
            recommendation="Grant s3:GetBucketOwnershipControls permission to check this control."
        )


def check_no_overly_permissive_data_policies(session):
    """Privacy: IAM policies must not grant wildcard read access to all S3 objects."""
    iam = session.client("iam")
    risky_policies = []

    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                try:
                    version = iam.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"]
                    )
                    doc = version["PolicyVersion"]["Document"]
                    if isinstance(doc.get("Statement"), list):
                        for stmt in doc["Statement"]:
                            if stmt.get("Effect") != "Allow":
                                continue
                            actions = stmt.get("Action", [])
                            resources = stmt.get("Resource", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            # Flag policies that allow reading all S3 objects with wildcard resource
                            data_read_actions = {"s3:GetObject", "s3:*", "*"}
                            if (any(a in data_read_actions or a == "*" for a in actions) and
                                    "*" in resources):
                                risky_policies.append({
                                    "policy_name": policy["PolicyName"],
                                    "policy_arn": policy["Arn"],
                                    "reason": "Allows broad data read access (S3 GetObject/*) on all resources (*)"
                                })
                                break
                except Exception:
                    continue
    except Exception:
        pass

    return create_check_result(
        name="IAM Data Access Policies — No Wildcard S3 Read",
        description="Identifies IAM policies that grant unrestricted read access to all S3 objects, risking unintended data exposure",
        status="PASS" if not risky_policies else "FAIL",
        severity="HIGH",
        details={
            "risky_policies_count": len(risky_policies),
            "risky_policies": risky_policies[:10],
            "explanation": (
                "No policies grant wildcard S3 read access" if not risky_policies
                else f"{len(risky_policies)} policy/policies grant broad S3 data read access"
            )
        },
        recommendation=None if not risky_policies else (
            "Restrict S3 read policies to specific bucket ARNs and prefixes. "
            "Apply least-privilege: grant s3:GetObject only on specific bucket paths (e.g. arn:aws:s3:::bucket-name/*)."
        )
    )


def check_secrets_manager_rotation(session):
    """Security: Secrets Manager secrets should have automatic rotation enabled (SOC 2 CC6.1)."""
    secrets_without_rotation = []
    access_denied_regions = []

    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        all_regions = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False).get("Regions", [])]
    except Exception:
        all_regions = ["us-east-1"]

    def check_region(region):
        result = []
        access_denied = False
        try:
            sm = session.client("secretsmanager", region_name=region)
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    if not secret.get("RotationEnabled", False):
                        last_changed = secret.get("LastChangedDate")
                        result.append({
                            "secret_name": secret.get("Name"),
                            "arn": secret.get("ARN"),
                            "region": region,
                            "last_changed": last_changed.isoformat() if last_changed else None
                        })
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AccessDeniedException", "AccessDenied"):
                access_denied = True
        except Exception:
            pass
        return result, access_denied

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_region, r): r for r in all_regions}
        for future in as_completed(futures):
            secrets, ad = future.result()
            secrets_without_rotation.extend(secrets)
            if ad:
                access_denied_regions.append(futures[future])

    if access_denied_regions:
        return create_check_result(
            name="Secrets Manager Rotation",
            description="Verifies that Secrets Manager secrets have automatic rotation enabled",
            status="WARNING",
            severity="HIGH",
            details={"error": f"Insufficient permissions to list Secrets Manager secrets in {len(access_denied_regions)} region(s): {sorted(access_denied_regions)}"},
            recommendation="Grant secretsmanager:ListSecrets permission to audit secret rotation."
        )

    return create_check_result(
        name="Secrets Manager Rotation",
        description="Verifies that Secrets Manager secrets have automatic rotation enabled",
        status="PASS" if not secrets_without_rotation else "FAIL",
        severity="HIGH",
        details={
            "secrets_without_rotation": secrets_without_rotation[:20],
            "count": len(secrets_without_rotation),
            "explanation": (
                "All Secrets Manager secrets have automatic rotation enabled" if not secrets_without_rotation
                else f"{len(secrets_without_rotation)} secret(s) do not have automatic rotation enabled"
            )
        },
        recommendation=None if not secrets_without_rotation else (
            f"Enable automatic rotation for {len(secrets_without_rotation)} secret(s). "
            "Configure a Lambda rotation function and set a rotation schedule (30–90 days) "
            "to ensure credentials are cycled without manual intervention."
        )
    )


# ---------- EXECUTIVE SUMMARY ----------

def generate_executive_summary(result):
    """Generate a markdown-formatted executive summary of the SOC2 audit results"""
    summary = result["metadata"]["summary"]
    account_id = result["metadata"].get("aws_account_id", "Unknown")

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
        md_lines.append(f"**AWS Account {account_id}** demonstrates **strong SOC2 compliance** with a **{compliance_score}%** pass rate across **{total_checks}** security controls.")
    elif compliance_score >= 70:
        md_lines.append(f"**AWS Account {account_id}** shows **moderate SOC2 compliance** with a **{compliance_score}%** pass rate across **{total_checks}** security controls, requiring targeted improvements.")
    else:
        md_lines.append(f"**AWS Account {account_id}** requires **significant security improvements** with a **{compliance_score}%** pass rate across **{total_checks}** security controls.")
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

    # Trust Service Categories status
    md_lines.append("## Trust Service Categories")
    md_lines.append("")
    categories_with_issues = []
    if any(c["status"] == "FAIL" for c in result["security"]["checks"]):
        categories_with_issues.append("**Security**")
    if any(c["status"] == "FAIL" for c in result["confidentiality"]["checks"]):
        categories_with_issues.append("**Confidentiality**")
    if any(c["status"] == "FAIL" for c in result["availability"]["checks"]):
        categories_with_issues.append("**Availability**")
    if any(c["status"] == "FAIL" for c in result["processing_integrity"]["checks"]):
        categories_with_issues.append("**Processing Integrity**")
    if any(c["status"] == "FAIL" for c in result["privacy"]["checks"]):
        categories_with_issues.append("**Privacy**")

    if categories_with_issues:
        md_lines.append(f"Trust Service Categories requiring attention: {', '.join(categories_with_issues)}")
    else:
        md_lines.append("All five Trust Service Categories (**Security**, **Availability**, **Processing Integrity**, **Confidentiality**, **Privacy**) meet compliance standards.")
    md_lines.append("")

    # Key areas of concern or strength
    md_lines.append("## Priority Areas")
    md_lines.append("")
    all_checks = (
        result["security"]["checks"] +
        result["availability"]["checks"] +
        result["confidentiality"]["checks"] +
        result["processing_integrity"]["checks"] +
        result["privacy"]["checks"]
    )
    failed_checks = [c for c in all_checks if c["status"] == "FAIL" and c["severity"] in ["CRITICAL", "HIGH"]]

    if failed_checks:
        top_concerns = [f"- {c['check_name']}" for c in failed_checks[:3]]
        md_lines.append("**Priority remediation areas:**")
        md_lines.append("")
        md_lines.extend(top_concerns)
    else:
        passed_checks = [c for c in all_checks if c["status"] == "PASS"]
        if passed_checks:
            strengths = [f"- {c['check_name']}" for c in passed_checks[:5]]
            md_lines.append("**Key security strengths demonstrated:**")
            md_lines.append("")
            md_lines.extend(strengths)
    md_lines.append("")

    # Recommendations summary
    md_lines.append("## Additional Observations")
    md_lines.append("")

    # Add permission error note if any
    if permission_errors > 0:
        md_lines.append(f"**Note:** {permission_errors} check(s) could not be completed due to insufficient IAM permissions. Grant necessary permissions for a complete audit.")
        md_lines.append("")

    if warnings > 0:
        warnings_without_permission = warnings - permission_errors
        if warnings_without_permission > 0:
            md_lines.append(f"Additionally, **{warnings_without_permission} warning(s)** were identified that should be reviewed for continuous improvement and long-term compliance maintenance.")
        elif permission_errors == 0:
            md_lines.append(f"**{warnings} warning(s)** were identified that should be reviewed for continuous improvement and long-term compliance maintenance.")
    else:
        if permission_errors == 0:
            md_lines.append("No warnings were identified, indicating robust security configurations across the infrastructure.")
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

def run_soc2_audit(profile_name=None):
    # Always use us-east-1 as the default region
    # us-east-1 is AWS's default region and works for both global services (IAM, S3) and regional services
    region = 'us-east-1'

    # Create session with specified profile and region
    if profile_name:
        session = boto3.Session(profile_name=profile_name, region_name=region)
    else:
        session = boto3.Session(region_name=region)

    RESULT = _make_result()

    # Add profile info to metadata
    RESULT["metadata"]["aws_profile"] = profile_name or "default"
    RESULT["metadata"]["aws_region"] = region
    RESULT["metadata"]["aws_account_id"] = session.client("sts").get_caller_identity()["Account"]

    # Initialize cache for shared resources
    cache = AWSResourceCache(session)

    # Define all checks to run with their categories
    check_tasks = [
        # Security checks
        ("security", lambda: check_root_mfa(session)),
        ("security", lambda: check_iam_users_mfa(session)),
        ("security", lambda: check_old_access_keys(session, cache.iam_users)),
        ("security", lambda: check_overly_permissive_policies(session)),
        ("security", lambda: check_inactive_users(session, cache.iam_users)),
        ("security", lambda: check_password_rotation(session, cache.iam_users)),
        ("security", lambda: check_cloudtrail(session, cache.cloudtrail_trails)),
        ("security", lambda: check_ebs_encryption(session)),
        ("security", lambda: check_public_instances(session, cache.ec2_instances)),
        ("security", lambda: check_security_group_rules(session, cache.security_groups)),
        ("security", lambda: check_default_security_groups(session, cache.security_groups, cache.ec2_instances)),
        ("security", lambda: check_instance_tagging(session, cache.ec2_instances)),
        ("security", lambda: check_guardduty_enabled(session)),
        ("security", lambda: check_iam_access_analyzer(session)),
        ("security", lambda: check_ec2_imdsv2(cache.ec2_instances)),
        ("security", lambda: check_secrets_manager_rotation(session)),

        # Availability checks
        ("availability", lambda: check_cloudwatch_alarms(session)),
        ("availability", lambda: check_rds_backups(cache.rds_instances)),
        ("availability", lambda: check_rds_backup_retention(cache.rds_instances)),
        ("availability", lambda: check_rds_deletion_protection(cache.rds_instances)),
        ("availability", lambda: check_rds_auto_minor_version(cache.rds_instances)),

        # Confidentiality checks
        ("confidentiality", lambda: check_s3_public_access(session, cache.s3_buckets)),
        ("confidentiality", lambda: check_s3_encryption(session, cache.s3_buckets)),
        ("confidentiality", lambda: check_s3_versioning(session, cache.s3_buckets)),
        ("confidentiality", lambda: check_s3_logging(session, cache.s3_buckets)),
        ("confidentiality", lambda: check_s3_lifecycle(session, cache.s3_buckets)),
        ("confidentiality", lambda: check_rds_encryption(cache.rds_instances)),
        ("confidentiality", lambda: check_rds_public_access(cache.rds_instances)),
        ("confidentiality", lambda: check_kms_key_rotation(session)),

        # Processing integrity checks
        ("processing_integrity", lambda: check_cloudtrail_validation(cache.cloudtrail_trails)),
        ("processing_integrity", lambda: check_cloudtrail_multiregion(cache.cloudtrail_trails)),
        ("processing_integrity", lambda: check_cloudtrail_encryption(session, cache.cloudtrail_trails)),
        ("processing_integrity", lambda: check_cloudtrail_log_retention(session, cache.cloudtrail_trails)),
        ("processing_integrity", lambda: check_vpc_flow_logs(session, cache.vpcs)),
        ("processing_integrity", lambda: check_aws_config(session)),
        ("processing_integrity", lambda: check_cloudwatch_log_retention(session)),

        # Privacy checks
        ("privacy", lambda: check_password_policy(session)),
        ("privacy", lambda: check_macie_enabled(session)),
        ("privacy", lambda: check_s3_object_ownership(session, cache.s3_buckets)),
        ("privacy", lambda: check_no_overly_permissive_data_policies(session)),
    ]

    # Run checks in parallel with ThreadPoolExecutor
    # Use max_workers=10 for good parallelism without overwhelming AWS API
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all tasks - store original check function names for better error reporting
        future_to_check = {}
        for category, check_func in check_tasks:
            future = executor.submit(check_func)
            # Extract actual function name from lambda by inspecting its code
            actual_check_name = "Unknown Check"
            try:
                # Lambda functions contain the actual function call in their code
                # We can extract the function name from the lambda's code object
                if hasattr(check_func, '__code__'):
                    code = check_func.__code__
                    # Get the first constant which is usually the function being called
                    for const in code.co_consts:
                        if callable(const) and hasattr(const, '__name__'):
                            actual_check_name = const.__name__
                            break
            except Exception:
                pass
            future_to_check[future] = (category, check_func, actual_check_name)

        # Collect results as they complete
        for future in as_completed(future_to_check):
            category, check_func, actual_check_name = future_to_check[future]
            try:
                result = future.result()
                RESULT[category]["checks"].append(result)
            except Exception as e:
                # Handle different types of errors
                error_type = type(e).__name__
                error_message = str(e)

                # Check if it's a NoRegionError - specific handling for region configuration issues
                is_region_error = error_type == "NoRegionError" or "You must specify a region" in error_message

                # Check if it's a permission/access error
                is_permission_error = (
                    "AccessDenied" in error_message or
                    "UnauthorizedOperation" in error_message or
                    "AccessDeniedException" in error_message or
                    "Forbidden" in error_message or
                    error_type in ["ClientError", "NoCredentialsError", "CredentialRetrievalError"]
                )

                # Map of region-dependent checks
                region_dependent_checks = {
                    "check_cloudwatch_alarms": "CloudWatch Alarms",
                    "check_ebs_encryption": "EBS Encryption",
                    "check_public_instances": "Public EC2 Instances",
                    "check_security_group_rules": "Security Group Rules",
                    "check_default_security_groups": "Default Security Groups",
                    "check_instance_tagging": "EC2 Instance Tagging",
                    "check_vpc_flow_logs": "VPC Flow Logs",
                    "check_aws_config": "AWS Config",
                    "check_cloudtrail_encryption": "CloudTrail Log Encryption",
                    "check_cloudtrail_log_retention": "CloudTrail Log Retention"
                }

                # Get friendly check name
                friendly_check_name = region_dependent_checks.get(actual_check_name, actual_check_name.replace('check_', '').replace('_', ' ').title())

                if is_region_error:
                    # Provide specific guidance for region configuration
                    profile_name = session.profile_name if hasattr(session, 'profile_name') and session.profile_name else "default"
                    profile_config_example = f"[profile {profile_name}]" if profile_name != "default" else "[default]"

                    error_result = create_check_result(
                        name=f"Configuration Required: {friendly_check_name}",
                        description=f"This check requires a default AWS region to be configured in your profile",
                        status="WARNING",
                        severity="LOW",
                        details={
                            "error_type": error_type,
                            "error_message": error_message,
                            "category": category,
                            "check_name": actual_check_name,
                            "reason": "Regional AWS services require a default region to be specified in the AWS profile configuration"
                        },
                        recommendation=f"Configure a default region for the '{profile_name}' profile. Add 'region = us-east-1' (or your preferred region) to the profile section in ~/.aws/config. Example:\n\n{profile_config_example}\nregion = us-east-1\n\nAlternatively, set the AWS_DEFAULT_REGION environment variable."
                    )
                elif is_permission_error:
                    error_result = create_check_result(
                        name=f"Permission Error: {friendly_check_name}",
                        description="Unable to perform this check due to insufficient permissions",
                        status="WARNING",
                        severity="LOW",
                        details={
                            "error_type": error_type,
                            "error_message": error_message,
                            "category": category,
                            "check_name": actual_check_name,
                            "reason": "IAM permissions may be missing for this service/action"
                        },
                        recommendation="Grant necessary IAM permissions to perform this security check. Review AWS IAM policies for the account/role being used."
                    )
                else:
                    # Other types of errors
                    error_result = create_check_result(
                        name=f"Check Failed: {friendly_check_name}",
                        description=f"Check encountered an unexpected error: {error_message}",
                        status="WARNING",
                        severity="LOW",
                        details={
                            "error_type": error_type,
                            "error_message": error_message,
                            "category": category,
                            "check_name": actual_check_name
                        },
                        recommendation="Review error details and ensure AWS resources are accessible and properly configured."
                    )

                RESULT[category]["checks"].append(error_result)

    # Add summary statistics
    all_checks = (
        RESULT["security"]["checks"] +
        RESULT["availability"]["checks"] +
        RESULT["confidentiality"]["checks"] +
        RESULT["processing_integrity"]["checks"] +
        RESULT["privacy"]["checks"]
    )

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


def transform_to_presentation_format(raw_result):
    """Transform raw audit results into presentation format"""

    # Extract all checks
    all_checks = (
        raw_result["security"]["checks"] +
        raw_result["availability"]["checks"] +
        raw_result["confidentiality"]["checks"] +
        raw_result["processing_integrity"]["checks"] +
        raw_result["privacy"]["checks"]
    )

    summary = raw_result["metadata"]["summary"]

    # Calculate compliance score
    total_checks = summary["total_checks"]
    passed_checks = summary["passed"]
    overall_compliance_score = int((passed_checks / total_checks * 100)) if total_checks > 0 else 0
    compliance_score_text = passed_checks

    # Group failures by severity
    failed_checks = [c for c in all_checks if c["status"] == "FAIL"]
    critical_failures = [c for c in failed_checks if c["severity"] == "CRITICAL"]
    high_failures = [c for c in failed_checks if c["severity"] == "HIGH"]
    medium_failures = [c for c in failed_checks if c["severity"] == "MEDIUM"]
    low_failures = [c for c in failed_checks if c["severity"] == "LOW"]

    # Categorize by Trust Service Categories
    def get_category_status(category_name, checks):
        category_checks = [c for c in checks if c in raw_result.get(category_name, {}).get("checks", [])]
        if not category_checks:
            return "Unable to Access", "No checks performed"

        failed = [c for c in category_checks if c["status"] == "FAIL"]
        warnings = [c for c in category_checks if c["status"] == "WARNING"]

        if failed:
            # Get severity counts
            critical_count = len([c for c in failed if c["severity"] == "CRITICAL"])
            high_count = len([c for c in failed if c["severity"] == "HIGH"])

            issues_desc = f"{len(failed)} failed check(s)"
            if critical_count > 0:
                issues_desc += f" ({critical_count} critical)"
            if high_count > 0:
                issues_desc += f" ({high_count} high)"
            if warnings:
                issues_desc += f", {len(warnings)} warning(s)"

            return "Failed", issues_desc
        elif warnings:
            return "Warning", f"{len(warnings)} warning(s)"
        else:
            return "Passed", "All checks passed"

    # Build trust service categories
    security_status, security_issues = get_category_status("security", all_checks)
    availability_status, availability_issues = get_category_status("availability", all_checks)
    confidentiality_status, confidentiality_issues = get_category_status("confidentiality", all_checks)
    processing_integrity_status, processing_integrity_issues = get_category_status("processing_integrity", all_checks)
    privacy_status, privacy_issues = get_category_status("privacy", all_checks)

    # Build recommendations from failed checks and warnings
    immediate_recommendations = []
    urgent_recommendations = []
    long_term_recommendations = []

    # Critical failures -> Immediate
    for check in critical_failures:
        if check.get("recommendation"):
            immediate_recommendations.append({
                "action": check["check_name"],
                "description": check.get("recommendation", check["description"]),
                "action_button": "Apply",
                "check_details": check
            })

    # High failures -> Urgent
    for check in high_failures:
        if check.get("recommendation"):
            urgent_recommendations.append({
                "action": check["check_name"],
                "description": check.get("recommendation", check["description"]),
                "action_button": "Apply",
                "check_details": check
            })

    # Medium/Low failures and warnings -> Long-term
    for check in medium_failures + low_failures:
        if check.get("recommendation"):
            long_term_recommendations.append({
                "action": check["check_name"],
                "description": check.get("recommendation", check["description"]),
                "action_button": "Apply",
                "check_details": check
            })

    # Add warnings to long-term
    warning_checks = [c for c in all_checks if c["status"] == "WARNING" and c.get("recommendation")]
    for check in warning_checks:
        long_term_recommendations.append({
            "action": check["check_name"],
            "description": check.get("recommendation", check["description"]),
            "action_button": "Apply",
            "check_details": check
        })

    # Build risk summary
    risk_summary = []

    # Group failed checks by risk category
    auth_failures = [c for c in failed_checks if "MFA" in c["check_name"] or "root" in c["check_name"].lower()]
    if auth_failures:
        max_severity = "CRITICAL" if any(c["severity"] == "CRITICAL" for c in auth_failures) else "HIGH"
        risk_summary.append({
            "risk_category": "Authentication Controls",
            "severity": max_severity,
            "findings": f"{len(auth_failures)} issue(s)",
            "potential_impact": "Complete account compromise" if max_severity == "CRITICAL" else "Unauthorized access",
            "failed_checks": auth_failures
        })

    authorization_failures = [c for c in failed_checks if "policy" in c["check_name"].lower() or "permission" in c["check_name"].lower()]
    if authorization_failures:
        max_severity = "CRITICAL" if any(c["severity"] == "CRITICAL" for c in authorization_failures) else "HIGH"
        risk_summary.append({
            "risk_category": "Authorization & Privileges",
            "severity": max_severity,
            "findings": f"{len(authorization_failures)} issue(s)",
            "potential_impact": "Privilege escalation",
            "failed_checks": authorization_failures
        })

    data_failures = [c for c in failed_checks if "S3" in c["check_name"] or "encryption" in c["check_name"].lower() or "RDS" in c["check_name"]]
    warning_data = [c for c in all_checks if c["status"] == "WARNING" and ("S3" in c["check_name"] or "RDS" in c["check_name"])]
    if data_failures or warning_data:
        critical_count = len([c for c in data_failures if c["severity"] == "CRITICAL"])
        max_severity = "CRITICAL" if critical_count > 0 else "HIGH"
        findings_text = f"{len(data_failures)} failure(s)"
        if warning_data:
            findings_text += f", {len(warning_data)} warning(s)"
        risk_summary.append({
            "risk_category": "Data Confidentiality",
            "severity": max_severity,
            "findings": findings_text,
            "potential_impact": "Data exposure" if max_severity == "CRITICAL" else "Potential data leakage",
            "failed_checks": data_failures,
            "warning_checks": warning_data
        })

    audit_failures = [c for c in failed_checks if "cloudtrail" in c["check_name"].lower() or "log" in c["check_name"].lower() or "config" in c["check_name"].lower()]
    if audit_failures:
        max_severity = max([c["severity"] for c in audit_failures], key=lambda x: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x))
        risk_summary.append({
            "risk_category": "Audit & Compliance",
            "severity": max_severity,
            "findings": f"{len(audit_failures)} issue(s)",
            "potential_impact": "Inability to investigate incidents",
            "failed_checks": audit_failures
        })

    # Generate analysis text
    audit_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    aws_account = raw_result["metadata"].get("aws_account_id", "Unknown")

    current_state_summary = (
        f"This SOC 2 compliance audit was conducted on AWS account {aws_account} on {audit_date}. "
        f"The assessment evaluated your infrastructure against the five Trust Services Criteria that form the foundation of SOC 2 compliance: "
        f"Security, Availability, Processing Integrity, Confidentiality, and Privacy."
    )

    compliance_assessment = (
        f"The audit identified {len(failed_checks)} security gap(s) across {total_checks} checks performed. "
        f"Your current compliance score of {overall_compliance_score}% "
        + ("indicates strong security posture with minor improvements needed." if overall_compliance_score >= 80
           else "indicates substantial remediation work is required across multiple control categories." if overall_compliance_score >= 50
           else "indicates significant security improvements are required before achieving SOC 2 certification.")
    )

    # Determine compliance status
    if overall_compliance_score >= 90:
        compliance_status = "Meets threshold for SOC 2 Type I certification with minor improvements"
    elif overall_compliance_score >= 70:
        compliance_status = "Approaching SOC 2 readiness with targeted improvements needed"
    else:
        compliance_status = "Significantly below threshold required for SOC 2 Type I or Type II certification"

    # Generate conclusion
    conclusion_summary = (
        f"This comprehensive SOC 2 compliance audit reveals your AWS infrastructure "
        + ("demonstrates strong security posture. " if overall_compliance_score >= 80
           else "requires security improvements before pursuing formal certification. " if overall_compliance_score >= 50
           else "requires significant security improvements before pursuing formal certification. ")
        + f"With a current compliance score of {overall_compliance_score}%, "
        + ("you are well-positioned for SOC 2 certification." if overall_compliance_score >= 80
           else "you are progressing toward SOC 2 readiness." if overall_compliance_score >= 50
           else "you are at the beginning stages of the SOC 2 journey.")
    )

    critical_findings_text = ""
    if critical_failures:
        critical_findings_text = (
            f"The most critical findings include: {', '.join([c['check_name'] for c in critical_failures[:3]])}. "
            f"These issues must be remediated immediately as they represent significant security risks to your AWS infrastructure."
        )
    else:
        critical_findings_text = "No critical security vulnerabilities were identified during this audit."

    positive_notes = ""
    passed_checks_list = [c for c in all_checks if c["status"] == "PASS"]
    if passed_checks_list:
        positive_notes = (
            f"On a positive note, your environment demonstrates strong foundational security in {len(passed_checks_list)} area(s): "
            f"{', '.join([c['check_name'] for c in passed_checks_list[:5]])}."
        )

    timeline_to_compliance = ""
    if overall_compliance_score >= 80:
        timeline_to_compliance = "With focused effort on the identified gaps, your organization can realistically achieve SOC 2 compliance within 30 days."
    elif overall_compliance_score >= 60:
        timeline_to_compliance = "With focused effort on the identified gaps, your organization can realistically achieve SOC 2 compliance within 45-60 days."
    else:
        timeline_to_compliance = "With dedicated resources and focused effort, your organization can realistically achieve SOC 2 compliance within 60-90 days."

    # Build final presentation format
    presentation = {
        "audit_metadata": {
            "aws_account": aws_account,
            "audit_date": audit_date,
            "report_type": "SOC 2 Compliance Audit",
            "generated_at": raw_result["metadata"]["generated_at"],
            "aws_profile": raw_result["metadata"].get("aws_profile", "default")
        },
        "overview": {
            "overall_compliance_score": overall_compliance_score,
            "compliance_score_text": compliance_score_text,
            "total_failed_checks": len(failed_checks),
            "checks_with_critical_failure": len(critical_failures),
            "compliance_posture": {
                "passed": summary["passed"],
                "failed": summary["failed"],
                "warnings": summary["warnings"],
                "skipped": 0,  # Not applicable in current implementation
                "total_checks": total_checks
            },
            "failure_severity": {
                "critical": len(critical_failures),
                "high": len(high_failures),
                "medium": len(medium_failures),
                "low": len(low_failures),
                "total_failed": len(failed_checks)
            },
            "trust_service_categories": [
                {
                    "category": "Security",
                    "status": security_status,
                    "issues": security_issues,
                    "checks": raw_result["security"]["checks"]
                },
                {
                    "category": "Confidentiality",
                    "status": confidentiality_status,
                    "issues": confidentiality_issues,
                    "checks": raw_result["confidentiality"]["checks"]
                },
                {
                    "category": "Privacy",
                    "status": privacy_status,
                    "issues": privacy_issues,
                    "checks": raw_result["privacy"]["checks"]
                },
                {
                    "category": "Availability",
                    "status": availability_status,
                    "issues": availability_issues,
                    "checks": raw_result["availability"]["checks"]
                },
                {
                    "category": "Processing Integrity",
                    "status": processing_integrity_status,
                    "issues": processing_integrity_issues,
                    "checks": raw_result["processing_integrity"]["checks"]
                }
            ]
        },
        "recommendations": {
            "immediate": immediate_recommendations,
            "urgent": urgent_recommendations,
            "long_term": long_term_recommendations
        },
        "analysis": {
            "current_state": {
                "summary": current_state_summary,
                "compliance_assessment": compliance_assessment
            },
            "overall_compliance_status": {
                "compliance_percentage": overall_compliance_score,
                "controls_passing": passed_checks,
                "controls_total": total_checks,
                "failed_controls": len(failed_checks),
                "critical_severity_findings": len(critical_failures),
                "high_severity_findings": len(high_failures),
                "status": compliance_status
            },
            "risk_summary": risk_summary,
            "conclusion": {
                "summary": conclusion_summary,
                "critical_findings": critical_findings_text,
                "positive_notes": positive_notes,
                "timeline_to_compliance": timeline_to_compliance
            }
        },
        "raw_data": raw_result  # Preserve all original data
    }

    return presentation


def main():
    parser = argparse.ArgumentParser(description="Run SOC 2 compliance audit on AWS account")
    parser.add_argument(
        "--profile",
        "-p",
        type=str,
        help="AWS profile name to use (from ~/.aws/credentials or ~/.aws/config)",
        default=None
    )

    args = parser.parse_args()

    try:
        raw_report = run_soc2_audit(profile_name=args.profile)

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
    

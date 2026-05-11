import boto3
import argparse
import csv
import io
import sys
import time
from datetime import datetime, timezone, timedelta
import json
from botocore.config import Config
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed


# ===================== RESULT STRUCTURE =====================

def _make_result():
    """Create a fresh result structure for each audit run — avoids stale state across multiple calls."""
    return {
        "metadata": {
            "framework": "ISO/IEC 27001:2022",
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "a8_access_control": {
            "category_description": "Access control and identity management ensuring only authorized users can access resources",
            "controls": []
        },
        "a8_logging_monitoring": {
            "category_description": "Logging, monitoring, and detection capabilities to identify security incidents",
            "controls": []
        },
        "a8_data_protection": {
            "category_description": "Data encryption and protection mechanisms to ensure confidentiality",
            "controls": []
        },
        "a8_configuration_management": {
            "category_description": "Secure configuration and change management to maintain system integrity",
            "controls": []
        },
        "a8_cloud_security": {
            "category_description": "Information security controls specific to cloud service usage",
            "controls": []
        }
    }

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
    error_code = "Unknown"
    if isinstance(e, ClientError):
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
    return create_control_result(
        control_id, name, description,
        "WARNING", severity,
        {"error": error_code, "message": str(e)},
        f"Ensure the auditing role has permission to perform this check (error: {error_code})."
    )

def _get_enabled_regions(session):
    """Return all enabled AWS regions for the account."""
    try:
        ec2 = session.client("ec2")
        regions = ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )["Regions"]
        return [r["RegionName"] for r in regions]
    except Exception:
        return [session.region_name or "us-east-1"]


def _get_credential_report(iam):
    """Fetch IAM credential report as a list of row dicts. Generates it if needed.

    One API call returns all user data (MFA status, key ages, last login) — far
    faster than per-user get_login_profile / list_mfa_devices / list_access_keys loops.
    """
    for _ in range(12):  # poll up to ~24 s on first-ever generation
        state = iam.generate_credential_report().get("State", "STARTED")
        if state == "COMPLETE":
            break
        time.sleep(2)
    else:
        raise TimeoutError("IAM credential report did not become COMPLETE after 24 s")
    resp = iam.get_credential_report()
    content = resp["Content"]
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    return list(csv.DictReader(io.StringIO(content)))


# ===================== A.8.2 / A.8.5 — ACCESS CONTROL =====================

def check_root_mfa(session):
    """A.8.2 — MFA is enabled on the AWS root account."""
    try:
        iam = session.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1

        return create_control_result(
            "A.8.2",
            "Root Account MFA",
            "Verifies that MFA is enabled on the AWS root account",
            "PASS" if mfa_enabled else "FAIL",
            "CRITICAL",
            {"root_mfa_enabled": mfa_enabled},
            None if mfa_enabled else "Enable MFA on the root account immediately. Use a hardware MFA device for maximum security."
        )
    except Exception as e:
        return _warning("A.8.2", "Root Account MFA",
                        "Verifies that MFA is enabled on the AWS root account", "CRITICAL", e)

def check_iam_users_mfa(session):
    """A.8.2 — All IAM users with console access have MFA enabled."""
    try:
        iam = session.client("iam")
        report = _get_credential_report(iam)
        users_without_mfa = [
            row["user"] for row in report
            if row.get("user") != "<root_account>"
            and row.get("password_enabled") == "true"
            and row.get("mfa_active") == "false"
        ]
        return create_control_result(
            "A.8.2",
            "IAM Users MFA",
            "Ensures all IAM users with console access have MFA enabled",
            "PASS" if not users_without_mfa else "FAIL",
            "HIGH",
            {"users_without_mfa": users_without_mfa, "users_without_mfa_count": len(users_without_mfa)},
            None if not users_without_mfa else f"Enable MFA for {len(users_without_mfa)} user(s) without MFA: {', '.join(users_without_mfa[:5])}{'...' if len(users_without_mfa) > 5 else ''}."
        )
    except Exception as e:
        return _warning("A.8.2", "IAM Users MFA",
                        "Ensures all IAM users with console access have MFA enabled", "HIGH", e)


def check_root_no_active_keys(session):
    """A.8.2 — The root account has no active IAM access keys."""
    try:
        iam = session.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        keys_present = summary.get("AccountAccessKeysPresent", 0)

        return create_control_result(
            "A.8.2",
            "Root Account No Active Keys",
            "Verifies the root account has no active IAM access keys",
            "PASS" if keys_present == 0 else "FAIL",
            "CRITICAL",
            {"root_access_keys_present": keys_present},
            None if keys_present == 0 else "Delete all root account access keys immediately. Use IAM roles and users for all programmatic access."
        )
    except Exception as e:
        return _warning("A.8.2", "Root Account No Active Keys",
                        "Verifies the root account has no active IAM access keys", "CRITICAL", e)


def check_password_policy(session):
    """A.8.5 — Account password policy enforces minimum length, complexity, expiration, and reuse prevention."""
    try:
        iam = session.client("iam")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return create_control_result(
                    "A.8.5", "IAM Password Policy",
                    "Ensures the account password policy enforces strong credentials",
                    "FAIL", "MEDIUM",
                    {"policy_exists": False},
                    "Create an account password policy with minimum length 14, complexity requirements, 90-day expiry, and reuse prevention."
                )
            raise

        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append(f"minimum length {policy.get('MinimumPasswordLength', 0)} (require 14+)")
        if not policy.get("RequireSymbols", False):
            issues.append("symbols not required")
        if not policy.get("RequireNumbers", False):
            issues.append("numbers not required")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("uppercase not required")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("lowercase not required")
        max_age = policy.get("MaxPasswordAge", 0)
        if max_age == 0 or max_age > 90:
            issues.append(f"expiry {'never' if max_age == 0 else f'{max_age} days'} (require ≤90 days)")
        reuse = policy.get("PasswordReusePrevention", 0)
        if reuse < 5:
            issues.append(f"reuse prevention {reuse} (require 5+)")

        return create_control_result(
            "A.8.5", "IAM Password Policy",
            "Ensures the account password policy enforces strong credentials",
            "PASS" if not issues else "FAIL",
            "MEDIUM",
            {"policy": policy, "issues": issues, "issues_count": len(issues)},
            None if not issues else f"Update the password policy to fix: {'; '.join(issues)}."
        )
    except Exception as e:
        return _warning("A.8.5", "IAM Password Policy",
                        "Ensures the account password policy enforces strong credentials", "MEDIUM", e)


def check_access_key_rotation(session):
    """A.8.5 — No active IAM access keys are older than 90 days."""
    try:
        iam = session.client("iam")
        report = _get_credential_report(iam)
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        stale_keys = []

        for row in report:
            if row.get("user") == "<root_account>":
                continue
            username = row["user"]
            for key_num in ("1", "2"):
                active = row.get(f"access_key_{key_num}_active") == "true"
                rotated_str = row.get(f"access_key_{key_num}_last_rotated", "N/A")
                if active and rotated_str not in ("N/A", "no_information", ""):
                    rotated = datetime.fromisoformat(rotated_str.replace("Z", "+00:00"))
                    if rotated < cutoff:
                        stale_keys.append({
                            "user": username,
                            "key_number": key_num,
                            "age_days": (datetime.now(timezone.utc) - rotated).days,
                        })

        return create_control_result(
            "A.8.5", "IAM Access Key Rotation",
            "Ensures no active IAM access keys are older than 90 days",
            "PASS" if not stale_keys else "FAIL",
            "HIGH",
            {"stale_keys": stale_keys, "stale_keys_count": len(stale_keys)},
            None if not stale_keys else f"Rotate {len(stale_keys)} access key(s) older than 90 days."
        )
    except Exception as e:
        return _warning("A.8.5", "IAM Access Key Rotation",
                        "Ensures no active IAM access keys are older than 90 days", "HIGH", e)


# ===================== A.8.15 / A.8.16 — LOGGING & MONITORING =====================

def check_cloudtrail_enabled(session):
    """A.8.15 — At least one multi-region CloudTrail trail is actively logging."""
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

        multi_region_active = []
        for trail in trails:
            if trail.get("IsMultiRegionTrail", False):
                try:
                    status = ct.get_trail_status(Name=trail["TrailARN"])
                    if status.get("IsLogging", False):
                        multi_region_active.append(trail["Name"])
                except Exception:
                    pass

        has_multi_region = len(multi_region_active) > 0
        return create_control_result(
            "A.8.15",
            "CloudTrail Multi-Region",
            "Ensures at least one multi-region CloudTrail trail is actively logging",
            "PASS" if has_multi_region else "FAIL",
            "CRITICAL",
            {
                "total_trails": len(trails),
                "multi_region_active_trails": multi_region_active,
                "multi_region_active_count": len(multi_region_active),
            },
            None if has_multi_region else "Enable a multi-region CloudTrail trail to capture API activity across all AWS regions."
        )
    except Exception as e:
        return _warning("A.8.15", "CloudTrail Multi-Region",
                        "Ensures at least one multi-region CloudTrail trail is actively logging", "CRITICAL", e)

def check_cloudtrail_log_validation(session):
    """A.8.15 — All CloudTrail trails have log file integrity validation enabled."""
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

        if not trails:
            return create_control_result(
                "A.8.15", "CloudTrail Log File Validation",
                "Ensures CloudTrail log file integrity validation is enabled on all trails",
                "FAIL", "HIGH",
                {"total_trails": 0},
                "Enable CloudTrail with log file integrity validation to detect tampering."
            )

        trails_without_validation = [
            t["Name"] for t in trails if not t.get("LogFileValidationEnabled", False)
        ]
        return create_control_result(
            "A.8.15", "CloudTrail Log File Validation",
            "Ensures CloudTrail log file integrity validation is enabled on all trails",
            "PASS" if not trails_without_validation else "FAIL",
            "HIGH",
            {
                "total_trails": len(trails),
                "trails_without_validation": trails_without_validation,
                "trails_without_validation_count": len(trails_without_validation),
            },
            None if not trails_without_validation else f"Enable log file validation on {len(trails_without_validation)} trail(s): {', '.join(trails_without_validation)}."
        )
    except Exception as e:
        return _warning("A.8.15", "CloudTrail Log File Validation",
                        "Ensures CloudTrail log file integrity validation is enabled on all trails", "HIGH", e)


def check_cloudtrail_encryption(session):
    """A.8.15 — All CloudTrail trails encrypt logs with a KMS customer-managed key."""
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

        if not trails:
            return create_control_result(
                "A.8.15", "CloudTrail Log Encryption",
                "Ensures CloudTrail logs are encrypted with a KMS customer-managed key",
                "FAIL", "MEDIUM",
                {"total_trails": 0},
                "Enable CloudTrail with KMS log encryption."
            )

        trails_without_kms = [
            t["Name"] for t in trails if not t.get("KMSKeyId")
        ]
        return create_control_result(
            "A.8.15", "CloudTrail Log Encryption",
            "Ensures CloudTrail logs are encrypted with a KMS customer-managed key",
            "PASS" if not trails_without_kms else "FAIL",
            "MEDIUM",
            {
                "total_trails": len(trails),
                "trails_without_kms_encryption": trails_without_kms,
                "trails_without_kms_count": len(trails_without_kms),
            },
            None if not trails_without_kms else f"Enable KMS encryption on {len(trails_without_kms)} trail(s): {', '.join(trails_without_kms)}."
        )
    except Exception as e:
        return _warning("A.8.15", "CloudTrail Log Encryption",
                        "Ensures CloudTrail logs are encrypted with a KMS customer-managed key", "MEDIUM", e)


def check_cloudtrail_s3_not_public(session):
    """A.8.15 — The S3 bucket storing CloudTrail logs is not publicly accessible."""
    try:
        ct = session.client("cloudtrail")
        s3 = session.client("s3")
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

        if not trails:
            return create_control_result(
                "A.8.15", "CloudTrail S3 Bucket Not Public",
                "Ensures the S3 bucket storing CloudTrail logs is not publicly accessible",
                "FAIL", "HIGH",
                {"total_trails": 0},
                "Enable CloudTrail and ensure its S3 bucket blocks all public access."
            )

        public_buckets = []
        inaccessible_buckets = []
        checked_buckets = set()
        for trail in trails:
            bucket = trail.get("S3BucketName")
            if not bucket or bucket in checked_buckets:
                continue
            checked_buckets.add(bucket)
            try:
                block = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                if not all([
                    block.get("BlockPublicAcls", False),
                    block.get("IgnorePublicAcls", False),
                    block.get("BlockPublicPolicy", False),
                    block.get("RestrictPublicBuckets", False),
                ]):
                    public_buckets.append(bucket)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "NoSuchPublicAccessBlockConfiguration":
                    public_buckets.append(bucket)
                elif code in ("AccessDenied", "AccessDeniedException"):
                    # Record and continue — don't let one inaccessible bucket
                    # hide the compliance status of the remaining buckets
                    inaccessible_buckets.append(bucket)
                else:
                    raise

        details = {
            "buckets_checked": list(checked_buckets),
            "public_buckets": public_buckets,
            "public_buckets_count": len(public_buckets),
        }
        if inaccessible_buckets:
            details["inaccessible_buckets"] = inaccessible_buckets
            details["inaccessible_buckets_count"] = len(inaccessible_buckets)

        return create_control_result(
            "A.8.15", "CloudTrail S3 Bucket Not Public",
            "Ensures the S3 bucket storing CloudTrail logs is not publicly accessible",
            "PASS" if not public_buckets else "FAIL",
            "HIGH",
            details,
            None if not public_buckets else f"Enable full public access block on CloudTrail S3 bucket(s): {', '.join(public_buckets)}."
        )
    except Exception as e:
        return _warning("A.8.15", "CloudTrail S3 Bucket Not Public",
                        "Ensures the S3 bucket storing CloudTrail logs is not publicly accessible", "HIGH", e)


def check_vpc_flow_logs(session, regions=None):
    """A.8.15 — All VPCs across all regions have flow logs enabled."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        def _check_region(region):
            try:
                ec2 = session.client("ec2", region_name=region)
                vpcs = ec2.describe_vpcs()["Vpcs"]
                if not vpcs:
                    return [], 0
                vpc_ids = [v["VpcId"] for v in vpcs]
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": vpc_ids}]
                )["FlowLogs"]
                monitored = {fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"}
                missing = [
                    {"vpc_id": v["VpcId"], "region": region, "is_default": v.get("IsDefault", False)}
                    for v in vpcs if v["VpcId"] not in monitored
                ]
                return missing, len(vpcs)
            except ClientError:
                return [], 0

        vpcs_without_logs = []
        total_vpcs = 0
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for missing, count in pool.map(_check_region, regions):
                vpcs_without_logs.extend(missing)
                total_vpcs += count

        return create_control_result(
            "A.8.15", "VPC Flow Logs",
            "Ensures all VPCs have flow logs enabled for network traffic monitoring",
            "PASS" if not vpcs_without_logs else "FAIL",
            "MEDIUM",
            {
                "regions_checked": len(regions),
                "total_vpcs": total_vpcs,
                "vpcs_without_flow_logs": vpcs_without_logs,
                "vpcs_without_flow_logs_count": len(vpcs_without_logs),
            },
            None if not vpcs_without_logs else f"Enable VPC flow logs on {len(vpcs_without_logs)} VPC(s) across {len({v['region'] for v in vpcs_without_logs})} region(s)."
        )
    except Exception as e:
        return _warning("A.8.15", "VPC Flow Logs",
                        "Ensures all VPCs have flow logs enabled for network traffic monitoring", "MEDIUM", e)


def check_guardduty_enabled(session, regions=None):
    """A.8.16 — GuardDuty threat detection is active in all regions."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)
        def _check_region(region):
            try:
                gd = session.client("guardduty", region_name=region)
                return region if not gd.list_detectors()["DetectorIds"] else None
            except ClientError:
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            regions_without_guardduty = [r for r in pool.map(_check_region, regions) if r is not None]

        return create_control_result(
            "A.8.16",
            "GuardDuty Enabled",
            "Ensures GuardDuty threat detection is active in all regions",
            "PASS" if not regions_without_guardduty else "FAIL",
            "CRITICAL",
            {
                "regions_checked": len(regions),
                "regions_without_guardduty": regions_without_guardduty,
                "regions_without_guardduty_count": len(regions_without_guardduty),
            },
            None if not regions_without_guardduty else f"Enable GuardDuty in {len(regions_without_guardduty)} region(s): {', '.join(regions_without_guardduty)}."
        )
    except Exception as e:
        return _warning("A.8.16", "GuardDuty Enabled",
                        "Ensures GuardDuty threat detection is active in all regions", "CRITICAL", e)

# ===================== A.8.24 — DATA PROTECTION =====================

def check_rds_encryption(session, regions=None):
    """A.8.24 — All RDS instances across all regions have storage encryption enabled."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)
        def _check_region(region):
            try:
                rds = session.client("rds", region_name=region)
                paginator = rds.get_paginator("describe_db_instances")
                return [
                    {"instance": db["DBInstanceIdentifier"], "region": region}
                    for page in paginator.paginate()
                    for db in page["DBInstances"]
                    if not db["StorageEncrypted"]
                ]
            except ClientError:
                return []

        unencrypted = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for region_result in pool.map(_check_region, regions):
                unencrypted.extend(region_result)

        return create_control_result(
            "A.8.24",
            "RDS Encryption at Rest",
            "Ensures all RDS database instances have storage encryption enabled",
            "PASS" if not unencrypted else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "unencrypted_instances": unencrypted,
                "unencrypted_count": len(unencrypted),
            },
            None if not unencrypted else f"Enable encryption on {len(unencrypted)} unencrypted RDS instance(s). Encryption must be enabled at creation time — migrate data to a new encrypted instance."
        )
    except Exception as e:
        return _warning("A.8.24", "RDS Encryption at Rest",
                        "Ensures all RDS database instances have storage encryption enabled", "HIGH", e)

def check_s3_encryption(session):
    """A.8.24 — All S3 buckets have default encryption enabled."""
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets()["Buckets"]

        if not buckets:
            return create_control_result(
                "A.8.24", "S3 Bucket Encryption",
                "Ensures all S3 buckets have default encryption enabled",
                "PASS", "HIGH",
                {"total_buckets": 0},
            )

        unencrypted = []
        for bucket in buckets:
            name = bucket["Name"]
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    unencrypted.append(name)
                else:
                    raise

        return create_control_result(
            "A.8.24", "S3 Bucket Encryption",
            "Ensures all S3 buckets have default encryption enabled",
            "PASS" if not unencrypted else "FAIL",
            "HIGH",
            {"total_buckets": len(buckets), "unencrypted_buckets": unencrypted, "unencrypted_count": len(unencrypted)},
            None if not unencrypted else f"Enable default encryption on {len(unencrypted)} bucket(s): {', '.join(unencrypted[:5])}{'...' if len(unencrypted) > 5 else ''}."
        )
    except Exception as e:
        return _warning("A.8.24", "S3 Bucket Encryption",
                        "Ensures all S3 buckets have default encryption enabled", "HIGH", e)


def check_s3_public_access_block(session):
    """A.8.24 — The account-level S3 public access block is fully enabled."""
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        s3control = session.client("s3control")
        try:
            block = s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return create_control_result(
                    "A.8.24", "S3 Public Access Block",
                    "Ensures the account-level S3 public access block is fully enabled",
                    "FAIL", "CRITICAL",
                    {"account_level_block_configured": False},
                    "Enable all four account-level S3 public access block settings to prevent accidental public exposure of S3 data."
                )
            raise

        flags = {
            "BlockPublicAcls": block.get("BlockPublicAcls", False),
            "IgnorePublicAcls": block.get("IgnorePublicAcls", False),
            "BlockPublicPolicy": block.get("BlockPublicPolicy", False),
            "RestrictPublicBuckets": block.get("RestrictPublicBuckets", False),
        }
        disabled = [k for k, v in flags.items() if not v]

        return create_control_result(
            "A.8.24", "S3 Public Access Block",
            "Ensures the account-level S3 public access block is fully enabled",
            "PASS" if not disabled else "FAIL",
            "CRITICAL",
            {"flags": flags, "disabled_flags": disabled},
            None if not disabled else f"Enable the following account-level S3 public access block flags: {', '.join(disabled)}."
        )
    except Exception as e:
        return _warning("A.8.24", "S3 Public Access Block",
                        "Ensures the account-level S3 public access block is fully enabled", "CRITICAL", e)


def check_ebs_default_encryption(session, regions=None):
    """A.8.24 — Default EBS encryption is enabled in all regions."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)
        def _check_region(region):
            try:
                ec2 = session.client("ec2", region_name=region)
                return region if not ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] else None
            except ClientError:
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            regions_without_encryption = [r for r in pool.map(_check_region, regions) if r is not None]

        return create_control_result(
            "A.8.24", "EBS Default Encryption",
            "Ensures default EBS encryption is enabled in all regions",
            "PASS" if not regions_without_encryption else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_encryption": regions_without_encryption,
                "regions_without_encryption_count": len(regions_without_encryption),
            },
            None if not regions_without_encryption else f"Enable default EBS encryption in {len(regions_without_encryption)} region(s): {', '.join(regions_without_encryption)}."
        )
    except Exception as e:
        return _warning("A.8.24", "EBS Default Encryption",
                        "Ensures default EBS encryption is enabled in all regions", "HIGH", e)


def check_kms_key_rotation(session):
    """A.8.24 — All customer-managed KMS keys have automatic annual rotation enabled."""
    try:
        # Shared across up to 10 concurrent threads — raise pool above the default 10
        kms = session.client("kms", config=Config(max_pool_connections=25))
        paginator = kms.get_paginator("list_keys")
        all_key_ids = [k["KeyId"] for page in paginator.paginate() for k in page["Keys"]]

        def _check_key(key_id):
            try:
                meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
                    return None
                if not kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"]:
                    return {"key_id": key_id, "key_alias": meta.get("Description", "")}
            except ClientError:
                pass  # Skip keys we cannot inspect (e.g. pending deletion)
            return None

        keys_without_rotation = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(all_key_ids), 10))) as pool:
            for result in pool.map(_check_key, all_key_ids):
                if result:
                    keys_without_rotation.append(result)

        return create_control_result(
            "A.8.24", "KMS Key Rotation",
            "Ensures all customer-managed KMS keys have automatic annual rotation enabled",
            "PASS" if not keys_without_rotation else "FAIL",
            "MEDIUM",
            {"keys_without_rotation": keys_without_rotation, "keys_without_rotation_count": len(keys_without_rotation)},
            None if not keys_without_rotation else f"Enable automatic rotation on {len(keys_without_rotation)} KMS key(s)."
        )
    except Exception as e:
        return _warning("A.8.24", "KMS Key Rotation",
                        "Ensures all customer-managed KMS keys have automatic annual rotation enabled", "MEDIUM", e)


# ===================== A.8.9 — CONFIGURATION MANAGEMENT =====================

def check_config_enabled(session, regions=None):
    """A.8.9 — AWS Config is recording configuration changes in all regions."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)
        def _check_region(region):
            try:
                config = session.client("config", region_name=region)
                statuses = config.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
                return region if not any(s.get("recording", False) for s in statuses) else None
            except ClientError:
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            regions_without_config = [r for r in pool.map(_check_region, regions) if r is not None]

        return create_control_result(
            "A.8.9",
            "AWS Config Enabled",
            "Ensures AWS Config is recording resource configuration changes in all regions",
            "PASS" if not regions_without_config else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_config": regions_without_config,
                "regions_without_config_count": len(regions_without_config),
            },
            None if not regions_without_config else f"Enable AWS Config in {len(regions_without_config)} region(s): {', '.join(regions_without_config)}."
        )
    except Exception as e:
        return _warning("A.8.9", "AWS Config Enabled",
                        "Ensures AWS Config is recording resource configuration changes in all regions", "HIGH", e)

def check_ec2_imdsv2(session, regions=None):
    """A.8.9 — All running EC2 instances across all regions require IMDSv2."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)
        def _check_region(region):
            try:
                ec2 = session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_instances")
                found = []
                for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                    for reservation in page["Reservations"]:
                        for instance in reservation["Instances"]:
                            metadata_options = instance.get("MetadataOptions", {})
                            if metadata_options.get("HttpTokens") != "required":
                                name = next(
                                    (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                                    instance["InstanceId"]
                                )
                                found.append({
                                    "instance_id": instance["InstanceId"],
                                    "name": name,
                                    "region": region,
                                    "http_tokens": metadata_options.get("HttpTokens", "optional"),
                                })
                return found
            except ClientError:
                return []

        instances_without_imdsv2 = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for region_result in pool.map(_check_region, regions):
                instances_without_imdsv2.extend(region_result)

        return create_control_result(
            "A.8.9", "EC2 IMDSv2 Enforcement",
            "Ensures all running EC2 instances require IMDSv2 to prevent SSRF-based credential theft",
            "PASS" if not instances_without_imdsv2 else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "instances_without_imdsv2": instances_without_imdsv2,
                "instances_without_imdsv2_count": len(instances_without_imdsv2),
            },
            None if not instances_without_imdsv2 else f"Enforce IMDSv2 on {len(instances_without_imdsv2)} instance(s) by setting HttpTokens to 'required'."
        )
    except Exception as e:
        return _warning("A.8.9", "EC2 IMDSv2 Enforcement",
                        "Ensures all running EC2 instances require IMDSv2 to prevent SSRF-based credential theft", "HIGH", e)


def check_security_group_unrestricted(session, regions=None):
    """A.8.20 — No security groups across all regions allow unrestricted inbound access on SSH (22) or RDP (3389)."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)
        sensitive_ports = {22, 3389}

        def _check_region(region):
            try:
                ec2 = session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_security_groups")
                found = []
                for page in paginator.paginate():
                    for sg in page["SecurityGroups"]:
                        for rule in sg.get("IpPermissions", []):
                            from_port = rule.get("FromPort", 0)
                            to_port = rule.get("ToPort", 65535)
                            if not any(from_port <= p <= to_port for p in sensitive_ports):
                                continue
                            open_cidrs = [r["CidrIp"] for r in rule.get("IpRanges", []) if r["CidrIp"] == "0.0.0.0/0"]
                            open_ipv6 = [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", []) if r["CidrIpv6"] == "::/0"]
                            if open_cidrs or open_ipv6:
                                found.append({
                                    "security_group_id": sg["GroupId"],
                                    "security_group_name": sg["GroupName"],
                                    "region": region,
                                    "port_range": f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                                    "open_to": open_cidrs + open_ipv6,
                                })
                return found
            except ClientError:
                return []

        open_rules = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for region_result in pool.map(_check_region, regions):
                open_rules.extend(region_result)

        return create_control_result(
            "A.8.20", "Security Group Unrestricted Access",
            "Ensures no security groups allow unrestricted inbound access on SSH (22) or RDP (3389)",
            "PASS" if not open_rules else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "open_rules": open_rules,
                "open_rules_count": len(open_rules),
            },
            None if not open_rules else f"Restrict {len(open_rules)} security group rule(s) across {len({r['region'] for r in open_rules})} region(s) — replace 0.0.0.0/0 with specific trusted IP ranges."
        )
    except Exception as e:
        return _warning("A.8.20", "Security Group Unrestricted Access",
                        "Ensures no security groups allow unrestricted inbound access on SSH (22) or RDP (3389)", "HIGH", e)


# ===================== A.8.23 — CLOUD SECURITY =====================

def check_scp_usage(session):
    """A.8.23 — AWS Organizations Service Control Policies are in use."""
    try:
        org = session.client("organizations")
        scps = org.list_policies(Filter="SERVICE_CONTROL_POLICY")["Policies"]
        # Exclude the default FullAWSAccess SCP that AWS attaches automatically
        custom_scps = [p for p in scps if p["Name"] != "FullAWSAccess"]
        enabled = len(custom_scps) > 0

        return create_control_result(
            "A.8.23",
            "Service Control Policies",
            "Ensures AWS Organizations Service Control Policies enforce security guardrails",
            "PASS" if enabled else "FAIL",
            "MEDIUM",
            {"total_scps": len(scps), "custom_scp_count": len(custom_scps)},
            None if enabled else "Create and attach Service Control Policies to enforce security guardrails across the organization."
        )
    except Exception as e:
        return _warning("A.8.23", "Service Control Policies",
                        "Ensures AWS Organizations Service Control Policies enforce security guardrails", "MEDIUM", e)

# ===================== A.8.16 — SECURITY HUB & CLOUDWATCH ALARMS =====================

def check_securityhub_enabled(session, regions=None):
    """A.8.16 — AWS Security Hub is enabled in all active regions."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)
        regions_without_hub = []

        def _check_region(region):
            try:
                hub = session.client("securityhub", region_name=region)
                hub.describe_hub()
                return None
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("InvalidAccessException", "ResourceNotFoundException"):
                    return region
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError"):
                    raise
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 15))) as pool:
            for result in pool.map(_check_region, regions):
                if result:
                    regions_without_hub.append(result)

        return create_control_result(
            "A.8.16",
            "Security Hub Enabled",
            "Verifies AWS Security Hub is enabled across all active regions for centralised findings",
            "PASS" if not regions_without_hub else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_hub_count": len(regions_without_hub),
                "regions_without_hub": regions_without_hub,
            },
            None if not regions_without_hub else (
                f"Enable AWS Security Hub in {len(regions_without_hub)} region(s): "
                f"{', '.join(regions_without_hub[:5])}{'...' if len(regions_without_hub) > 5 else ''}. "
                "Use the Security Hub console or run: aws securityhub enable-security-hub --enable-default-standards"
            ),
        )
    except Exception as e:
        return _warning("A.8.16", "Security Hub Enabled",
                        "Verifies AWS Security Hub is enabled across all active regions", "HIGH", e)


def check_cloudwatch_alarms(session):
    """A.8.16 — CloudWatch metric alarms exist for critical security events."""
    _REQUIRED_PATTERNS = [
        ("root_login", ["RootAccount", "Root", "root_login", "root-login"]),
        ("unauthorized_api", ["UnauthorizedAPI", "unauthorized-api", "UnauthorizedAPICalls"]),
        ("sg_changes", ["SecurityGroupChanges", "security-group-changes", "SGChanges"]),
        ("mfa_disable", ["MFADisable", "mfa-disable", "DisableMFA", "NoMFA"]),
    ]
    try:
        cw = session.client("cloudwatch")
        paginator = cw.get_paginator("describe_alarms")
        all_alarm_names = []
        for page in paginator.paginate():
            all_alarm_names.extend(a["AlarmName"] for a in page.get("MetricAlarms", []))

        missing = []
        for label, patterns in _REQUIRED_PATTERNS:
            matched = any(
                any(p.lower() in name.lower() for p in patterns)
                for name in all_alarm_names
            )
            if not matched:
                missing.append(label)

        return create_control_result(
            "A.8.16",
            "CloudWatch Security Alarms",
            "Ensures CloudWatch alarms exist for root login, unauthorized API calls, security group changes, and MFA disable events",
            "PASS" if not missing else "FAIL",
            "MEDIUM",
            {
                "total_alarms": len(all_alarm_names),
                "missing_alarm_categories": missing,
                "missing_count": len(missing),
                "naming_note": (
                    "Detection uses substring matching against common alarm name patterns "
                    "(e.g. 'RootAccount', 'UnauthorizedAPI'). Alarms using non-standard "
                    "naming conventions may be present but not detected. Review manually "
                    "if your organization uses custom alarm names."
                ),
            },
            None if not missing else (
                f"Create CloudWatch metric alarms for: {', '.join(missing)}. "
                "Use CloudTrail log metric filters to detect these events and alert via SNS."
            ),
        )
    except Exception as e:
        return _warning("A.8.16", "CloudWatch Security Alarms",
                        "Ensures CloudWatch alarms exist for critical security events", "MEDIUM", e)


# ===================== A.8.24 — DATA PROTECTION: RDS PUBLIC ACCESS & ACM EXPIRY =====================

def check_rds_publicly_accessible(session, regions=None):
    """A.8.24 — No RDS instances are configured as publicly accessible."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)
        public_instances = []

        def _check_region(region):
            found = []
            try:
                rds = session.client("rds", region_name=region)
                paginator = rds.get_paginator("describe_db_instances")
                for page in paginator.paginate():
                    for db in page["DBInstances"]:
                        if db.get("PubliclyAccessible", False):
                            found.append({
                                "instance": db["DBInstanceIdentifier"],
                                "region": region,
                                "engine": db.get("Engine", "unknown"),
                            })
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                    raise
            return found

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 15))) as pool:
            for region_results in pool.map(_check_region, regions):
                public_instances.extend(region_results)

        return create_control_result(
            "A.8.24",
            "RDS Publicly Accessible",
            "Verifies no RDS instances are publicly accessible from the internet",
            "PASS" if not public_instances else "FAIL",
            "HIGH",
            {
                "public_instances_count": len(public_instances),
                "public_instances": public_instances,
                "regions_checked": len(regions),
            },
            None if not public_instances else (
                f"Disable public accessibility on {len(public_instances)} RDS instance(s). "
                "Use VPC security groups and private subnets; access via bastion hosts or VPN."
            ),
        )
    except Exception as e:
        return _warning("A.8.24", "RDS Publicly Accessible",
                        "Verifies no RDS instances are publicly accessible from the internet", "HIGH", e)


def check_acm_certificate_expiry(session, regions=None):
    """A.8.24 — No ACM certificates are expiring within 30 days."""
    _EXPIRY_DAYS = 30
    try:
        if regions is None:
            regions = _get_enabled_regions(session)
        expiring_certs = []
        now = datetime.now(timezone.utc)
        threshold = now + timedelta(days=_EXPIRY_DAYS)

        def _check_region(region):
            found = []
            try:
                acm = session.client("acm", region_name=region)
                paginator = acm.get_paginator("list_certificates")
                arns = []
                for page in paginator.paginate(CertificateStatuses=["ISSUED"]):
                    arns.extend(c["CertificateArn"] for c in page.get("CertificateSummaryList", []))

                def _describe(arn):
                    detail = acm.describe_certificate(CertificateArn=arn)["Certificate"]
                    expiry = detail.get("NotAfter")
                    if expiry and expiry <= threshold:
                        return {
                            "arn": arn,
                            "domain": detail.get("DomainName", "unknown"),
                            "expires_at": expiry.isoformat(),
                            "days_remaining": (expiry - now).days,
                            "region": region,
                        }
                    return None

                if arns:
                    with ThreadPoolExecutor(max_workers=max(1, min(len(arns), 10))) as inner_pool:
                        for cert in inner_pool.map(_describe, arns):
                            if cert:
                                found.append(cert)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                    raise
            return found

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 15))) as pool:
            for region_results in pool.map(_check_region, regions):
                expiring_certs.extend(region_results)

        return create_control_result(
            "A.8.24",
            "ACM Certificate Expiry",
            f"Verifies no ACM certificates are expiring within {_EXPIRY_DAYS} days",
            "PASS" if not expiring_certs else "FAIL",
            "HIGH",
            {
                "expiring_within_days": _EXPIRY_DAYS,
                "expiring_count": len(expiring_certs),
                "expiring_certificates": expiring_certs,
                "regions_checked": len(regions),
            },
            None if not expiring_certs else (
                f"Renew {len(expiring_certs)} ACM certificate(s) expiring within {_EXPIRY_DAYS} days. "
                "Enable ACM auto-renewal for certificates validated via DNS."
            ),
        )
    except Exception as e:
        return _warning("A.8.24", "ACM Certificate Expiry",
                        f"Verifies no ACM certificates are expiring within {_EXPIRY_DAYS} days", "HIGH", e)


# ===================== A.8.2 — ACCESS CONTROL: IAM ADMINS & UNUSED CREDENTIALS =====================

def check_iam_admin_policies(session):
    """A.8.2 — No IAM users or roles have full admin (*:*) policies attached directly."""
    try:
        # Shared across up to 10 concurrent threads — raise pool above the default 10
        iam = session.client("iam", config=Config(max_pool_connections=25))

        def _check_user(user):
            findings = []
            username = user["UserName"]
            attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
            for pol in attached:
                if pol["PolicyName"] == "AdministratorAccess":
                    findings.append({"type": "user", "name": username, "policy": pol["PolicyName"]})
            for pname in iam.list_user_policies(UserName=username)["PolicyNames"]:
                doc = iam.get_user_policy(UserName=username, PolicyName=pname)["PolicyDocument"]
                if _has_admin_statement(doc):
                    findings.append({"type": "user", "name": username, "policy": pname, "inline": True})
            return findings

        def _check_role(role):
            findings = []
            if role.get("Path", "").startswith("/aws-service-role/"):
                return findings
            rname = role["RoleName"]
            attached = iam.list_attached_role_policies(RoleName=rname)["AttachedPolicies"]
            for pol in attached:
                if pol["PolicyName"] == "AdministratorAccess":
                    findings.append({"type": "role", "name": rname, "policy": pol["PolicyName"]})
            for pname in iam.list_role_policies(RoleName=rname)["PolicyNames"]:
                doc = iam.get_role_policy(RoleName=rname, PolicyName=pname)["PolicyDocument"]
                if _has_admin_statement(doc):
                    findings.append({"type": "role", "name": rname, "policy": pname, "inline": True})
            return findings

        all_users = [u for page in iam.get_paginator("list_users").paginate() for u in page["Users"]]
        all_roles = [r for page in iam.get_paginator("list_roles").paginate() for r in page["Roles"]]

        admin_principals = []
        with ThreadPoolExecutor(max_workers=10) as pool:
            for result in pool.map(_check_user, all_users):
                admin_principals.extend(result)
            for result in pool.map(_check_role, all_roles):
                admin_principals.extend(result)

        return create_control_result(
            "A.8.2",
            "IAM Admin Policies",
            "Verifies no users or roles have AdministratorAccess or inline *:* policies attached",
            "PASS" if not admin_principals else "FAIL",
            "HIGH",
            {
                "admin_principals_count": len(admin_principals),
                "admin_principals": admin_principals[:20],  # cap list length
            },
            None if not admin_principals else (
                f"Review and remove full admin access from {len(admin_principals)} principal(s). "
                "Apply least-privilege IAM policies. Use Permission Boundaries for delegated administration."
            ),
        )
    except Exception as e:
        return _warning("A.8.2", "IAM Admin Policies",
                        "Verifies no users or roles have AdministratorAccess or inline *:* policies", "HIGH", e)


def _has_admin_statement(policy_doc):
    """Return True if an IAM policy document grants Action=* on Resource=*."""
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
        if "*" in actions and "*" in resources:
            return True
    return False


def check_unused_iam_credentials(session):
    """A.8.2 — IAM users with console access have logged in within the last 90 days."""
    _STALE_DAYS = 90
    try:
        iam = session.client("iam")
        report = _get_credential_report(iam)
        threshold = datetime.now(timezone.utc) - timedelta(days=_STALE_DAYS)
        stale_users = []

        for row in report:
            if row.get("user") == "<root_account>":
                continue
            if row.get("password_enabled") != "true":
                continue  # programmatic-only user, skip
            username = row["user"]
            last_used_str = row.get("password_last_used", "N/A")
            if last_used_str in ("N/A", "no_information", ""):
                stale_users.append({"username": username, "last_login": None, "days_inactive": None})
            else:
                last_used = datetime.fromisoformat(last_used_str.replace("Z", "+00:00"))
                if last_used < threshold:
                    stale_users.append({
                        "username": username,
                        "last_login": last_used.isoformat(),
                        "days_inactive": (datetime.now(timezone.utc) - last_used).days,
                    })

        return create_control_result(
            "A.8.2",
            "Unused IAM Credentials",
            f"Identifies console IAM users who have not logged in within {_STALE_DAYS} days",
            "PASS" if not stale_users else "FAIL",
            "MEDIUM",
            {
                "stale_threshold_days": _STALE_DAYS,
                "stale_users_count": len(stale_users),
                "stale_users": stale_users[:20],
            },
            None if not stale_users else (
                f"Disable or remove console access for {len(stale_users)} inactive user(s). "
                "Review whether these accounts are still required and apply the principle of least privilege."
            ),
        )
    except Exception as e:
        return _warning("A.8.2", "Unused IAM Credentials",
                        f"Identifies console IAM users inactive for {_STALE_DAYS} days", "MEDIUM", e)


# ===================== A.8.24 — DATA PROTECTION: SSM PLAINTEXT SECRETS =====================

_SECRET_KEYWORDS = [
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "private_key", "privatekey", "credentials", "credential",
    "auth", "access_key", "accesskey",
]


def check_ssm_plaintext_secrets(session):
    """A.8.24 — SSM Parameter Store has no plaintext (non-SecureString) parameters with secret-like names."""
    try:
        ssm = session.client("ssm")
        paginator = ssm.get_paginator("describe_parameters")
        plaintext_secrets = []

        for page in paginator.paginate():
            for param in page.get("Parameters", []):
                if param.get("Type") == "SecureString":
                    continue
                name_lower = param["Name"].lower()
                if any(kw in name_lower for kw in _SECRET_KEYWORDS):
                    plaintext_secrets.append({
                        "name": param["Name"],
                        "type": param.get("Type", "String"),
                    })

        return create_control_result(
            "A.8.24",
            "SSM Plaintext Secrets",
            "Checks SSM Parameter Store for non-SecureString parameters whose names suggest they contain secrets",
            "PASS" if not plaintext_secrets else "FAIL",
            "HIGH",
            {
                "plaintext_secrets_count": len(plaintext_secrets),
                "plaintext_secrets": plaintext_secrets[:20],
            },
            None if not plaintext_secrets else (
                f"Migrate {len(plaintext_secrets)} SSM parameter(s) to SecureString type using a KMS key. "
                "Use aws ssm put-parameter --type SecureString to re-create each parameter securely."
            ),
        )
    except Exception as e:
        return _warning("A.8.24", "SSM Plaintext Secrets",
                        "Checks SSM Parameter Store for plaintext parameters with secret-like names", "HIGH", e)


# ===================== EXECUTIVE SUMMARY =====================

def generate_executive_summary(result):
    """Generate a markdown-formatted executive summary of the ISO 27001 audit results."""
    summary = result["metadata"]["summary"]
    account_id = result["metadata"].get("aws_account_id", "Unknown")

    total_controls = summary["total_controls"]
    passed = summary["passed"]
    failed = summary["failed"]
    warnings = summary["warnings"]
    critical_failures = summary["critical_failures"]
    high_failures = summary["high_failures"]
    permission_errors = summary.get("permission_errors", 0)

    # Compliance score based on total controls — honest even when permissions are missing
    compliance_score = int((passed / total_controls * 100)) if total_controls > 0 else 0

    md_lines = []

    md_lines.append("# ISO/IEC 27001:2022 Compliance Summary")
    md_lines.append("")

    md_lines.append("## Overall Compliance Status")
    md_lines.append("")
    if compliance_score >= 90:
        md_lines.append(f"**AWS Account {account_id}** demonstrates **strong ISO 27001 compliance** with a **{compliance_score}%** pass rate across **{total_controls}** security controls.")
    elif compliance_score >= 70:
        md_lines.append(f"**AWS Account {account_id}** shows **moderate ISO 27001 compliance** with a **{compliance_score}%** pass rate across **{total_controls}** security controls, requiring targeted improvements.")
    else:
        md_lines.append(f"**AWS Account {account_id}** requires **significant security improvements** with a **{compliance_score}%** pass rate across **{total_controls}** security controls.")
    md_lines.append("")

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

    md_lines.append("## ISO 27001 Annex A.8 Control Categories")
    md_lines.append("")
    categories = [
        ("a8_access_control", "Access Control (A.8.2, A.8.5)"),
        ("a8_logging_monitoring", "Logging & Monitoring (A.8.15–16)"),
        ("a8_data_protection", "Data Protection (A.8.24)"),
        ("a8_configuration_management", "Configuration Management (A.8.9, A.8.20)"),
        ("a8_cloud_security", "Cloud Security (A.8.23)"),
    ]
    categories_with_issues = [
        label for key, label in categories
        if any(c["status"] == "FAIL" for c in result[key]["controls"])
    ]
    if categories_with_issues:
        md_lines.append(f"Control categories requiring attention: {', '.join(f'**{c}**' for c in categories_with_issues)}")
    else:
        md_lines.append("All ISO 27001 Annex A.8 control categories meet compliance standards.")
    md_lines.append("")

    md_lines.append("## Additional Observations")
    md_lines.append("")
    if permission_errors > 0:
        md_lines.append(f"**Note:** {permission_errors} control(s) could not be completed due to insufficient IAM permissions. Grant necessary permissions for a complete audit.")
        md_lines.append("")
    warnings_non_perm = warnings - permission_errors
    if warnings_non_perm > 0:
        md_lines.append(f"Additionally, **{warnings_non_perm} warning(s)** were identified that should be reviewed.")
    elif permission_errors == 0 and warnings == 0:
        md_lines.append("No warnings were identified, indicating robust security configurations.")
    md_lines.append("")

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

def run_iso_audit(profile=None):
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()

        if not session.region_name:
            session = boto3.Session(profile_name=profile, region_name="us-east-1") if profile else boto3.Session(region_name="us-east-1")

        result = _make_result()

        try:
            result["metadata"]["aws_account_id"] = session.client("sts").get_caller_identity()["Account"]
        except Exception as e:
            result["metadata"]["aws_account_id"] = "unknown"
            result["metadata"]["account_error"] = str(e)

        result["metadata"]["aws_profile"] = profile or "default"

        # Pre-fetch regions once so all regional checks share the same list without
        # each making a separate describe_regions API call.
        regions = _get_enabled_regions(session)

        check_tasks = [
            ("a8_access_control",        lambda: check_root_mfa(session)),
            ("a8_access_control",        lambda: check_iam_users_mfa(session)),
            ("a8_access_control",        lambda: check_root_no_active_keys(session)),
            ("a8_access_control",        lambda: check_password_policy(session)),
            ("a8_access_control",        lambda: check_access_key_rotation(session)),
            ("a8_logging_monitoring",     lambda: check_cloudtrail_enabled(session)),
            ("a8_logging_monitoring",     lambda: check_cloudtrail_log_validation(session)),
            ("a8_logging_monitoring",     lambda: check_cloudtrail_encryption(session)),
            ("a8_logging_monitoring",     lambda: check_cloudtrail_s3_not_public(session)),
            ("a8_logging_monitoring",     lambda r=regions: check_vpc_flow_logs(session, r)),
            ("a8_logging_monitoring",     lambda r=regions: check_guardduty_enabled(session, r)),
            ("a8_data_protection",        lambda r=regions: check_rds_encryption(session, r)),
            ("a8_data_protection",        lambda: check_s3_encryption(session)),
            ("a8_data_protection",        lambda: check_s3_public_access_block(session)),
            ("a8_data_protection",        lambda r=regions: check_ebs_default_encryption(session, r)),
            ("a8_data_protection",        lambda: check_kms_key_rotation(session)),
            ("a8_configuration_management", lambda r=regions: check_config_enabled(session, r)),
            ("a8_configuration_management", lambda r=regions: check_ec2_imdsv2(session, r)),
            ("a8_configuration_management", lambda r=regions: check_security_group_unrestricted(session, r)),
            ("a8_cloud_security",         lambda: check_scp_usage(session)),
            ("a8_logging_monitoring",     lambda r=regions: check_securityhub_enabled(session, r)),
            ("a8_logging_monitoring",     lambda: check_cloudwatch_alarms(session)),
            ("a8_data_protection",        lambda r=regions: check_rds_publicly_accessible(session, r)),
            ("a8_data_protection",        lambda r=regions: check_acm_certificate_expiry(session, r)),
            ("a8_access_control",         lambda: check_iam_admin_policies(session)),
            ("a8_access_control",         lambda: check_unused_iam_credentials(session)),
            ("a8_data_protection",        lambda: check_ssm_plaintext_secrets(session)),
        ]

        with ThreadPoolExecutor(max_workers=20) as executor:
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
                        "Review error details and ensure AWS resources are accessible."
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
                kw in str(c.get("details", {}).get("error", ""))
                for kw in ("AccessDenied", "Unauthorized", "Forbidden")
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

    except Exception:
        raise

# ===================== MAIN =====================

def main():
    parser = argparse.ArgumentParser(description="Run ISO 27001 compliance audit on AWS account")
    parser.add_argument("--profile", "-p", type=str, default=None,
                        help="AWS profile name to use (from ~/.aws/credentials or ~/.aws/config)")
    args = parser.parse_args()

    try:
        result = run_iso_audit(profile=args.profile)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

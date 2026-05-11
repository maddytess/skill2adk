import boto3
import argparse
import csv
import io
import sys
import time
from datetime import datetime, timezone, timedelta
import json
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

_EXPIRY_DAYS = 30  # ACM certificates expiring within this many days are flagged

# ===================== RESULT STRUCTURE =====================

def _make_result():
    """Create a fresh result structure for each audit run — avoids stale state across multiple calls."""
    return {
        "metadata": {
            "framework": "HIPAA Security Rule",
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "administrative_safeguards": {
            "category_description": "Policies and procedures to manage the selection, development, and use of security measures to protect ePHI",
            "controls": []
        },
        "physical_safeguards": {
            "category_description": "Physical measures to protect electronic information systems and related facilities from natural and environmental hazards and unauthorized intrusion",
            "controls": []
        },
        "technical_safeguards": {
            "category_description": "Technology and policies that protect ePHI and control access to it",
            "controls": []
        }
    }

# ===================== HELPERS =====================

def create_control_result(rule, name, description, status, severity, details, recommendation=None):
    result = {
        "hipaa_rule": rule,
        "control_name": name,
        "description": description,
        "status": status,        # PASS / FAIL / WARNING
        "severity": severity,    # CRITICAL / HIGH / MEDIUM / LOW
        "details": details
    }
    if recommendation:
        result["recommendation"] = recommendation
    return result


def _warning(rule, name, description, severity, e):
    """Return a WARNING result for a check that failed due to an exception."""
    error_code = "Unknown"
    if isinstance(e, ClientError):
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
    return create_control_result(
        rule, name, description,
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
    """Fetch IAM credential report as a list of row dicts, generating it if needed."""
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


# ===================== ADMINISTRATIVE SAFEGUARDS — §164.308 =====================

def _s3_data_event_coverage(selectors_resp):
    """
    Parse a get_event_selectors response and return (has_readwrite, has_any, trails_coverage).

    has_readwrite — True if at least one selector captures S3 object read+write events
    has_any       — True if any S3 data events are configured (even read-only or specific buckets)
    coverage      — list of dicts describing what was found, for the details payload
    """
    has_rw = False
    has_any = False
    coverage = []

    # Classic EventSelectors
    for es in selectors_resp.get("EventSelectors", []):
        for dr in es.get("DataResources", []):
            if dr.get("Type") != "AWS::S3::Object":
                continue
            has_any = True
            rw = es.get("ReadWriteType", "All")
            is_all_s3 = "arn:aws:s3" in dr.get("Values", [])
            coverage.append({
                "format": "classic",
                "scope": "all_s3" if is_all_s3 else "specific_buckets",
                "read_write_type": rw,
            })
            if rw == "All":
                has_rw = True

    # AdvancedEventSelectors (newer format)
    for aes in selectors_resp.get("AdvancedEventSelectors", []):
        fields = {fs["Field"]: fs for fs in aes.get("FieldSelectors", [])}
        resources_type = fields.get("resources.type", {})
        if "AWS::S3::Object" not in resources_type.get("Equals", []):
            continue
        has_any = True
        # Determine read/write scope from optional readOnly field condition
        readonly = fields.get("readOnly", {})
        equals = readonly.get("Equals", [])
        if equals == ["true"]:
            rw = "ReadOnly"
        elif equals == ["false"]:
            rw = "WriteOnly"
        else:
            rw = "All"  # no readOnly filter → both reads and writes captured
        # Determine bucket scope
        resources_arn = fields.get("resources.ARN", {})
        starts_with = resources_arn.get("StartsWith", [])
        is_all_s3 = not resources_arn or any(v in ("arn:aws:s3", "arn:aws:s3:::") for v in starts_with)
        coverage.append({
            "format": "advanced",
            "scope": "all_s3" if is_all_s3 else "specific_buckets",
            "read_write_type": rw,
        })
        if rw == "All":
            has_rw = True

    return has_rw, has_any, coverage


def check_cloudtrail_s3_data_events(session):
    """§164.312(b) — At least one CloudTrail trail captures S3 object-level read and write data events."""
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

        if not trails:
            return create_control_result(
                "164.312(b)", "CloudTrail S3 Data Events",
                "Ensures CloudTrail captures S3 object-level read and write events for ePHI access auditing",
                "FAIL", "HIGH",
                {"total_trails": 0},
                "Enable a CloudTrail trail with S3 data events (ReadWriteType: All) to audit access to ePHI in S3."
            )

        any_rw = False
        any_s3_events = False
        trail_details = []

        for trail in trails:
            try:
                resp = ct.get_event_selectors(TrailName=trail["TrailARN"])
                has_rw, has_any, coverage = _s3_data_event_coverage(resp)
                if has_rw:
                    any_rw = True
                if has_any:
                    any_s3_events = True
                if coverage:
                    trail_details.append({"trail": trail["Name"], "coverage": coverage})
            except ClientError:
                pass

        if any_rw:
            status = "PASS"
            recommendation = None
        elif any_s3_events:
            # Data events configured but incomplete (read-only or write-only)
            status = "FAIL"
            recommendation = (
                "S3 data events are partially configured but do not capture both reads and writes. "
                "Set ReadWriteType to 'All' on S3 object data resources to audit both GetObject "
                "and PutObject/DeleteObject operations."
            )
        else:
            status = "FAIL"
            recommendation = (
                "Enable S3 data events on at least one CloudTrail trail (ReadWriteType: All, "
                "DataResources: [{Type: AWS::S3::Object, Values: ['arn:aws:s3']}]). "
                "Without data events, GetObject and PutObject calls on ePHI are not logged."
            )

        details = {
            "total_trails": len(trails),
            "any_s3_data_events_configured": any_s3_events,
            "read_write_coverage": any_rw,
            "trails_with_s3_data_events": trail_details,
            "note": (
                "S3 data events capture GetObject, PutObject, and DeleteObject — required to "
                "audit who accessed or modified ePHI. Management events alone do not record "
                "object-level access."
            ),
        }

        return create_control_result(
            "164.312(b)", "CloudTrail S3 Data Events",
            "Ensures CloudTrail captures S3 object-level read and write events for ePHI access auditing",
            status, "HIGH",
            details,
            recommendation
        )
    except Exception as e:
        return _warning("164.312(b)", "CloudTrail S3 Data Events",
                        "Ensures CloudTrail captures S3 object-level read and write events for ePHI access auditing",
                        "HIGH", e)


def check_cloudtrail_multi_region(session):
    """§164.308(a)(1)(ii)(D) — Multi-region trail actively logging, log validation enabled, S3 access logging on trail bucket."""
    try:
        ct = session.client("cloudtrail")
        s3 = session.client("s3")
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

        if not trails:
            return create_control_result(
                "164.308(a)(1)(ii)(D)", "CloudTrail Multi-Region",
                "Ensures CloudTrail captures activity across all regions with integrity verification",
                "FAIL", "CRITICAL",
                {"total_trails": 0},
                "Enable a multi-region CloudTrail trail with log file validation and S3 access logging."
            )

        # Find multi-region trails that are actively logging
        active_multi_region = []
        for trail in trails:
            if not trail.get("IsMultiRegionTrail", False):
                continue
            try:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                if status.get("IsLogging", False):
                    active_multi_region.append(trail)
            except Exception:
                pass

        issues = []

        if not active_multi_region:
            issues.append("no multi-region trail is actively logging")

        # Check log file validation on all trails
        trails_without_validation = [
            t["Name"] for t in trails if not t.get("LogFileValidationEnabled", False)
        ]
        if trails_without_validation:
            issues.append(f"log file validation disabled on: {', '.join(trails_without_validation)}")

        # Check S3 access logging on trail buckets
        buckets_without_logging = []
        checked_buckets = set()
        for trail in trails:
            bucket = trail.get("S3BucketName")
            if not bucket or bucket in checked_buckets:
                continue
            checked_buckets.add(bucket)
            try:
                logging_cfg = s3.get_bucket_logging(Bucket=bucket)
                if "LoggingEnabled" not in logging_cfg:
                    buckets_without_logging.append(bucket)
            except ClientError:
                pass  # Can't check — don't penalise
        if buckets_without_logging:
            issues.append(f"S3 access logging disabled on trail bucket(s): {', '.join(buckets_without_logging)}")

        return create_control_result(
            "164.308(a)(1)(ii)(D)", "CloudTrail Multi-Region",
            "Ensures CloudTrail captures activity across all regions with integrity verification",
            "PASS" if not issues else "FAIL",
            "CRITICAL",
            {
                "total_trails": len(trails),
                "active_multi_region_trails": [t["Name"] for t in active_multi_region],
                "trails_without_log_validation": trails_without_validation,
                "trail_buckets_without_s3_logging": buckets_without_logging,
                "issues": issues,
            },
            None if not issues else f"Fix the following CloudTrail issues: {'; '.join(issues)}."
        )
    except Exception as e:
        return _warning("164.308(a)(1)(ii)(D)", "CloudTrail Multi-Region",
                        "Ensures CloudTrail captures activity across all regions with integrity verification",
                        "CRITICAL", e)


def check_guardduty_all_regions(session, regions=None):
    """§164.308(a)(1)(ii)(A) — GuardDuty threat detection is active in all enabled regions."""
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
            "164.308(a)(1)(ii)(A)", "GuardDuty All Regions",
            "Ensures GuardDuty threat detection is active in all enabled regions",
            "PASS" if not regions_without_guardduty else "FAIL",
            "CRITICAL",
            {
                "regions_checked": len(regions),
                "regions_without_guardduty": regions_without_guardduty,
                "regions_without_guardduty_count": len(regions_without_guardduty),
            },
            None if not regions_without_guardduty else
            f"Enable GuardDuty in {len(regions_without_guardduty)} region(s): {', '.join(regions_without_guardduty)}."
        )
    except Exception as e:
        return _warning("164.308(a)(1)(ii)(A)", "GuardDuty All Regions",
                        "Ensures GuardDuty threat detection is active in all enabled regions", "CRITICAL", e)


def check_security_hub_enabled(session, regions=None):
    """§164.308(a)(1)(ii)(A) — AWS Security Hub is enabled across all regions."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        def _check_region(region):
            try:
                hub = session.client("securityhub", region_name=region)
                hub.describe_hub()
                return None  # Hub is enabled
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("InvalidAccessException", "ResourceNotFoundException"):
                    return region  # Hub not subscribed in this region
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                    raise
                return None

        regions_without_hub = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 15))) as pool:
            for result in pool.map(_check_region, regions):
                if result:
                    regions_without_hub.append(result)

        return create_control_result(
            "164.308(a)(1)(ii)(A)", "Security Hub Enabled",
            "Ensures AWS Security Hub is enabled across all regions for centralised security findings",
            "PASS" if not regions_without_hub else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_hub": regions_without_hub,
                "regions_without_hub_count": len(regions_without_hub),
            },
            None if not regions_without_hub else
            f"Enable Security Hub in {len(regions_without_hub)} region(s): {', '.join(regions_without_hub)}."
        )
    except Exception as e:
        return _warning("164.308(a)(1)(ii)(A)", "Security Hub Enabled",
                        "Ensures AWS Security Hub is enabled across all regions for centralised security findings",
                        "HIGH", e)


def check_iam_password_policy(session):
    """§164.308(a)(5)(ii)(D) — Password policy enforces length, complexity, expiration, and reuse prevention."""
    try:
        iam = session.client("iam")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return create_control_result(
                    "164.308(a)(5)(ii)(D)", "IAM Password Policy",
                    "Ensures the account password policy enforces strong credentials",
                    "FAIL", "HIGH",
                    {"policy_exists": False},
                    "Create a password policy with minimum length 14, complexity, 90-day expiry, and 24-password reuse prevention."
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
        if reuse < 24:
            issues.append(f"reuse prevention {reuse} (require 24+)")

        return create_control_result(
            "164.308(a)(5)(ii)(D)", "IAM Password Policy",
            "Ensures the account password policy enforces strong credentials",
            "PASS" if not issues else "FAIL",
            "HIGH",
            {"policy": policy, "issues": issues, "issues_count": len(issues)},
            None if not issues else f"Update the password policy to fix: {'; '.join(issues)}."
        )
    except Exception as e:
        return _warning("164.308(a)(5)(ii)(D)", "IAM Password Policy",
                        "Ensures the account password policy enforces strong credentials", "HIGH", e)


def check_root_account_mfa(session):
    """§164.308(a)(3) — MFA is enabled on the AWS root account."""
    try:
        iam = session.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1

        return create_control_result(
            "164.308(a)(3)", "Root Account MFA",
            "Verifies that MFA is enabled on the AWS root account",
            "PASS" if mfa_enabled else "FAIL",
            "CRITICAL",
            {"root_mfa_enabled": mfa_enabled},
            None if mfa_enabled else
            "Enable MFA on the root account immediately. Use a hardware MFA device for maximum security."
        )
    except Exception as e:
        return _warning("164.308(a)(3)", "Root Account MFA",
                        "Verifies that MFA is enabled on the AWS root account", "CRITICAL", e)


def check_macie_enabled(session, regions=None):
    """§164.308(a)(1)(ii)(A) — Amazon Macie is enabled to discover and protect PHI in S3 buckets."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        def _check_region(region):
            try:
                macie = session.client("macie2", region_name=region)
                status = macie.get_macie_session().get("status")
                return region if status != "ENABLED" else None
            except ClientError as e:
                code = e.response["Error"]["Code"]
                # Macie not enrolled in this region — treated as disabled
                if code in ("AccessDeniedException",):
                    msg = e.response["Error"].get("Message", "")
                    if "Macie is not enabled" in msg or "not subscribed" in msg.lower():
                        return region
                    raise  # real IAM AccessDenied — let outer handler catch it
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            regions_without_macie = [r for r in pool.map(_check_region, regions) if r is not None]

        return create_control_result(
            "164.308(a)(1)(ii)(A)", "Macie Enabled",
            "Ensures Amazon Macie is enabled to automatically discover and protect PHI stored in S3 buckets",
            "PASS" if not regions_without_macie else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_macie": regions_without_macie,
                "regions_without_macie_count": len(regions_without_macie),
                "note": (
                    "Macie is the primary AWS service for PHI discovery in S3. "
                    "Without it, ePHI may exist in buckets you have not identified, "
                    "preventing accurate risk analysis under §164.308(a)(1)(ii)(A)."
                ),
            },
            None if not regions_without_macie else
            f"Enable Amazon Macie in {len(regions_without_macie)} region(s): {', '.join(regions_without_macie)}. "
            "Configure automated sensitive data discovery to continuously scan S3 buckets for PHI."
        )
    except Exception as e:
        return _warning("164.308(a)(1)(ii)(A)", "Macie Enabled",
                        "Ensures Amazon Macie is enabled to discover and protect PHI in S3 buckets", "HIGH", e)


# ===================== PHYSICAL SAFEGUARDS — §164.310 =====================

def check_region_inventory(session, regions=None):
    """§164.310(a)(1) — Informational: lists active regions with EC2 workloads."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        active_regions = []
        for region in regions:
            try:
                ec2 = session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_instances")
                for page in paginator.paginate(
                    Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
                ):
                    if page.get("Reservations"):
                        active_regions.append(region)
                        break  # found at least one — no need to fetch further pages
            except ClientError:
                pass

        return create_control_result(
            "164.310(a)(1)", "Region Inventory",
            "Lists AWS regions with active EC2 workloads to support documentation of ePHI processing locations",
            "PASS",
            "LOW",
            {
                "regions_checked": len(regions),
                "regions_with_ec2_workloads": active_regions,
                "regions_with_ec2_workloads_count": len(active_regions),
                "note": "This is an informational check. Document approved regions for ePHI workloads in your risk analysis.",
            },
            None
        )
    except Exception as e:
        return _warning("164.310(a)(1)", "Region Inventory",
                        "Lists AWS regions with active EC2 workloads", "LOW", e)


def check_ebs_default_encryption(session, regions=None):
    """§164.310(d)(1) — Default EBS encryption is enabled in all regions."""
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
            "164.310(d)(1)", "EBS Default Encryption",
            "Ensures default EBS encryption is enabled in all regions so new volumes are encrypted at creation",
            "PASS" if not regions_without_encryption else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_default_encryption": regions_without_encryption,
                "regions_without_default_encryption_count": len(regions_without_encryption),
            },
            None if not regions_without_encryption else
            f"Enable EBS default encryption in {len(regions_without_encryption)} region(s): {', '.join(regions_without_encryption)}."
        )
    except Exception as e:
        return _warning("164.310(d)(1)", "EBS Default Encryption",
                        "Ensures default EBS encryption is enabled in all regions", "HIGH", e)


# ===================== TECHNICAL SAFEGUARDS — §164.312 =====================

def check_iam_mfa_users(session):
    """§164.312(d) — All IAM users with console access have MFA enabled."""
    try:
        iam = session.client("iam")
        report = _get_credential_report(iam)
        users_without_mfa = [
            row["user"] for row in report
            if row.get("user") != "<root_account>"
            and row.get("password_enabled") == "true"
            and row.get("mfa_active") == "false"
        ]
        console_users = sum(
            1 for row in report
            if row.get("user") != "<root_account>"
            and row.get("password_enabled") == "true"
        )
        return create_control_result(
            "164.312(d)", "IAM MFA for Console Users",
            "Ensures all IAM users with console access have MFA enabled",
            "PASS" if not users_without_mfa else "FAIL",
            "CRITICAL",
            {
                "console_users_checked": console_users,
                "users_without_mfa": users_without_mfa,
                "users_without_mfa_count": len(users_without_mfa),
                "note": "Programmatic-only users (no console password) are excluded from this check.",
            },
            None if not users_without_mfa else
            f"Enable MFA for {len(users_without_mfa)} console user(s): {', '.join(users_without_mfa[:5])}{'...' if len(users_without_mfa) > 5 else ''}."
        )
    except Exception as e:
        return _warning("164.312(d)", "IAM MFA for Console Users",
                        "Ensures all IAM users with console access have MFA enabled", "CRITICAL", e)


def check_rds_encryption(session, regions=None):
    """§164.312(a)(2)(iv) — All RDS instances have storage encryption enabled."""
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
            "164.312(a)(2)(iv)", "RDS Encryption at Rest",
            "Ensures all RDS database instances have storage encryption enabled",
            "PASS" if not unencrypted else "FAIL",
            "CRITICAL",
            {
                "regions_checked": len(regions),
                "unencrypted_instances": unencrypted,
                "unencrypted_count": len(unencrypted),
            },
            None if not unencrypted else
            f"Enable encryption on {len(unencrypted)} RDS instance(s). "
            "Encryption must be enabled at creation — snapshot and restore to a new encrypted instance."
        )
    except Exception as e:
        return _warning("164.312(a)(2)(iv)", "RDS Encryption at Rest",
                        "Ensures all RDS database instances have storage encryption enabled", "CRITICAL", e)


def check_rds_publicly_accessible(session, regions=None):
    """§164.312(a)(1) — No RDS instances are publicly accessible from the internet."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        def _check_region(region):
            try:
                rds = session.client("rds", region_name=region)
                paginator = rds.get_paginator("describe_db_instances")
                return [
                    {
                        "instance": db["DBInstanceIdentifier"],
                        "engine": db.get("Engine", "unknown"),
                        "endpoint": db.get("Endpoint", {}).get("Address", "N/A"),
                        "region": region,
                    }
                    for page in paginator.paginate()
                    for db in page["DBInstances"]
                    if db.get("PubliclyAccessible", False)
                ]
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                    raise
                return []

        public_instances = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 15))) as pool:
            for region_result in pool.map(_check_region, regions):
                public_instances.extend(region_result)

        return create_control_result(
            "164.312(a)(1)", "RDS Publicly Accessible",
            "Ensures no RDS instances are configured as publicly accessible from the internet",
            "PASS" if not public_instances else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "public_instances": public_instances,
                "public_instances_count": len(public_instances),
            },
            None if not public_instances else
            f"Disable public accessibility on {len(public_instances)} RDS instance(s). "
            "Place databases in private subnets and use VPN or bastion hosts for access."
        )
    except Exception as e:
        return _warning("164.312(a)(1)", "RDS Publicly Accessible",
                        "Ensures no RDS instances are configured as publicly accessible from the internet", "HIGH", e)


def check_rds_backup_retention(session, regions=None):
    """§164.308(a)(7)(ii)(A) — All RDS instances have automated backups enabled with retention ≥ 7 days."""
    _MIN_RETENTION_DAYS = 7
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        def _check_region(region):
            try:
                rds = session.client("rds", region_name=region)
                paginator = rds.get_paginator("describe_db_instances")
                return [
                    {
                        "instance": db["DBInstanceIdentifier"],
                        "engine": db.get("Engine", "unknown"),
                        "retention_days": db.get("BackupRetentionPeriod", 0),
                        "region": region,
                    }
                    for page in paginator.paginate()
                    for db in page["DBInstances"]
                    if db.get("BackupRetentionPeriod", 0) < _MIN_RETENTION_DAYS
                ]
            except ClientError:
                return []

        insufficient = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for region_result in pool.map(_check_region, regions):
                insufficient.extend(region_result)

        return create_control_result(
            "164.308(a)(7)(ii)(A)", "RDS Backup Retention",
            f"Ensures all RDS instances have automated backups enabled with retention of at least {_MIN_RETENTION_DAYS} days",
            "PASS" if not insufficient else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "minimum_retention_days": _MIN_RETENTION_DAYS,
                "instances_below_threshold": insufficient,
                "instances_below_threshold_count": len(insufficient),
                "note": "BackupRetentionPeriod of 0 means automated backups are disabled entirely.",
            },
            None if not insufficient else
            f"Increase backup retention to at least {_MIN_RETENTION_DAYS} days on "
            f"{len(insufficient)} RDS instance(s). A retention period of 0 disables automated backups entirely."
        )
    except Exception as e:
        return _warning("164.308(a)(7)(ii)(A)", "RDS Backup Retention",
                        f"Ensures all RDS instances have automated backups enabled with retention ≥ {_MIN_RETENTION_DAYS} days",
                        "HIGH", e)


def check_s3_public_access(session, buckets):
    """§164.312(c)(1) — All S3 buckets have public access blocked. AccessDenied → WARNING, not FAIL."""
    try:
        s3 = session.client("s3")

        if not buckets:
            return create_control_result(
                "164.312(c)(1)", "S3 Public Access Block",
                "Ensures all S3 buckets have public access blocked",
                "PASS", "CRITICAL",
                {"total_buckets": 0},
            )

        public_buckets = []
        inaccessible_buckets = []

        for bucket in buckets:
            name = bucket["Name"]
            try:
                block = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if not all([
                    block.get("BlockPublicAcls", False),
                    block.get("IgnorePublicAcls", False),
                    block.get("BlockPublicPolicy", False),
                    block.get("RestrictPublicBuckets", False),
                ]):
                    public_buckets.append(name)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "NoSuchPublicAccessBlockConfiguration":
                    public_buckets.append(name)
                elif code in ("AccessDenied", "AccessDeniedException"):
                    # Record and continue — AccessDenied ≠ public
                    inaccessible_buckets.append(name)
                else:
                    raise

        details = {
            "total_buckets": len(buckets),
            "public_buckets": public_buckets,
            "public_buckets_count": len(public_buckets),
        }
        if inaccessible_buckets:
            details["inaccessible_buckets"] = inaccessible_buckets
            details["inaccessible_buckets_count"] = len(inaccessible_buckets)

        # If we couldn't check any bucket, escalate to WARNING
        if not public_buckets and inaccessible_buckets and len(inaccessible_buckets) == len(buckets):
            return create_control_result(
                "164.312(c)(1)", "S3 Public Access Block",
                "Ensures all S3 buckets have public access blocked",
                "WARNING", "CRITICAL",
                details,
                "Grant s3:GetPublicAccessBlock to complete this check."
            )

        return create_control_result(
            "164.312(c)(1)", "S3 Public Access Block",
            "Ensures all S3 buckets have public access blocked",
            "PASS" if not public_buckets else "FAIL",
            "CRITICAL",
            details,
            None if not public_buckets else
            f"Enable public access block on {len(public_buckets)} bucket(s): {', '.join(public_buckets[:5])}{'...' if len(public_buckets) > 5 else ''}."
        )
    except Exception as e:
        return _warning("164.312(c)(1)", "S3 Public Access Block",
                        "Ensures all S3 buckets have public access blocked", "CRITICAL", e)


def check_s3_encryption(session, buckets):
    """§164.312(a)(2)(iv) — All S3 buckets have default server-side encryption enabled."""
    try:
        s3 = session.client("s3")

        if not buckets:
            return create_control_result(
                "164.312(a)(2)(iv)", "S3 Encryption at Rest",
                "Ensures all S3 buckets have default server-side encryption enabled",
                "PASS", "HIGH",
                {"total_buckets": 0},
            )

        unencrypted = []
        inaccessible_buckets = []
        for bucket in buckets:
            name = bucket["Name"]
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    unencrypted.append(name)
                elif code in ("AccessDenied", "AccessDeniedException"):
                    inaccessible_buckets.append(name)
                elif code == "NoSuchBucket":
                    pass  # deleted mid-run, skip
                else:
                    raise

        details = {
            "total_buckets": len(buckets),
            "unencrypted_buckets": unencrypted,
            "unencrypted_count": len(unencrypted),
        }
        if inaccessible_buckets:
            details["inaccessible_buckets"] = inaccessible_buckets
            details["inaccessible_buckets_count"] = len(inaccessible_buckets)

        if not unencrypted and inaccessible_buckets and len(inaccessible_buckets) == len(buckets):
            return create_control_result(
                "164.312(a)(2)(iv)", "S3 Encryption at Rest",
                "Ensures all S3 buckets have default server-side encryption enabled",
                "WARNING", "HIGH",
                details,
                "Grant s3:GetEncryptionConfiguration to complete this check."
            )

        return create_control_result(
            "164.312(a)(2)(iv)", "S3 Encryption at Rest",
            "Ensures all S3 buckets have default server-side encryption enabled",
            "PASS" if not unencrypted else "FAIL",
            "HIGH",
            details,
            None if not unencrypted else
            f"Enable default encryption on {len(unencrypted)} bucket(s): {', '.join(unencrypted[:5])}{'...' if len(unencrypted) > 5 else ''}."
        )
    except Exception as e:
        return _warning("164.312(a)(2)(iv)", "S3 Encryption at Rest",
                        "Ensures all S3 buckets have default server-side encryption enabled", "HIGH", e)


def check_s3_versioning(session, buckets):
    """§164.312(c)(1) — All S3 buckets have versioning enabled for ePHI integrity and recovery."""
    try:
        s3 = session.client("s3")

        if not buckets:
            return create_control_result(
                "164.312(c)(1)", "S3 Versioning",
                "Ensures all S3 buckets have versioning enabled",
                "PASS", "MEDIUM",
                {"total_buckets": 0},
            )

        without_versioning = []
        inaccessible_buckets = []
        for bucket in buckets:
            name = bucket["Name"]
            try:
                versioning = s3.get_bucket_versioning(Bucket=name)
                if versioning.get("Status") != "Enabled":
                    without_versioning.append(name)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDenied", "AccessDeniedException"):
                    inaccessible_buckets.append(name)
                elif code == "NoSuchBucket":
                    pass  # deleted mid-run, skip
                else:
                    raise

        details = {
            "total_buckets": len(buckets),
            "buckets_without_versioning": without_versioning,
            "buckets_without_versioning_count": len(without_versioning),
        }
        if inaccessible_buckets:
            details["inaccessible_buckets"] = inaccessible_buckets
            details["inaccessible_buckets_count"] = len(inaccessible_buckets)

        if not without_versioning and inaccessible_buckets and len(inaccessible_buckets) == len(buckets):
            return create_control_result(
                "164.312(c)(1)", "S3 Versioning",
                "Ensures all S3 buckets have versioning enabled for ePHI integrity and recovery",
                "WARNING", "MEDIUM",
                details,
                "Grant s3:GetBucketVersioning to complete this check."
            )

        return create_control_result(
            "164.312(c)(1)", "S3 Versioning",
            "Ensures all S3 buckets have versioning enabled for ePHI integrity and recovery",
            "PASS" if not without_versioning else "FAIL",
            "MEDIUM",
            details,
            None if not without_versioning else
            f"Enable versioning on {len(without_versioning)} bucket(s) to protect against accidental deletion and enable point-in-time recovery."
        )
    except Exception as e:
        return _warning("164.312(c)(1)", "S3 Versioning",
                        "Ensures all S3 buckets have versioning enabled", "MEDIUM", e)


def check_ebs_encryption(session, regions=None):
    """§164.312(a)(2)(iv) — No unencrypted EBS volumes exist across all regions."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        def _check_region(region):
            try:
                ec2 = session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_volumes")
                results = []
                for page in paginator.paginate():
                    for volume in page.get("Volumes", []):
                        if not volume.get("Encrypted", False):
                            attachment = next(iter(volume.get("Attachments", [])), {})
                            results.append({
                                "volume_id": volume["VolumeId"],
                                "instance_id": attachment.get("InstanceId"),
                                "size_gb": volume.get("Size"),
                                "state": volume.get("State"),
                                "region": region,
                            })
                return results
            except ClientError:
                return []

        unencrypted_volumes = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for region_result in pool.map(_check_region, regions):
                unencrypted_volumes.extend(region_result)

        return create_control_result(
            "164.312(a)(2)(iv)", "EBS Volume Encryption",
            "Ensures no unencrypted EBS volumes exist",
            "PASS" if not unencrypted_volumes else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "unencrypted_volumes": unencrypted_volumes,
                "unencrypted_volumes_count": len(unencrypted_volumes),
            },
            None if not unencrypted_volumes else
            f"Encrypt {len(unencrypted_volumes)} unencrypted EBS volume(s). "
            "Create an encrypted snapshot and restore to a new encrypted volume. "
            "Enable EBS default encryption to prevent future unencrypted volumes."
        )
    except Exception as e:
        return _warning("164.312(a)(2)(iv)", "EBS Volume Encryption",
                        "Ensures no unencrypted EBS volumes exist", "HIGH", e)


def check_kms_key_rotation(session):
    """§164.312(a)(2)(iv) — All customer-managed KMS keys have automatic rotation enabled."""
    try:
        regions = _get_enabled_regions(session)

        def _check_region(region):
            results = []
            try:
                kms = session.client("kms", region_name=region)
                paginator = kms.get_paginator("list_keys")
                for page in paginator.paginate():
                    for key in page.get("Keys", []):
                        kid = key["KeyId"]
                        try:
                            meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
                            if (meta.get("KeyManager") == "CUSTOMER"
                                    and meta.get("KeyState") == "Enabled"
                                    and meta.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT"):
                                rotation = kms.get_key_rotation_status(KeyId=kid)
                                if not rotation.get("KeyRotationEnabled"):
                                    results.append({"key_id": kid, "region": region})
                        except ClientError:
                            pass  # skip keys we cannot inspect (pending deletion, etc.)
            except ClientError:
                pass
            return results

        keys_without_rotation = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for region_result in pool.map(_check_region, regions):
                keys_without_rotation.extend(region_result)

        return create_control_result(
            "164.312(a)(2)(iv)", "KMS Key Rotation",
            "Ensures all customer-managed KMS keys have automatic annual rotation enabled",
            "PASS" if not keys_without_rotation else "FAIL",
            "MEDIUM",
            {
                "keys_without_rotation": keys_without_rotation,
                "keys_without_rotation_count": len(keys_without_rotation),
                "note": "AWS-managed keys are excluded — rotation is handled by AWS.",
            },
            None if not keys_without_rotation else
            f"Enable annual key rotation on {len(keys_without_rotation)} customer-managed KMS key(s)."
        )
    except Exception as e:
        return _warning("164.312(a)(2)(iv)", "KMS Key Rotation",
                        "Ensures all customer-managed KMS keys have automatic annual rotation enabled", "MEDIUM", e)


def check_vpc_flow_logs(session, regions=None):
    """§164.312(b) — All VPCs have active flow logs for network traffic audit trails."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        def _check_region(region):
            try:
                ec2 = session.client("ec2", region_name=region)
                vpc_paginator = ec2.get_paginator("describe_vpcs")
                vpcs = [
                    v
                    for page in vpc_paginator.paginate()
                    for v in page.get("Vpcs", [])
                ]
                if not vpcs:
                    return [], 0
                # Paginate flow logs without a VPC filter to avoid filter size limits
                # on accounts with many VPCs, then match in memory
                fl_paginator = ec2.get_paginator("describe_flow_logs")
                monitored = {
                    fl["ResourceId"]
                    for page in fl_paginator.paginate()
                    for fl in page.get("FlowLogs", [])
                    if fl.get("FlowLogStatus") == "ACTIVE"
                }
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
            "164.312(b)", "VPC Flow Logs",
            "Ensures all VPCs have active flow logs enabled for network traffic audit trails",
            "PASS" if not vpcs_without_logs else "FAIL",
            "MEDIUM",
            {
                "regions_checked": len(regions),
                "total_vpcs": total_vpcs,
                "vpcs_without_flow_logs": vpcs_without_logs,
                "vpcs_without_flow_logs_count": len(vpcs_without_logs),
            },
            None if not vpcs_without_logs else
            f"Enable VPC flow logs on {len(vpcs_without_logs)} VPC(s) across "
            f"{len({v['region'] for v in vpcs_without_logs})} region(s)."
        )
    except Exception as e:
        return _warning("164.312(b)", "VPC Flow Logs",
                        "Ensures all VPCs have active flow logs enabled for network traffic audit trails", "MEDIUM", e)


def check_cloudwatch_alarms(session, regions=None):
    """§164.312(b) — CloudWatch alarms exist for root login, unauthorized API calls, and security group changes."""
    _REQUIRED_PATTERNS = [
        ("root_login",       ["RootAccount", "Root", "root_login", "root-login"]),
        ("unauthorized_api", ["UnauthorizedAPI", "unauthorized-api", "UnauthorizedAPICalls"]),
        ("sg_changes",       ["SecurityGroupChanges", "security-group-changes", "SGChanges"]),
    ]
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        def _get_region_alarms(region):
            try:
                cw = session.client("cloudwatch", region_name=region)
                paginator = cw.get_paginator("describe_alarms")
                return [
                    a["AlarmName"]
                    for page in paginator.paginate()
                    for a in page.get("MetricAlarms", [])
                ]
            except ClientError:
                return []

        all_alarm_names = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for region_names in pool.map(_get_region_alarms, regions):
                all_alarm_names.extend(region_names)

        missing = []
        for label, patterns in _REQUIRED_PATTERNS:
            matched = any(
                any(p.lower() in name.lower() for p in patterns)
                for name in all_alarm_names
            )
            if not matched:
                missing.append(label)

        return create_control_result(
            "164.312(b)", "CloudWatch Security Alarms",
            "Ensures CloudWatch alarms exist for root login, unauthorized API calls, and security group changes",
            "PASS" if not missing else "FAIL",
            "MEDIUM",
            {
                "regions_checked": len(regions),
                "total_alarms": len(all_alarm_names),
                "missing_alarm_categories": missing,
                "missing_count": len(missing),
                "naming_note": (
                    "Detection uses substring matching against common alarm name patterns "
                    "(e.g. 'RootAccount', 'UnauthorizedAPI'). Alarms using non-standard "
                    "naming conventions may be present but not detected. Review manually "
                    "if your organisation uses custom alarm names."
                ),
            },
            None if not missing else
            f"Create CloudWatch metric alarms for: {', '.join(missing)}. "
            "Use CloudTrail log metric filters to detect these events and alert via SNS."
        )
    except Exception as e:
        return _warning("164.312(b)", "CloudWatch Security Alarms",
                        "Ensures CloudWatch alarms exist for critical security events", "MEDIUM", e)


def check_alb_https(session, regions=None):
    """§164.312(e)(1) — No Application Load Balancers have HTTP-only listeners."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        def _check_region(region):
            try:
                elb = session.client("elbv2", region_name=region)
                paginator = elb.get_paginator("describe_load_balancers")
                http_listeners = []
                for page in paginator.paginate():
                    for lb in page.get("LoadBalancers", []):
                        if lb.get("Type") != "application":
                            continue
                        try:
                            listeners = elb.describe_listeners(
                                LoadBalancerArn=lb["LoadBalancerArn"]
                            )["Listeners"]
                            for listener in listeners:
                                if listener.get("Protocol") == "HTTP":
                                    http_listeners.append({
                                        "alb_name": lb["LoadBalancerName"],
                                        "lb_arn": lb["LoadBalancerArn"],
                                        "port": listener.get("Port"),
                                        "region": region,
                                    })
                        except ClientError:
                            pass
                return http_listeners
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                    raise
                return []

        http_listeners = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 15))) as pool:
            for region_result in pool.map(_check_region, regions):
                http_listeners.extend(region_result)

        return create_control_result(
            "164.312(e)(1)", "ALB HTTPS Enforcement",
            "Ensures no Application Load Balancers have HTTP-only listeners",
            "PASS" if not http_listeners else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "http_listeners": http_listeners,
                "http_listeners_count": len(http_listeners),
            },
            None if not http_listeners else
            f"Replace or redirect HTTP listeners on {len(http_listeners)} ALB listener(s). "
            "Configure HTTPS listeners with a valid ACM certificate and add an HTTP→HTTPS redirect rule."
        )
    except Exception as e:
        return _warning("164.312(e)(1)", "ALB HTTPS Enforcement",
                        "Ensures no Application Load Balancers have HTTP-only listeners", "HIGH", e)


def check_secrets_manager_rotation(session, regions=None):
    """§164.312(a)(2)(iii) — All Secrets Manager secrets have automatic rotation enabled."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        def _check_region(region):
            try:
                sm = session.client("secretsmanager", region_name=region)
                paginator = sm.get_paginator("list_secrets")
                results = []
                for page in paginator.paginate():
                    for secret in page.get("SecretList", []):
                        if not secret.get("RotationEnabled", False):
                            last_changed = secret.get("LastChangedDate")
                            results.append({
                                "secret_name": secret.get("Name"),
                                "region": region,
                                "last_changed": last_changed.isoformat() if last_changed else None,
                            })
                return results
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDeniedException", "AccessDenied"):
                    raise
                return []

        secrets_without_rotation = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for region_result in pool.map(_check_region, regions):
                secrets_without_rotation.extend(region_result)

        return create_control_result(
            "164.312(a)(2)(iii)", "Secrets Manager Rotation",
            "Ensures all Secrets Manager secrets have automatic rotation enabled",
            "PASS" if not secrets_without_rotation else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "secrets_without_rotation": secrets_without_rotation[:20],
                "secrets_without_rotation_count": len(secrets_without_rotation),
            },
            None if not secrets_without_rotation else
            f"Enable automatic rotation for {len(secrets_without_rotation)} secret(s). "
            "Configure a Lambda rotation function and set a rotation schedule (30–90 days)."
        )
    except Exception as e:
        return _warning("164.312(a)(2)(iii)", "Secrets Manager Rotation",
                        "Ensures all Secrets Manager secrets have automatic rotation enabled", "HIGH", e)


def check_acm_certificate_expiry(session, regions=None):
    """§164.312(e)(1) — No ACM certificates are expiring within the next 30 days."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        now = datetime.now(timezone.utc)
        threshold = now + timedelta(days=_EXPIRY_DAYS)

        def _check_region(region):
            try:
                acm = session.client("acm", region_name=region)
                paginator = acm.get_paginator("list_certificates")
                found = []
                arns = [
                    cert["CertificateArn"]
                    for page in paginator.paginate(CertificateStatuses=["ISSUED"])
                    for cert in page.get("CertificateSummaryList", [])
                ]

                def _describe(arn):
                    try:
                        detail = acm.describe_certificate(CertificateArn=arn)["Certificate"]
                        expiry = detail.get("NotAfter")
                        if expiry and expiry < threshold:
                            return {
                                "arn": arn,
                                "domain": detail.get("DomainName", "unknown"),
                                "expires_at": expiry.isoformat(),
                                "days_remaining": (expiry - now).days,
                                "region": region,
                            }
                        return None
                    except ClientError:
                        return None

                if arns:
                    with ThreadPoolExecutor(max_workers=max(1, min(len(arns), 10))) as inner_pool:
                        for cert in inner_pool.map(_describe, arns):
                            if cert:
                                found.append(cert)
                return found
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                    raise
                return []

        expiring_certs = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 15))) as pool:
            for region_result in pool.map(_check_region, regions):
                expiring_certs.extend(region_result)

        return create_control_result(
            "164.312(e)(1)", "ACM Certificate Expiry",
            f"Ensures no ACM certificates are expiring within the next {_EXPIRY_DAYS} days",
            "PASS" if not expiring_certs else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "expiry_threshold_days": _EXPIRY_DAYS,
                "expiring_certificates": expiring_certs,
                "expiring_certificates_count": len(expiring_certs),
            },
            None if not expiring_certs else
            f"Renew or replace {len(expiring_certs)} ACM certificate(s) expiring within {_EXPIRY_DAYS} days."
        )
    except Exception as e:
        return _warning("164.312(e)(1)", "ACM Certificate Expiry",
                        f"Ensures no ACM certificates are expiring within the next {_EXPIRY_DAYS} days", "HIGH", e)


def check_ec2_imdsv2(session, regions=None):
    """§164.312(a)(1) — All EC2 instances enforce IMDSv2 (HttpTokens=required)."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        def _check_region(region):
            try:
                ec2 = session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_instances")
                imdsv1_instances = []
                for page in paginator.paginate(
                    Filters=[{"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}]
                ):
                    for reservation in page.get("Reservations", []):
                        for instance in reservation.get("Instances", []):
                            tokens = instance.get("MetadataOptions", {}).get("HttpTokens", "optional")
                            if tokens != "required":
                                name_tag = next(
                                    (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                                    None
                                )
                                imdsv1_instances.append({
                                    "instance_id": instance["InstanceId"],
                                    "instance_name": name_tag,
                                    "region": region,
                                    "http_tokens": tokens,
                                })
                return imdsv1_instances
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                    raise
                return []

        imdsv1_instances = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for region_result in pool.map(_check_region, regions):
                imdsv1_instances.extend(region_result)

        return create_control_result(
            "164.312(a)(1)", "EC2 IMDSv2 Enforcement",
            "Ensures all EC2 instances enforce IMDSv2 to prevent SSRF-based credential theft",
            "PASS" if not imdsv1_instances else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "imdsv1_instances": imdsv1_instances,
                "imdsv1_instances_count": len(imdsv1_instances),
            },
            None if not imdsv1_instances else
            f"Enable IMDSv2 on {len(imdsv1_instances)} EC2 instance(s) by setting HttpTokens to 'required'. "
            "Use: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required. "
            "IMDSv1 is vulnerable to SSRF attacks that can expose IAM credentials and allow unauthorized ePHI access."
        )
    except Exception as e:
        return _warning("164.312(a)(1)", "EC2 IMDSv2 Enforcement",
                        "Ensures all EC2 instances enforce IMDSv2 to prevent SSRF-based credential theft", "HIGH", e)


_SENSITIVE_PORTS = [22, 3389, 3306, 5432, 1433, 1521, 27017, 6379, 5439]
_UNRESTRICTED_CIDRS = {"0.0.0.0/0", "::/0"}


def check_security_group_unrestricted_inbound(session, regions=None):
    """§164.312(a)(1) — No security groups allow unrestricted inbound on sensitive ports."""
    try:
        if regions is None:
            regions = _get_enabled_regions(session)

        def _check_region(region):
            try:
                ec2 = session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_security_groups")
                exposed = []
                for page in paginator.paginate():
                    for sg in page.get("SecurityGroups", []):
                        open_ports = []
                        for rule in sg.get("IpPermissions", []):
                            from_port = rule.get("FromPort", -1)
                            to_port = rule.get("ToPort", -1)
                            # Check if any sensitive port falls within this rule's port range
                            open_to_world = (
                                any(r.get("CidrIp") in _UNRESTRICTED_CIDRS for r in rule.get("IpRanges", []))
                                or any(r.get("CidrIpv6") in _UNRESTRICTED_CIDRS for r in rule.get("Ipv6Ranges", []))
                            )
                            if not open_to_world:
                                continue
                            # from_port == -1 means all traffic (e.g. ICMP or protocol -1)
                            if from_port == -1:
                                open_ports.extend(_SENSITIVE_PORTS)
                            else:
                                open_ports.extend(
                                    p for p in _SENSITIVE_PORTS if from_port <= p <= to_port
                                )
                        if open_ports:
                            exposed.append({
                                "sg_id": sg["GroupId"],
                                "sg_name": sg.get("GroupName", ""),
                                "region": region,
                                "open_sensitive_ports": sorted(set(open_ports)),
                            })
                return exposed
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                    raise
                return []

        exposed_sgs = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for region_result in pool.map(_check_region, regions):
                exposed_sgs.extend(region_result)

        return create_control_result(
            "164.312(a)(1)", "Security Group Unrestricted Inbound",
            "Ensures no security groups allow unrestricted inbound access on sensitive ports",
            "PASS" if not exposed_sgs else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "exposed_security_groups": exposed_sgs,
                "exposed_security_groups_count": len(exposed_sgs),
                "sensitive_ports_checked": _SENSITIVE_PORTS,
            },
            None if not exposed_sgs else
            f"Restrict inbound rules on {len(exposed_sgs)} security group(s) to known IP ranges. "
            f"Remove 0.0.0.0/0 and ::/0 from inbound rules for sensitive ports "
            f"(SSH/22, RDP/3389, database ports). Use VPN or bastion hosts for administrative access."
        )
    except Exception as e:
        return _warning("164.312(a)(1)", "Security Group Unrestricted Inbound",
                        "Ensures no security groups allow unrestricted inbound access on sensitive ports", "HIGH", e)


# ===================== EXECUTIVE SUMMARY =====================

def generate_executive_summary(result):
    """Generate a markdown-formatted executive summary of the HIPAA audit results."""
    summary = result["metadata"]["summary"]
    account_id = result["metadata"].get("aws_account_id", "Unknown")

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
            f"**AWS Account {account_id}** demonstrates **strong HIPAA compliance** with a "
            f"**{compliance_score}%** pass rate across **{total_controls}** controls."
        )
    elif compliance_score >= 70:
        md_lines.append(
            f"**AWS Account {account_id}** shows **moderate HIPAA compliance** with a "
            f"**{compliance_score}%** pass rate across **{total_controls}** controls, requiring targeted improvements."
        )
    else:
        md_lines.append(
            f"**AWS Account {account_id}** requires **significant improvements** with a "
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
    all_controls = [
        c
        for section in safeguard_sections.values()
        for c in section
    ]
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
            f"**Note:** {permission_errors} control(s) could not be completed due to insufficient IAM permissions. "
            "Grant necessary permissions for a complete audit."
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

def run_hipaa_audit(profile=None):
    """Run HIPAA Security Rule audit for the given AWS profile."""
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        if not session.region_name:
            session = (
                boto3.Session(profile_name=profile, region_name="us-east-1")
                if profile else boto3.Session(region_name="us-east-1")
            )

        result = _make_result()

        try:
            result["metadata"]["aws_account_id"] = session.client("sts").get_caller_identity()["Account"]
        except Exception as e:
            result["metadata"]["aws_account_id"] = "unknown"
            result["metadata"]["account_error"] = str(e)

        result["metadata"]["aws_profile"] = profile or "default"

        # Pre-fetch regions once — all regional checks share the same list
        regions = _get_enabled_regions(session)

        # Pre-fetch S3 buckets once — three S3 checks use them
        try:
            s3_buckets = session.client("s3").list_buckets()["Buckets"]
        except Exception:
            s3_buckets = []

        check_tasks = [
            # Administrative Safeguards
            ("administrative_safeguards", lambda: check_cloudtrail_s3_data_events(session)),
            ("administrative_safeguards", lambda: check_cloudtrail_multi_region(session)),
            ("administrative_safeguards", lambda r=regions: check_guardduty_all_regions(session, r)),
            ("administrative_safeguards", lambda r=regions: check_security_hub_enabled(session, r)),
            ("administrative_safeguards", lambda: check_iam_password_policy(session)),
            ("administrative_safeguards", lambda: check_root_account_mfa(session)),
            ("administrative_safeguards", lambda r=regions: check_macie_enabled(session, r)),
            # Physical Safeguards
            ("physical_safeguards",       lambda r=regions: check_region_inventory(session, r)),
            ("physical_safeguards",       lambda r=regions: check_ebs_default_encryption(session, r)),
            # Technical Safeguards
            ("technical_safeguards",      lambda: check_iam_mfa_users(session)),
            ("technical_safeguards",      lambda r=regions: check_rds_encryption(session, r)),
            ("technical_safeguards",      lambda r=regions: check_rds_publicly_accessible(session, r)),
            ("technical_safeguards",      lambda r=regions: check_rds_backup_retention(session, r)),
            ("technical_safeguards",      lambda b=s3_buckets: check_s3_public_access(session, b)),
            ("technical_safeguards",      lambda b=s3_buckets: check_s3_encryption(session, b)),
            ("technical_safeguards",      lambda b=s3_buckets: check_s3_versioning(session, b)),
            ("technical_safeguards",      lambda r=regions: check_ebs_encryption(session, r)),
            ("technical_safeguards",      lambda: check_kms_key_rotation(session)),
            ("technical_safeguards",      lambda r=regions: check_vpc_flow_logs(session, r)),
            ("technical_safeguards",      lambda r=regions: check_cloudwatch_alarms(session, r)),
            ("technical_safeguards",      lambda r=regions: check_alb_https(session, r)),
            ("technical_safeguards",      lambda r=regions: check_secrets_manager_rotation(session, r)),
            ("technical_safeguards",      lambda r=regions: check_acm_certificate_expiry(session, r)),
            ("technical_safeguards",      lambda r=regions: check_security_group_unrestricted_inbound(session, r)),
            ("technical_safeguards",      lambda r=regions: check_ec2_imdsv2(session, r)),
        ]

        with ThreadPoolExecutor(max_workers=25) as executor:
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
            "passed":          sum(1 for c in all_controls if c["status"] == "PASS"),
            "failed":          sum(1 for c in all_controls if c["status"] == "FAIL"),
            "warnings":        sum(1 for c in all_controls if c["status"] == "WARNING"),
            "critical_failures": sum(1 for c in all_controls if c["status"] == "FAIL" and c["severity"] == "CRITICAL"),
            "high_failures":   sum(1 for c in all_controls if c["status"] == "FAIL" and c["severity"] == "HIGH"),
            "permission_errors": permission_errors,
            "controls_completed": len(all_controls) - permission_errors,
        }

        result["metadata"]["executive_summary"] = generate_executive_summary(result)

        return result

    except Exception:
        raise


# ===================== MAIN =====================

def main():
    parser = argparse.ArgumentParser(
        description="AWS HIPAA Security Rule Compliance Audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 aws_hipaa.py --profile my-profile
  python3 aws_hipaa.py --profile my-profile --output report.json
  python3 aws_hipaa.py  # uses default AWS credential chain
        """
    )
    parser.add_argument("--profile", "-p", type=str, default=None,
                        help="AWS CLI profile name (from ~/.aws/credentials or ~/.aws/config)")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Write JSON output to a file instead of stdout")
    args = parser.parse_args()

    try:
        result = run_hipaa_audit(profile=args.profile)
        output = json.dumps(result, indent=2)

        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
        else:
            print(output)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

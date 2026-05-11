import boto3
import argparse
import sys
from datetime import datetime, timezone
import json
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

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

# ===================== ARTICLE 5 =====================

def check_cloudtrail_enabled(session):
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails()["trailList"]

        return create_check_result(
            "Article 5(1)(f)",
            "CloudTrail Logging",
            "Ensures audit logging is enabled to protect integrity and confidentiality of data",
            "PASS" if trails else "FAIL",
            "CRITICAL",
            {
                "trail_count": len(trails),
                "trails": [t["Name"] for t in trails]
            },
            None if trails else "Enable CloudTrail for all regions to log API activity."
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        return create_check_result(
            "Article 5(1)(f)",
            "CloudTrail Logging",
            "Ensures audit logging is enabled to protect integrity and confidentiality of data",
            "WARNING",
            "CRITICAL",
            {"error": f"Permission denied: {error_code}", "message": str(e)},
            "Grant cloudtrail:DescribeTrails permission to check this control."
        )

def check_s3_public_access(session):
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets()["Buckets"]
        public = []

        for b in buckets:
            try:
                cfg = s3.get_public_access_block(Bucket=b["Name"])["PublicAccessBlockConfiguration"]
                if not all(cfg.values()):
                    public.append(b["Name"])
            except Exception:
                public.append(b["Name"])

        return create_check_result(
            "Article 5(1)(f)",
            "S3 Public Access",
            "Checks whether personal data could be publicly exposed",
            "PASS" if not public else "FAIL",
            "CRITICAL",
            {
                "public_buckets": public
            },
            None if not public else "Block public access on all S3 buckets containing personal data."
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        return create_check_result(
            "Article 5(1)(f)",
            "S3 Public Access",
            "Checks whether personal data could be publicly exposed",
            "WARNING",
            "CRITICAL",
            {"error": f"Permission denied: {error_code}", "message": str(e)},
            "Grant s3:ListBuckets and s3:GetPublicAccessBlock permissions to check this control."
        )

# ===================== ARTICLE 25 =====================

def check_encryption_at_rest(session):
    try:
        rds = session.client("rds")
        unencrypted = [
            db["DBInstanceIdentifier"]
            for db in rds.describe_db_instances()["DBInstances"]
            if not db["StorageEncrypted"]
        ]

        return create_check_result(
            "Article 25",
            "Encryption at Rest",
            "Verifies encryption by default for stored personal data",
            "PASS" if not unencrypted else "FAIL",
            "HIGH",
            {"unencrypted_rds_instances": unencrypted},
            None if not unencrypted else "Use encrypted RDS instances by default."
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        return create_check_result(
            "Article 25",
            "Encryption at Rest",
            "Verifies encryption by default for stored personal data",
            "WARNING",
            "HIGH",
            {"error": f"Permission denied: {error_code}", "message": str(e)},
            "Grant rds:DescribeDBInstances permission to check this control."
        )

# ===================== ARTICLE 30 =====================

def check_regions_in_use(session):
    try:
        ec2 = session.client("ec2")
        regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
        used = []

        for r in regions:
            ec2r = session.client("ec2", region_name=r)
            if ec2r.describe_instances()["Reservations"]:
                used.append(r)

        return create_check_result(
            "Article 30",
            "Regions of Processing",
            "Identifies regions where personal data is processed",
            "PASS",
            "LOW",
            {"regions_in_use": used},
            "Document these regions in your Record of Processing Activities (RoPA)."
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        return create_check_result(
            "Article 30",
            "Regions of Processing",
            "Identifies regions where personal data is processed",
            "WARNING",
            "LOW",
            {"error": f"Permission denied: {error_code}", "message": str(e)},
            "Grant ec2:DescribeRegions and ec2:DescribeInstances permissions to check this control."
        )

# ===================== ARTICLE 32 =====================

def check_guardduty(session):
    gd = session.client("guardduty")
    try:
        detectors = gd.list_detectors()["DetectorIds"]
        return create_check_result(
            "Article 32",
            "Threat Detection",
            "Ensures capability to detect security incidents",
            "PASS" if detectors else "FAIL",
            "CRITICAL",
            {"guardduty_enabled": bool(detectors)},
            None if detectors else "Enable GuardDuty in all regions."
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        return create_check_result(
            "Article 32",
            "Threat Detection",
            "Ensures capability to detect security incidents",
            "WARNING",
            "CRITICAL",
            {"error": f"Permission denied: {error_code}", "message": str(e)},
            "Grant guardduty:ListDetectors permission to check this control."
        )

def check_macie(session):
    macie = session.client("macie2")
    try:
        status = macie.get_macie_session()["status"]
        enabled = status == "ENABLED"
        return create_check_result(
            "Article 32",
            "PII Discovery",
            "Ability to discover and classify personal data",
            "PASS" if enabled else "WARNING",
            "MEDIUM",
            {"macie_enabled": enabled},
            None if enabled else "Enable Amazon Macie to discover personal data."
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        return create_check_result(
            "Article 32",
            "PII Discovery",
            "Ability to discover and classify personal data",
            "WARNING",
            "MEDIUM",
            {"error": f"Permission denied: {error_code}", "message": str(e), "macie_enabled": "unknown"},
            "Grant macie2:GetMacieSession permission to check this control."
        )

# ===================== EXECUTIVE SUMMARY =====================

def generate_executive_summary(result):
    """Generate a markdown-formatted executive summary of the GDPR audit results"""
    summary = result["metadata"]["summary"]
    account_id = result["metadata"].get("aws_account_id", "Unknown")

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
        md_lines.append(f"**AWS Account {account_id}** demonstrates **strong GDPR compliance** with a **{compliance_score}%** pass rate across **{total_checks}** checks.")
    elif compliance_score >= 70:
        md_lines.append(f"**AWS Account {account_id}** shows **moderate GDPR compliance** with a **{compliance_score}%** pass rate across **{total_checks}** checks, requiring targeted improvements.")
    else:
        md_lines.append(f"**AWS Account {account_id}** requires **significant improvements** with a **{compliance_score}%** pass rate across **{total_checks}** checks.")
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
        md_lines.append(f"**Note:** {permission_errors} check(s) could not be completed due to insufficient IAM permissions. Grant necessary permissions for a complete audit.")
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
        md_lines.append("**Action:** Focus on critical and high-severity findings before processing personal data.")
    else:
        md_lines.append("**Action:** Implement comprehensive security improvements before processing EU personal data.")

    return "\n".join(md_lines)

# ===================== ARTICLE 33 / 34 =====================

def check_security_findings(session):
    gd = session.client("guardduty")
    try:
        detectors = gd.list_detectors()["DetectorIds"]

        findings = []
        if detectors:
            findings = gd.list_findings(DetectorId=detectors[0])["FindingIds"]

        return create_check_result(
            "Article 33 / 34",
            "Breach Detection Capability",
            "Ability to detect breaches within required timelines",
            "PASS" if detectors else "FAIL",
            "HIGH",
            {
                "active_findings": len(findings)
            },
            None if detectors else "Enable GuardDuty and alerting via SNS."
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        return create_check_result(
            "Article 33 / 34",
            "Breach Detection Capability",
            "Ability to detect breaches within required timelines",
            "WARNING",
            "HIGH",
            {"error": f"Permission denied: {error_code}", "message": str(e)},
            "Grant guardduty:ListDetectors and guardduty:ListFindings permissions to check this control."
        )

# ===================== RUN AUDIT =====================

def run_gdpr_audit(profile=None):
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()

        try:
            RESULT["metadata"]["aws_account_id"] = session.client("sts").get_caller_identity()["Account"]
        except Exception as e:
            RESULT["metadata"]["aws_account_id"] = "unknown"
            RESULT["metadata"]["account_error"] = str(e)

        RESULT["metadata"]["aws_profile"] = profile or "default"

        # Define all checks with their categories
        check_tasks = [
            ("article_5_integrity_confidentiality", lambda: check_cloudtrail_enabled(session)),
            ("article_5_integrity_confidentiality", lambda: check_s3_public_access(session)),
            ("article_25_privacy_by_design", lambda: check_encryption_at_rest(session)),
            ("article_30_records_of_processing", lambda: check_regions_in_use(session)),
            ("article_32_security_of_processing", lambda: check_guardduty(session)),
            ("article_32_security_of_processing", lambda: check_macie(session)),
            ("article_33_34_breach_management", lambda: check_security_findings(session))
        ]

        # Run checks in parallel with ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=7) as executor:
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
                        "AccessDenied" in error_message or
                        "UnauthorizedOperation" in error_message or
                        "AccessDeniedException" in error_message or
                        "Forbidden" in error_message or
                        error_type in ["ClientError", "NoCredentialsError", "CredentialRetrievalError"]
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
                                "reason": "IAM permissions may be missing for this service/action"
                            },
                            "Grant necessary IAM permissions to perform this GDPR check."
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
                            "Review error details and ensure AWS resources are accessible."
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

    except Exception:
        raise

# ===================== MAIN =====================

def main():
    parser = argparse.ArgumentParser(description="Run GDPR compliance audit on AWS account")
    parser.add_argument(
        "--profile",
        "-p",
        type=str,
        help="AWS profile name to use (from ~/.aws/credentials or ~/.aws/config)",
        default=None
    )

    args = parser.parse_args()

    try:
        raw_report = run_gdpr_audit(profile=args.profile)

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

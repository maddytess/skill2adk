import boto3
import argparse
import base64
import sys
import csv
import io
import re
import time
import json
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

# ===================== CONSTANTS =====================

_EXPIRY_DAYS = 30
_SENSITIVE_PORTS = [22, 3389, 3306, 5432, 1433, 1521, 27017, 6379, 5439]
_UNRESTRICTED_CIDRS = {"0.0.0.0/0", "::/0"}
_KEY_ROTATION_DAYS = 90
_INACTIVE_DAYS = 90
_LOG_RETENTION_DAYS = 365
_CT_RETENTION_DAYS = 365
_RDS_BACKUP_MIN_DAYS = 7
_MIN_PASSWORD_LENGTH = 12

# ===================== RESULT STRUCTURE =====================


def _make_result():
    """Create a fresh result structure for each audit run — avoids stale state across multiple calls."""
    return {
        "metadata": {
            "framework": "PCI-DSS v4.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "network_security": {
            "category_description": "Network security controls ensure segmentation and protection of the Cardholder Data Environment (PCI-DSS Requirements 1 & 2)",
            "checks": [],
        },
        "data_protection": {
            "category_description": "Data protection controls ensure cardholder data is encrypted at rest and in transit (PCI-DSS Requirements 3 & 4)",
            "checks": [],
        },
        "access_control": {
            "category_description": "Access control measures restrict access to cardholder data by business need to know and enforce strong authentication (PCI-DSS Requirements 7 & 8)",
            "checks": [],
        },
        "logging_monitoring": {
            "category_description": "Logging and monitoring controls ensure all access to system components and cardholder data is tracked and reviewed (PCI-DSS Requirements 10 & 11)",
            "checks": [],
        },
        "vulnerability_management": {
            "category_description": "Vulnerability management controls protect systems against malware and ensure secure development practices (PCI-DSS Requirements 5 & 6)",
            "checks": [],
        },
        "data_retention_recovery": {
            "category_description": "Data retention and recovery controls support information security policies and business continuity (PCI-DSS Requirements 9 & 12)",
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
    error_code = "Unknown"
    if isinstance(e, ClientError):
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
    return create_control_result(
        requirement, name, description,
        "WARNING", severity,
        {"error": error_code, "message": str(e)},
        f"Ensure the auditing role has permission to perform this check (error: {error_code}).",
    )


def _get_enabled_regions(session):
    """Return all enabled AWS regions for the account."""
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        regions = ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )["Regions"]
        return [r["RegionName"] for r in regions] or ["us-east-1"]
    except Exception:
        return [session.region_name or "us-east-1"]


def _get_credential_report(iam):
    """Fetch IAM credential report as a list of row dicts, generating it if needed."""
    for _ in range(12):
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


def _s3_data_event_coverage(selectors_resp):
    """Parse get_event_selectors response and return (has_readwrite, has_any, coverage)."""
    has_rw = False
    has_any = False
    coverage = []

    for es in selectors_resp.get("EventSelectors", []):
        for dr in es.get("DataResources", []):
            if dr.get("Type") != "AWS::S3::Object":
                continue
            has_any = True
            rw = es.get("ReadWriteType", "All")
            is_all_s3 = any(v.startswith("arn:aws:s3") for v in dr.get("Values", []))
            coverage.append({"format": "classic", "scope": "all_s3" if is_all_s3 else "specific_buckets", "read_write_type": rw})
            if rw == "All" and is_all_s3:
                has_rw = True

    for aes in selectors_resp.get("AdvancedEventSelectors", []):
        fields = {fs["Field"]: fs for fs in aes.get("FieldSelectors", [])}
        resources_type = fields.get("resources.type", {})
        if "AWS::S3::Object" not in resources_type.get("Equals", []):
            continue
        has_any = True
        readonly = fields.get("readOnly", {})
        equals = readonly.get("Equals", [])
        if equals == ["true"]:
            rw = "ReadOnly"
        elif equals == ["false"]:
            rw = "WriteOnly"
        else:
            rw = "All"
        resources_arn = fields.get("resources.ARN", {})
        starts_with = resources_arn.get("StartsWith", [])
        # No ARN filter, or no StartsWith restriction, or prefix covers all S3 → all_s3
        is_all_s3 = not resources_arn or not starts_with or any(v in ("arn:aws:s3", "arn:aws:s3:::") for v in starts_with)
        coverage.append({"format": "advanced", "scope": "all_s3" if is_all_s3 else "specific_buckets", "read_write_type": rw})
        if rw == "All" and is_all_s3:
            has_rw = True

    return has_rw, has_any, coverage


# ===================== RESOURCE CACHE =====================


class AWSResourceCache:
    """Pre-fetch shared AWS resources eagerly in the main thread before parallel execution."""

    def __init__(self, session):
        self.regions = _get_enabled_regions(session)
        self.fetch_errors = {}  # resource_type -> Exception

        # Fetch global (non-region) resources in parallel
        with ThreadPoolExecutor(max_workers=3) as pool:
            f_s3 = pool.submit(self._fetch_s3_buckets, session)
            f_ct = pool.submit(self._fetch_cloudtrail_trails, session)
            f_iam = pool.submit(self._fetch_iam_users, session)
            self.s3_buckets, err = f_s3.result()
            if err: self.fetch_errors["s3"] = err
            self.cloudtrail_trails, err = f_ct.result()
            if err: self.fetch_errors["cloudtrail"] = err
            self.iam_users, err = f_iam.result()
            if err: self.fetch_errors["iam"] = err

        # Fetch per-region resources in parallel
        with ThreadPoolExecutor(max_workers=4) as pool:
            f_ec2 = pool.submit(self._fetch_ec2_instances, session, self.regions)
            f_sg = pool.submit(self._fetch_security_groups, session, self.regions)
            f_rds = pool.submit(self._fetch_rds_instances, session, self.regions)
            f_vpc = pool.submit(self._fetch_vpcs, session, self.regions)
            self.ec2_instances = f_ec2.result()
            self.security_groups = f_sg.result()
            self.rds_instances = f_rds.result()
            self.vpcs = f_vpc.result()

        # Pre-fetch S3 per-bucket metadata in parallel for all S3 checks
        self.s3_metadata = self._fetch_s3_metadata(session, self.s3_buckets)
        self.active_regions = self._derive_active_regions()

    def _derive_active_regions(self):
        """Return the set of regions that contain at least one resource (EC2, RDS, VPC, or SG)."""
        active = set()
        for r in self.ec2_instances:
            active.add(r.get("_region", "us-east-1"))
        for r in self.rds_instances:
            active.add(r.get("_region", "us-east-1"))
        for r in self.vpcs:
            active.add(r.get("_region", "us-east-1"))
        for r in self.security_groups:
            active.add(r.get("_region", "us-east-1"))
        return active

    @staticmethod
    def _fetch_s3_metadata(session, s3_buckets):
        """Pre-fetch per-bucket metadata (public access, encryption, versioning, lifecycle, logging) in parallel."""
        if not s3_buckets:
            return {}
        s3 = session.client("s3")
        metadata = {}

        def fetch_bucket(bucket_name):
            info = {}
            for api, key in [
                ("get_public_access_block", "public_access"),
                ("get_bucket_encryption", "encryption"),
                ("get_bucket_versioning", "versioning"),
                ("get_bucket_lifecycle_configuration", "lifecycle"),
                ("get_bucket_logging", "logging"),
                ("get_bucket_acl", "acl"),
            ]:
                try:
                    info[key] = getattr(s3, api)(Bucket=bucket_name)
                except ClientError as e:
                    info[key] = {"_error": e.response["Error"]["Code"]}
                except Exception:
                    info[key] = {"_error": "Unknown"}
            return bucket_name, info

        with ThreadPoolExecutor(max_workers=10) as pool:
            for name, info in pool.map(lambda b: fetch_bucket(b["Name"]), s3_buckets):
                metadata[name] = info
        return metadata

    @staticmethod
    def _fetch_s3_buckets(session):
        try:
            return session.client("s3").list_buckets()["Buckets"], None
        except Exception as e:
            return [], e

    @staticmethod
    def _fetch_cloudtrail_trails(session):
        try:
            trails = session.client("cloudtrail").describe_trails(includeShadowTrails=True)["trailList"]
            # Deduplicate by TrailARN — shadow trails appear once per region
            seen = set()
            unique = []
            for t in trails:
                arn = t.get("TrailARN")
                if arn not in seen:
                    seen.add(arn)
                    unique.append(t)
            return unique, None
        except Exception as e:
            return [], e

    @staticmethod
    def _fetch_iam_users(session):
        try:
            iam = session.client("iam")
            paginator = iam.get_paginator("list_users")
            users = []
            for page in paginator.paginate():
                users.extend(page["Users"])
            return users, None
        except Exception as e:
            return [], e

    @staticmethod
    def _fetch_ec2_instances(session, regions):
        all_reservations = []

        def fetch_region(region):
            try:
                paginator = session.client("ec2", region_name=region).get_paginator("describe_instances")
                reservations = []
                for page in paginator.paginate():
                    reservations.extend(page["Reservations"])
                for r in reservations:
                    r["_region"] = region
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
                for sg in sgs:
                    sg["_region"] = region
                return sgs
            except Exception:
                return []

        with ThreadPoolExecutor(max_workers=10) as executor:
            for result in executor.map(fetch_region, regions):
                all_sgs.extend(result)
        return all_sgs

    @staticmethod
    def _fetch_rds_instances(session, regions):
        all_instances = []

        def fetch_region(region):
            try:
                paginator = session.client("rds", region_name=region).get_paginator("describe_db_instances")
                instances = []
                for page in paginator.paginate():
                    instances.extend(page["DBInstances"])
                for inst in instances:
                    inst["_region"] = region
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


# ===================== NETWORK SECURITY CONTROLS (Req 1 & 2) =====================


def check_vpc_flow_logs(session, vpcs):
    """Req 10.2 — All VPCs have flow logs enabled to capture traffic in and out of the CDE."""
    try:
        if not vpcs:
            return create_control_result(
                "10.2", "VPC Flow Logs",
                "Verifies all VPCs have flow logs enabled",
                "PASS", "HIGH",
                {"total_vpcs": 0, "vpcs_without_flow_logs": []},
            )

        vpcs_by_region = {}
        for vpc in vpcs:
            region = vpc.get("_region", "us-east-1")
            vpcs_by_region.setdefault(region, []).append(vpc)

        vpcs_without = []
        for region, region_vpcs in vpcs_by_region.items():
            try:
                ec2 = session.client("ec2", region_name=region)
                vpc_ids = [v["VpcId"] for v in region_vpcs]
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": vpc_ids}]
                )["FlowLogs"]
                active_flow_log_vpcs = {
                    fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"
                }
                for vpc in region_vpcs:
                    if vpc["VpcId"] not in active_flow_log_vpcs:
                        vpcs_without.append({"vpc_id": vpc["VpcId"], "region": region})
            except ClientError:
                pass

        return create_control_result(
            "10.2", "VPC Flow Logs",
            "Verifies all VPCs have flow logs enabled",
            "PASS" if not vpcs_without else "FAIL",
            "HIGH",
            {
                "total_vpcs": len(vpcs),
                "vpcs_without_flow_logs_count": len(vpcs_without),
                "vpcs_without_flow_logs": vpcs_without,
            },
            None if not vpcs_without else
            f"Enable VPC flow logs on {len(vpcs_without)} VPC(s). Flow logs capture network traffic metadata required for PCI-DSS audit trails.",
        )
    except Exception as e:
        return _warning("10.2", "VPC Flow Logs", "Verifies all VPCs have flow logs enabled", "HIGH", e)


def check_unrestricted_sg_ingress(security_groups):
    """Req 1.3 — No security groups allow 0.0.0.0/0 or ::/0 on sensitive ports."""
    try:
        risky_rules = []
        for sg in security_groups:
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", "All")
                to_port = rule.get("ToPort", "All")
                protocol = rule.get("IpProtocol", "-1")

                if protocol == "-1":
                    is_sensitive = True
                elif from_port == "All" or to_port == "All":
                    is_sensitive = True
                else:
                    is_sensitive = any(from_port <= p <= to_port for p in _SENSITIVE_PORTS)

                if not is_sensitive:
                    continue

                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") in _UNRESTRICTED_CIDRS:
                        risky_rules.append({
                            "security_group_id": sg["GroupId"],
                            "security_group_name": sg["GroupName"],
                            "from_port": from_port,
                            "to_port": to_port,
                            "protocol": protocol,
                            "cidr": ip_range["CidrIp"],
                            "region": sg.get("_region", "unknown"),
                        })

                for ip_range in rule.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") in _UNRESTRICTED_CIDRS:
                        risky_rules.append({
                            "security_group_id": sg["GroupId"],
                            "security_group_name": sg["GroupName"],
                            "from_port": from_port,
                            "to_port": to_port,
                            "protocol": protocol,
                            "cidr": ip_range["CidrIpv6"],
                            "region": sg.get("_region", "unknown"),
                        })

        return create_control_result(
            "1.3", "Unrestricted Security Group Ingress",
            "Verifies no security groups allow unrestricted access on sensitive ports",
            "PASS" if not risky_rules else "FAIL",
            "CRITICAL",
            {
                "risky_rules_count": len(risky_rules),
                "risky_rules": risky_rules[:20],
                "sensitive_ports_checked": _SENSITIVE_PORTS,
            },
            None if not risky_rules else
            f"Restrict {len(risky_rules)} security group rule(s). Remove 0.0.0.0/0 and ::/0 ingress on sensitive ports. Use specific CIDR ranges or AWS Systems Manager Session Manager for remote access.",
        )
    except Exception as e:
        return _warning("1.3", "Unrestricted Security Group Ingress",
                        "Verifies no security groups allow unrestricted access on sensitive ports", "CRITICAL", e)


def check_default_sg_in_use(security_groups, ec2_instances):
    """Req 1.2 — No EC2 instances use the default VPC security group."""
    try:
        default_sg_ids = {sg["GroupId"] for sg in security_groups if sg["GroupName"] == "default"}
        instances_using_default = []

        for reservation in ec2_instances:
            region = reservation.get("_region", "unknown")
            for instance in reservation.get("Instances", []):
                if instance.get("State", {}).get("Name") == "terminated":
                    continue
                instance_sg_ids = {sg["GroupId"] for sg in instance.get("SecurityGroups", [])}
                if instance_sg_ids & default_sg_ids:
                    instances_using_default.append({
                        "instance_id": instance["InstanceId"],
                        "security_groups": [sg["GroupName"] for sg in instance.get("SecurityGroups", [])],
                        "region": region,
                    })

        return create_control_result(
            "1.2", "Default Security Groups in Use",
            "Verifies no EC2 instances use the default VPC security group",
            "PASS" if not instances_using_default else "FAIL",
            "HIGH",
            {
                "instances_using_default_count": len(instances_using_default),
                "instances_using_default": instances_using_default[:20],
            },
            None if not instances_using_default else
            f"Create custom security groups for {len(instances_using_default)} instance(s). Default security groups should not be used in the CDE.",
        )
    except Exception as e:
        return _warning("1.2", "Default Security Groups in Use",
                        "Verifies no EC2 instances use the default VPC security group", "HIGH", e)


def check_public_subnets_igw(session, vpcs):
    """Req 1.3 — Identify subnets with direct internet gateway routes."""
    try:
        if not vpcs:
            return create_control_result(
                "1.3", "Public Subnets with Route to IGW",
                "Identifies subnets with direct internet gateway routes",
                "PASS", "HIGH", {"total_vpcs": 0, "public_subnets": []},
            )

        vpcs_by_region = {}
        for vpc in vpcs:
            region = vpc.get("_region", "us-east-1")
            vpcs_by_region.setdefault(region, []).append(vpc)

        public_subnets = []
        for region, region_vpcs in vpcs_by_region.items():
            try:
                ec2 = session.client("ec2", region_name=region)
                vpc_ids = [v["VpcId"] for v in region_vpcs]
                route_tables = ec2.describe_route_tables(
                    Filters=[{"Name": "vpc-id", "Values": vpc_ids}]
                )["RouteTables"]

                igw_rt_ids = set()
                for rt in route_tables:
                    for route in rt.get("Routes", []):
                        gw = route.get("GatewayId", "")
                        if gw.startswith("igw-") and route.get("State") == "active":
                            igw_rt_ids.add(rt["RouteTableId"])

                if not igw_rt_ids:
                    continue

                subnets = ec2.describe_subnets(
                    Filters=[{"Name": "vpc-id", "Values": vpc_ids}]
                )["Subnets"]

                # Find explicit subnet→route-table associations
                subnet_rt_map = {}
                for rt in route_tables:
                    for assoc in rt.get("Associations", []):
                        sid = assoc.get("SubnetId")
                        if sid:
                            subnet_rt_map[sid] = rt["RouteTableId"]

                # Find main route tables per VPC
                vpc_main_rt = {}
                for rt in route_tables:
                    for assoc in rt.get("Associations", []):
                        if assoc.get("Main"):
                            vpc_main_rt[rt.get("VpcId")] = rt["RouteTableId"]

                for subnet in subnets:
                    rt_id = subnet_rt_map.get(subnet["SubnetId"])
                    if rt_id is None:
                        rt_id = vpc_main_rt.get(subnet.get("VpcId"))
                    if rt_id and rt_id in igw_rt_ids:
                        public_subnets.append({
                            "subnet_id": subnet["SubnetId"],
                            "vpc_id": subnet.get("VpcId"),
                            "availability_zone": subnet.get("AvailabilityZone"),
                            "cidr_block": subnet.get("CidrBlock"),
                            "region": region,
                        })
            except ClientError:
                pass

        return create_control_result(
            "1.3", "Public Subnets with Route to IGW",
            "Identifies subnets with direct internet gateway routes",
            "PASS" if not public_subnets else "FAIL",
            "HIGH",
            {
                "public_subnets_count": len(public_subnets),
                "public_subnets": public_subnets[:30],
                "note": "CDE resources must not reside in public subnets without additional compensating controls.",
            },
            None if not public_subnets else
            f"Review {len(public_subnets)} public subnet(s). Ensure no CDE resources are deployed in these subnets without compensating controls such as WAF, NACLs, or proxy layers.",
        )
    except Exception as e:
        return _warning("1.3", "Public Subnets with Route to IGW",
                        "Identifies subnets with direct internet gateway routes", "HIGH", e)


def check_nacl_restrictiveness(session, vpcs):
    """Req 1.3 — NACLs are not set to allow all traffic on inbound rules."""
    try:
        if not vpcs:
            return create_control_result(
                "1.3", "Network ACL Restrictiveness",
                "Verifies NACLs are not set to allow all traffic on inbound rules",
                "PASS", "MEDIUM", {"total_vpcs": 0, "permissive_nacls": []},
            )

        vpcs_by_region = {}
        for vpc in vpcs:
            region = vpc.get("_region", "us-east-1")
            vpcs_by_region.setdefault(region, []).append(vpc)

        permissive_nacls = []
        for region, region_vpcs in vpcs_by_region.items():
            try:
                ec2 = session.client("ec2", region_name=region)
                vpc_ids = [v["VpcId"] for v in region_vpcs]
                nacls = ec2.describe_network_acls(
                    Filters=[{"Name": "vpc-id", "Values": vpc_ids}]
                )["NetworkAcls"]

                for nacl in nacls:
                    for entry in nacl.get("Entries", []):
                        if (entry.get("Egress") is False
                                and entry.get("RuleAction") == "allow"
                                and entry.get("Protocol") == "-1"
                                and entry.get("RuleNumber", 0) != 32767
                                and (entry.get("CidrBlock") == "0.0.0.0/0"
                                     or entry.get("Ipv6CidrBlock") == "::/0")):
                            permissive_nacls.append({
                                "nacl_id": nacl["NetworkAclId"],
                                "vpc_id": nacl.get("VpcId"),
                                "rule_number": entry.get("RuleNumber"),
                                "cidr": entry.get("CidrBlock") or entry.get("Ipv6CidrBlock"),
                                "region": region,
                            })
            except ClientError:
                pass

        return create_control_result(
            "1.3", "Network ACL Restrictiveness",
            "Verifies NACLs are not set to allow all traffic on inbound rules",
            "PASS" if not permissive_nacls else "FAIL",
            "MEDIUM",
            {
                "permissive_nacls_count": len(permissive_nacls),
                "permissive_nacls": permissive_nacls[:20],
            },
            None if not permissive_nacls else
            f"Restrict {len(permissive_nacls)} NACL rule(s) that allow all inbound traffic. Replace with specific port and CIDR allowlists.",
        )
    except Exception as e:
        return _warning("1.3", "Network ACL Restrictiveness",
                        "Verifies NACLs are not set to allow all traffic on inbound rules", "MEDIUM", e)


def check_ec2_imdsv2(ec2_instances):
    """Req 2.2 — All running EC2 instances require IMDSv2."""
    try:
        non_compliant = []
        total_checked = 0

        for reservation in ec2_instances:
            region = reservation.get("_region", "unknown")
            for instance in reservation.get("Instances", []):
                if instance.get("State", {}).get("Name") != "running":
                    continue
                total_checked += 1
                http_tokens = instance.get("MetadataOptions", {}).get("HttpTokens", "optional")
                if http_tokens != "required":
                    non_compliant.append({
                        "instance_id": instance["InstanceId"],
                        "http_tokens": http_tokens,
                        "region": region,
                    })

        return create_control_result(
            "2.2", "EC2 IMDSv2 Enforcement",
            "Verifies all running EC2 instances require IMDSv2",
            "PASS" if not non_compliant else "FAIL",
            "HIGH",
            {
                "instances_checked": total_checked,
                "non_compliant_count": len(non_compliant),
                "non_compliant_instances": non_compliant[:20],
            },
            None if not non_compliant else
            f"Enforce IMDSv2 on {len(non_compliant)} instance(s). Set HttpTokens to 'required' to prevent SSRF-based credential theft.",
        )
    except Exception as e:
        return _warning("2.2", "EC2 IMDSv2 Enforcement",
                        "Verifies all running EC2 instances require IMDSv2", "HIGH", e)


def check_default_vpc_in_use(_session, vpcs, ec2_instances):
    """Req 1.2 — No resources are deployed in the AWS default VPC."""
    try:
        default_vpc_ids = {vpc["VpcId"] for vpc in vpcs if vpc.get("IsDefault")}

        if not default_vpc_ids:
            return create_control_result(
                "1.2", "Default VPC in Use",
                "Verifies no resources are deployed in the AWS default VPC",
                "PASS", "MEDIUM",
                {"default_vpcs_found": 0, "instances_in_default_vpc": []},
            )

        instances_in_default = []
        for reservation in ec2_instances:
            region = reservation.get("_region", "unknown")
            for instance in reservation.get("Instances", []):
                if instance.get("State", {}).get("Name") == "terminated":
                    continue
                vpc_id = instance.get("VpcId")
                if vpc_id in default_vpc_ids:
                    instances_in_default.append({
                        "instance_id": instance["InstanceId"],
                        "vpc_id": vpc_id,
                        "region": region,
                    })

        return create_control_result(
            "1.2", "Default VPC in Use",
            "Verifies no resources are deployed in the AWS default VPC",
            "PASS" if not instances_in_default else "FAIL",
            "MEDIUM",
            {
                "default_vpcs_found": len(default_vpc_ids),
                "instances_in_default_vpc_count": len(instances_in_default),
                "instances_in_default_vpc": instances_in_default[:20],
            },
            None if not instances_in_default else
            f"Migrate {len(instances_in_default)} instance(s) out of the default VPC. Use dedicated VPCs with proper network segmentation for CDE workloads.",
        )
    except Exception as e:
        return _warning("1.2", "Default VPC in Use",
                        "Verifies no resources are deployed in the AWS default VPC", "MEDIUM", e)


def check_public_ec2_instances(_session, ec2_instances):
    """Req 1.3 — No running EC2 instances are directly exposed to the internet."""
    try:
        public_instances = []
        for reservation in ec2_instances:
            region = reservation.get("_region", "us-east-1")
            for instance in reservation.get("Instances", []):
                if instance.get("State", {}).get("Name") != "running":
                    continue
                public_ip = instance.get("PublicIpAddress")
                if public_ip:
                    public_instances.append({
                        "instance_id": instance["InstanceId"],
                        "public_ip": public_ip,
                        "instance_type": instance.get("InstanceType"),
                        "subnet_id": instance.get("SubnetId"),
                        "region": region,
                    })

        return create_control_result(
            "1.3", "Public EC2 Instances",
            "Verifies no running EC2 instances are directly exposed to the internet",
            "PASS" if not public_instances else "FAIL",
            "HIGH",
            {
                "public_instances_count": len(public_instances),
                "public_instances": public_instances[:20],
            },
            None if not public_instances else
            f"Review {len(public_instances)} public instance(s). CDE instances must not be directly internet-accessible. Use load balancers, NAT gateways, or bastion hosts.",
        )
    except Exception as e:
        return _warning("1.3", "Public EC2 Instances",
                        "Verifies no running EC2 instances are directly exposed to the internet", "HIGH", e)


# ===================== CARDHOLDER DATA PROTECTION (Req 3 & 4) =====================


def check_s3_public_access(session, s3_buckets, s3_metadata=None):
    """Req 3.4 — All S3 buckets have public access blocked."""
    try:
        if not s3_buckets:
            return create_control_result(
                "3.4", "S3 Public Access Block",
                "Verifies all S3 buckets have public access blocked",
                "PASS", "CRITICAL", {"total_buckets": 0, "public_buckets": []},
            )

        public_buckets = []
        inaccessible = []
        s3 = session.client("s3") if not s3_metadata else None
        for bucket in s3_buckets:
            name = bucket["Name"]
            try:
                if s3_metadata and name in s3_metadata:
                    resp = s3_metadata[name]["public_access"]
                    if "_error" in resp:
                        code = resp["_error"]
                        if code == "NoSuchPublicAccessBlockConfiguration":
                            public_buckets.append(name)
                        elif code in ("AccessDenied", "AccessDeniedException"):
                            inaccessible.append(name)
                        continue
                else:
                    resp = s3.get_public_access_block(Bucket=name)
                block = resp["PublicAccessBlockConfiguration"]
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
                    inaccessible.append(name)
                else:
                    raise

        if not public_buckets and inaccessible and len(inaccessible) == len(s3_buckets):
            return create_control_result(
                "3.4", "S3 Public Access Block",
                "Verifies all S3 buckets have public access blocked",
                "WARNING", "CRITICAL",
                {"total_buckets": len(s3_buckets), "inaccessible_buckets": len(inaccessible)},
                "Grant s3:GetBucketPublicAccessBlock to the auditing role to complete this check.",
            )

        return create_control_result(
            "3.4", "S3 Public Access Block",
            "Verifies all S3 buckets have public access blocked",
            "PASS" if not public_buckets else "FAIL",
            "CRITICAL",
            {
                "total_buckets": len(s3_buckets),
                "public_buckets_count": len(public_buckets),
                "public_buckets": public_buckets[:20],
                "inaccessible_buckets": len(inaccessible),
            },
            None if not public_buckets else
            f"Enable public access block on {len(public_buckets)} bucket(s). Cardholder data must never be publicly accessible.",
        )
    except Exception as e:
        return _warning("3.4", "S3 Public Access Block",
                        "Verifies all S3 buckets have public access blocked", "CRITICAL", e)


def check_s3_bucket_acl(session, s3_buckets, s3_metadata=None):
    """Req 3.4 — No S3 buckets have public or overly permissive ACL grants."""
    _PUBLIC_URIS = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
    try:
        if not s3_buckets:
            return create_control_result(
                "3.4", "S3 Bucket ACLs",
                "Verifies no S3 buckets have public ACL grants",
                "PASS", "HIGH", {"total_buckets": 0, "public_acl_buckets": []},
            )

        public_acl = []
        s3 = session.client("s3") if not s3_metadata else None
        for bucket in s3_buckets:
            name = bucket["Name"]
            try:
                if s3_metadata and name in s3_metadata:
                    resp = s3_metadata[name]["acl"]
                    if "_error" in resp:
                        continue
                else:
                    resp = s3.get_bucket_acl(Bucket=name)
                for grant in resp.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if uri in _PUBLIC_URIS:
                        public_acl.append({
                            "bucket": name,
                            "grantee": uri,
                            "permission": grant.get("Permission", ""),
                        })
                        break
            except ClientError:
                pass

        return create_control_result(
            "3.4", "S3 Bucket ACLs",
            "Verifies no S3 buckets have public ACL grants",
            "PASS" if not public_acl else "FAIL",
            "HIGH",
            {
                "total_buckets": len(s3_buckets),
                "public_acl_buckets_count": len(public_acl),
                "public_acl_buckets": public_acl[:20],
                "note": "PublicAccessBlock can override ACLs at the account level, but per-bucket ACL grants still indicate misconfiguration.",
            },
            None if not public_acl else
            f"Remove public ACL grants from {len(public_acl)} bucket(s). Use bucket policies with explicit deny for public access.",
        )
    except Exception as e:
        return _warning("3.4", "S3 Bucket ACLs",
                        "Verifies no S3 buckets have public ACL grants", "HIGH", e)


def check_s3_encryption(session, s3_buckets, s3_metadata=None):
    """Req 3.5 — All S3 buckets have an explicit encryption configuration (KMS or SSE-S3)."""
    try:
        if not s3_buckets:
            return create_control_result(
                "3.5", "S3 Encryption at Rest",
                "Verifies all S3 buckets have an explicit encryption configuration",
                "PASS", "MEDIUM", {"total_buckets": 0, "unencrypted_buckets": []},
            )

        no_explicit_config = []
        s3 = session.client("s3") if not s3_metadata else None
        for bucket in s3_buckets:
            name = bucket["Name"]
            try:
                if s3_metadata and name in s3_metadata:
                    resp = s3_metadata[name]["encryption"]
                    if "_error" in resp:
                        code = resp["_error"]
                        if code == "ServerSideEncryptionConfigurationNotFoundError":
                            no_explicit_config.append(name)
                        continue
                else:
                    s3.get_bucket_encryption(Bucket=name)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    no_explicit_config.append(name)
                elif code not in ("AccessDenied", "AccessDeniedException"):
                    raise

        return create_control_result(
            "3.5", "S3 Encryption at Rest",
            "Verifies all S3 buckets have an explicit encryption configuration",
            "PASS" if not no_explicit_config else "FAIL",
            "MEDIUM",
            {
                "total_buckets": len(s3_buckets),
                "unencrypted_buckets_count": len(no_explicit_config),
                "unencrypted_buckets": no_explicit_config[:20],
                "note": "Since January 2023, S3 encrypts all new objects by default with SSE-S3 (AES-256). "
                        "Buckets without explicit configuration still have default encryption. "
                        "This check flags buckets without an explicit policy, which may be required "
                        "for KMS encryption compliance or organisational policy enforcement.",
            },
            None if not no_explicit_config else
            f"Configure explicit encryption (KMS recommended) on {len(no_explicit_config)} bucket(s). "
            "These buckets use S3 default encryption (AES-256) but lack an explicit configuration.",
        )
    except Exception as e:
        return _warning("3.5", "S3 Encryption at Rest",
                        "Verifies all S3 buckets have an explicit encryption configuration", "MEDIUM", e)


def check_rds_encryption(rds_instances):
    """Req 3.5 — All RDS instances have storage encryption enabled."""
    try:
        if not rds_instances:
            return create_control_result(
                "3.5", "RDS Encryption at Rest",
                "Verifies all RDS instances have storage encryption enabled",
                "PASS", "CRITICAL", {"total_instances": 0, "unencrypted_instances": []},
            )

        unencrypted = [
            {
                "db_instance_id": db["DBInstanceIdentifier"],
                "engine": db.get("Engine"),
                "region": db.get("_region", "unknown"),
            }
            for db in rds_instances if not db.get("StorageEncrypted")
        ]

        return create_control_result(
            "3.5", "RDS Encryption at Rest",
            "Verifies all RDS instances have storage encryption enabled",
            "PASS" if not unencrypted else "FAIL",
            "CRITICAL",
            {
                "total_instances": len(rds_instances),
                "unencrypted_count": len(unencrypted),
                "unencrypted_instances": unencrypted,
            },
            None if not unencrypted else
            f"Encrypt {len(unencrypted)} RDS instance(s). Note: encryption cannot be enabled on an existing unencrypted instance — create an encrypted snapshot and restore to a new instance.",
        )
    except Exception as e:
        return _warning("3.5", "RDS Encryption at Rest",
                        "Verifies all RDS instances have storage encryption enabled", "CRITICAL", e)


def check_rds_public_access(rds_instances):
    """Req 1.3 — No RDS instances are publicly accessible."""
    try:
        if not rds_instances:
            return create_control_result(
                "1.3", "RDS Public Accessibility",
                "Verifies no RDS instances are publicly accessible",
                "PASS", "CRITICAL", {"total_instances": 0, "public_instances": []},
            )

        public = [
            {
                "db_instance_id": db["DBInstanceIdentifier"],
                "engine": db.get("Engine"),
                "region": db.get("_region", "unknown"),
            }
            for db in rds_instances if db.get("PubliclyAccessible")
        ]

        return create_control_result(
            "1.3", "RDS Public Accessibility",
            "Verifies no RDS instances are publicly accessible",
            "PASS" if not public else "FAIL",
            "CRITICAL",
            {
                "total_instances": len(rds_instances),
                "public_count": len(public),
                "public_instances": public,
            },
            None if not public else
            f"Disable public accessibility on {len(public)} RDS instance(s). Database instances in the CDE must not be directly internet-accessible.",
        )
    except Exception as e:
        return _warning("1.3", "RDS Public Accessibility",
                        "Verifies no RDS instances are publicly accessible", "CRITICAL", e)


def check_ebs_encryption(session, regions):
    """Req 3.5 — All EBS volumes are encrypted."""
    try:
        unencrypted = []
        skipped_regions = []

        def check_region(region):
            volumes = []
            try:
                ec2 = session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_volumes")
                for page in paginator.paginate():
                    for vol in page.get("Volumes", []):
                        if not vol.get("Encrypted"):
                            instance_id = None
                            for att in vol.get("Attachments", []):
                                instance_id = att.get("InstanceId")
                                break
                            volumes.append({
                                "volume_id": vol["VolumeId"],
                                "instance_id": instance_id,
                                "size_gb": vol.get("Size"),
                                "state": vol.get("State"),
                                "region": region,
                            })
                return volumes, None
            except Exception as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown") if isinstance(e, ClientError) else type(e).__name__
                return volumes, {"region": region, "reason": error_code}

        with ThreadPoolExecutor(max_workers=10) as executor:
            for volumes, error in executor.map(check_region, regions):
                unencrypted.extend(volumes)
                if error:
                    skipped_regions.append(error)

        status = "FAIL" if unencrypted else ("WARNING" if skipped_regions else "PASS")
        details = {
            "unencrypted_volumes_count": len(unencrypted),
            "unencrypted_volumes": unencrypted[:20],
        }
        if skipped_regions:
            details["skipped_regions"] = skipped_regions
            details["skipped_regions_note"] = "These regions could not be checked — results may be incomplete"

        rec = None
        if unencrypted:
            rec = f"Encrypt {len(unencrypted)} EBS volume(s). Create encrypted snapshots and restore to new encrypted volumes. Enable EBS encryption by default in account settings."
        elif skipped_regions:
            rec = f"Could not check {len(skipped_regions)} region(s). Ensure the auditing role has ec2:DescribeVolumes permission in all regions."

        return create_control_result(
            "3.5", "EBS Encryption",
            "Verifies all EBS volumes are encrypted",
            status, "HIGH", details, rec,
        )
    except Exception as e:
        return _warning("3.5", "EBS Encryption", "Verifies all EBS volumes are encrypted", "HIGH", e)


def check_ebs_default_encryption(session, regions):
    """Req 3.5 — Account-level default EBS encryption is enabled in all regions."""
    try:
        regions_without = []

        def check_region(region):
            try:
                ec2 = session.client("ec2", region_name=region)
                enabled = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
                return None if enabled else region
            except ClientError:
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for result in pool.map(check_region, regions):
                if result:
                    regions_without.append(result)

        return create_control_result(
            "3.5", "EBS Default Encryption",
            "Verifies account-level default EBS encryption is enabled in all regions",
            "PASS" if not regions_without else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_default_encryption": regions_without,
                "regions_without_count": len(regions_without),
            },
            None if not regions_without else
            f"Enable default EBS encryption in {len(regions_without)} region(s): {', '.join(regions_without[:5])}.",
        )
    except Exception as e:
        return _warning("3.5", "EBS Default Encryption",
                        "Verifies account-level default EBS encryption is enabled in all regions", "HIGH", e)


def check_dynamodb_encryption(session, regions):
    """Req 3.5 — All DynamoDB tables are encrypted with KMS (not just default AWS-owned key)."""
    try:
        non_compliant = []

        def check_region(region):
            result = []
            try:
                ddb = session.client("dynamodb", region_name=region)
                paginator = ddb.get_paginator("list_tables")
                for page in paginator.paginate():
                    for table_name in page.get("TableNames", []):
                        try:
                            desc = ddb.describe_table(TableName=table_name)["Table"]
                            sse = desc.get("SSEDescription", {})
                            status = sse.get("Status", "")
                            sse_type = sse.get("SSEType", "")
                            # Tables without explicit SSE use AWS-owned keys (default)
                            if status != "ENABLED" or sse_type != "KMS":
                                result.append({
                                    "table_name": table_name,
                                    "region": region,
                                    "sse_status": status or "DEFAULT_AWS_OWNED",
                                    "sse_type": sse_type or "AES256 (AWS-owned)",
                                })
                        except ClientError:
                            pass
            except ClientError:
                pass
            return result

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for region_result in pool.map(check_region, regions):
                non_compliant.extend(region_result)

        return create_control_result(
            "3.5", "DynamoDB Encryption",
            "Verifies all DynamoDB tables are encrypted with a customer-managed or AWS-managed KMS key",
            "PASS" if not non_compliant else "FAIL",
            "HIGH",
            {
                "non_compliant_count": len(non_compliant),
                "non_compliant_tables": non_compliant[:20],
                "note": "This check enforces explicit KMS encryption (stricter than the PCI-DSS v4.0 minimum). "
                        "Tables using the default AWS-owned AES-256 key are flagged because they provide no key rotation control, "
                        "key access policies, or CloudTrail audit trail for the encryption key itself.",
            },
            None if not non_compliant else
            f"Enable KMS encryption on {len(non_compliant)} DynamoDB table(s). Use AWS-managed or customer-managed KMS keys.",
        )
    except Exception as e:
        return _warning("3.5", "DynamoDB Encryption",
                        "Verifies all DynamoDB tables are encrypted with KMS", "HIGH", e)


def check_kms_key_rotation(session, regions):
    """Req 3.7 — All customer-managed KMS keys have annual automatic rotation enabled."""
    try:
        non_rotating = []
        skipped_keys = []
        skipped_regions = []

        def check_region(region):
            result = []
            skipped = []
            try:
                kms = session.client("kms", region_name=region)
                paginator = kms.get_paginator("list_keys")
                for page in paginator.paginate():
                    for key_entry in page.get("Keys", []):
                        kid = key_entry["KeyId"]
                        try:
                            desc = kms.describe_key(KeyId=kid)["KeyMetadata"]
                            if (desc.get("KeyManager") != "CUSTOMER"
                                    or desc.get("KeyState") != "Enabled"
                                    or desc.get("KeySpec") != "SYMMETRIC_DEFAULT"):
                                continue
                            rotation = kms.get_key_rotation_status(KeyId=kid)
                            if not rotation.get("KeyRotationEnabled"):
                                result.append({
                                    "key_id": kid,
                                    "key_arn": desc.get("Arn"),
                                    "description": desc.get("Description", ""),
                                    "region": region,
                                })
                        except ClientError as e:
                            error_code = e.response.get("Error", {}).get("Code", "Unknown")
                            skipped.append({"key_id": kid, "region": region, "reason": error_code})
                return result, skipped, None
            except Exception as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown") if isinstance(e, ClientError) else type(e).__name__
                return result, skipped, {"region": region, "reason": error_code}

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for result, skipped, error in pool.map(check_region, regions):
                non_rotating.extend(result)
                skipped_keys.extend(skipped)
                if error:
                    skipped_regions.append(error)

        status = "FAIL" if non_rotating else ("WARNING" if (skipped_keys or skipped_regions) else "PASS")
        details = {
            "non_rotating_keys_count": len(non_rotating),
            "non_rotating_keys": non_rotating[:20],
        }
        if skipped_keys:
            details["skipped_keys"] = skipped_keys[:20]
            details["skipped_keys_note"] = "These keys could not be checked — results may be incomplete"
        if skipped_regions:
            details["skipped_regions"] = skipped_regions
            details["skipped_regions_note"] = "These regions could not be checked — results may be incomplete"

        rec = None
        if non_rotating:
            rec = f"Enable automatic annual rotation on {len(non_rotating)} KMS key(s)."
        elif skipped_keys or skipped_regions:
            rec = f"Could not check {len(skipped_keys)} key(s) and {len(skipped_regions)} region(s). Ensure the auditing role has kms:DescribeKey and kms:GetKeyRotationStatus permissions."

        return create_control_result(
            "3.7", "KMS Key Rotation",
            "Verifies all customer-managed KMS keys have annual rotation enabled",
            status, "HIGH", details, rec,
        )
    except Exception as e:
        return _warning("3.7", "KMS Key Rotation",
                        "Verifies all customer-managed KMS keys have annual rotation enabled", "HIGH", e)


def check_secrets_no_plaintext(session, ec2_instances):
    """Req 3.4 — No plaintext secrets detected in EC2 user-data or environment variables."""
    try:
        secret_patterns = [
            re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE),
            re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*\S+", re.IGNORECASE),
            re.compile(r"(?:secret[_-]?key|secretkey)\s*[:=]\s*\S+", re.IGNORECASE),
            re.compile(r"(?:access[_-]?key[_-]?id)\s*[:=]\s*\S+", re.IGNORECASE),
            re.compile(r"AKIA[0-9A-Z]{16}"),
        ]

        flagged = []
        unchecked_instances = []
        ec2_clients = {}

        # Collect running instances to check
        running_instances = []
        for reservation in ec2_instances:
            region = reservation.get("_region", "us-east-1")
            for instance in reservation.get("Instances", []):
                if instance.get("State", {}).get("Name") == "running":
                    running_instances.append((region, instance))
                    if region not in ec2_clients:
                        ec2_clients[region] = session.client("ec2", region_name=region)

        total_checked = len(running_instances)

        def check_instance(region_instance):
            region, instance = region_instance
            try:
                ec2 = ec2_clients[region]
                attr = ec2.describe_instance_attribute(
                    InstanceId=instance["InstanceId"], Attribute="userData"
                )
                user_data = attr.get("UserData", {}).get("Value", "")
                if user_data:
                    try:
                        decoded = base64.b64decode(user_data).decode("utf-8", errors="ignore")
                    except Exception:
                        decoded = user_data
                    for pattern in secret_patterns:
                        if pattern.search(decoded):
                            return ("flagged", {
                                "instance_id": instance["InstanceId"],
                                "region": region,
                                "detection": "user-data contains potential plaintext credential",
                            })
                return ("ok", None)
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                return ("unchecked", {
                    "instance_id": instance["InstanceId"],
                    "region": region,
                    "reason": error_code,
                })

        with ThreadPoolExecutor(max_workers=min(len(running_instances), 20) if running_instances else 1) as pool:
            for kind, item in pool.map(check_instance, running_instances):
                if kind == "flagged":
                    flagged.append(item)
                elif kind == "unchecked":
                    unchecked_instances.append(item)

        status = "FAIL" if flagged else ("WARNING" if unchecked_instances else "PASS")
        details = {
            "instances_checked": total_checked,
            "flagged_count": len(flagged),
            "flagged_instances": flagged[:20],
            "note": "This is a heuristic check using pattern matching. Manual review of flagged instances is recommended.",
        }
        if unchecked_instances:
            details["unchecked_instances"] = unchecked_instances[:20]
            details["unchecked_note"] = "These instances could not be scanned — results may be incomplete"

        return create_control_result(
            "3.4", "Secrets Manager — No Plaintext Credentials",
            "Verifies no plaintext secrets are detected in EC2 user-data",
            status, "HIGH", details,
            f"Remove plaintext credentials from {len(flagged)} instance(s). Store secrets in AWS Secrets Manager or SSM Parameter Store (SecureString)." if flagged
            else f"Could not scan {len(unchecked_instances)} instance(s). Ensure the auditing role has ec2:DescribeInstanceAttribute permission." if unchecked_instances
            else None,
        )
    except Exception as e:
        return _warning("3.4", "Secrets Manager — No Plaintext Credentials",
                        "Verifies no plaintext secrets are detected in EC2 user-data", "HIGH", e)


def check_s3_versioning(session, s3_buckets, s3_metadata=None):
    """Req 10.7 — All S3 buckets have versioning enabled to protect audit trail integrity."""
    try:
        if not s3_buckets:
            return create_control_result(
                "10.7", "S3 Bucket Versioning",
                "Verifies all S3 buckets have versioning enabled to protect data and audit trail integrity",
                "PASS", "MEDIUM", {"total_buckets": 0, "unversioned_buckets": []},
            )

        unversioned = []
        s3 = session.client("s3") if not s3_metadata else None
        for bucket in s3_buckets:
            name = bucket["Name"]
            try:
                if s3_metadata and name in s3_metadata:
                    resp = s3_metadata[name]["versioning"]
                    if "_error" in resp:
                        if resp["_error"] not in ("AccessDenied", "AccessDeniedException"):
                            continue
                    elif resp.get("Status", "Disabled") != "Enabled":
                        unversioned.append(name)
                    continue
                status = s3.get_bucket_versioning(Bucket=name).get("Status", "Disabled")
                if status != "Enabled":
                    unversioned.append(name)
            except ClientError as e:
                if e.response["Error"]["Code"] not in ("AccessDenied", "AccessDeniedException"):
                    raise

        return create_control_result(
            "10.7", "S3 Bucket Versioning",
            "Verifies all S3 buckets have versioning enabled to protect data and audit trail integrity",
            "PASS" if not unversioned else "FAIL",
            "MEDIUM",
            {
                "total_buckets": len(s3_buckets),
                "unversioned_count": len(unversioned),
                "unversioned_buckets": unversioned[:20],
            },
            None if not unversioned else
            f"Enable versioning on {len(unversioned)} bucket(s) to prevent accidental deletion of cardholder data.",
        )
    except Exception as e:
        return _warning("10.7", "S3 Bucket Versioning",
                        "Verifies all S3 buckets have versioning enabled to protect data and audit trail integrity", "MEDIUM", e)


def check_s3_lifecycle(session, s3_buckets, s3_metadata=None):
    """Req 3.1 — All S3 buckets have lifecycle policies configured for data retention and disposal."""
    try:
        if not s3_buckets:
            return create_control_result(
                "3.1", "S3 Lifecycle Policies",
                "Verifies all S3 buckets have lifecycle policies for data retention and disposal",
                "PASS", "MEDIUM", {"total_buckets": 0, "buckets_without_lifecycle": []},
            )

        no_lifecycle = []
        s3 = session.client("s3") if not s3_metadata else None
        for bucket in s3_buckets:
            name = bucket["Name"]
            try:
                if s3_metadata and name in s3_metadata:
                    resp = s3_metadata[name]["lifecycle"]
                    if "_error" in resp:
                        code = resp["_error"]
                        if code == "NoSuchLifecycleConfiguration":
                            no_lifecycle.append(name)
                    continue
                s3.get_bucket_lifecycle_configuration(Bucket=name)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "NoSuchLifecycleConfiguration":
                    no_lifecycle.append(name)
                elif code not in ("AccessDenied", "AccessDeniedException"):
                    raise

        return create_control_result(
            "3.1", "S3 Lifecycle Policies",
            "Verifies all S3 buckets have lifecycle policies for data retention and disposal",
            "PASS" if not no_lifecycle else "FAIL",
            "MEDIUM",
            {
                "total_buckets": len(s3_buckets),
                "buckets_without_lifecycle_count": len(no_lifecycle),
                "buckets_without_lifecycle": no_lifecycle[:20],
            },
            None if not no_lifecycle else
            f"Configure lifecycle policies on {len(no_lifecycle)} bucket(s) for data retention and disposal per PCI-DSS data retention requirements.",
        )
    except Exception as e:
        return _warning("3.1", "S3 Lifecycle Policies",
                        "Verifies all S3 buckets have lifecycle policies for data retention and disposal", "MEDIUM", e)


def check_rds_tls(session, rds_instances):
    """Req 4.2 — RDS parameter groups enforce SSL/TLS connections."""
    try:
        if not rds_instances:
            return create_control_result(
                "4.2", "TLS on RDS",
                "Verifies RDS parameter groups enforce SSL/TLS connections",
                "PASS", "HIGH", {"total_instances": 0, "non_compliant": []},
            )

        ssl_params = {"rds.force_ssl": "1", "require_secure_transport": "ON"}
        non_compliant = []
        cluster_tls_cache = {}  # cluster_id -> bool
        rds_clients = {}  # region -> RDS client

        def _check_param_group(rds_client, pg_name):
            """Return True if a parameter group enforces TLS."""
            try:
                for page in rds_client.get_paginator("describe_db_parameters").paginate(DBParameterGroupName=pg_name):
                    for param in page.get("Parameters", []):
                        pname = param.get("ParameterName", "")
                        pval = param.get("ParameterValue", "")
                        if pname in ssl_params and pval == ssl_params[pname]:
                            return True
            except ClientError:
                pass
            return False

        def _check_cluster_tls(rds_client, cluster_id):
            """Return True if an Aurora cluster parameter group enforces TLS."""
            if cluster_id in cluster_tls_cache:
                return cluster_tls_cache[cluster_id]
            try:
                clusters = rds_client.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"]
                if clusters:
                    cpg = clusters[0].get("DBClusterParameterGroup", "")
                    if cpg:
                        result = _check_param_group(rds_client, cpg)
                        cluster_tls_cache[cluster_id] = result
                        return result
            except ClientError:
                pass
            cluster_tls_cache[cluster_id] = False
            return False

        for db in rds_instances:
            region = db.get("_region", "us-east-1")
            engine = db.get("Engine", "")
            db_id = db["DBInstanceIdentifier"]

            try:
                if region not in rds_clients:
                    rds_clients[region] = session.client("rds", region_name=region)
                rds = rds_clients[region]
                tls_enforced = False

                if engine.startswith("aurora"):
                    # Aurora: TLS is enforced at cluster parameter group level
                    cluster_id = db.get("DBClusterIdentifier")
                    if cluster_id:
                        tls_enforced = _check_cluster_tls(rds, cluster_id)
                else:
                    # Standard RDS: check instance parameter groups
                    for pg in db.get("DBParameterGroups", []):
                        if _check_param_group(rds, pg["DBParameterGroupName"]):
                            tls_enforced = True
                            break

                if not tls_enforced:
                    non_compliant.append({
                        "db_instance_id": db_id,
                        "engine": engine,
                        "region": region,
                        "param_type": "cluster" if engine.startswith("aurora") else "instance",
                    })
            except ClientError:
                pass

        return create_control_result(
            "4.2", "TLS on RDS",
            "Verifies RDS parameter groups enforce SSL/TLS connections",
            "PASS" if not non_compliant else "FAIL",
            "HIGH",
            {
                "total_instances": len(rds_instances),
                "non_compliant_count": len(non_compliant),
                "non_compliant": non_compliant[:20],
                "note": "Checks instance parameter groups for standard RDS and cluster parameter groups for Aurora.",
            },
            None if not non_compliant else
            f"Enforce TLS on {len(non_compliant)} RDS instance(s). Set rds.force_ssl=1 (PostgreSQL) or require_secure_transport=ON (MySQL/Aurora) in the appropriate parameter group.",
        )
    except Exception as e:
        return _warning("4.2", "TLS on RDS",
                        "Verifies RDS parameter groups enforce SSL/TLS connections", "HIGH", e)


def check_alb_https(session, regions):
    """Req 4.2 — No ALBs have HTTP-only listeners."""
    try:
        non_compliant = []

        def check_region(region):
            result = []
            try:
                elb = session.client("elbv2", region_name=region)
                paginator = elb.get_paginator("describe_load_balancers")
                for page in paginator.paginate():
                    for lb in page.get("LoadBalancers", []):
                        if lb.get("Type") != "application":
                            continue
                        lb_arn = lb["LoadBalancerArn"]
                        listeners = elb.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
                        for listener in listeners:
                            if listener.get("Protocol") == "HTTP":
                                # Check if it's a redirect-to-HTTPS action
                                actions = listener.get("DefaultActions", [])
                                is_redirect = any(
                                    a.get("Type") == "redirect"
                                    and a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
                                    for a in actions
                                )
                                if not is_redirect:
                                    result.append({
                                        "load_balancer_name": lb.get("LoadBalancerName"),
                                        "load_balancer_arn": lb_arn,
                                        "listener_port": listener.get("Port"),
                                        "region": region,
                                    })
            except Exception:
                pass
            return result

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for region_result in pool.map(check_region, regions):
                non_compliant.extend(region_result)

        return create_control_result(
            "4.2", "ALB HTTPS Enforcement",
            "Verifies no Application Load Balancers have HTTP-only listeners",
            "PASS" if not non_compliant else "FAIL",
            "HIGH",
            {
                "non_compliant_count": len(non_compliant),
                "non_compliant_listeners": non_compliant[:20],
                "note": "HTTP listeners that redirect to HTTPS are excluded.",
            },
            None if not non_compliant else
            f"Configure HTTPS on {len(non_compliant)} ALB listener(s). All traffic in transit must be encrypted per PCI-DSS Requirement 4.",
        )
    except Exception as e:
        return _warning("4.2", "ALB HTTPS Enforcement",
                        "Verifies no Application Load Balancers have HTTP-only listeners", "HIGH", e)


def check_api_gateway_tls(session, regions):
    """Req 4.2 — All API Gateway REST APIs enforce TLS 1.2 minimum."""
    try:
        non_compliant = []

        def check_region(region):
            result = []
            try:
                apigw = session.client("apigateway", region_name=region)

                # Build a map of api_id -> set of SecurityPolicy values from custom domain names.
                # TLS policy is enforced on the custom domain, not on the stage or API resource.
                domain_policy_by_api = {}
                try:
                    position = None
                    while True:
                        kwargs = {"limit": 500}
                        if position:
                            kwargs["position"] = position
                        domain_resp = apigw.get_domain_names(**kwargs)
                        for domain in domain_resp.get("items", []):
                            security_policy = domain.get("securityPolicy", "TLS_1_0")
                            domain_name = domain.get("domainName", "")
                            try:
                                map_position = None
                                while True:
                                    map_kwargs = {"domainName": domain_name, "limit": 500}
                                    if map_position:
                                        map_kwargs["position"] = map_position
                                    map_resp = apigw.get_base_path_mappings(**map_kwargs)
                                    for mapping in map_resp.get("items", []):
                                        api_id = mapping.get("restApiId", "")
                                        if api_id:
                                            domain_policy_by_api.setdefault(api_id, set()).add(security_policy)
                                    map_position = map_resp.get("position")
                                    if not map_position:
                                        break
                            except ClientError:
                                pass
                        position = domain_resp.get("position")
                        if not position:
                            break
                except ClientError:
                    pass

                # Fetch all REST APIs
                apis = []
                position = None
                while True:
                    kwargs = {"limit": 500}
                    if position:
                        kwargs["position"] = position
                    resp = apigw.get_rest_apis(**kwargs)
                    apis.extend(resp.get("items", []))
                    position = resp.get("position")
                    if not position:
                        break

                for api in apis:
                    api_id = api["id"]
                    api_name = api.get("name", api_id)
                    endpoint_type = api.get("endpointConfiguration", {}).get("types", ["EDGE"])

                    # EDGE APIs use CloudFront (TLS 1.2 min) — skip
                    # PRIVATE APIs are only accessible inside a VPC via VPC endpoint — no public exposure, skip
                    if "EDGE" in endpoint_type or "PRIVATE" in endpoint_type:
                        continue

                    try:
                        stages = apigw.get_stages(restApiId=api_id).get("item", [])
                        for stage in stages:
                            stage_name = stage.get("stageName", "")
                            domain_policies = domain_policy_by_api.get(api_id, set())

                            if not domain_policies:
                                # No custom domain — REGIONAL API is accessed via execute-api URL
                                # which defaults to TLS 1.0; flag as non-compliant
                                result.append({
                                    "api_name": api_name,
                                    "api_id": api_id,
                                    "stage": stage_name,
                                    "endpoint_type": endpoint_type,
                                    "reason": "no_custom_domain",
                                    "region": region,
                                })
                            elif any(p == "TLS_1_0" for p in domain_policies):
                                # Custom domain exists but uses insecure TLS 1.0 policy
                                result.append({
                                    "api_name": api_name,
                                    "api_id": api_id,
                                    "stage": stage_name,
                                    "endpoint_type": endpoint_type,
                                    "reason": "insecure_tls_policy",
                                    "security_policy": "TLS_1_0",
                                    "region": region,
                                })
                    except ClientError:
                        pass
            except ClientError:
                pass
            return result

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for region_result in pool.map(check_region, regions):
                non_compliant.extend(region_result)

        return create_control_result(
            "4.2", "API Gateway TLS",
            "Verifies API Gateway REST APIs enforce TLS 1.2 via custom domain security policy",
            "PASS" if not non_compliant else "FAIL",
            "HIGH",
            {
                "non_compliant_count": len(non_compliant),
                "non_compliant_apis": non_compliant[:20],
                "note": "REGIONAL REST APIs are checked via their custom domain SecurityPolicy. "
                        "EDGE APIs use CloudFront (TLS 1.2 minimum) and are excluded. "
                        "REGIONAL APIs without any custom domain are flagged as non-compliant.",
            },
            None if not non_compliant else
            f"Fix TLS on {len(non_compliant)} API Gateway stage(s): create or update custom domain names with SecurityPolicy=TLS_1_2.",
        )
    except Exception as e:
        return _warning("4.2", "API Gateway TLS",
                        "Verifies API Gateway REST APIs enforce TLS 1.2 via custom domain security policy", "HIGH", e)


def check_acm_certificate_expiry(session, regions):
    """Req 4.2 — No ACM certificates are expiring within 30 days."""
    try:
        now = datetime.now(timezone.utc)
        threshold = now + timedelta(days=_EXPIRY_DAYS)
        expiring = []

        def check_region(region):
            result = []
            try:
                acm = session.client("acm", region_name=region)
                paginator = acm.get_paginator("list_certificates")
                arns = [
                    cert["CertificateArn"]
                    for page in paginator.paginate(CertificateStatuses=["ISSUED"])
                    for cert in page.get("CertificateSummaryList", [])
                ]
                for arn in arns:
                    try:
                        detail = acm.describe_certificate(CertificateArn=arn)["Certificate"]
                        expiry = detail.get("NotAfter")
                        if expiry and expiry < threshold:
                            result.append({
                                "arn": arn,
                                "domain": detail.get("DomainName", "unknown"),
                                "expires_at": expiry.isoformat(),
                                "days_remaining": (expiry - now).days,
                                "region": region,
                            })
                    except ClientError:
                        pass
            except Exception:
                pass
            return result

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for region_result in pool.map(check_region, regions):
                expiring.extend(region_result)

        return create_control_result(
            "4.2", "ACM Certificate Expiry",
            "Verifies no ACM certificates are expiring within 30 days",
            "PASS" if not expiring else "FAIL",
            "HIGH",
            {
                "expiring_certificates_count": len(expiring),
                "expiring_certificates": expiring,
            },
            None if not expiring else
            f"Renew {len(expiring)} expiring ACM certificate(s) to maintain encrypted transit for cardholder data.",
        )
    except Exception as e:
        return _warning("4.2", "ACM Certificate Expiry",
                        "Verifies no ACM certificates are expiring within 30 days", "HIGH", e)


def check_macie_cardholder_data(session, regions):
    """Req 3.1 — Amazon Macie is enabled to discover sensitive data in S3."""
    try:
        disabled_regions = []

        def check_region(region):
            try:
                macie = session.client("macie2", region_name=region)
                resp = macie.get_macie_session()
                status = resp.get("status")
                if status != "ENABLED":
                    return region
                return None
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("AccessDeniedException", "Macie2Exception"):
                    return region
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for result in pool.map(check_region, regions):
                if result:
                    disabled_regions.append(result)

        return create_control_result(
            "3.1", "Macie Cardholder Data Discovery",
            "Verifies Amazon Macie is enabled to discover cardholder data in S3",
            "PASS" if not disabled_regions else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_macie": disabled_regions,
                "regions_without_macie_count": len(disabled_regions),
            },
            None if not disabled_regions else
            f"Enable Amazon Macie in {len(disabled_regions)} region(s) to automatically discover and classify PAN and cardholder data in S3 buckets.",
        )
    except Exception as e:
        return _warning("3.1", "Macie Cardholder Data Discovery",
                        "Verifies Amazon Macie is enabled to discover cardholder data in S3", "HIGH", e)


# ===================== ACCESS CONTROL (Req 7 & 8) =====================


def check_root_mfa(session):
    """Req 8.4 — MFA is enabled on the AWS root account."""
    try:
        iam = session.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1

        return create_control_result(
            "8.4", "Root Account MFA",
            "Verifies MFA is enabled on the AWS root account",
            "PASS" if mfa_enabled else "FAIL",
            "CRITICAL",
            {"mfa_enabled": mfa_enabled},
            None if mfa_enabled else
            "Enable MFA on the root account immediately. Use a hardware MFA device for the strongest protection.",
        )
    except Exception as e:
        return _warning("8.4", "Root Account MFA",
                        "Verifies MFA is enabled on the AWS root account", "CRITICAL", e)


def check_root_access_keys(session):
    """Req 8.2 — Root account must not have active access keys."""
    try:
        iam = session.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        keys_present = summary.get("AccountAccessKeysPresent", 0) > 0

        return create_control_result(
            "8.2", "Root Account Access Keys",
            "Verifies the root account does not have active access keys",
            "FAIL" if keys_present else "PASS",
            "CRITICAL",
            {"root_access_keys_present": keys_present},
            "Delete all root account access keys immediately. Use IAM users or roles for programmatic access."
            if keys_present else None,
        )
    except Exception as e:
        return _warning("8.2", "Root Account Access Keys",
                        "Verifies the root account does not have active access keys", "CRITICAL", e)


def check_iam_users_mfa(session):
    """Req 8.4 — All console IAM users have MFA enabled."""
    try:
        iam = session.client("iam")
        report = _get_credential_report(iam)

        users_without_mfa = []
        console_users = 0

        for row in report:
            if row.get("user") == "<root_account>":
                continue
            if row.get("password_enabled") != "true":
                continue
            console_users += 1
            if row.get("mfa_active") != "true":
                users_without_mfa.append(row["user"])

        return create_control_result(
            "8.4", "IAM Users MFA",
            "Verifies all console IAM users have MFA enabled",
            "PASS" if not users_without_mfa else "FAIL",
            "HIGH",
            {
                "console_users_checked": console_users,
                "users_without_mfa_count": len(users_without_mfa),
                "users_without_mfa": users_without_mfa[:20],
                "note": "Programmatic-only users (no console password) are excluded.",
            },
            None if not users_without_mfa else
            f"Enable MFA for {len(users_without_mfa)} console user(s): {', '.join(users_without_mfa[:5])}{'...' if len(users_without_mfa) > 5 else ''}.",
        )
    except Exception as e:
        return _warning("8.4", "IAM Users MFA",
                        "Verifies all console IAM users have MFA enabled", "HIGH", e)


def check_stale_access_keys(session, iam_users, days=_KEY_ROTATION_DAYS):
    """Req 8.3 — IAM access keys are rotated within 90 days."""
    try:
        iam = session.client("iam")
        now = datetime.now(timezone.utc)
        stale_keys = []

        for user in iam_users:
            username = user["UserName"]
            try:
                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                for key in keys:
                    if key.get("Status") != "Active":
                        continue
                    created = key.get("CreateDate")
                    if created and (now - created).days > days:
                        stale_keys.append({
                            "user": username,
                            "access_key_id": key["AccessKeyId"],
                            "age_days": (now - created).days,
                        })
            except ClientError:
                pass

        return create_control_result(
            "8.3", "Stale Access Keys",
            f"Verifies IAM access keys are rotated within {days} days",
            "PASS" if not stale_keys else "FAIL",
            "HIGH",
            {
                "users_checked": len(iam_users),
                "stale_keys_count": len(stale_keys),
                "stale_keys": stale_keys[:20],
            },
            None if not stale_keys else
            f"Rotate {len(stale_keys)} access key(s) older than {days} days.",
        )
    except Exception as e:
        return _warning("8.3", "Stale Access Keys",
                        f"Verifies IAM access keys are rotated within {days} days", "HIGH", e)


def _has_wildcard_statement(document):
    """Return (wildcard_action, wildcard_resource) if the policy document grants wildcard permissions."""
    statements = document.get("Statement", [])
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
        if "*" in actions or "*" in resources:
            return ("*" in actions, "*" in resources)
    return None


def check_overly_permissive_policies(session):
    """Req 7.2 — No customer-managed or inline policies contain wildcard actions or resources."""
    try:
        iam = session.client("iam")
        risky_policies = []

        # --- Scan customer-managed policies ---
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                try:
                    version_id = policy["DefaultVersionId"]
                    doc = iam.get_policy_version(
                        PolicyArn=policy["Arn"], VersionId=version_id
                    )["PolicyVersion"]["Document"]
                    result = _has_wildcard_statement(doc)
                    if result:
                        risky_policies.append({
                            "policy_name": policy["PolicyName"],
                            "policy_arn": policy["Arn"],
                            "type": "managed",
                            "wildcard_action": result[0],
                            "wildcard_resource": result[1],
                        })
                except ClientError:
                    pass

        # --- Scan inline policies on users, roles, and groups (in parallel) ---
        def _scan_principal_inline(args):
            principal_type, name, policy_method, name_key = args
            findings = []
            try:
                inline_pag = iam.get_paginator(f"list_{principal_type}_policies")
                for ip_page in inline_pag.paginate(**{name_key: name}):
                    for policy_name in ip_page.get("PolicyNames", []):
                        try:
                            doc = getattr(iam, policy_method)(
                                **{name_key: name, "PolicyName": policy_name}
                            )["PolicyDocument"]
                            result = _has_wildcard_statement(doc)
                            if result:
                                findings.append({
                                    "policy_name": policy_name,
                                    "attached_to": f"{principal_type}/{name}",
                                    "type": "inline",
                                    "wildcard_action": result[0],
                                    "wildcard_resource": result[1],
                                })
                        except ClientError:
                            pass
            except ClientError:
                pass
            return findings

        # Collect all principals to scan
        scan_tasks = []
        for principal_type, list_method, policy_method, name_key in [
            ("user", "list_users", "get_user_policy", "UserName"),
            ("role", "list_roles", "get_role_policy", "RoleName"),
            ("group", "list_groups", "get_group_policy", "GroupName"),
        ]:
            try:
                list_pag = iam.get_paginator(list_method)
                for page in list_pag.paginate():
                    for principal in page.get(f"{principal_type.capitalize()}s", []):
                        name = principal[name_key]
                        if principal_type == "role" and principal.get("Path", "").startswith("/aws-service-role/"):
                            continue
                        scan_tasks.append((principal_type, name, policy_method, name_key))
            except ClientError:
                pass

        with ThreadPoolExecutor(max_workers=15) as pool:
            for findings in pool.map(_scan_principal_inline, scan_tasks):
                risky_policies.extend(findings)

        return create_control_result(
            "7.2", "Overly Permissive IAM Policies",
            "Verifies no customer-managed or inline policies contain wildcard actions or resources",
            "PASS" if not risky_policies else "FAIL",
            "HIGH",
            {
                "risky_policies_count": len(risky_policies),
                "risky_policies": risky_policies[:20],
            },
            None if not risky_policies else
            f"Review and restrict {len(risky_policies)} IAM polic(ies) with wildcard permissions. Apply least-privilege access per PCI-DSS Requirement 7.",
        )
    except Exception as e:
        return _warning("7.2", "Overly Permissive IAM Policies",
                        "Verifies no customer-managed or inline policies contain wildcard actions or resources", "HIGH", e)


def check_admin_iam_principals(session):
    """Req 7.1 — Identify IAM roles and users with AdministratorAccess or PowerUserAccess attached."""
    _ADMIN_POLICIES = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
    }
    try:
        iam = session.client("iam")
        admin_principals = []

        # Collect all roles and users first
        all_roles = []
        for page in iam.get_paginator("list_roles").paginate():
            for role in page["Roles"]:
                if not role.get("Path", "").startswith("/aws-service-role/"):
                    all_roles.append(role)

        all_users = []
        for page in iam.get_paginator("list_users").paginate():
            all_users.extend(page["Users"])

        # Check attached policies in parallel
        def check_role(role):
            try:
                attached = iam.list_attached_role_policies(RoleName=role["RoleName"])["AttachedPolicies"]
                for p in attached:
                    if p["PolicyArn"] in _ADMIN_POLICIES:
                        return {"type": "role", "name": role["RoleName"], "arn": role["Arn"], "policy": p["PolicyArn"]}
            except ClientError:
                pass
            return None

        def check_user(user):
            try:
                attached = iam.list_attached_user_policies(UserName=user["UserName"])["AttachedPolicies"]
                for p in attached:
                    if p["PolicyArn"] in _ADMIN_POLICIES:
                        return {"type": "user", "name": user["UserName"], "arn": user["Arn"], "policy": p["PolicyArn"]}
            except ClientError:
                pass
            return None

        with ThreadPoolExecutor(max_workers=15) as pool:
            role_futures = [pool.submit(check_role, r) for r in all_roles]
            user_futures = [pool.submit(check_user, u) for u in all_users]
            for fut in as_completed(role_futures + user_futures):
                result = fut.result()
                if result:
                    admin_principals.append(result)

        return create_control_result(
            "7.1", "Admin IAM Principals",
            "Identifies IAM roles and users with AdministratorAccess or PowerUserAccess attached",
            "PASS" if not admin_principals else "FAIL",
            "CRITICAL",
            {
                "admin_principals_count": len(admin_principals),
                "admin_principals": admin_principals[:20],
                "note": "AWS service-linked roles are excluded. Admin access should be limited to break-glass scenarios.",
            },
            None if not admin_principals else
            f"Review {len(admin_principals)} IAM principal(s) with admin-level managed policies. Restrict to least privilege per PCI-DSS Requirement 7.",
        )
    except Exception as e:
        return _warning("7.1", "Admin IAM Principals",
                        "Identifies IAM roles and users with AdministratorAccess or PowerUserAccess attached", "CRITICAL", e)


def check_cross_account_trust(session):
    """Req 7.1 — Identify IAM roles with trust policies that allow cross-account or wildcard principals."""
    try:
        iam = session.client("iam")
        sts = session.client("sts")
        own_account = sts.get_caller_identity()["Account"]

        risky_roles = []
        for page in iam.get_paginator("list_roles").paginate():
            for role in page["Roles"]:
                if role.get("Path", "").startswith("/aws-service-role/"):
                    continue
                trust = role.get("AssumeRolePolicyDocument", {})
                for stmt in trust.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue
                    principal = stmt.get("Principal", {})
                    # Normalize principal to a list of ARN/account strings
                    arns = []
                    if principal == "*":
                        arns = ["*"]
                    elif isinstance(principal, dict):
                        for key in ("AWS", "Federated"):
                            val = principal.get(key, [])
                            if isinstance(val, str):
                                val = [val]
                            arns.extend(val)

                    for arn in arns:
                        if arn == "*":
                            risky_roles.append({
                                "role_name": role["RoleName"],
                                "role_arn": role["Arn"],
                                "issue": "wildcard_principal",
                                "principal": "*",
                            })
                            break
                        # Extract account ID from ARN
                        parts = arn.split(":")
                        acct_id = parts[4] if len(parts) >= 5 and parts[4] else None
                        if acct_id and acct_id != own_account:
                            conditions = stmt.get("Condition", {})
                            has_external_id = any("sts:ExternalId" in str(v) for v in conditions.values())
                            risky_roles.append({
                                "role_name": role["RoleName"],
                                "role_arn": role["Arn"],
                                "issue": "cross_account",
                                "principal": arn,
                                "external_account": acct_id,
                                "has_external_id": has_external_id,
                            })
                            break

        return create_control_result(
            "7.1", "Cross-Account Trust Policies",
            "Identifies IAM roles with trust policies allowing cross-account or wildcard access",
            "PASS" if not risky_roles else "FAIL",
            "HIGH",
            {
                "risky_roles_count": len(risky_roles),
                "wildcard_count": sum(1 for r in risky_roles if r["issue"] == "wildcard_principal"),
                "cross_account_count": sum(1 for r in risky_roles if r["issue"] == "cross_account"),
                "risky_roles": risky_roles[:20],
            },
            None if not risky_roles else
            f"Review {len(risky_roles)} role(s) with cross-account or wildcard trust policies. Restrict to specific principals and require ExternalId conditions.",
        )
    except Exception as e:
        return _warning("7.1", "Cross-Account Trust Policies",
                        "Identifies IAM roles with trust policies allowing cross-account or wildcard access", "HIGH", e)


def check_inactive_users(session, iam_users, days=_INACTIVE_DAYS):
    """Req 8.2 — No IAM users have been inactive for more than 90 days."""
    try:
        iam = session.client("iam")
        now = datetime.now(timezone.utc)
        inactive = []

        for user in iam_users:
            username = user["UserName"]

            # Skip users created within the inactivity threshold — they're new, not inactive
            created = user.get("CreateDate")
            if created and (now - created).days < days:
                continue

            last_activity = user.get("PasswordLastUsed")

            try:
                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                for key in keys:
                    if key.get("Status") != "Active":
                        continue
                    try:
                        last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                        key_last = last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                        if key_last and (last_activity is None or key_last > last_activity):
                            last_activity = key_last
                    except ClientError:
                        pass
            except ClientError:
                pass

            if last_activity is None:
                inactive.append({"user": username, "days_inactive": "Never used"})
            elif (now - last_activity).days > days:
                inactive.append({"user": username, "days_inactive": (now - last_activity).days})

        return create_control_result(
            "8.2", "Inactive IAM Users",
            f"Verifies no IAM users have been inactive for more than {days} days",
            "PASS" if not inactive else "FAIL",
            "HIGH",
            {
                "users_checked": len(iam_users),
                "inactive_count": len(inactive),
                "inactive_users": inactive[:20],
            },
            None if not inactive else
            f"Disable or remove {len(inactive)} inactive IAM user(s). Inactive accounts increase the attack surface.",
        )
    except Exception as e:
        return _warning("8.2", "Inactive IAM Users",
                        f"Verifies no IAM users have been inactive for more than {days} days", "HIGH", e)


def check_password_policy(session):
    """Req 8.3 — Account password policy enforces minimum length (12+), complexity, and 90-day expiration."""
    try:
        iam = session.client("iam")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return create_control_result(
                    "8.3", "Password Policy",
                    "Verifies account password policy meets PCI-DSS requirements",
                    "FAIL", "HIGH",
                    {"policy_exists": False},
                    "Create an account password policy with minimum length 12, complexity requirements, and 90-day expiration.",
                )
            raise

        issues = []
        notes = []
        min_len = policy.get("MinimumPasswordLength", 0)
        if min_len < _MIN_PASSWORD_LENGTH:
            issues.append(f"Minimum length {min_len} is below {_MIN_PASSWORD_LENGTH}")
        if not policy.get("RequireUppercaseCharacters"):
            issues.append("Uppercase characters not required")
        if not policy.get("RequireLowercaseCharacters"):
            issues.append("Lowercase characters not required")
        if not policy.get("RequireNumbers"):
            issues.append("Numbers not required")
        if not policy.get("RequireSymbols"):
            issues.append("Symbols not required")
        if not policy.get("ExpirePasswords"):
            # PCI-DSS v4.0 allows no expiry if MFA is enforced for all users
            notes.append("Password expiration not enabled (acceptable under PCI-DSS v4.0 if MFA is enforced for all users)")
        elif policy.get("MaxPasswordAge", 999) > 90:
            notes.append(f"Max password age {policy.get('MaxPasswordAge')} exceeds 90 days (acceptable under PCI-DSS v4.0 if MFA is enforced for all users)")

        return create_control_result(
            "8.3", "Password Policy",
            "Verifies account password policy meets PCI-DSS requirements",
            "PASS" if not issues else "FAIL",
            "HIGH",
            {
                "policy": {
                    "minimum_length": min_len,
                    "require_uppercase": policy.get("RequireUppercaseCharacters", False),
                    "require_lowercase": policy.get("RequireLowercaseCharacters", False),
                    "require_numbers": policy.get("RequireNumbers", False),
                    "require_symbols": policy.get("RequireSymbols", False),
                    "expire_passwords": policy.get("ExpirePasswords", False),
                    "max_password_age": policy.get("MaxPasswordAge"),
                    "password_reuse_prevention": policy.get("PasswordReusePrevention"),
                },
                "issues": issues,
                "notes": notes,
                "v4_note": "PCI-DSS v4.0 (Req 8.3.9) allows longer or no password expiry if multi-factor authentication is enforced for all users.",
            },
            None if not issues else
            f"Update password policy to fix: {'; '.join(issues)}.",
        )
    except Exception as e:
        return _warning("8.3", "Password Policy",
                        "Verifies account password policy meets PCI-DSS requirements", "HIGH", e)


def check_iam_access_analyzer(session, regions):
    """Req 7.2 — IAM Access Analyzer is active in all enabled regions."""
    try:
        inactive_regions = []

        def check_region(region):
            try:
                aa = session.client("accessanalyzer", region_name=region)
                analyzers = aa.list_analyzers(Type="ACCOUNT")["analyzers"]
                has_active = any(a.get("status") == "ACTIVE" for a in analyzers)
                return None if has_active else region
            except ClientError:
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for result in pool.map(check_region, regions):
                if result:
                    inactive_regions.append(result)

        return create_control_result(
            "7.2", "IAM Access Analyzer",
            "Verifies IAM Access Analyzer is active in all enabled regions",
            "PASS" if not inactive_regions else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_analyzer_count": len(inactive_regions),
                "regions_without_analyzer": inactive_regions,
            },
            None if not inactive_regions else
            f"Enable IAM Access Analyzer in {len(inactive_regions)} region(s) to detect overly broad resource access.",
        )
    except Exception as e:
        return _warning("7.2", "IAM Access Analyzer",
                        "Verifies IAM Access Analyzer is active in all enabled regions", "HIGH", e)


def check_secrets_rotation(session, regions):
    """Req 8.3 — All Secrets Manager secrets have automatic rotation enabled."""
    try:
        non_rotating = []

        def check_region(region):
            result = []
            try:
                sm = session.client("secretsmanager", region_name=region)
                paginator = sm.get_paginator("list_secrets")
                for page in paginator.paginate():
                    for secret in page.get("SecretList", []):
                        if not secret.get("RotationEnabled", False):
                            result.append({
                                "secret_name": secret["Name"],
                                "secret_arn": secret.get("ARN"),
                                "region": region,
                            })
            except Exception:
                pass
            return result

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for region_result in pool.map(check_region, regions):
                non_rotating.extend(region_result)

        return create_control_result(
            "8.3", "Secrets Manager Rotation",
            "Verifies all Secrets Manager secrets have automatic rotation enabled",
            "PASS" if not non_rotating else "FAIL",
            "HIGH",
            {
                "non_rotating_count": len(non_rotating),
                "non_rotating_secrets": non_rotating[:20],
            },
            None if not non_rotating else
            f"Enable automatic rotation on {len(non_rotating)} secret(s) to prevent use of long-lived static credentials.",
        )
    except Exception as e:
        return _warning("8.3", "Secrets Manager Rotation",
                        "Verifies all Secrets Manager secrets have automatic rotation enabled", "HIGH", e)


def check_secrets_rotation_success(session, regions):
    """Req 8.3 — Secrets with rotation enabled have actually rotated recently."""
    try:
        stale = []
        now = datetime.now(timezone.utc)

        def check_region(region):
            result = []
            try:
                sm = session.client("secretsmanager", region_name=region)
                paginator = sm.get_paginator("list_secrets")
                for page in paginator.paginate():
                    for secret in page.get("SecretList", []):
                        if not secret.get("RotationEnabled", False):
                            continue
                        last_rotated = secret.get("LastRotatedDate")
                        if last_rotated:
                            age_days = (now - last_rotated).days
                            if age_days > _KEY_ROTATION_DAYS:
                                result.append({
                                    "secret_name": secret["Name"],
                                    "region": region,
                                    "last_rotated_days_ago": age_days,
                                })
                        else:
                            # Rotation enabled but never rotated
                            result.append({
                                "secret_name": secret["Name"],
                                "region": region,
                                "last_rotated_days_ago": "never",
                            })
            except Exception:
                pass
            return result

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for region_result in pool.map(check_region, regions):
                stale.extend(region_result)

        return create_control_result(
            "8.3", "Secrets Rotation Success",
            "Verifies secrets with rotation enabled have actually rotated within 90 days",
            "PASS" if not stale else "FAIL",
            "HIGH",
            {
                "stale_rotation_count": len(stale),
                "stale_secrets": stale[:20],
                "note": "Secrets with RotationEnabled=True but LastRotatedDate older than 90 days likely have a broken rotation Lambda.",
            },
            None if not stale else
            f"Investigate rotation failures on {len(stale)} secret(s). Check the rotation Lambda function logs for errors.",
        )
    except Exception as e:
        return _warning("8.3", "Secrets Rotation Success",
                        "Verifies secrets with rotation enabled have actually rotated within 90 days", "HIGH", e)


def check_shared_iam_users(session, iam_users):
    """Req 8.2 — No IAM users appear to be shared accounts."""
    _ADMIN_ARNS = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
    }
    try:
        iam = session.client("iam")
        shared_patterns = re.compile(
            r"^(admin|shared|generic|service|team|common|test|dev|ops|deploy|cicd|automation|root|default)$",
            re.IGNORECASE,
        )

        suspects = []
        for user in iam_users:
            username = user["UserName"]
            reasons = []

            # Signal 1: name matches shared account pattern
            if shared_patterns.match(username):
                reasons.append("name matches shared account pattern")

            try:
                # Signal 2: has both console access AND access keys (dual access)
                has_console = False
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchEntity":
                        raise

                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                has_active_keys = any(k["Status"] == "Active" for k in keys)

                if has_console and has_active_keys:
                    reasons.append("has both console access and active access keys")

                    # Signal 3: admin policy attached on top of dual access
                    attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
                    admin_policies = [p["PolicyArn"] for p in attached if p["PolicyArn"] in _ADMIN_ARNS]
                    if admin_policies:
                        reasons.append(f"admin policy attached: {admin_policies[0]}")
            except ClientError:
                pass

            if reasons:
                suspects.append({
                    "user": username,
                    "reasons": reasons,
                    "signal_count": len(reasons),
                })

        return create_control_result(
            "8.2", "No Shared IAM Users",
            "Verifies no IAM users appear to be shared accounts",
            "PASS" if not suspects else "FAIL",
            "MEDIUM",
            {
                "users_checked": len(iam_users),
                "suspects_count": len(suspects),
                "suspects": suspects[:20],
                "note": "Detection uses naming patterns, dual-access signals (console + access keys), and admin policy presence. "
                        "Users matching multiple signals are higher confidence.",
            },
            None if not suspects else
            f"Review {len(suspects)} IAM user(s) flagged as potential shared accounts. PCI-DSS requires unique user IDs for all individuals.",
        )
    except Exception as e:
        return _warning("8.2", "No Shared IAM Users",
                        "Verifies no IAM users appear to be shared accounts", "MEDIUM", e)


# ===================== LOGGING AND MONITORING (Req 10 & 11) =====================


def check_cloudtrail_logging(session, trails):
    """Req 10.2 — At least one CloudTrail trail is actively logging."""
    try:
        if not trails:
            return create_control_result(
                "10.2", "CloudTrail Logging",
                "Verifies at least one CloudTrail trail is actively logging",
                "FAIL", "CRITICAL",
                {"total_trails": 0},
                "Create and enable a CloudTrail trail immediately. CloudTrail is required for PCI-DSS audit logging.",
            )

        ct = session.client("cloudtrail")
        active = []
        inactive = []
        for trail in trails:
            try:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                if status.get("IsLogging"):
                    active.append(trail["Name"])
                else:
                    inactive.append(trail["Name"])
            except ClientError:
                inactive.append(trail["Name"])

        # FAIL only if no trails are active at all — inactive trails alongside active ones are a WARNING
        has_active = len(active) > 0
        status = "FAIL" if not has_active else ("WARNING" if inactive else "PASS")
        if not has_active:
            rec = "Enable logging on at least one CloudTrail trail."
        elif inactive:
            rec = f"Enable logging on {len(inactive)} disabled trail(s): {', '.join(inactive[:5])}. Disabled trails create audit gaps even when other trails are active."
        else:
            rec = None

        return create_control_result(
            "10.2", "CloudTrail Logging",
            "Verifies all CloudTrail trails are actively logging",
            status,
            "CRITICAL",
            {
                "total_trails": len(trails),
                "active_trails": active,
                "inactive_trails": inactive,
            },
            rec,
        )
    except Exception as e:
        return _warning("10.2", "CloudTrail Logging",
                        "Verifies at least one CloudTrail trail is actively logging", "CRITICAL", e)


def check_cloudtrail_multiregion(trails):
    """Req 10.2 — At least one multi-region CloudTrail trail is configured."""
    try:
        multi_region = [t["Name"] for t in trails if t.get("IsMultiRegionTrail")]

        return create_control_result(
            "10.2", "CloudTrail Multi-Region",
            "Verifies at least one multi-region CloudTrail trail is configured",
            "PASS" if multi_region else "FAIL",
            "HIGH",
            {
                "total_trails": len(trails),
                "multi_region_trails": multi_region,
            },
            None if multi_region else
            "Configure at least one multi-region CloudTrail trail to capture API activity in all AWS regions.",
        )
    except Exception as e:
        return _warning("10.2", "CloudTrail Multi-Region",
                        "Verifies at least one multi-region CloudTrail trail is configured", "HIGH", e)


def check_cloudtrail_validation(trails):
    """Req 10.5 — All CloudTrail trails have log file integrity validation enabled."""
    try:
        no_validation = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]

        return create_control_result(
            "10.5", "CloudTrail Log File Validation",
            "Verifies all CloudTrail trails have log file integrity validation enabled",
            "PASS" if not no_validation else "FAIL",
            "HIGH",
            {
                "total_trails": len(trails),
                "trails_without_validation": no_validation,
            },
            None if not no_validation else
            f"Enable log file validation on {len(no_validation)} trail(s) to ensure log integrity.",
        )
    except Exception as e:
        return _warning("10.5", "CloudTrail Log File Validation",
                        "Verifies all CloudTrail trails have log file integrity validation enabled", "HIGH", e)


def check_cloudtrail_encryption(session, trails):
    """Req 10.5 — All CloudTrail trails store logs encrypted with KMS."""
    try:
        ct = session.client("cloudtrail")
        unencrypted = []

        for trail in trails:
            try:
                detail = ct.get_trail(Name=trail["TrailARN"])["Trail"]
                if not detail.get("KmsKeyId"):
                    unencrypted.append(trail["Name"])
            except ClientError:
                pass

        return create_control_result(
            "10.5", "CloudTrail Log Encryption",
            "Verifies all CloudTrail trails store logs encrypted with KMS",
            "PASS" if not unencrypted else "FAIL",
            "MEDIUM",
            {
                "total_trails": len(trails),
                "unencrypted_trails": unencrypted,
            },
            None if not unencrypted else
            f"Enable KMS encryption on {len(unencrypted)} CloudTrail trail(s).",
        )
    except Exception as e:
        return _warning("10.5", "CloudTrail Log Encryption",
                        "Verifies all CloudTrail trails store logs encrypted with KMS", "MEDIUM", e)


def check_cloudtrail_s3_data_events(session, trails):
    """Req 10.2 — At least one CloudTrail trail captures S3 object-level read and write data events."""
    try:
        if not trails:
            return create_control_result(
                "10.2", "CloudTrail S3 Data Events",
                "Verifies CloudTrail captures S3 object-level data events",
                "FAIL", "HIGH",
                {"total_trails": 0},
                "Enable a CloudTrail trail with S3 data events to audit access to cardholder data.",
            )

        ct = session.client("cloudtrail")
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
            status = "FAIL"
            recommendation = (
                "S3 data events are configured but do not satisfy both requirements: "
                "ReadWriteType=All AND scope covering all S3 buckets (arn:aws:s3 prefix). "
                "A single-bucket or read-only trail is insufficient for PCI-DSS audit coverage."
            )
        else:
            status = "FAIL"
            recommendation = "Enable S3 data events on at least one CloudTrail trail to audit access to cardholder data."

        return create_control_result(
            "10.2", "CloudTrail S3 Data Events",
            "Verifies CloudTrail captures S3 object-level data events",
            status, "HIGH",
            {
                "total_trails": len(trails),
                "any_s3_data_events_configured": any_s3_events,
                "read_write_coverage": any_rw,
                "trails_with_s3_data_events": trail_details,
            },
            recommendation,
        )
    except Exception as e:
        return _warning("10.2", "CloudTrail S3 Data Events",
                        "Verifies CloudTrail captures S3 object-level data events", "HIGH", e)


def check_cloudtrail_s3_not_public(session, trails):
    """Req 10.5 — The S3 bucket storing CloudTrail logs is not publicly accessible."""
    try:
        s3 = session.client("s3")
        public_buckets = []

        for trail in trails:
            bucket_name = trail.get("S3BucketName")
            if not bucket_name:
                continue
            try:
                block = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
                if not all([
                    block.get("BlockPublicAcls", False),
                    block.get("IgnorePublicAcls", False),
                    block.get("BlockPublicPolicy", False),
                    block.get("RestrictPublicBuckets", False),
                ]):
                    public_buckets.append({"trail": trail["Name"], "bucket": bucket_name})
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "NoSuchPublicAccessBlockConfiguration":
                    public_buckets.append({"trail": trail["Name"], "bucket": bucket_name})

        return create_control_result(
            "10.5", "CloudTrail S3 Bucket Not Public",
            "Verifies the S3 bucket storing CloudTrail logs is not publicly accessible",
            "PASS" if not public_buckets else "FAIL",
            "HIGH",
            {
                "trails_checked": len(trails),
                "public_trail_buckets": public_buckets,
            },
            None if not public_buckets else
            f"Enable public access block on {len(public_buckets)} CloudTrail log bucket(s). Audit logs must be protected from unauthorized access.",
        )
    except Exception as e:
        return _warning("10.5", "CloudTrail S3 Bucket Not Public",
                        "Verifies the S3 bucket storing CloudTrail logs is not publicly accessible", "HIGH", e)


def check_cloudtrail_log_retention(session, trails, min_days=_CT_RETENTION_DAYS):
    """Req 10.7 — CloudTrail log S3 buckets retain logs for at least 12 months."""
    try:
        s3 = session.client("s3")
        short_retention = []

        for trail in trails:
            bucket_name = trail.get("S3BucketName")
            if not bucket_name:
                continue
            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                for rule in lifecycle.get("Rules", []):
                    if rule.get("Status") != "Enabled":
                        continue
                    expiration = rule.get("Expiration", {})
                    exp_days = expiration.get("Days", 0)
                    exp_date = expiration.get("Date")
                    if exp_date:
                        # Date-based expiration: compute days from now
                        from datetime import timezone as _tz
                        exp_dt = exp_date if hasattr(exp_date, "tzinfo") else exp_date.replace(tzinfo=_tz.utc)
                        delta = (exp_dt - datetime.now(_tz.utc)).days
                        exp_days = max(delta, 0)
                    if 0 < exp_days < min_days:
                        short_retention.append({
                            "trail": trail["Name"],
                            "bucket": bucket_name,
                            "retention_days": exp_days,
                        })
                        break
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "NoSuchLifecycleConfiguration":
                    pass  # No lifecycle = logs retained indefinitely = PASS
                elif code not in ("AccessDenied", "AccessDeniedException"):
                    raise

        return create_control_result(
            "10.7", "CloudTrail Log Retention",
            f"Verifies CloudTrail log S3 buckets retain logs for at least {min_days} days",
            "PASS" if not short_retention else "FAIL",
            "HIGH",
            {
                "trails_checked": len(trails),
                "short_retention": short_retention,
                "note": f"PCI-DSS requires 12 months retention. Buckets without lifecycle policies retain logs indefinitely.",
            },
            None if not short_retention else
            f"Extend log retention to at least {min_days} days on {len(short_retention)} CloudTrail bucket(s).",
        )
    except Exception as e:
        return _warning("10.7", "CloudTrail Log Retention",
                        f"Verifies CloudTrail log S3 buckets retain logs for at least {min_days} days", "HIGH", e)


def check_vpc_flow_log_retention(session, vpcs):
    """Req 10.7 — VPC flow logs deliver to destinations with adequate retention (365+ days)."""
    try:
        if not vpcs:
            return create_control_result(
                "10.7", "VPC Flow Log Retention",
                "Verifies VPC flow logs have adequate retention",
                "PASS", "HIGH", {"total_vpcs": 0, "short_retention": []},
            )

        short_retention = []
        vpcs_by_region = {}
        for vpc in vpcs:
            region = vpc.get("_region", "us-east-1")
            vpcs_by_region.setdefault(region, []).append(vpc)

        for region, region_vpcs in vpcs_by_region.items():
            try:
                ec2 = session.client("ec2", region_name=region)
                vpc_ids = [v["VpcId"] for v in region_vpcs]
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": vpc_ids}]
                ).get("FlowLogs", [])

                for fl in flow_logs:
                    if fl.get("FlowLogStatus") != "ACTIVE":
                        continue
                    dest_type = fl.get("LogDestinationType", "cloud-watch-logs")
                    log_group = fl.get("LogGroupName", "")

                    if dest_type == "cloud-watch-logs" and log_group:
                        try:
                            logs = session.client("logs", region_name=region)
                            groups = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"]
                            for g in groups:
                                if g["logGroupName"] == log_group:
                                    retention = g.get("retentionInDays")
                                    if retention and retention < _LOG_RETENTION_DAYS:
                                        short_retention.append({
                                            "vpc_id": fl.get("ResourceId"),
                                            "flow_log_id": fl.get("FlowLogId"),
                                            "destination": log_group,
                                            "destination_type": "CloudWatch",
                                            "retention_days": retention,
                                            "region": region,
                                        })
                                    break
                        except ClientError:
                            pass
            except ClientError:
                pass

        return create_control_result(
            "10.7", "VPC Flow Log Retention",
            "Verifies VPC flow logs have adequate retention (365+ days)",
            "PASS" if not short_retention else "FAIL",
            "HIGH",
            {
                "short_retention_count": len(short_retention),
                "short_retention": short_retention[:20],
                "minimum_days": _LOG_RETENTION_DAYS,
                "note": "Checks CloudWatch log group retention for flow logs using cloud-watch-logs destination. "
                        "S3-destination flow logs are not checked (retention is managed via S3 lifecycle).",
            },
            None if not short_retention else
            f"Extend retention to at least {_LOG_RETENTION_DAYS} days on {len(short_retention)} flow log destination(s).",
        )
    except Exception as e:
        return _warning("10.7", "VPC Flow Log Retention",
                        "Verifies VPC flow logs have adequate retention", "HIGH", e)


def check_rds_audit_logging(session, rds_instances):
    """Req 10.2 — RDS instances have database audit logging enabled."""
    try:
        if not rds_instances:
            return create_control_result(
                "10.2", "RDS Audit Logging",
                "Verifies RDS instances have audit/connection logging enabled",
                "PASS", "HIGH", {"total_instances": 0, "non_compliant": []},
            )

        # Engine-specific logging parameters
        _LOGGING_PARAMS = {
            "mysql": [("general_log", "1"), ("audit_log", "ON")],
            "postgres": [("log_connections", "1"), ("log_disconnections", "1")],
            "oracle": [("audit_trail", "db"), ("audit_trail", "os"), ("audit_trail", "db,extended")],
            "sqlserver": [],  # SQL Server uses RDS option groups, not parameter groups
        }

        non_compliant = []
        for db in rds_instances:
            region = db.get("_region", "us-east-1")
            engine = db.get("Engine", "").lower()
            db_id = db["DBInstanceIdentifier"]

            # Determine engine family
            if engine.startswith("aurora-mysql") or engine == "mysql" or engine == "mariadb":
                engine_family = "mysql"
            elif engine.startswith("aurora-postgres") or engine == "postgres":
                engine_family = "postgres"
            elif "oracle" in engine:
                engine_family = "oracle"
            elif "sqlserver" in engine:
                engine_family = "sqlserver"
            else:
                continue  # Unknown engine, skip

            expected_params = _LOGGING_PARAMS.get(engine_family, [])
            if not expected_params:
                continue  # SQL Server uses option groups, skip

            try:
                rds = session.client("rds", region_name=region)

                # For Aurora, check cluster parameter group; for standard RDS, instance parameter group
                if engine.startswith("aurora"):
                    cluster_id = db.get("DBClusterIdentifier")
                    if not cluster_id:
                        continue
                    clusters = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"]
                    pg_name = clusters[0].get("DBClusterParameterGroup", "") if clusters else ""
                else:
                    pg_groups = db.get("DBParameterGroups", [])
                    pg_name = pg_groups[0]["DBParameterGroupName"] if pg_groups else ""

                if not pg_name:
                    non_compliant.append({"db_instance_id": db_id, "engine": engine, "region": region, "reason": "no_parameter_group"})
                    continue

                logging_found = False
                for page in rds.get_paginator("describe_db_parameters").paginate(DBParameterGroupName=pg_name):
                    for param in page.get("Parameters", []):
                        pname = param.get("ParameterName", "")
                        pval = param.get("ParameterValue", "")
                        if any(pname == ep and pval == ev for ep, ev in expected_params):
                            logging_found = True
                            break
                    if logging_found:
                        break

                if not logging_found:
                    non_compliant.append({"db_instance_id": db_id, "engine": engine, "region": region, "reason": "logging_not_enabled"})
            except ClientError:
                pass

        return create_control_result(
            "10.2", "RDS Audit Logging",
            "Verifies RDS instances have audit/connection logging enabled",
            "PASS" if not non_compliant else "FAIL",
            "HIGH",
            {
                "total_instances": len(rds_instances),
                "non_compliant_count": len(non_compliant),
                "non_compliant": non_compliant[:20],
                "note": "Checks general_log/audit_log (MySQL), log_connections (PostgreSQL), audit_trail (Oracle). "
                        "SQL Server instances are skipped (uses RDS option groups). Aurora checks cluster parameter groups.",
            },
            None if not non_compliant else
            f"Enable audit logging on {len(non_compliant)} RDS instance(s). Set appropriate logging parameters in the parameter group.",
        )
    except Exception as e:
        return _warning("10.2", "RDS Audit Logging",
                        "Verifies RDS instances have audit/connection logging enabled", "HIGH", e)


def check_cloudwatch_alarms(session, regions, active_regions=None):
    """Req 10.6 — CloudWatch alarms configured in all active regions.

    If *active_regions* (regions that contain resources) is provided, regions
    without alarms are split into two buckets: active regions without alarms
    cause a FAIL, while inactive regions without alarms are reported as
    informational only.  When *active_regions* is ``None`` every region is
    treated as active (backwards-compatible).
    """
    try:
        total_alarm_count = 0
        regions_without_alarms = []

        def check_region(region):
            try:
                cw = session.client("cloudwatch", region_name=region)
                paginator = cw.get_paginator("describe_alarms")
                count = 0
                for page in paginator.paginate():
                    count += len(page.get("MetricAlarms", []))
                return region, count
            except ClientError:
                return region, 0

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for region, count in pool.map(check_region, regions):
                total_alarm_count += count
                if count == 0:
                    regions_without_alarms.append(region)

        if active_regions is not None:
            active_set = set(active_regions)
            active_without = [r for r in regions_without_alarms if r in active_set]
            inactive_without = [r for r in regions_without_alarms if r not in active_set]
        else:
            active_without = regions_without_alarms
            inactive_without = []

        status = "PASS" if not active_without else "FAIL"

        return create_control_result(
            "10.6", "CloudWatch Alarms",
            "Verifies CloudWatch alarms are configured in all regions with active resources",
            status,
            "MEDIUM",
            {
                "alarm_count": total_alarm_count,
                "regions_checked": len(regions),
                "active_regions_without_alarms": active_without,
                "inactive_regions_without_alarms": inactive_without,
            },
            None if status == "PASS" else
            f"Configure CloudWatch alarms in {len(active_without)} active region(s) for security-relevant events: root login, unauthorized API calls, security group changes.",
        )
    except Exception as e:
        return _warning("10.6", "CloudWatch Alarms",
                        "Verifies CloudWatch alarms are configured in all regions with active resources", "MEDIUM", e)


def check_cloudwatch_security_alarms(session, regions=None):
    """Req 10.6 — CloudWatch alarms exist for security-relevant events."""
    _REQUIRED_PATTERNS = {
        "root_login": ["rootaccount", "root-login", "root-account", "rootsignin", "consolelogin"],
        "unauthorized_api": ["unauthorizedapi", "unauthorized-api", "accessdenied", "unauthorized"],
        "security_group_changes": ["securitygroup", "security-group", "sgchanges"],
        "iam_changes": ["iamchanges", "iam-changes", "iampolicy"],
    }
    try:
        alarms = []
        query_regions = regions if regions else ["us-east-1"]
        for region in query_regions:
            try:
                cw = session.client("cloudwatch", region_name=region)
                for page in cw.get_paginator("describe_alarms").paginate():
                    alarms.extend(page.get("MetricAlarms", []))
            except Exception:
                pass

        alarm_names_lower = [a.get("AlarmName", "").lower().replace(" ", "") for a in alarms]
        alarm_metrics = [(a.get("Namespace", ""), a.get("MetricName", "")) for a in alarms]

        missing_categories = []
        matched_categories = []
        for category, patterns in _REQUIRED_PATTERNS.items():
            found = False
            for name in alarm_names_lower:
                if any(p in name for p in patterns):
                    found = True
                    break
            if not found:
                # Also check metric filter names
                for ns, metric in alarm_metrics:
                    metric_lower = metric.lower().replace(" ", "")
                    if any(p in metric_lower for p in patterns):
                        found = True
                        break
            if found:
                matched_categories.append(category)
            else:
                missing_categories.append(category)

        return create_control_result(
            "10.6", "Security-Relevant CloudWatch Alarms",
            "Verifies CloudWatch alarms exist for key security events (root login, unauthorized API, SG changes, IAM changes)",
            "PASS" if not missing_categories else "FAIL",
            "HIGH",
            {
                "total_alarms": len(alarms),
                "required_categories": list(_REQUIRED_PATTERNS.keys()),
                "matched_categories": matched_categories,
                "missing_categories": missing_categories,
                "note": "Matches alarm names and metric names against known patterns. "
                        "Custom naming conventions may not be detected.",
            },
            None if not missing_categories else
            f"Create CloudWatch alarms for: {', '.join(missing_categories)}. PCI-DSS Req 10.6 requires alerting on specific security events.",
        )
    except Exception as e:
        return _warning("10.6", "Security-Relevant CloudWatch Alarms",
                        "Verifies CloudWatch alarms exist for key security events", "HIGH", e)


def check_cloudwatch_log_retention(session, regions):
    """Req 10.7 — All CloudWatch log groups retain logs for at least 365 days."""
    try:
        short_retention = []

        def check_region(region):
            result = []
            try:
                logs = session.client("logs", region_name=region)
                paginator = logs.get_paginator("describe_log_groups")
                for page in paginator.paginate():
                    for lg in page.get("logGroups", []):
                        retention = lg.get("retentionInDays")
                        if retention is not None and retention < _LOG_RETENTION_DAYS:
                            result.append({
                                "log_group": lg["logGroupName"],
                                "retention_days": retention,
                                "region": region,
                            })
            except Exception:
                pass
            return result

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for region_result in pool.map(check_region, regions):
                short_retention.extend(region_result)

        return create_control_result(
            "10.7", "CloudWatch Log Retention",
            f"Verifies all CloudWatch log groups retain logs for at least {_LOG_RETENTION_DAYS} days",
            "PASS" if not short_retention else "FAIL",
            "HIGH",
            {
                "short_retention_count": len(short_retention),
                "short_retention_groups": short_retention[:20],
                "note": "Log groups without an explicit retention policy retain logs indefinitely and are compliant.",
            },
            None if not short_retention else
            f"Extend retention to at least {_LOG_RETENTION_DAYS} days on {len(short_retention)} log group(s).",
        )
    except Exception as e:
        return _warning("10.7", "CloudWatch Log Retention",
                        f"Verifies all CloudWatch log groups retain logs for at least {_LOG_RETENTION_DAYS} days", "HIGH", e)


def check_aws_config(session, regions):
    """Req 10.2 — AWS Config is recording in all enabled regions."""
    try:
        disabled_regions = []

        def check_region(region):
            try:
                cfg = session.client("config", region_name=region)
                recorders = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
                if not recorders:
                    return region
                statuses = cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
                if not any(s.get("recording") for s in statuses):
                    return region
                return None
            except ClientError:
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for result in pool.map(check_region, regions):
                if result:
                    disabled_regions.append(result)

        return create_control_result(
            "10.2", "AWS Config",
            "Verifies AWS Config is recording in all enabled regions",
            "PASS" if not disabled_regions else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_config_count": len(disabled_regions),
                "regions_without_config": disabled_regions,
            },
            None if not disabled_regions else
            f"Enable AWS Config recording in {len(disabled_regions)} region(s): {', '.join(disabled_regions[:5])}.",
        )
    except Exception as e:
        return _warning("10.2", "AWS Config",
                        "Verifies AWS Config is recording in all enabled regions", "HIGH", e)


def check_guardduty(session, regions):
    """Req 11.5 — GuardDuty threat detection is active in all enabled regions."""
    try:
        disabled_regions = []

        def check_region(region):
            try:
                gd = session.client("guardduty", region_name=region)
                detectors = gd.list_detectors()["DetectorIds"]
                if not detectors:
                    return region
                for did in detectors:
                    det = gd.get_detector(DetectorId=did)
                    if det.get("Status") == "ENABLED":
                        return None
                return region
            except ClientError:
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for result in pool.map(check_region, regions):
                if result:
                    disabled_regions.append(result)

        return create_control_result(
            "11.5", "GuardDuty Enabled",
            "Verifies GuardDuty threat detection is active in all enabled regions",
            "PASS" if not disabled_regions else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_guardduty_count": len(disabled_regions),
                "regions_without_guardduty": disabled_regions,
            },
            None if not disabled_regions else
            f"Enable GuardDuty in {len(disabled_regions)} region(s): {', '.join(disabled_regions[:5])}.",
        )
    except Exception as e:
        return _warning("11.5", "GuardDuty Enabled",
                        "Verifies GuardDuty threat detection is active in all enabled regions", "HIGH", e)


def check_security_hub(session, regions):
    """Req 10.6 — AWS Security Hub is enabled across all active regions."""
    try:
        disabled_regions = []

        def check_region(region):
            try:
                sh = session.client("securityhub", region_name=region)
                sh.describe_hub()
                return None
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("InvalidAccessException", "NotFoundException"):
                    return region
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for result in pool.map(check_region, regions):
                if result:
                    disabled_regions.append(result)

        return create_control_result(
            "10.6", "Security Hub Enabled",
            "Verifies AWS Security Hub is enabled across all active regions",
            "PASS" if not disabled_regions else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_security_hub_count": len(disabled_regions),
                "regions_without_security_hub": disabled_regions,
            },
            None if not disabled_regions else
            f"Enable Security Hub in {len(disabled_regions)} region(s) for centralised security findings and PCI-DSS compliance scoring.",
        )
    except Exception as e:
        return _warning("10.6", "Security Hub Enabled",
                        "Verifies AWS Security Hub is enabled across all active regions", "HIGH", e)


def check_security_hub_pci_standard(session, regions):
    """Req 10.6 — Security Hub has the PCI-DSS compliance standard enabled."""
    try:
        _PCI_ARN_PATTERN = "pci-dss"
        regions_without_pci = []

        def check_region(region):
            try:
                sh = session.client("securityhub", region_name=region)
                # First verify hub is enabled
                try:
                    sh.describe_hub()
                except ClientError:
                    return None  # Hub not enabled — covered by check_security_hub

                # Check enabled standards
                standards = []
                kwargs = {}
                while True:
                    resp = sh.get_enabled_standards(**kwargs)
                    standards.extend(resp.get("StandardsSubscriptions", []))
                    next_token = resp.get("NextToken")
                    if not next_token:
                        break
                    kwargs["NextToken"] = next_token

                pci_enabled = any(
                    _PCI_ARN_PATTERN in s.get("StandardsArn", "").lower()
                    for s in standards
                    if s.get("StandardsStatus") in ("READY", "INCOMPLETE")
                )
                if not pci_enabled:
                    return region
                return None
            except ClientError:
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for result in pool.map(check_region, regions):
                if result:
                    regions_without_pci.append(result)

        return create_control_result(
            "10.6", "Security Hub PCI-DSS Standard",
            "Verifies the PCI-DSS compliance standard is enabled in Security Hub",
            "PASS" if not regions_without_pci else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_pci_standard_count": len(regions_without_pci),
                "regions_without_pci_standard": regions_without_pci,
                "note": "Only checks regions where Security Hub is enabled. "
                        "Regions without Security Hub are reported by the 'Security Hub Enabled' check.",
            },
            None if not regions_without_pci else
            f"Enable the PCI-DSS compliance standard in Security Hub in {len(regions_without_pci)} region(s).",
        )
    except Exception as e:
        return _warning("10.6", "Security Hub PCI-DSS Standard",
                        "Verifies the PCI-DSS compliance standard is enabled in Security Hub", "HIGH", e)


def check_aws_config_completeness(session, regions):
    """Req 10.2 — AWS Config records all resource types and has at least one Config rule."""
    try:
        incomplete_regions = []

        def check_region(region):
            try:
                cfg = session.client("config", region_name=region)
                recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
                if not recorders:
                    return None  # No recorder — covered by check_aws_config

                recorder = recorders[0]
                recording_group = recorder.get("recordingGroup", {})
                all_supported = recording_group.get("allSupported", False)

                # Check recorder status
                statuses = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
                is_recording = any(s.get("recording", False) for s in statuses)
                if not is_recording:
                    return None  # Not recording — covered by check_aws_config

                # Check if all resource types are recorded
                issues = []
                if not all_supported:
                    resource_types = recording_group.get("resourceTypes", [])
                    issues.append(f"only {len(resource_types)} resource types recorded (allSupported=false)")

                # Check for Config rules
                try:
                    rules = cfg.describe_config_rules().get("ConfigRules", [])
                    if not rules:
                        issues.append("no Config rules deployed")
                except ClientError:
                    pass

                if issues:
                    return {"region": region, "issues": issues}
                return None
            except ClientError:
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for result in pool.map(check_region, regions):
                if result:
                    incomplete_regions.append(result)

        return create_control_result(
            "10.2", "AWS Config Completeness",
            "Verifies AWS Config records all resource types and has Config rules deployed",
            "PASS" if not incomplete_regions else "FAIL",
            "MEDIUM",
            {
                "regions_checked": len(regions),
                "incomplete_regions_count": len(incomplete_regions),
                "incomplete_regions": incomplete_regions[:20],
                "note": "Only checks regions where Config is enabled and recording. "
                        "Regions without Config are reported by the 'AWS Config' check.",
            },
            None if not incomplete_regions else
            f"Fix Config completeness in {len(incomplete_regions)} region(s). Enable allSupported=true and deploy Config rules.",
        )
    except Exception as e:
        return _warning("10.2", "AWS Config Completeness",
                        "Verifies AWS Config records all resource types and has Config rules deployed", "MEDIUM", e)


def check_guardduty_findings_export(session, regions):
    """Req 10.6 — GuardDuty findings are configured for export (not just enabled)."""
    try:
        regions_without_export = []

        def check_region(region):
            try:
                gd = session.client("guardduty", region_name=region)
                detectors = gd.list_detectors().get("DetectorIds", [])
                if not detectors:
                    return None  # Not enabled — covered by check_guardduty

                detector_id = detectors[0]
                try:
                    det = gd.get_detector(DetectorId=detector_id)
                    if det.get("Status") != "ENABLED":
                        return None

                    # Check publishing destination (S3 export)
                    destinations = gd.list_publishing_destinations(DetectorId=detector_id).get("Destinations", [])
                    has_export = any(
                        d.get("Status") in ("PUBLISHING", "UNABLE_TO_PUBLISH_FIX_DESTINATION_PROPERTY")
                        for d in destinations
                    )

                    # Check finding publishing frequency
                    freq = det.get("FindingPublishingFrequency", "SIX_HOURS")
                    if not has_export and freq == "SIX_HOURS":
                        return region  # Default frequency and no export
                    return None
                except ClientError:
                    return None
            except ClientError:
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for result in pool.map(check_region, regions):
                if result:
                    regions_without_export.append(result)

        return create_control_result(
            "10.6", "GuardDuty Findings Export",
            "Verifies GuardDuty findings are configured for export and alerting",
            "PASS" if not regions_without_export else "FAIL",
            "MEDIUM",
            {
                "regions_checked": len(regions),
                "regions_without_export_count": len(regions_without_export),
                "regions_without_export": regions_without_export,
                "note": "Checks for S3 publishing destinations. Regions where GuardDuty is not enabled are excluded.",
            },
            None if not regions_without_export else
            f"Configure finding export in {len(regions_without_export)} region(s). Use S3 publishing destination or EventBridge rules for alerting.",
        )
    except Exception as e:
        return _warning("10.6", "GuardDuty Findings Export",
                        "Verifies GuardDuty findings are configured for export and alerting", "MEDIUM", e)


# ===================== VULNERABILITY MANAGEMENT (Req 5 & 6) =====================


def check_inspector(session, regions, account_id):
    """Req 6.3 — AWS Inspector is enabled for continuous vulnerability scanning of EC2 instances."""
    try:
        disabled_regions = []

        def check_region(region):
            try:
                inspector = session.client("inspector2", region_name=region)
                resp = inspector.batch_get_account_status(accountIds=[account_id])
                accounts = resp.get("accounts", [])
                if not accounts:
                    return region
                for acct in accounts:
                    state = acct.get("state", {}).get("status", "")
                    if state in ("ENABLED", "ENABLING"):
                        return None
                return region
            except ClientError:
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 8))) as pool:
            for result in pool.map(check_region, regions):
                if result:
                    disabled_regions.append(result)

        return create_control_result(
            "6.3", "EC2 Inspector",
            "Verifies AWS Inspector is enabled for continuous vulnerability scanning",
            "PASS" if not disabled_regions else "FAIL",
            "HIGH",
            {
                "regions_checked": len(regions),
                "regions_without_inspector_count": len(disabled_regions),
                "regions_without_inspector": disabled_regions,
            },
            None if not disabled_regions else
            f"Enable AWS Inspector in {len(disabled_regions)} region(s) for continuous vulnerability scanning of EC2 instances.",
        )
    except Exception as e:
        return _warning("6.3", "EC2 Inspector",
                        "Verifies AWS Inspector is enabled for continuous vulnerability scanning", "HIGH", e)


def check_rds_auto_minor_version(rds_instances):
    """Req 6.3 — RDS instances have auto minor version upgrade enabled."""
    try:
        if not rds_instances:
            return create_control_result(
                "6.3", "RDS Auto Minor Version Upgrade",
                "Verifies RDS instances have auto minor version upgrade enabled",
                "PASS", "MEDIUM", {"total_instances": 0, "non_compliant": []},
            )

        non_compliant = [
            {
                "db_instance_id": db["DBInstanceIdentifier"],
                "engine": db.get("Engine"),
                "region": db.get("_region", "unknown"),
            }
            for db in rds_instances if not db.get("AutoMinorVersionUpgrade")
        ]

        return create_control_result(
            "6.3", "RDS Auto Minor Version Upgrade",
            "Verifies RDS instances have auto minor version upgrade enabled",
            "PASS" if not non_compliant else "FAIL",
            "MEDIUM",
            {
                "total_instances": len(rds_instances),
                "non_compliant_count": len(non_compliant),
                "non_compliant": non_compliant[:20],
            },
            None if not non_compliant else
            f"Enable auto minor version upgrade on {len(non_compliant)} RDS instance(s) to receive security patches.",
        )
    except Exception as e:
        return _warning("6.3", "RDS Auto Minor Version Upgrade",
                        "Verifies RDS instances have auto minor version upgrade enabled", "MEDIUM", e)


def check_waf_public_resources(session, regions):
    """Req 6.4 — AWS WAF is associated with public-facing ALBs, API Gateway stages, and CloudFront distributions."""
    try:
        unprotected = []

        def check_region(region):
            result = []
            try:
                elb = session.client("elbv2", region_name=region)
                waf = session.client("wafv2", region_name=region)

                # Check ALBs
                paginator = elb.get_paginator("describe_load_balancers")
                for page in paginator.paginate():
                    for lb in page.get("LoadBalancers", []):
                        if lb.get("Scheme") != "internet-facing":
                            continue
                        lb_arn = lb["LoadBalancerArn"]
                        try:
                            web_acl = waf.get_web_acl_for_resource(ResourceArn=lb_arn)
                            if not web_acl.get("WebACL"):
                                result.append({
                                    "resource_type": "ALB",
                                    "resource_name": lb.get("LoadBalancerName"),
                                    "resource_arn": lb_arn,
                                    "region": region,
                                })
                        except ClientError as e:
                            code = e.response.get("Error", {}).get("Code", "")
                            if code == "WAFNonexistentItemException":
                                result.append({
                                    "resource_type": "ALB",
                                    "resource_name": lb.get("LoadBalancerName"),
                                    "resource_arn": lb_arn,
                                    "region": region,
                                })

                # Check API Gateway stages
                try:
                    apigw = session.client("apigateway", region_name=region)
                    apis = []
                    position = None
                    while True:
                        kwargs = {"limit": 500}
                        if position:
                            kwargs["position"] = position
                        resp = apigw.get_rest_apis(**kwargs)
                        apis.extend(resp.get("items", []))
                        position = resp.get("position")
                        if not position:
                            break
                    for api in apis:
                        api_id = api["id"]
                        api_name = api.get("name", api_id)
                        try:
                            stages = apigw.get_stages(restApiId=api_id).get("item", [])
                            for stage in stages:
                                stage_name = stage.get("stageName", "")
                                stage_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}"
                                try:
                                    web_acl = waf.get_web_acl_for_resource(ResourceArn=stage_arn)
                                    if not web_acl.get("WebACL"):
                                        result.append({
                                            "resource_type": "API Gateway",
                                            "resource_name": f"{api_name}/{stage_name}",
                                            "resource_arn": stage_arn,
                                            "region": region,
                                        })
                                except ClientError as e:
                                    code = e.response.get("Error", {}).get("Code", "")
                                    if code == "WAFNonexistentItemException":
                                        result.append({
                                            "resource_type": "API Gateway",
                                            "resource_name": f"{api_name}/{stage_name}",
                                            "resource_arn": stage_arn,
                                            "region": region,
                                        })
                        except ClientError:
                            pass
                except ClientError:
                    pass
            except Exception:
                pass
            return result

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for region_result in pool.map(check_region, regions):
                unprotected.extend(region_result)

        # Also check CloudFront (global, us-east-1)
        try:
            cf = session.client("cloudfront")
            paginator = cf.get_paginator("list_distributions")
            for page in paginator.paginate():
                for dist in page.get("DistributionList", {}).get("Items", []):
                    web_acl_id = dist.get("WebACLId", "")
                    if not web_acl_id:
                        unprotected.append({
                            "resource_type": "CloudFront",
                            "resource_name": dist.get("DomainName"),
                            "resource_arn": dist.get("ARN"),
                            "region": "global",
                        })
        except Exception:
            pass

        return create_control_result(
            "6.4", "WAF on Public-Facing Resources",
            "Verifies AWS WAF is associated with public-facing ALBs, API Gateway stages, and CloudFront distributions",
            "PASS" if not unprotected else "FAIL",
            "HIGH",
            {
                "unprotected_count": len(unprotected),
                "unprotected_resources": unprotected[:20],
            },
            None if not unprotected else
            f"Associate AWS WAF with {len(unprotected)} unprotected public-facing resource(s) to protect against web application attacks.",
        )
    except Exception as e:
        return _warning("6.4", "WAF on Public-Facing Resources",
                        "Verifies AWS WAF is associated with public-facing load balancers and CloudFront distributions", "HIGH", e)


def check_lambda_runtime_eol(session, regions):
    """Req 6.3 — No Lambda functions use deprecated/EOL runtimes."""
    _EOL_RUNTIMES = {
        "python2.7", "python3.6", "python3.7", "python3.8",
        "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x",
        "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1", "dotnet5.0",
        "ruby2.5",
        "java8", "go1.x",
    }
    try:
        eol_functions = []

        def check_region(region):
            result = []
            try:
                lam = session.client("lambda", region_name=region)
                paginator = lam.get_paginator("list_functions")
                for page in paginator.paginate():
                    for fn in page.get("Functions", []):
                        runtime = fn.get("Runtime", "")
                        if runtime in _EOL_RUNTIMES:
                            result.append({
                                "function_name": fn["FunctionName"],
                                "runtime": runtime,
                                "region": region,
                            })
            except ClientError:
                pass
            return result

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for region_result in pool.map(check_region, regions):
                eol_functions.extend(region_result)

        return create_control_result(
            "6.3", "Lambda Runtime EOL",
            "Verifies no Lambda functions use deprecated or end-of-life runtimes",
            "PASS" if not eol_functions else "FAIL",
            "MEDIUM",
            {
                "eol_functions_count": len(eol_functions),
                "eol_functions": eol_functions[:20],
                "eol_runtimes_checked": sorted(_EOL_RUNTIMES),
            },
            None if not eol_functions else
            f"Upgrade {len(eol_functions)} Lambda function(s) to supported runtimes. EOL runtimes do not receive security patches.",
        )
    except Exception as e:
        return _warning("6.3", "Lambda Runtime EOL",
                        "Verifies no Lambda functions use deprecated or end-of-life runtimes", "MEDIUM", e)


def check_ssm_patch_compliance(session, regions):
    """Req 6.3 — EC2 instances managed by SSM have no missing critical patches."""
    try:
        non_compliant = []

        def check_region(region):
            result = []
            try:
                ssm = session.client("ssm", region_name=region)
                paginator = ssm.get_paginator("describe_instance_patch_states")
                for page in paginator.paginate():
                    for state in page.get("InstancePatchStates", []):
                        missing_critical = state.get("MissingCount", 0)
                        failed = state.get("FailedCount", 0)
                        if missing_critical > 0 or failed > 0:
                            result.append({
                                "instance_id": state["InstanceId"],
                                "missing_patches": missing_critical,
                                "failed_patches": failed,
                                "region": region,
                            })
            except Exception:
                pass
            return result

        with ThreadPoolExecutor(max_workers=max(1, min(len(regions), 10))) as pool:
            for region_result in pool.map(check_region, regions):
                non_compliant.extend(region_result)

        return create_control_result(
            "6.3", "SSM Patch Compliance",
            "Verifies EC2 instances managed by SSM have no missing critical patches",
            "PASS" if not non_compliant else "FAIL",
            "MEDIUM",
            {
                "non_compliant_count": len(non_compliant),
                "non_compliant_instances": non_compliant[:20],
            },
            None if not non_compliant else
            f"Apply missing patches to {len(non_compliant)} instance(s). Use SSM Patch Manager to automate patching.",
        )
    except Exception as e:
        return _warning("6.3", "SSM Patch Compliance",
                        "Verifies EC2 instances managed by SSM have no missing critical patches", "MEDIUM", e)


# ===================== DATA RETENTION & RECOVERY (Req 9 & 12) =====================


def check_s3_access_logging(session, s3_buckets, s3_metadata=None):
    """Req 10.2 — All S3 buckets have server access logging enabled."""
    try:
        if not s3_buckets:
            return create_control_result(
                "10.2", "S3 Access Logging",
                "Verifies all S3 buckets have server access logging enabled",
                "PASS", "MEDIUM", {"total_buckets": 0, "buckets_without_logging": []},
            )

        no_logging = []
        s3 = session.client("s3") if not s3_metadata else None
        for bucket in s3_buckets:
            name = bucket["Name"]
            try:
                if s3_metadata and name in s3_metadata:
                    resp = s3_metadata[name]["logging"]
                    if "_error" in resp:
                        continue
                    if "LoggingEnabled" not in resp:
                        no_logging.append(name)
                    continue
                logging_config = s3.get_bucket_logging(Bucket=name)
                if "LoggingEnabled" not in logging_config:
                    no_logging.append(name)
            except ClientError as e:
                if e.response["Error"]["Code"] not in ("AccessDenied", "AccessDeniedException"):
                    raise

        return create_control_result(
            "10.2", "S3 Access Logging",
            "Verifies all S3 buckets have server access logging enabled",
            "PASS" if not no_logging else "FAIL",
            "MEDIUM",
            {
                "total_buckets": len(s3_buckets),
                "buckets_without_logging_count": len(no_logging),
                "buckets_without_logging": no_logging[:20],
            },
            None if not no_logging else
            f"Enable server access logging on {len(no_logging)} bucket(s).",
        )
    except Exception as e:
        return _warning("10.2", "S3 Access Logging",
                        "Verifies all S3 buckets have server access logging enabled", "MEDIUM", e)


def check_rds_automated_backups(rds_instances):
    """Req 12.3 — All RDS instances have automated backups enabled."""
    try:
        if not rds_instances:
            return create_control_result(
                "12.3", "RDS Automated Backups",
                "Verifies all RDS instances have automated backups enabled",
                "PASS", "HIGH", {"total_instances": 0, "no_backups": []},
            )

        no_backups = [
            {
                "db_instance_id": db["DBInstanceIdentifier"],
                "engine": db.get("Engine"),
                "region": db.get("_region", "unknown"),
            }
            for db in rds_instances if db.get("BackupRetentionPeriod", 0) == 0
        ]

        return create_control_result(
            "12.3", "RDS Automated Backups",
            "Verifies all RDS instances have automated backups enabled",
            "PASS" if not no_backups else "FAIL",
            "HIGH",
            {
                "total_instances": len(rds_instances),
                "no_backups_count": len(no_backups),
                "no_backups": no_backups,
            },
            None if not no_backups else
            f"Enable automated backups on {len(no_backups)} RDS instance(s).",
        )
    except Exception as e:
        return _warning("12.3", "RDS Automated Backups",
                        "Verifies all RDS instances have automated backups enabled", "HIGH", e)


def check_rds_deletion_protection(rds_instances):
    """Req 12.3 — Production RDS instances have deletion protection enabled."""
    try:
        if not rds_instances:
            return create_control_result(
                "12.3", "RDS Deletion Protection",
                "Verifies RDS instances have deletion protection enabled",
                "PASS", "MEDIUM", {"total_instances": 0, "unprotected": []},
            )

        unprotected = [
            {
                "db_instance_id": db["DBInstanceIdentifier"],
                "engine": db.get("Engine"),
                "region": db.get("_region", "unknown"),
            }
            for db in rds_instances if not db.get("DeletionProtection")
        ]

        return create_control_result(
            "12.3", "RDS Deletion Protection",
            "Verifies RDS instances have deletion protection enabled",
            "PASS" if not unprotected else "FAIL",
            "MEDIUM",
            {
                "total_instances": len(rds_instances),
                "unprotected_count": len(unprotected),
                "unprotected": unprotected[:20],
            },
            None if not unprotected else
            f"Enable deletion protection on {len(unprotected)} RDS instance(s).",
        )
    except Exception as e:
        return _warning("12.3", "RDS Deletion Protection",
                        "Verifies RDS instances have deletion protection enabled", "MEDIUM", e)


def check_rds_backup_retention(rds_instances, min_days=_RDS_BACKUP_MIN_DAYS):
    """Req 12.3 — RDS backup retention period is at least 7 days."""
    try:
        if not rds_instances:
            return create_control_result(
                "12.3", "RDS Backup Retention",
                f"Verifies RDS backup retention period is at least {min_days} days",
                "PASS", "MEDIUM", {"total_instances": 0, "short_retention": []},
            )

        short_retention = [
            {
                "db_instance_id": db["DBInstanceIdentifier"],
                "retention_period": db.get("BackupRetentionPeriod", 0),
                "engine": db.get("Engine"),
                "region": db.get("_region", "unknown"),
            }
            for db in rds_instances
            if 0 < db.get("BackupRetentionPeriod", 0) < min_days
        ]

        return create_control_result(
            "12.3", "RDS Backup Retention",
            f"Verifies RDS backup retention period is at least {min_days} days",
            "PASS" if not short_retention else "FAIL",
            "MEDIUM",
            {
                "total_instances": len(rds_instances),
                "short_retention_count": len(short_retention),
                "short_retention": short_retention,
            },
            None if not short_retention else
            f"Increase backup retention to at least {min_days} days on {len(short_retention)} RDS instance(s).",
        )
    except Exception as e:
        return _warning("12.3", "RDS Backup Retention",
                        f"Verifies RDS backup retention period is at least {min_days} days", "MEDIUM", e)


def check_organizations_scp(session):
    """Req 12.1 — AWS Organizations SCPs are in use to enforce security guardrails."""
    try:
        orgs = session.client("organizations")
        try:
            policies = orgs.list_policies(Filter="SERVICE_CONTROL_POLICY")["Policies"]
            # Exclude the default FullAWSAccess policy
            custom_scps = [p for p in policies if p.get("Name") != "FullAWSAccess"]

            return create_control_result(
                "12.1", "Organizations SCP Enforcement",
                "Verifies AWS Organizations SCPs are in use to enforce security guardrails",
                "PASS" if custom_scps else "FAIL",
                "MEDIUM",
                {
                    "total_scps": len(policies),
                    "custom_scps_count": len(custom_scps),
                    "custom_scps": [{"name": p["Name"], "id": p["Id"]} for p in custom_scps[:10]],
                },
                None if custom_scps else
                "Create Service Control Policies to enforce security guardrails across the organisation. SCPs can restrict regions, deny insecure actions, and enforce encryption.",
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AWSOrganizationsNotInUseException", "AccessDeniedException"):
                return create_control_result(
                    "12.1", "Organizations SCP Enforcement",
                    "Verifies AWS Organizations SCPs are in use to enforce security guardrails",
                    "WARNING", "MEDIUM",
                    {"error": code, "note": "Account is not part of an AWS Organization or lacks permission to check."},
                    "Set up AWS Organizations with SCPs, or grant organizations:ListPolicies permission.",
                )
            raise
    except Exception as e:
        return _warning("12.1", "Organizations SCP Enforcement",
                        "Verifies AWS Organizations SCPs are in use to enforce security guardrails", "MEDIUM", e)


# ===================== EXECUTIVE SUMMARY =====================


def generate_executive_summary(result):
    """Generate a markdown-formatted executive summary of the PCI-DSS audit results."""
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

    compliance_score = int((passed / checks_completed * 100)) if checks_completed > 0 else 0

    md_lines = []

    md_lines.append("# PCI-DSS v4.0 — Executive Summary")
    md_lines.append("")

    md_lines.append("## Overall Compliance Status")
    md_lines.append("")
    if compliance_score >= 90:
        md_lines.append(f"**AWS Account {account_id}** demonstrates **strong PCI-DSS compliance** with a **{compliance_score}%** pass rate across **{total_checks}** security controls.")
    elif compliance_score >= 70:
        md_lines.append(f"**AWS Account {account_id}** shows **moderate PCI-DSS compliance** with a **{compliance_score}%** pass rate across **{total_checks}** security controls, requiring targeted improvements.")
    else:
        md_lines.append(f"**AWS Account {account_id}** requires **significant security improvements** with a **{compliance_score}%** pass rate across **{total_checks}** security controls.")
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

    md_lines.append("## PCI-DSS Requirement Areas")
    md_lines.append("")
    category_labels = {
        "network_security": "Network Security (Req 1 & 2)",
        "data_protection": "Data Protection (Req 3 & 4)",
        "access_control": "Access Control (Req 7 & 8)",
        "logging_monitoring": "Logging & Monitoring (Req 10 & 11)",
        "vulnerability_management": "Vulnerability Management (Req 5 & 6)",
        "data_retention_recovery": "Data Retention & Recovery (Req 9 & 12)",
    }
    categories_with_issues = []
    for key, label in category_labels.items():
        checks = result.get(key, {}).get("checks", [])
        failed_count = sum(1 for c in checks if c["status"] == "FAIL")
        if failed_count > 0:
            categories_with_issues.append(f"**{label}** ({failed_count} failed)")

    if categories_with_issues:
        md_lines.append("Requirement areas needing attention:")
        md_lines.append("")
        for cat in categories_with_issues:
            md_lines.append(f"- {cat}")
    else:
        md_lines.append("All PCI-DSS requirement areas meet compliance standards.")
    md_lines.append("")

    md_lines.append("## Priority Remediation")
    md_lines.append("")
    all_checks = []
    for key in category_labels:
        all_checks.extend(result.get(key, {}).get("checks", []))
    priority = [c for c in all_checks if c["status"] == "FAIL" and c["severity"] in ("CRITICAL", "HIGH")]

    if priority:
        for control in priority[:5]:
            md_lines.append(f"- **{control['control_name']}** (Req {control['pci_requirement']}) — {control['severity']}")
    else:
        passed_checks = [c for c in all_checks if c["status"] == "PASS"]
        if passed_checks:
            md_lines.append("**Key security strengths demonstrated:**")
            md_lines.append("")
            for c in passed_checks[:5]:
                md_lines.append(f"- {c['control_name']}")
    md_lines.append("")

    md_lines.append("## Additional Observations")
    md_lines.append("")
    if permission_errors > 0:
        md_lines.append(f"**Note:** {permission_errors} check(s) could not be completed due to insufficient IAM permissions. Grant necessary permissions for a complete audit.")
        md_lines.append("")
    if warnings > permission_errors:
        md_lines.append(f"**{warnings - permission_errors} warning(s)** were identified that should be reviewed for continuous improvement.")
    elif permission_errors == 0:
        md_lines.append("No warnings were identified, indicating robust security configurations.")
    md_lines.append("")

    md_lines.append("## Recommendation")
    md_lines.append("")
    if compliance_score >= 90:
        md_lines.append("**Action:** Address minor findings and proceed with PCI-DSS assessment preparation. Share this report with your QSA as supporting evidence.")
    elif compliance_score >= 70:
        md_lines.append("**Action:** Focus on critical and high-severity findings before the next PCI-DSS assessment cycle.")
    else:
        md_lines.append("**Action:** Implement comprehensive security improvements across all requirement areas. Engage your QSA early to align remediation with assessment scope.")

    return "\n".join(md_lines)


# ===================== RUN AUDIT =====================


def run_pci_dss_audit(profile=None):
    """Run the full PCI-DSS v4.0 compliance audit and return structured results."""
    region = "us-east-1"

    if profile:
        session = boto3.Session(profile_name=profile, region_name=region)
    else:
        session = boto3.Session(region_name=region)

    RESULT = _make_result()
    RESULT["metadata"]["aws_profile"] = profile or "default"
    account_id = session.client("sts").get_caller_identity()["Account"]
    RESULT["metadata"]["aws_account_id"] = account_id

    # Pre-fetch all shared resources
    cache = AWSResourceCache(session)

    def _guard(resource_key, req, name, desc, severity, check_fn):
        """Wrap a check: if its resource failed to fetch, return WARNING instead of calling the check."""
        err = cache.fetch_errors.get(resource_key)
        if err is not None:
            return _warning(req, name, desc, severity, err)
        return check_fn()

    _s3 = lambda req, name, desc, sev, fn: (lambda: _guard("s3", req, name, desc, sev, fn))
    _ct = lambda req, name, desc, sev, fn: (lambda: _guard("cloudtrail", req, name, desc, sev, fn))
    _iam = lambda req, name, desc, sev, fn: (lambda: _guard("iam", req, name, desc, sev, fn))

    # Define all 66 checks with their categories
    check_tasks = [
        # --- Network Security Controls (Req 1 & 2) — 8 checks ---
        ("network_security", lambda: check_vpc_flow_logs(session, cache.vpcs)),
        ("network_security", lambda: check_unrestricted_sg_ingress(cache.security_groups)),
        ("network_security", lambda: check_default_sg_in_use(cache.security_groups, cache.ec2_instances)),
        ("network_security", lambda: check_public_subnets_igw(session, cache.vpcs)),
        ("network_security", lambda: check_nacl_restrictiveness(session, cache.vpcs)),
        ("network_security", lambda: check_ec2_imdsv2(cache.ec2_instances)),
        ("network_security", lambda: check_default_vpc_in_use(session, cache.vpcs, cache.ec2_instances)),
        ("network_security", lambda: check_public_ec2_instances(session, cache.ec2_instances)),

        # --- Cardholder Data Protection (Req 3 & 4) — 16 checks ---
        ("data_protection", _s3("3.4", "S3 Public Access Block", "Verifies all S3 buckets have public access blocked", "CRITICAL",
                               lambda: check_s3_public_access(session, cache.s3_buckets, cache.s3_metadata))),
        ("data_protection", _s3("3.4", "S3 Bucket ACLs", "Verifies no S3 buckets have public ACL grants", "HIGH",
                               lambda: check_s3_bucket_acl(session, cache.s3_buckets, cache.s3_metadata))),
        ("data_protection", _s3("3.5", "S3 Encryption at Rest", "Verifies all S3 buckets have an explicit encryption configuration", "MEDIUM",
                               lambda: check_s3_encryption(session, cache.s3_buckets, cache.s3_metadata))),
        ("data_protection", lambda: check_rds_encryption(cache.rds_instances)),
        ("data_protection", lambda: check_rds_public_access(cache.rds_instances)),
        ("data_protection", lambda r=cache.regions: check_ebs_encryption(session, r)),
        ("data_protection", lambda r=cache.regions: check_ebs_default_encryption(session, r)),
        ("data_protection", lambda r=cache.regions: check_dynamodb_encryption(session, r)),
        ("data_protection", lambda r=cache.regions: check_kms_key_rotation(session, r)),
        ("data_protection", lambda: check_secrets_no_plaintext(session, cache.ec2_instances)),
        ("data_protection", _s3("3.1", "S3 Lifecycle Policies", "Verifies all S3 buckets have lifecycle policies for data retention and disposal", "MEDIUM",
                               lambda: check_s3_lifecycle(session, cache.s3_buckets, cache.s3_metadata))),
        ("data_protection", lambda: check_rds_tls(session, cache.rds_instances)),
        ("data_protection", lambda r=cache.regions: check_alb_https(session, r)),
        ("data_protection", lambda r=cache.regions: check_api_gateway_tls(session, r)),
        ("data_protection", lambda r=cache.regions: check_acm_certificate_expiry(session, r)),
        ("data_protection", lambda r=cache.regions: check_macie_cardholder_data(session, r)),

        # --- Access Control (Req 7 & 8) — 13 checks ---
        ("access_control", lambda: check_root_mfa(session)),
        ("access_control", lambda: check_root_access_keys(session)),
        ("access_control", lambda: check_iam_users_mfa(session)),
        ("access_control", _iam("8.3", "Stale Access Keys", "Verifies IAM access keys are rotated within 90 days", "HIGH",
                               lambda: check_stale_access_keys(session, cache.iam_users))),
        ("access_control", lambda: check_overly_permissive_policies(session)),
        ("access_control", lambda: check_admin_iam_principals(session)),
        ("access_control", lambda: check_cross_account_trust(session)),
        ("access_control", _iam("8.2", "Inactive IAM Users", "Verifies no IAM users have been inactive for more than 90 days", "HIGH",
                               lambda: check_inactive_users(session, cache.iam_users))),
        ("access_control", lambda: check_password_policy(session)),
        ("access_control", lambda r=cache.regions: check_iam_access_analyzer(session, r)),
        ("access_control", lambda r=cache.regions: check_secrets_rotation(session, r)),
        ("access_control", lambda r=cache.regions: check_secrets_rotation_success(session, r)),
        ("access_control", _iam("8.2", "No Shared IAM Users", "Verifies no IAM users appear to be shared accounts", "MEDIUM",
                               lambda: check_shared_iam_users(session, cache.iam_users))),

        # --- Logging and Monitoring (Req 10 & 11) — 19 checks ---
        ("logging_monitoring", _ct("10.2", "CloudTrail Logging", "Verifies at least one CloudTrail trail is actively logging", "CRITICAL",
                                  lambda: check_cloudtrail_logging(session, cache.cloudtrail_trails))),
        ("logging_monitoring", _ct("10.2", "CloudTrail Multi-Region", "Verifies at least one multi-region CloudTrail trail is configured", "HIGH",
                                  lambda: check_cloudtrail_multiregion(cache.cloudtrail_trails))),
        ("logging_monitoring", _ct("10.5", "CloudTrail Log File Validation", "Verifies all CloudTrail trails have log file integrity validation enabled", "HIGH",
                                  lambda: check_cloudtrail_validation(cache.cloudtrail_trails))),
        ("logging_monitoring", _ct("10.5", "CloudTrail Log Encryption", "Verifies all CloudTrail trails store logs encrypted with KMS", "MEDIUM",
                                  lambda: check_cloudtrail_encryption(session, cache.cloudtrail_trails))),
        ("logging_monitoring", _ct("10.2", "CloudTrail S3 Data Events", "Verifies at least one CloudTrail trail captures S3 data events", "HIGH",
                                  lambda: check_cloudtrail_s3_data_events(session, cache.cloudtrail_trails))),
        ("logging_monitoring", _ct("10.5", "CloudTrail S3 Bucket Not Public", "Verifies CloudTrail log S3 bucket is not publicly accessible", "HIGH",
                                  lambda: check_cloudtrail_s3_not_public(session, cache.cloudtrail_trails))),
        ("logging_monitoring", _ct("10.7", "CloudTrail Log Retention", "Verifies CloudTrail log S3 buckets retain logs for at least 365 days", "HIGH",
                                  lambda: check_cloudtrail_log_retention(session, cache.cloudtrail_trails))),
        ("logging_monitoring", _s3("10.7", "S3 Bucket Versioning", "Verifies all S3 buckets have versioning enabled to protect data and audit trail integrity", "MEDIUM",
                                   lambda: check_s3_versioning(session, cache.s3_buckets, cache.s3_metadata))),
        ("logging_monitoring", lambda: check_vpc_flow_log_retention(session, cache.vpcs)),
        ("logging_monitoring", lambda: check_rds_audit_logging(session, cache.rds_instances)),
        ("logging_monitoring", lambda r=cache.regions, ar=cache.active_regions: check_cloudwatch_alarms(session, r, ar)),
        ("logging_monitoring", lambda r=cache.regions: check_cloudwatch_security_alarms(session, r)),
        ("logging_monitoring", lambda r=cache.regions: check_cloudwatch_log_retention(session, r)),
        ("logging_monitoring", lambda r=cache.regions: check_aws_config(session, r)),
        ("logging_monitoring", lambda r=cache.regions: check_guardduty(session, r)),
        ("logging_monitoring", lambda r=cache.regions: check_security_hub(session, r)),
        ("logging_monitoring", lambda r=cache.regions: check_security_hub_pci_standard(session, r)),
        ("logging_monitoring", lambda r=cache.regions: check_aws_config_completeness(session, r)),
        ("logging_monitoring", lambda r=cache.regions: check_guardduty_findings_export(session, r)),

        # --- Vulnerability Management (Req 5 & 6) — 5 checks ---
        ("vulnerability_management", lambda r=cache.regions: check_inspector(session, r, account_id)),
        ("vulnerability_management", lambda: check_rds_auto_minor_version(cache.rds_instances)),
        ("vulnerability_management", lambda r=cache.regions: check_waf_public_resources(session, r)),
        ("vulnerability_management", lambda r=cache.regions: check_ssm_patch_compliance(session, r)),
        ("vulnerability_management", lambda r=cache.regions: check_lambda_runtime_eol(session, r)),

        # --- Data Retention & Recovery (Req 9 & 12) — 5 checks ---
        ("data_retention_recovery", _s3("10.2", "S3 Access Logging", "Verifies all S3 buckets have server access logging enabled", "MEDIUM",
                                       lambda: check_s3_access_logging(session, cache.s3_buckets, cache.s3_metadata))),
        ("data_retention_recovery", lambda: check_rds_automated_backups(cache.rds_instances)),
        ("data_retention_recovery", lambda: check_rds_deletion_protection(cache.rds_instances)),
        ("data_retention_recovery", lambda: check_rds_backup_retention(cache.rds_instances)),
        ("data_retention_recovery", lambda: check_organizations_scp(session)),
    ]

    # Run all checks in parallel
    with ThreadPoolExecutor(max_workers=25) as executor:
        future_to_check = {}
        for category, check_func in check_tasks:
            future = executor.submit(check_func)
            future_to_check[future] = category

        for future in as_completed(future_to_check):
            category = future_to_check[future]
            try:
                check_result = future.result()
                RESULT[category]["checks"].append(check_result)
            except Exception as e:
                error_result = create_control_result(
                    "CHECK-ERROR", "Unexpected Check Error",
                    f"Control check encountered an unexpected error: {e}",
                    "WARNING", "LOW",
                    {"error_type": type(e).__name__, "message": str(e), "category": category},
                    "Review error details and ensure AWS resources are accessible.",
                )
                RESULT[category]["checks"].append(error_result)

    # Calculate summary statistics
    category_keys = [
        "network_security", "data_protection", "access_control",
        "logging_monitoring", "vulnerability_management", "data_retention_recovery",
    ]
    all_controls = []
    for key in category_keys:
        all_controls.extend(RESULT[key]["checks"])

    permission_errors = sum(
        1 for c in all_controls
        if c["status"] == "WARNING" and any(
            kw in str(c.get("details", {}).get("error", ""))
            for kw in ("AccessDenied", "Unauthorized", "Forbidden")
        )
    )

    RESULT["metadata"]["summary"] = {
        "total_checks": len(all_controls),
        "passed": sum(1 for c in all_controls if c["status"] == "PASS"),
        "failed": sum(1 for c in all_controls if c["status"] == "FAIL"),
        "warnings": sum(1 for c in all_controls if c["status"] == "WARNING"),
        "critical_failures": sum(1 for c in all_controls if c["status"] == "FAIL" and c["severity"] == "CRITICAL"),
        "high_failures": sum(1 for c in all_controls if c["status"] == "FAIL" and c["severity"] == "HIGH"),
        "permission_errors": permission_errors,
        "checks_completed": len(all_controls) - permission_errors,
    }

    RESULT["metadata"]["executive_summary"] = generate_executive_summary(RESULT)

    return RESULT


# ===================== CLI =====================


def main():
    parser = argparse.ArgumentParser(
        description="AWS PCI-DSS v4.0 Compliance Audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 aws_pci_dss_checker.py --profile my-profile
  python3 aws_pci_dss_checker.py --profile my-profile --output report.json
  python3 aws_pci_dss_checker.py  # uses default AWS credential chain
        """,
    )
    parser.add_argument("--profile", "-p", type=str, default=None,
                        help="AWS CLI profile name (from ~/.aws/credentials or ~/.aws/config)")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Write JSON output to a file instead of stdout")
    args = parser.parse_args()

    try:
        report = run_pci_dss_audit(profile=args.profile)
        output = json.dumps(report, indent=2, default=str)

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

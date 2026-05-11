#!/usr/bin/env python3
import argparse
import boto3
import json
import sys
import re
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError

# =============================================================================
# SERVICE REGISTRY (equivalent to Bash arrays)
# =============================================================================

SERVICE_REGISTRY = {
    "ec2": {
        "default_metrics": ["CPUUtilization", "NetworkIn", "NetworkOut"],
        "dimension": "InstanceId",
        "tag_type": "native",
        "namespace": "AWS/EC2",
    },
    "rds": {
        "default_metrics": ["CPUUtilization", "DatabaseConnections", "FreeStorageSpace"],
        "dimension": "DBInstanceIdentifier",
        "tag_type": "arn",
        "namespace": "AWS/RDS",
    },
    "lambda": {
        "default_metrics": ["Invocations", "Duration", "Errors"],
        "dimension": "FunctionName",
        "tag_type": "arn",
        "namespace": "AWS/Lambda",
    },
    "dynamodb": {
        "default_metrics": ["ConsumedReadCapacityUnits", "ConsumedWriteCapacityUnits"],
        "dimension": "TableName",
        "tag_type": "none",
        "namespace": "AWS/DynamoDB",
    },
    "s3": {
        "default_metrics": ["NumberOfObjects", "BucketSizeBytes"],
        "dimension": "BucketName",
        "tag_type": "bucket",
        "namespace": "AWS/S3",
    },
    "elb": {
        "default_metrics": ["RequestCount", "HealthyHostCount", "Latency"],
        "dimension": "LoadBalancerName",
        "tag_type": "elb",
        "namespace": "AWS/ELB",
    },
    "alb": {
        "default_metrics": ["RequestCount", "TargetResponseTime", "HealthyHostCount"],
        "dimension": "LoadBalancer",
        "tag_type": "arn",
        "namespace": "AWS/ApplicationELB",
    },
    "nlb": {
        "default_metrics": ["ActiveFlowCount", "HealthyHostCount", "UnHealthyHostCount"],
        "dimension": "LoadBalancer",
        "tag_type": "arn",
        "namespace": "AWS/NetworkELB",
    },
    "ecs": {
        "default_metrics": ["CPUUtilization", "MemoryUtilization"],
        "dimension": "ServiceName",
        "tag_type": "arn",
        "namespace": "AWS/ECS",
    },
}

# =============================================================================
# UTILITIES
# =============================================================================

def parse_duration(duration: str) -> timedelta:
    match = re.match(r"(\d+)([hmd])$", duration)
    if not match:
        raise ValueError(f"Invalid duration format: {duration}")

    value, unit = match.groups()
    value = int(value)

    if unit == "h":
        return timedelta(hours=value)
    elif unit == "m":
        return timedelta(minutes=value)
    elif unit == "d":
        return timedelta(days=value)

    raise ValueError(f"Unknown time unit: {unit}")


def calculate_period(duration: timedelta) -> int:
    seconds = int(duration.total_seconds())
    period = max(60, seconds // 1000)

    if period < 300:
        return 60
    if period < 3600:
        return ((period + 59) // 60) * 60
    return ((period + 3599) // 3600) * 3600


def parse_kv_list(value: str) -> dict:
    result = {}
    for item in value.split(","):
        # Support both = and : as separators
        if "=" in item:
            key, val = item.split("=", 1)
        elif ":" in item:
            key, val = item.split(":", 1)
        else:
            raise ValueError(f"Invalid key-value pair: {item}. Expected format: key=value or key:value")
        result[key] = val
    return result


# =============================================================================
# AWS HELPERS
# =============================================================================

def get_all_regions(session):
    """Get all AWS regions. Always uses us-east-1 to query the regions list."""
    ec2 = session.client("ec2", region_name="us-east-1")
    return [r["RegionName"] for r in ec2.describe_regions()["Regions"]]


def verify_credentials(session):
    sts = session.client("sts", region_name="us-east-1")
    sts.get_caller_identity()


# =============================================================================
# RESOURCE DISCOVERY (subset – easily extendable)
# =============================================================================

def discover_ec2_instances(session, region, tags):
    """Discover EC2 instances in a region. Returns empty list on errors."""
    try:
        ec2 = session.client("ec2", region_name=region)
        filters = [{"Name": "instance-state-name", "Values": ["running"]}]

        if tags:
            for k, v in tags.items():
                filters.append({"Name": f"tag:{k}", "Values": [v]})

        reservations = ec2.describe_instances(Filters=filters)["Reservations"]
        return [
            i["InstanceId"]
            for r in reservations
            for i in r["Instances"]
        ]
    except ClientError:
        # AccessDenied or other errors - return empty list
        return []


def discover_rds_instances(session, region, tags):
    """Discover RDS instances in a region. Returns empty list on errors."""
    try:
        rds = session.client("rds", region_name=region)
        instances = rds.describe_db_instances()["DBInstances"]

        if not tags:
            return [i["DBInstanceIdentifier"] for i in instances]

        matched = []
        for i in instances:
            arn = i["DBInstanceArn"]
            tag_list = rds.list_tags_for_resource(ResourceName=arn)["TagList"]
            tag_map = {t["Key"]: t["Value"] for t in tag_list}
            if all(tag_map.get(k) == v for k, v in tags.items()):
                matched.append(i["DBInstanceIdentifier"])
        return matched
    except ClientError:
        # AccessDenied or other errors - return empty list
        return []


def discover_ecs_services(session, region, tags):
    """Discover ECS services in a region. Returns empty list on errors."""
    try:
        ecs = session.client("ecs", region_name=region)

        # Get all clusters
        cluster_arns = ecs.list_clusters()["clusterArns"]
        if not cluster_arns:
            return []

        services = []
        for cluster_arn in cluster_arns:
            cluster_name = cluster_arn.split("/")[-1]

            # Get all services in the cluster
            service_arns = ecs.list_services(cluster=cluster_name)["serviceArns"]

            if not service_arns:
                continue

            if not tags:
                # Return in format "cluster/service" for dimension building
                for service_arn in service_arns:
                    service_name = service_arn.split("/")[-1]
                    services.append(f"{cluster_name}/{service_name}")
            else:
                # Filter by tags if specified
                for service_arn in service_arns:
                    try:
                        tag_list = ecs.list_tags_for_resource(resourceArn=service_arn)["tags"]
                        tag_map = {t["key"]: t["value"] for t in tag_list}
                        if all(tag_map.get(k) == v for k, v in tags.items()):
                            service_name = service_arn.split("/")[-1]
                            services.append(f"{cluster_name}/{service_name}")
                    except ClientError:
                        # Skip services we can't get tags for
                        continue

        return services
    except ClientError:
        # AccessDenied or other errors - return empty list
        return []


def discover_lambda_functions(session, region, tags):
    """Discover Lambda functions in a region. Returns empty list on errors."""
    try:
        lambda_client = session.client("lambda", region_name=region)

        functions = []
        paginator = lambda_client.get_paginator("list_functions")

        for page in paginator.paginate():
            for func in page["Functions"]:
                function_name = func["FunctionName"]

                if not tags:
                    functions.append(function_name)
                else:
                    # Get tags for this function
                    try:
                        func_arn = func["FunctionArn"]
                        tag_response = lambda_client.list_tags(Resource=func_arn)
                        tag_map = tag_response.get("Tags", {})
                        if all(tag_map.get(k) == v for k, v in tags.items()):
                            functions.append(function_name)
                    except ClientError:
                        continue

        return functions
    except ClientError:
        return []


def discover_dynamodb_tables(session, region, tags):
    """Discover DynamoDB tables in a region. Returns empty list on errors."""
    try:
        dynamodb = session.client("dynamodb", region_name=region)

        table_names = dynamodb.list_tables().get("TableNames", [])

        if not tags:
            return table_names

        matched = []
        for table_name in table_names:
            try:
                table_arn = dynamodb.describe_table(TableName=table_name)["Table"]["TableArn"]
                tag_list = dynamodb.list_tags_of_resource(ResourceArn=table_arn).get("Tags", [])
                tag_map = {t["Key"]: t["Value"] for t in tag_list}
                if all(tag_map.get(k) == v for k, v in tags.items()):
                    matched.append(table_name)
            except ClientError:
                continue

        return matched
    except ClientError:
        return []


def discover_s3_buckets(session, region, tags):
    """Discover S3 buckets. Note: S3 is global, so region param is ignored. Returns empty list on errors."""
    # S3 buckets are global - region parameter kept for consistency with other discovery functions
    _ = region  # Unused but required for function signature consistency
    try:
        s3 = session.client("s3")

        buckets = s3.list_buckets().get("Buckets", [])
        bucket_names = [b["Name"] for b in buckets]

        if not tags:
            return bucket_names

        matched = []
        for bucket_name in bucket_names:
            try:
                tag_set = s3.get_bucket_tagging(Bucket=bucket_name).get("TagSet", [])
                tag_map = {t["Key"]: t["Value"] for t in tag_set}
                if all(tag_map.get(k) == v for k, v in tags.items()):
                    matched.append(bucket_name)
            except ClientError:
                # Bucket might not have tags
                continue

        return matched
    except ClientError:
        return []


def discover_elb_load_balancers(session, region, tags):
    """Discover Classic ELB load balancers in a region. Returns empty list on errors."""
    try:
        elb = session.client("elb", region_name=region)

        lbs = elb.describe_load_balancers().get("LoadBalancerDescriptions", [])

        if not tags:
            return [lb["LoadBalancerName"] for lb in lbs]

        matched = []
        for lb in lbs:
            lb_name = lb["LoadBalancerName"]
            try:
                tag_list = elb.describe_tags(LoadBalancerNames=[lb_name])["TagDescriptions"]
                if tag_list:
                    tag_map = {t["Key"]: t["Value"] for t in tag_list[0].get("Tags", [])}
                    if all(tag_map.get(k) == v for k, v in tags.items()):
                        matched.append(lb_name)
            except ClientError:
                continue

        return matched
    except ClientError:
        return []


def discover_alb_load_balancers(session, region, tags):
    """Discover Application Load Balancers in a region. Returns empty list on errors."""
    try:
        elbv2 = session.client("elbv2", region_name=region)

        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        albs = [lb for lb in lbs if lb["Type"] == "application"]

        if not tags:
            # Return in format for LoadBalancer dimension (app/name/id)
            return ["/".join(lb["LoadBalancerArn"].split(":loadbalancer/")[1].split("/")) for lb in albs]

        matched = []
        for lb in albs:
            try:
                lb_arn = lb["LoadBalancerArn"]
                tag_list = elbv2.describe_tags(ResourceArns=[lb_arn])["TagDescriptions"]
                if tag_list:
                    tag_map = {t["Key"]: t["Value"] for t in tag_list[0].get("Tags", [])}
                    if all(tag_map.get(k) == v for k, v in tags.items()):
                        matched.append("/".join(lb_arn.split(":loadbalancer/")[1].split("/")))
            except ClientError:
                continue

        return matched
    except ClientError:
        return []


def discover_nlb_load_balancers(session, region, tags):
    """Discover Network Load Balancers in a region. Returns empty list on errors."""
    try:
        elbv2 = session.client("elbv2", region_name=region)

        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        nlbs = [lb for lb in lbs if lb["Type"] == "network"]

        if not tags:
            # Return in format for LoadBalancer dimension (net/name/id)
            return ["/".join(lb["LoadBalancerArn"].split(":loadbalancer/")[1].split("/")) for lb in nlbs]

        matched = []
        for lb in nlbs:
            try:
                lb_arn = lb["LoadBalancerArn"]
                tag_list = elbv2.describe_tags(ResourceArns=[lb_arn])["TagDescriptions"]
                if tag_list:
                    tag_map = {t["Key"]: t["Value"] for t in tag_list[0].get("Tags", [])}
                    if all(tag_map.get(k) == v for k, v in tags.items()):
                        matched.append("/".join(lb_arn.split(":loadbalancer/")[1].split("/")))
            except ClientError:
                continue

        return matched
    except ClientError:
        return []


DISCOVERY_FUNCTIONS = {
    "ec2": discover_ec2_instances,
    "rds": discover_rds_instances,
    "ecs": discover_ecs_services,
    "lambda": discover_lambda_functions,
    "dynamodb": discover_dynamodb_tables,
    "s3": discover_s3_buckets,
    "elb": discover_elb_load_balancers,
    "alb": discover_alb_load_balancers,
    "nlb": discover_nlb_load_balancers,
}

# =============================================================================
# METRIC QUERY
# =============================================================================

def query_metrics_for_region(
    session,
    service,
    region,
    resources,
    metrics,
    start_time,
    end_time,
    period,
    statistic,
    dimensions_override=None,
):
    cw = session.client("cloudwatch", region_name=region)
    namespace = SERVICE_REGISTRY[service]["namespace"]
    dim_name = SERVICE_REGISTRY[service]["dimension"]

    results = []

    for resource in resources:
        for metric in metrics:
            dimensions = []

            if dimensions_override:
                dimensions = [
                    {"Name": k, "Value": v}
                    for k, v in dimensions_override.items()
                ]
            else:
                if service == "ecs":
                    cluster, svc = resource.split("/", 1)
                    dimensions = [
                        {"Name": "ClusterName", "Value": cluster},
                        {"Name": "ServiceName", "Value": svc},
                    ]
                else:
                    dimensions = [{"Name": dim_name, "Value": resource}]

            try:
                resp = cw.get_metric_statistics(
                    Namespace=namespace,
                    MetricName=metric,
                    Dimensions=dimensions,
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=period,
                    Statistics=[statistic],
                )
            except ClientError as e:
                results.append({
                    "region": region,
                    "resource": resource,
                    "metric": metric,
                    "error": str(e),
                })
                continue

            datapoints = resp.get("Datapoints", [])
            if not datapoints:
                continue

            values = [dp[statistic] for dp in datapoints]

            # Use the actual statistic operation on the values
            if statistic == "Maximum":
                result_value = round(max(values), 2)
            elif statistic == "Minimum":
                result_value = round(min(values), 2)
            elif statistic == "Sum":
                result_value = round(sum(values), 2)
            else:  # Average or SampleCount
                result_value = round(sum(values) / len(values), 2)

            results.append({
                "region": region,
                "resource": resource,
                "metric": metric,
                "value": result_value,
            })

    return results


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, help="AWS profile name")
    parser.add_argument("--service", required=True)
    parser.add_argument("--region")
    parser.add_argument("--metric")
    parser.add_argument("--dimensions")
    parser.add_argument("--tags")
    parser.add_argument("--duration", default="1h")
    parser.add_argument("--threshold")
    parser.add_argument("--top", type=int, default=0)
    parser.add_argument("--stats", default="Average")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    if args.service not in SERVICE_REGISTRY:
        sys.exit(json.dumps({"error": f"unsupported service: {args.service}"}))

    session = boto3.Session(profile_name=args.profile)

    try:
        verify_credentials(session)
    except (ClientError, NoCredentialsError):
        sys.exit(json.dumps({"error": "AWS credentials not configured"}))

    duration_td = parse_duration(args.duration)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - duration_td
    period = calculate_period(duration_td)

    # Handle region - default to us-east-1 if no region specified and profile has no default
    if args.region:
        regions = args.region.split(",")
    else:
        # Try to get profile's default region, otherwise default to us-east-1
        default_region = session.region_name or "us-east-1"
        if args.verbose:
            print(f"[DEBUG] No region specified, using profile default or us-east-1: {default_region}", file=sys.stderr)
        # When no region specified, query all regions
        try:
            regions = get_all_regions(session)
        except ClientError as e:
            if args.verbose:
                print(f"[DEBUG] Could not list all regions, using {default_region}: {e}", file=sys.stderr)
            regions = [default_region]
    metrics = (
        args.metric.split(",")
        if args.metric
        else SERVICE_REGISTRY[args.service]["default_metrics"]
    )

    tags = parse_kv_list(args.tags) if args.tags else None

    # Parse dimensions - AWS format is "Name=Key,Value=Val" which becomes {"Key": "Val"}
    dimensions_override = None
    if args.dimensions:
        parsed_dims = parse_kv_list(args.dimensions)
        # Convert from {'Name': 'InstanceId', 'Value': 'i-xxx'} to {'InstanceId': 'i-xxx'}
        if 'Name' in parsed_dims and 'Value' in parsed_dims:
            dimensions_override = {parsed_dims['Name']: parsed_dims['Value']}
        else:
            dimensions_override = parsed_dims

    all_results = []

    with ThreadPoolExecutor(max_workers=len(regions)) as executor:
        futures = []

        for region in regions:
            if dimensions_override:
                resources = ["single"]
            else:
                discover = DISCOVERY_FUNCTIONS.get(args.service)
                if not discover:
                    continue
                resources = discover(session, region, tags)

            futures.append(
                executor.submit(
                    query_metrics_for_region,
                    session,
                    args.service,
                    region,
                    resources,
                    metrics,
                    start_time,
                    end_time,
                    period,
                    args.stats,
                    dimensions_override,
                )
            )

        for future in as_completed(futures):
            all_results.extend(future.result())

    # Group by resource and collect errors
    grouped = {}
    errors = []

    for r in all_results:
        if "error" in r:
            # Extract error type from error string
            error_msg = r["error"]
            error_type = "Unknown"

            if "AccessDenied" in error_msg or "not authorized" in error_msg:
                error_type = "AccessDenied"
            elif "InvalidParameterValue" in error_msg:
                error_type = "InvalidParameterValue"

            errors.append({
                "region": r.get("region"),
                "resource": r.get("resource"),
                "metric": r.get("metric"),
                "errorType": error_type,
                "errorMessage": error_msg
            })
            continue

        if "value" in r:
            key = r["resource"]
            grouped.setdefault(key, {})[r["metric"]] = r["value"]

    output = {
        "query": {
            "service": args.service,
            "regions": regions,
            "metrics": metrics,
            "duration": args.duration,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "period": period,
        },
        "results": [
            {"resource": k, "metrics": v}
            for k, v in grouped.items()
        ],
    }

    # Add errors section if there are any errors
    if errors:
        output["errors"] = errors
        # Add summary of error types
        error_types = {}
        for err in errors:
            err_type = err["errorType"]
            error_types[err_type] = error_types.get(err_type, 0) + 1
        output["errorSummary"] = error_types

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()

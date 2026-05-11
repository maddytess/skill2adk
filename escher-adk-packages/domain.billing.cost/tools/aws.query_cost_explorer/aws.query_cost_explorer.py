#!/usr/bin/env python3
"""
AWS Cost Report Generator
Generate AWS cost and usage reports across multiple profiles.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
import re


def to_camel_case(obj: Any) -> Any:
    """Convert all JSON keys to camelCase recursively."""
    if isinstance(obj, dict):
        new_dict = {}
        for key, value in obj.items():
            # Convert snake_case to camelCase
            camel_key = re.sub(r'_([a-z])', lambda m: m.group(1).upper(), key)
            # Ensure first letter is lowercase (for PascalCase)
            camel_key = camel_key[0].lower() + camel_key[1:] if camel_key else camel_key
            new_dict[camel_key] = to_camel_case(value)
        return new_dict
    elif isinstance(obj, list):
        return [to_camel_case(item) for item in obj]
    else:
        return obj


def get_aws_profiles(aws_cmd: str) -> List[str]:
    """Get list of available AWS CLI profiles."""
    try:
        result = subprocess.run(
            [aws_cmd, 'configure', 'list-profiles'],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0 and result.stdout:
            return [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
        return []
    except Exception:
        return []


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Generate AWS cost and usage reports across multiple profiles.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate report for all profiles, last 365 days
  ./aws_cost_report.py

  # Generate report for specific date range (end date is inclusive)
  ./aws_cost_report.py --start 2024-01-01 --end 2024-12-31

  # Single-day cost query (end date is inclusive by default)
  ./aws_cost_report.py --start 2024-12-07 --end 2024-12-07 --granularity DAILY

  # Filter by service
  ./aws_cost_report.py --service "Amazon Elastic Compute Cloud - Compute"

  # Filter by region
  ./aws_cost_report.py --region us-east-1

  # Filter by multiple regions
  ./aws_cost_report.py --region us-east-1,eu-west-1,ap-south-1

  # Filter by cost allocation tag
  ./aws_cost_report.py --tag "Environment:Production"

  # Filter by account ID
  ./aws_cost_report.py --account-id 123456789012

  # Combine filters
  ./aws_cost_report.py --service "Amazon EC2" --region us-east-1 --account-id 123456789012
        '''
    )

    # Date parameters
    parser.add_argument('--start', dest='start_date',
                        help='Start date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, default: 365 days ago)')
    parser.add_argument('--end', dest='end_date',
                        help='End date inclusive (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, default: today)')

    # Filter parameters
    parser.add_argument('--service',
                        help='Filter by service name (optional)')
    parser.add_argument('--region',
                        help='Filter by region(s) (comma-separated for multiple)')
    parser.add_argument('--tag',
                        help='Filter by cost allocation tag (format: TagKey:Value1,Value2)')
    parser.add_argument('--account-id',
                        help='Filter by AWS account ID(s) (comma-separated for multiple)')

    # Query parameters
    parser.add_argument('--granularity', default='MONTHLY',
                        choices=['DAILY', 'MONTHLY'],
                        help='Granularity (default: MONTHLY)')
    parser.add_argument('--metric', default='AmortizedCost',
                        help='Metric name (default: AmortizedCost)')

    # Profile and output parameters
    parser.add_argument('--profiles',
                        help='Comma-separated profile names (default: all profiles)')
    parser.add_argument('--output',
                        help='Output JSON file (optional)')
    parser.add_argument('--config',
                        help='JSON file containing parameters (optional)')

    # Flags
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output to stderr')
    parser.add_argument('--group-by-usage-type', action='store_true',
                        help='Group results by usage type (e.g., to extract EBS costs from EC2 - Other)')

    return parser.parse_args()


def parse_date_input(date_str: str) -> str:
    """Accept YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ and return YYYY-MM-DD (UTC date)."""
    if 'T' in date_str:
        return (
            datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%SZ')
            .replace(tzinfo=timezone.utc)
            .strftime('%Y-%m-%d')
        )
    return date_str


def load_config(config_file: str, args: argparse.Namespace, verbose: bool) -> None:
    """Load configuration from JSON file and update args."""
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)

        if verbose:
            print(f"Loading configuration from: {config_file}", file=sys.stderr)

        # Override defaults with config file values (command-line args take precedence)
        if not args.start_date and 'start' in config:
            args.start_date = config['start']
        if not args.end_date and 'end' in config:
            args.end_date = config['end']
        if not args.service and 'service' in config:
            args.service = config['service']
        if not args.region and 'region' in config:
            args.region = config['region']
        if not args.tag and 'tag' in config:
            args.tag = config['tag']
        if not args.account_id and 'account_id' in config:
            args.account_id = config['account_id']
        if args.granularity == 'MONTHLY' and 'granularity' in config:
            args.granularity = config['granularity']
        if args.metric == 'AmortizedCost' and 'metric' in config:
            args.metric = config['metric']
        if not args.profiles and 'profiles' in config:
            args.profiles = config['profiles']
        if not args.output and 'output' in config:
            args.output = config['output']

    except FileNotFoundError:
        print(f"Error: Config file not found: {config_file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in config file: {e}", file=sys.stderr)
        sys.exit(1)


def build_filter(service: Optional[str], region: Optional[str],
                 tag: Optional[str], account_id: Optional[str]) -> Optional[Dict]:
    """Build AWS Cost Explorer filter from parameters."""
    filter_conditions = []

    # Add SERVICE filter
    if service:
        filter_conditions.append({
            'Dimensions': {
                'Key': 'SERVICE',
                'Values': [service]
            }
        })

    # Add REGION filter
    if region:
        regions = [r.strip() for r in region.split(',')]
        filter_conditions.append({
            'Dimensions': {
                'Key': 'REGION',
                'Values': regions
            }
        })

    # Add TAG filter
    if tag:
        if ':' not in tag:
            raise ValueError(
                f"Invalid --tag format '{tag}'. Expected Key:Value (e.g. Environment:Production)."
            )
        tag_key, tag_values_str = tag.split(':', 1)
        tag_values = [v.strip() for v in tag_values_str.split(',')]
        filter_conditions.append({
            'Tags': {
                'Key': tag_key,
                'Values': tag_values
            }
        })

    # Add ACCOUNT_ID filter
    if account_id:
        account_ids = [a.strip() for a in account_id.split(',')]
        filter_conditions.append({
            'Dimensions': {
                'Key': 'LINKED_ACCOUNT',
                'Values': account_ids
            }
        })

    # Combine filters
    if len(filter_conditions) == 0:
        return None
    elif len(filter_conditions) == 1:
        return filter_conditions[0]
    else:
        return {'And': filter_conditions}


def get_period_dates() -> Dict[str, Dict[str, str]]:
    """Calculate date ranges for MTD and YTD."""
    today = datetime.now(timezone.utc)

    # MTD: First day of current month to today
    mtd_start = today.replace(day=1).strftime('%Y-%m-%d')
    mtd_end = (today + timedelta(days=1)).strftime('%Y-%m-%d')  # AWS API needs exclusive end

    # YTD: Jan 1 of current year to today
    ytd_start = today.replace(month=1, day=1).strftime('%Y-%m-%d')
    ytd_end = (today + timedelta(days=1)).strftime('%Y-%m-%d')

    return {
        'mtd': {'start': mtd_start, 'end': mtd_end},
        'ytd': {'start': ytd_start, 'end': ytd_end}
    }


def get_cost_data(profile: str, start_date: str, end_date: str,
                  granularity: str, metric: str, filter_json: Optional[Dict],
                  account_id: Optional[str], aws_cmd: str = 'aws',
                  group_by_usage_type: bool = False) -> Dict:
    """Execute AWS CLI command to get cost data."""
    # Determine group-by parameter
    if group_by_usage_type:
        # Group by usage type to get detailed breakdown (e.g., EBS volumes, snapshots)
        group_by = [{'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'}]
    elif account_id:
        group_by = [
            {'Type': 'DIMENSION', 'Key': 'SERVICE'},
            {'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}
        ]
    else:
        group_by = [{'Type': 'DIMENSION', 'Key': 'SERVICE'}]

    # Build AWS CLI command
    cmd = [
        aws_cmd, 'ce', 'get-cost-and-usage',
        '--profile', profile,
        '--time-period', f'Start={start_date},End={end_date}',
        '--granularity', granularity,
        '--metrics', metric,
        '--output', 'json'
    ]

    # Add group-by
    for group in group_by:
        cmd.extend(['--group-by', f"Type={group['Type']},Key={group['Key']}"])

    # Add filter if provided
    if filter_json:
        cmd.extend(['--filter', json.dumps(filter_json)])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode != 0 or 'error occurred' in result.stderr.lower():
            error_msg = result.stderr.strip() if result.stderr else f"AWS CLI error (exit code: {result.returncode})"
            return {'error': error_msg, 'data': {'ResultsByTime': [], 'GroupDefinitions': []}}

        return {'data': json.loads(result.stdout)}

    except json.JSONDecodeError:
        return {'error': 'Invalid JSON response from AWS CLI',
                'data': {'ResultsByTime': [], 'GroupDefinitions': []}}
    except Exception as e:
        return {'error': str(e), 'data': {'ResultsByTime': [], 'GroupDefinitions': []}}


def extract_ebs_cost(results_by_time: List[Dict]) -> Dict[str, float]:
    """Extract EBS-related costs from usage type breakdown."""
    ebs_costs = {}
    ebs_keywords = ['EBS', 'VolumeUsage', 'SnapshotUsage', 'VolumeIOUsage', 'VolumeP-IOPS']

    for result in results_by_time:
        for group in result.get('groups', []):
            usage_type = group.get('keys', [''])[0]

            # Check if usage type contains EBS-related keywords
            if any(keyword in usage_type for keyword in ebs_keywords):
                metrics = group.get('metrics', {})
                for metric_data in metrics.values():
                    amount = float(metric_data.get('amount', 0))
                    if usage_type not in ebs_costs:
                        ebs_costs[usage_type] = 0.0
                    ebs_costs[usage_type] += amount

    return ebs_costs


def compute_totals(results_by_time: List[Dict]) -> tuple:
    """Return (total_cost, average_cost) across all periods and groups."""
    total_cost = 0.0
    total_periods = len(results_by_time)

    for result in results_by_time:
        for group in result.get('groups', []):
            metrics = group.get('metrics', {})
            for metric_data in metrics.values():
                total_cost += float(metric_data.get('amount', 0))

    average_cost = total_cost / total_periods if total_periods > 0 else 0.0
    return total_cost, average_cost


def compute_monthly_costs(results_by_time: List[Dict]) -> List[Dict]:
    """Return per-period cost list with startDate, endDate, and cost (rounded to 2dp)."""
    monthly_costs = []
    for result in results_by_time:
        month_total = 0.0
        for group in result.get('groups', []):
            metrics = group.get('metrics', {})
            for metric_data in metrics.values():
                month_total += float(metric_data.get('amount', 0))

        time_period = result.get('timePeriod', {})
        monthly_costs.append({
            'startDate': time_period.get('start', ''),
            'endDate': time_period.get('end', ''),
            'cost': round(month_total, 2)
        })
    return monthly_costs


def compute_service_breakdown(results_by_time: List[Dict]) -> Dict[str, float]:
    """Return total cost per service (first key in each group) across all periods."""
    breakdown: Dict[str, float] = {}
    for result in results_by_time:
        for group in result.get('groups', []):
            service_name = group.get('keys', ['Unknown'])[0]
            metrics = group.get('metrics', {})
            for metric_data in metrics.values():
                breakdown[service_name] = breakdown.get(service_name, 0.0) + float(metric_data.get('amount', 0))
    return breakdown


def get_period_cost(profile: str, start_date: str, end_date: str,
                   metric: str, filter_json: Optional[Dict],
                   account_id: Optional[str], aws_cmd: str = 'aws',
                   verbose: bool = False) -> float:
    """Get total cost for a specific period (MTD or YTD)."""
    result = get_cost_data(profile, start_date, end_date, 'MONTHLY',
                          metric, filter_json, account_id, aws_cmd)

    if 'error' in result:
        if verbose:
            print(f"Warning: Error fetching period cost: {result['error']}", file=sys.stderr)
        return 0.0

    total = 0.0
    raw_response = result.get('data', {})

    for time_period in raw_response.get('ResultsByTime', []):
        for group in time_period.get('Groups', []):
            metrics = group.get('Metrics', {})
            for metric_data in metrics.values():
                amount = float(metric_data.get('Amount', 0))
                total += amount

    return total


def find_command(cmd: str) -> Optional[str]:
    """Find command in PATH or common installation locations."""
    import shutil

    # First try to find in PATH
    found = shutil.which(cmd)
    if found:
        return found

    # Check common installation locations for aws
    if cmd == 'aws':
        common_paths = [
            '/usr/local/bin/aws',
            '/usr/bin/aws',
            '/opt/homebrew/bin/aws',
            '~/.local/bin/aws'
        ]
        for path in common_paths:
            expanded_path = os.path.expanduser(path)
            if os.path.isfile(expanded_path) and os.access(expanded_path, os.X_OK):
                return expanded_path

    return None


def main():
    """Main execution function."""
    args = parse_arguments()

    # Check dependencies and find their paths
    global AWS_CMD
    AWS_CMD = find_command('aws')

    if not AWS_CMD:
        print("Error: Missing dependency: aws", file=sys.stderr)
        print("Please install AWS CLI from: https://aws.amazon.com/cli/", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"Using AWS CLI: {AWS_CMD}", file=sys.stderr)

    # Load config file if provided
    if args.config:
        load_config(args.config, args, args.verbose)

    # Normalize date inputs (strip time component if UTC datetime provided)
    if args.start_date:
        args.start_date = parse_date_input(args.start_date)
    if args.end_date:
        args.end_date = parse_date_input(args.end_date)

    # Set default dates
    if not args.start_date:
        args.start_date = (datetime.now() - timedelta(days=365)).strftime('%Y-%m-%d')
    if not args.end_date:
        args.end_date = datetime.now().strftime('%Y-%m-%d')

    # Store original end date for output (before adjustment)
    original_end_date = args.end_date

    # Always make end date inclusive by adding 1 day for API call
    # AWS API uses exclusive end dates, so we add 1 day to include the specified end date
    end_date_obj = datetime.strptime(args.end_date, '%Y-%m-%d').date()
    adjusted_end_date = end_date_obj + timedelta(days=1)

    # Validate that the adjusted end date is not in the future
    today = datetime.now().date()

    if adjusted_end_date > today + timedelta(days=1):
        print(f"Error: End date '{original_end_date}' would query future dates after inclusive adjustment.", file=sys.stderr)
        print(f"Maximum allowed end date is: {today.strftime('%Y-%m-%d')} (today)", file=sys.stderr)
        sys.exit(1)

    args.end_date = adjusted_end_date.strftime('%Y-%m-%d')

    if args.verbose:
        print(f"End date adjusted to be inclusive: {original_end_date} -> {args.end_date} (for API call)", file=sys.stderr)

    # Verbose output
    if args.verbose:
        print("AWS Cost Report Generation", file=sys.stderr)
        print("=" * 30, file=sys.stderr)
        print(f"Date Range: {args.start_date} to {args.end_date}", file=sys.stderr)
        print(f"Granularity: {args.granularity}", file=sys.stderr)
        print(f"Metric: {args.metric}", file=sys.stderr)
        print(f"Service Filter: {args.service or 'All Services'}", file=sys.stderr)
        print(f"Region Filter: {args.region or 'All Regions'}", file=sys.stderr)
        print(f"Tag Filter: {args.tag or 'None'}", file=sys.stderr)
        print(f"Account ID Filter: {args.account_id or 'All Accounts'}", file=sys.stderr)

    # Get AWS profiles
    if args.verbose:
        print("Detecting AWS CLI profiles...", file=sys.stderr)

    available_profiles = get_aws_profiles(AWS_CMD)

    if not available_profiles:
        print("Error: No AWS profiles found. Configure one using:", file=sys.stderr)
        print("    aws configure --profile <name>", file=sys.stderr)
        print(json.dumps({'error': 'No AWS profiles configured',
                          'message': 'Run: aws configure --profile <name>'}))
        sys.exit(1)

    if args.verbose:
        print(f"Available AWS Profiles: {', '.join(available_profiles)}", file=sys.stderr)

    # Determine profiles to process
    profile_list = []
    profile_errors = []

    if args.profiles:
        requested_profiles = [p.strip() for p in args.profiles.split(',')]
        for requested_profile in requested_profiles:
            if requested_profile in available_profiles:
                profile_list.append(requested_profile)
            else:
                if args.verbose:
                    print(f"Warning: Profile '{requested_profile}' does not exist", file=sys.stderr)
                profile_errors.append({
                    'profile': requested_profile,
                    'error': 'Profile does not exist'
                })

        if args.verbose:
            if profile_list:
                print(f"Valid Profiles to Process: {', '.join(profile_list)}", file=sys.stderr)
            else:
                print("Valid Profiles to Process: None", file=sys.stderr)
            if profile_errors:
                print(f"Invalid Profiles: {len(profile_errors)}", file=sys.stderr)
    else:
        profile_list = available_profiles
        if args.verbose:
            print(f"Processing All Profiles ({len(profile_list)}): {', '.join(profile_list)}", file=sys.stderr)

    # Check if we have valid profiles
    if not profile_list:
        if args.verbose:
            print("\nError: No valid profiles to process", file=sys.stderr)
        print(json.dumps([]))
        if profile_errors:
            print(json.dumps(profile_errors), file=sys.stderr)
        sys.exit(0)

    # Build filter
    filter_json = build_filter(args.service, args.region, args.tag, args.account_id)

    # Get MTD and YTD date ranges
    period_dates = get_period_dates()

    if args.verbose:
        print(f"\nPeriod Calculations:", file=sys.stderr)
        print(f"  MTD: {period_dates['mtd']['start']} to {period_dates['mtd']['end']}", file=sys.stderr)
        print(f"  YTD: {period_dates['ytd']['start']} to {period_dates['ytd']['end']}", file=sys.stderr)

    # Process each profile
    final_output = []

    for profile in profile_list:
        if args.verbose:
            print(f"\nProcessing Profile: {profile}", file=sys.stderr)

        # Get cost data
        result = get_cost_data(profile, args.start_date, args.end_date,
                               args.granularity, args.metric, filter_json, args.account_id, AWS_CMD,
                               args.group_by_usage_type)

        if 'error' in result:
            if args.verbose:
                print(f"Warning: AWS CLI Error for profile '{profile}': {result['error']}", file=sys.stderr)
            profile_errors.append({
                'profile': profile,
                'error': result['error']
            })
            raw_response = result['data']
        else:
            raw_response = result['data']

        # Count results
        result_count = len(raw_response.get('ResultsByTime', []))
        if args.verbose:
            print(f"Found {result_count} time periods", file=sys.stderr)
            if result_count > 0:
                groups_in_first = len(raw_response['ResultsByTime'][0].get('Groups', []))
                print(f"Groups in first period: {groups_in_first}", file=sys.stderr)

        # Convert to camelCase
        camel_response = to_camel_case(raw_response)

        # Filter out time periods with no costs
        results_by_time = [
            r for r in camel_response.get('resultsByTime', [])
            if len(r.get('groups', [])) > 0
        ]

        # Replace end date with original only for the last period.
        # Earlier periods have natural CE bucket boundaries (e.g. 2025-12-01) which are correct.
        if args.start_date != original_end_date and results_by_time:
            last = results_by_time[-1]
            if 'timePeriod' in last:
                last['timePeriod']['end'] = original_end_date

        # Build service-wise breakdown if no specific service is provided.
        # When --service is not set, the main query already groups by SERVICE with
        # no service filter — reuse results_by_time directly (no duplicate API call).
        service_breakdown = {}
        if not args.service:
            service_breakdown = compute_service_breakdown(results_by_time)
            if args.verbose:
                print(f"Service breakdown: {len(service_breakdown)} services found", file=sys.stderr)

        # Calculate total and average cost
        total_cost, average_cost = compute_totals(results_by_time)

        # Extract EBS costs if grouping by usage type OR if service is "EC2 - Other"
        ebs_breakdown = {}
        total_ebs_cost = 0.0
        if args.group_by_usage_type:
            ebs_breakdown = extract_ebs_cost(results_by_time)
            total_ebs_cost = sum(ebs_breakdown.values())
            if args.verbose:
                print(f"EBS costs extracted: {len(ebs_breakdown)} usage types", file=sys.stderr)
                print(f"Total EBS cost: ${total_ebs_cost:.2f}", file=sys.stderr)
        elif args.service == "EC2 - Other":
            # Automatically fetch usage type breakdown for EC2 - Other to extract EBS costs
            if args.verbose:
                print("Fetching usage type breakdown for EC2 - Other to extract EBS costs...", file=sys.stderr)

            usage_type_result = get_cost_data(profile, args.start_date, args.end_date,
                                             args.granularity, args.metric, filter_json,
                                             args.account_id, AWS_CMD, group_by_usage_type=True)

            if 'error' not in usage_type_result:
                usage_type_response = to_camel_case(usage_type_result['data'])
                usage_type_results = [
                    r for r in usage_type_response.get('resultsByTime', [])
                    if len(r.get('groups', [])) > 0
                ]
                ebs_breakdown = extract_ebs_cost(usage_type_results)
                total_ebs_cost = sum(ebs_breakdown.values())
                if args.verbose:
                    print(f"EBS costs extracted: {len(ebs_breakdown)} usage types", file=sys.stderr)
                    print(f"Total EBS cost: ${total_ebs_cost:.2f}", file=sys.stderr)

        # Get MTD and YTD costs
        if args.verbose:
            print("Fetching MTD cost...", file=sys.stderr)
        mtd_cost = get_period_cost(profile, period_dates['mtd']['start'],
                                   period_dates['mtd']['end'], args.metric,
                                   filter_json, args.account_id, AWS_CMD, args.verbose)

        if args.verbose:
            print("Fetching YTD cost...", file=sys.stderr)
        ytd_cost = get_period_cost(profile, period_dates['ytd']['start'],
                                   period_dates['ytd']['end'], args.metric,
                                   filter_json, args.account_id, AWS_CMD, args.verbose)

        # Calculate monthly cost breakdown
        monthly_costs = compute_monthly_costs(results_by_time)

        profile_data = {
            'profile': profile,
            'metric': args.metric,
            'groupDefinitions': camel_response.get('groupDefinitions', []),
            'resultsByTime': results_by_time,
            'dimensionValueAttributes': camel_response.get('dimensionValueAttributes', []),
            'monthlyCosts': monthly_costs,
            'averageCost': round(average_cost, 2),
            'totalCost': round(total_cost, 2),
            'mtdCost': round(mtd_cost, 2),
            'ytdCost': round(ytd_cost, 2)
        }

        # Add message if no data
        if len(results_by_time) == 0 and 'error' not in result:
            profile_data['message'] = 'No cost has been incurred for the given period of time'

        # Add service breakdown if available (sort once and reuse)
        sorted_service_breakdown = None
        if service_breakdown:
            sorted_service_breakdown = sorted(service_breakdown.items(), key=lambda x: x[1], reverse=True)
            profile_data['serviceBreakdown'] = {k: round(v, 2) for k, v in sorted_service_breakdown}

        # Add EBS breakdown if available
        if ebs_breakdown:
            profile_data['ebsBreakdown'] = {k: round(v, 2) for k, v in ebs_breakdown.items()}
            profile_data['totalEbsCost'] = round(total_ebs_cost, 2)

        final_output.append(profile_data)

        if args.verbose:
            periods_with_data = len(results_by_time)
            total_groups = sum(len(r.get('groups', [])) for r in results_by_time)
            print(f"Periods with cost data: {periods_with_data}", file=sys.stderr)
            print(f"Total service entries across all periods: {total_groups}", file=sys.stderr)
            print(f"Total cost: ${total_cost:.2f}", file=sys.stderr)
            print(f"Average cost per period: ${average_cost:.2f}", file=sys.stderr)
            print(f"MTD cost: ${mtd_cost:.2f}", file=sys.stderr)
            print(f"YTD cost: ${ytd_cost:.2f}", file=sys.stderr)
            if sorted_service_breakdown:
                print(f"Services found: {len(sorted_service_breakdown)}", file=sys.stderr)
                for svc, cost in sorted_service_breakdown[:5]:
                    print(f"  - {svc}: ${cost:.2f}", file=sys.stderr)

    # Summary
    if args.verbose:
        print("\nSummary:", file=sys.stderr)
        profiles_with_data = len([p for p in final_output if len(p.get('resultsByTime', [])) > 0])
        profiles_without_data = len([p for p in final_output if len(p.get('resultsByTime', [])) == 0])
        print(f"  Profiles with data: {profiles_with_data}", file=sys.stderr)
        print(f"  Profiles without data: {profiles_without_data}", file=sys.stderr)
        print(f"  Profiles with errors: {len(profile_errors)}", file=sys.stderr)

    # Save to file if requested
    if args.output:
        if args.verbose:
            print(f"\nWriting output to: {args.output}", file=sys.stderr)

        complete_output = {
            'data': final_output,
            'errors': profile_errors
        }

        with open(args.output, 'w') as f:
            json.dump(complete_output, f, indent=2)

        if args.verbose:
            print(f"Done. Report saved to {args.output}", file=sys.stderr)

    # Output data to stdout
    print(json.dumps(final_output, indent=2))

    # Output errors to stderr
    if profile_errors:
        print(json.dumps(profile_errors, indent=2), file=sys.stderr)


if __name__ == '__main__':
    main()
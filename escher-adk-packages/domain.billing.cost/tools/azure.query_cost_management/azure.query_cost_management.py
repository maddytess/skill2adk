#!/usr/bin/env python3
"""
Azure Cost Report Generator
Generate Azure cost and usage reports across multiple subscriptions.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
import re

from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient


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


def get_azure_subscriptions() -> List[Dict[str, str]]:
    """Get list of available Azure subscriptions using Azure SDK."""
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)

        subscriptions = []
        for sub in subscription_client.subscriptions.list():
            # Get tenant_id - it may be in different attributes depending on SDK version
            tenant_id = ""
            if hasattr(sub, 'tenant_id'):
                tenant_id = sub.tenant_id or ""
            elif hasattr(sub, 'home_tenant_id'):
                tenant_id = sub.home_tenant_id or ""

            # Get state attribute safely
            state = "Enabled"
            if hasattr(sub, 'state'):
                state = str(sub.state) if sub.state else "Enabled"

            subscriptions.append({
                'name': sub.display_name,
                'subscriptionId': sub.subscription_id,
                'tenantId': tenant_id,
                'state': state
            })

        return subscriptions
    except Exception as e:
        print(f"Error getting Azure subscriptions: {e}", file=sys.stderr)
        return []


def resolve_subscription_name_to_id(subscription_name: str, subscriptions: List[Dict[str, str]]) -> Optional[str]:
    """Resolve subscription name to subscription ID."""
    for sub in subscriptions:
        if sub['name'].lower() == subscription_name.lower():
            return sub['subscriptionId']
    return None


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Generate Azure cost and usage reports across multiple subscriptions.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate report for all subscriptions, last 365 days
  python3 azure_cost.py

  # Generate report for specific date range (end date is inclusive)
  python3 azure_cost.py --start 2024-01-01 --end 2024-12-31

  # Generate report for a specific subscription by name
  python3 azure_cost.py --subscription-name "Tessell QA BYOA"
        '''
    )

    # Date parameters
    parser.add_argument('--start', dest='start_date',
                        help='Start date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, default: 364 days ago)')
    parser.add_argument('--end', dest='end_date',
                        help='End date inclusive (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, default: today)')

    # Filter parameters
    parser.add_argument('--service',
                        help='Filter by service name (optional)')
    parser.add_argument('--resource-group',
                        help='Filter by resource group name (optional)')
    parser.add_argument('--location',
                        help='Filter by Azure location/region (optional)')
    parser.add_argument('--tags',
                        help='Filter by tags (format: Key1=Value1,Key2=Value2)')

    # Query parameters
    parser.add_argument('--granularity', default='Monthly',
                        choices=['Daily', 'Monthly'],
                        help='Granularity (default: Monthly)')
    parser.add_argument('--metric', default='ActualCost',
                        choices=['ActualCost', 'AmortizedCost'],
                        help='Metric name (default: ActualCost)')

    # Subscription and output parameters
    parser.add_argument('--subscriptions',
                        help='Comma-separated subscription names (default: all subscriptions)')
    parser.add_argument('--subscription-name',
                        help='Specify the subscription name (case-insensitive).')
    parser.add_argument('--output',
                        help='Output JSON file (optional)')
    parser.add_argument('--config',
                        help='JSON file containing parameters (optional)')

    # Flags
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output to stderr')

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
        if not args.resource_group and 'resource_group' in config:
            args.resource_group = config['resource_group']
        if not args.location and 'location' in config:
            args.location = config['location']
        if not args.tags and 'tags' in config:
            args.tags = config['tags']
        elif not args.tags and 'tag' in config:
            # Support legacy 'tag' config for backward compatibility
            args.tags = config['tag']
        if args.granularity == 'Monthly' and 'granularity' in config:
            args.granularity = config['granularity']
        if args.metric == 'ActualCost' and 'metric' in config:
            args.metric = config['metric']
        if not args.subscriptions and 'subscriptions' in config:
            args.subscriptions = config['subscriptions']
        if not args.output and 'output' in config:
            args.output = config['output']

    except FileNotFoundError:
        print(f"Error: Config file not found: {config_file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in config file: {e}", file=sys.stderr)
        sys.exit(1)


def build_filter(service: Optional[str], resource_group: Optional[str],
                 location: Optional[str], tags_str: Optional[str]) -> Dict:
    """Build Azure Cost Management filter from parameters."""
    dimensions = []
    tags = []

    # Add ServiceName filter
    if service:
        dimensions.append({
            'name': 'ServiceName',
            'operator': 'In',
            'values': [service]
        })

    # Add ResourceGroup filter
    if resource_group:
        dimensions.append({
            'name': 'ResourceGroup',
            'operator': 'In',
            'values': [resource_group]
        })

    # Add ResourceLocation filter
    if location:
        dimensions.append({
            'name': 'ResourceLocation',
            'operator': 'In',
            'values': [location]
        })

    # Add Tag filters (support multiple tags: Key1=Value1,Key2=Value2)
    if tags_str:
        for tag_pair in tags_str.split(','):
            if '=' in tag_pair:
                tag_key, tag_value = tag_pair.split('=', 1)
                tags.append({
                    'name': tag_key.strip(),
                    'operator': 'In',
                    'values': [tag_value.strip()]
                })

    # Build filter object
    filter_obj = {}
    if dimensions:
        filter_obj['dimensions'] = dimensions[0] if len(dimensions) == 1 else {'and': dimensions}
    if tags:
        filter_obj['tags'] = tags[0] if len(tags) == 1 else {'and': tags}

    # Combine dimensions and tags with 'and'
    if dimensions and tags:
        return {
            'and': [
                {'dimensions': filter_obj['dimensions']},
                {'tags': filter_obj['tags']}
            ]
        }
    elif dimensions:
        return {'dimensions': filter_obj['dimensions']}
    elif tags:
        return {'tags': filter_obj['tags']}

    return {}


def parse_azure_response(response_data: Dict, granularity: str) -> List[Dict]:
    """Parse Azure tabular response into AWS-like structure."""
    results_by_time = []

    if 'properties' not in response_data:
        return results_by_time

    properties = response_data['properties']
    columns = properties.get('columns', [])
    rows = properties.get('rows', [])

    # Find column indices
    col_indices = {}
    for idx, col in enumerate(columns):
        col_name = col.get('name', '')
        col_indices[col_name] = idx

    # Determine date column name based on granularity
    # Monthly granularity uses "BillingMonth", Daily uses "UsageDate"
    date_col_name = 'BillingMonth' if granularity == 'Monthly' else 'UsageDate'

    # Determine cost column name (PreTaxCost for ActualCost, CostUSD for AmortizedCost)
    cost_col_name = None
    if 'PreTaxCost' in col_indices:
        cost_col_name = 'PreTaxCost'
    elif 'CostUSD' in col_indices:
        cost_col_name = 'CostUSD'
    elif 'Cost' in col_indices:
        cost_col_name = 'Cost'

    # Group data by time period
    time_periods = {}

    for row in rows:
        # Extract values based on column indices
        if date_col_name in col_indices:
            date_value = row[col_indices[date_col_name]]
        elif 'UsageDate' in col_indices:
            date_value = row[col_indices['UsageDate']]
        elif 'BillingMonth' in col_indices:
            date_value = row[col_indices['BillingMonth']]
        else:
            continue

        # Get cost value from the appropriate column
        if cost_col_name and cost_col_name in col_indices:
            cost_value = row[col_indices[cost_col_name]]
        else:
            cost_value = 0

        service_name = row[col_indices.get('ServiceName', len(row) - 2)] if 'ServiceName' in col_indices else 'Unknown'
        resource_group = row[col_indices.get('ResourceGroupName', len(row) - 1)] if 'ResourceGroupName' in col_indices else 'Unknown'

        if date_value is None:
            continue

        # Parse date and create time period
        # BillingMonth format: "2025-01-01T00:00:00"
        # UsageDate format: 20250101 (integer)
        try:
            if isinstance(date_value, str) and 'T' in date_value:
                # ISO format from BillingMonth
                date_obj = datetime.strptime(date_value.split('T')[0], '%Y-%m-%d')
            else:
                # Integer format from UsageDate
                date_obj = datetime.strptime(str(date_value), '%Y%m%d')
        except ValueError:
            continue

        if granularity == 'Monthly':
            period_start = date_obj.strftime('%Y-%m-01')
            # Last day of month
            if date_obj.month == 12:
                period_end = date_obj.strftime('%Y-12-31')
            else:
                next_month = date_obj.replace(day=1, month=date_obj.month + 1)
                period_end = (next_month - timedelta(days=1)).strftime('%Y-%m-%d')
        else:  # Daily
            period_start = date_obj.strftime('%Y-%m-%d')
            period_end = date_obj.strftime('%Y-%m-%d')

        period_key = f"{period_start}_{period_end}"

        if period_key not in time_periods:
            time_periods[period_key] = {
                'timePeriod': {
                    'start': period_start,
                    'end': period_end
                },
                'total': {
                    'cost': {
                        'amount': 0.0,
                        'unit': 'USD'
                    }
                },
                'groups': {}
            }

        # Create a composite key for service + resource group
        group_key = f"{service_name}||{resource_group}"

        # Add to service + resource group combination
        if group_key not in time_periods[period_key]['groups']:
            time_periods[period_key]['groups'][group_key] = {
                'keys': [service_name, resource_group],
                'metrics': {
                    'cost': {
                        'amount': 0.0,
                        'unit': 'USD'
                    }
                }
            }

        time_periods[period_key]['groups'][group_key]['metrics']['cost']['amount'] += float(cost_value)
        time_periods[period_key]['total']['cost']['amount'] += float(cost_value)

    # Convert to list and format
    for period_data in time_periods.values():
        period_data['groups'] = list(period_data['groups'].values())
        results_by_time.append(period_data)

    # Sort by time period
    results_by_time.sort(key=lambda x: x['timePeriod']['start'])

    return results_by_time


def get_cost_data(subscription_id: str, subscription_name: str, start_date: str,
                  end_date: str, granularity: str, metric: str,
                  filter_config: Dict, verbose: bool) -> Dict:
    """Execute Azure CLI command to get cost data."""

    # Build request body for Azure Cost Management API
    # Determine query type and metric name based on requested metric
    if metric == 'AmortizedCost':
        query_type = 'AmortizedCost'
        metric_name = 'Cost'
    else:  # ActualCost
        query_type = 'Usage'
        metric_name = 'PreTaxCost'

    request_body = {
        'type': query_type,
        'timeframe': 'Custom',
        'timePeriod': {
            'from': start_date,
            'to': end_date
        },
        'dataset': {
            'granularity': granularity,
            'aggregation': {
                'totalCost': {
                    'name': metric_name,
                    'function': 'Sum'
                }
            },
            'grouping': [
                {
                    'type': 'Dimension',
                    'name': 'ServiceName'
                },
                {
                    'type': 'Dimension',
                    'name': 'ResourceGroupName'
                }
            ]
        }
    }

    # Add filter if provided
    if filter_config:
        request_body['dataset']['filter'] = filter_config

    try:
        # Build Azure CLI command using 'az rest'
        # Azure Cost Management API endpoint
        api_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.CostManagement/query?api-version=2023-11-01"

        cmd = [
            'az', 'rest',
            '--method', 'post',
            '--url', api_url,
            '--body', json.dumps(request_body),
            '--output', 'json'
        ]

        if verbose:
            print(f"Calling Azure Cost Management API for subscription: {subscription_name}", file=sys.stderr)
            print(f"URL: {api_url}", file=sys.stderr)
            print(f"Request body: {json.dumps(request_body, indent=2)}", file=sys.stderr)

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else f"Azure CLI error (exit code: {result.returncode})"
            if verbose:
                print(f"Error response: {result.stdout}", file=sys.stderr)
            return {
                'error': error_msg,
                'data': {
                    'subscriptionName': subscription_name,
                    'subscriptionId': subscription_id,
                    'resultsByTime': []
                }
            }

        response_data = json.loads(result.stdout)

        # Check for errors in response
        if 'error' in response_data:
            error_msg = response_data.get('error', {}).get('message', 'Unknown API error')
            return {
                'error': error_msg,
                'data': {
                    'subscriptionName': subscription_name,
                    'subscriptionId': subscription_id,
                    'resultsByTime': []
                }
            }

        results_by_time = parse_azure_response(response_data, granularity)

        return {
            'data': {
                'subscriptionName': subscription_name,
                'subscriptionId': subscription_id,
                'groupDefinitions': [
                    {
                        'type': 'Dimension',
                        'name': 'ServiceName'
                    },
                    {
                        'type': 'Dimension',
                        'name': 'ResourceGroupName'
                    }
                ],
                'resultsByTime': results_by_time
            }
        }

    except json.JSONDecodeError as e:
        return {
            'error': f'Invalid JSON response from Azure CLI: {str(e)}',
            'data': {
                'subscriptionName': subscription_name,
                'subscriptionId': subscription_id,
                'resultsByTime': []
            }
        }
    except Exception as e:
        return {
            'error': str(e),
            'data': {
                'subscriptionName': subscription_name,
                'subscriptionId': subscription_id,
                'resultsByTime': []
            }
        }


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


def main():
    """Main execution function."""
    args = parse_arguments()

    # Check dependencies
    try:
        subprocess.run(['az', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: Missing dependency: az", file=sys.stderr)
        print("Please install Azure CLI from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli", file=sys.stderr)
        sys.exit(1)

    # Load config file if provided
    if args.config:
        load_config(args.config, args, args.verbose)

    # Normalize date inputs (strip time component if UTC datetime provided)
    if args.start_date:
        args.start_date = parse_date_input(args.start_date)
    if args.end_date:
        args.end_date = parse_date_input(args.end_date)

    # Set default dates (Azure has 1-year lookback limit)
    if not args.start_date:
        args.start_date = (datetime.now(timezone.utc) - timedelta(days=364)).strftime('%Y-%m-%d')
    if not args.end_date:
        args.end_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')

    # Store original end date for output (before adjustment)
    original_end_date = args.end_date

    # Always make end date inclusive by adding 1 day for API call
    # Azure API uses exclusive end dates, so we add 1 day to include the specified end date
    end_date_obj = datetime.strptime(args.end_date, '%Y-%m-%d').date()
    adjusted_end_date = end_date_obj + timedelta(days=1)

    # Validate that the adjusted end date is not in the future
    today = datetime.now(timezone.utc).date()

    if adjusted_end_date > today + timedelta(days=1):
        print(f"Error: End date '{original_end_date}' would query future dates after inclusive adjustment.", file=sys.stderr)
        print(f"Maximum allowed end date is: {today.strftime('%Y-%m-%d')} (today)", file=sys.stderr)
        sys.exit(1)

    args.end_date = adjusted_end_date.strftime('%Y-%m-%d')

    if args.verbose:
        print(f"End date adjusted to be inclusive: {original_end_date} -> {args.end_date} (for API call)", file=sys.stderr)

    # Verbose output
    if args.verbose:
        print("Azure Cost Report Generation", file=sys.stderr)
        print("=" * 30, file=sys.stderr)
        print(f"Date Range: {args.start_date} to {args.end_date}", file=sys.stderr)
        print(f"Granularity: {args.granularity}", file=sys.stderr)
        print(f"Metric: {args.metric}", file=sys.stderr)
        print(f"Service Filter: {args.service or 'All Services'}", file=sys.stderr)
        print(f"Resource Group Filter: {args.resource_group or 'All Resource Groups'}", file=sys.stderr)
        print(f"Location Filter: {args.location or 'All Locations'}", file=sys.stderr)
        print(f"Tag Filter: {args.tags or 'None'}", file=sys.stderr)

    # Get Azure subscriptions
    if args.verbose:
        print("Detecting Azure subscriptions...", file=sys.stderr)

    available_subscriptions = get_azure_subscriptions()

    if not available_subscriptions:
        print("Error: No Azure subscriptions found. Please authenticate using:", file=sys.stderr)
        print("    az login", file=sys.stderr)
        print(json.dumps({'error': 'No Azure subscriptions found',
                          'message': 'Run: az login'}))
        sys.exit(1)

    # Determine subscriptions to process
    subscription_errors = []
    subscription_list = []

    if args.subscription_name:
        subscription_id = resolve_subscription_name_to_id(args.subscription_name, available_subscriptions)
        if not subscription_id:
            print(f"Error: Subscription '{args.subscription_name}' does not exist in your Azure account.", file=sys.stderr)
            print("\nAvailable subscriptions:", file=sys.stderr)
            for sub in available_subscriptions:
                print(f"  - {sub['name']}", file=sys.stderr)
            sys.exit(1)
        subscription_list = [sub for sub in available_subscriptions if sub['subscriptionId'] == subscription_id]
        if args.verbose:
            print(f"Processing Subscription: {args.subscription_name}", file=sys.stderr)
    elif args.subscriptions:
        requested_subs = [s.strip() for s in args.subscriptions.split(',')]
        for requested_sub in requested_subs:
            found = False
            for sub in available_subscriptions:
                if sub['name'] == requested_sub:
                    subscription_list.append(sub)
                    found = True
                    break
            if not found:
                if args.verbose:
                    print(f"Warning: Subscription '{requested_sub}' does not exist", file=sys.stderr)
                subscription_errors.append({
                    'subscription': requested_sub,
                    'error': 'Subscription does not exist'
                })
        if args.verbose:
            if subscription_list:
                sub_names = [s['name'] for s in subscription_list]
                print(f"Valid Subscriptions to Process: {', '.join(sub_names)}", file=sys.stderr)
            else:
                print("Valid Subscriptions to Process: None", file=sys.stderr)
            if subscription_errors:
                print(f"Invalid Subscriptions: {len(subscription_errors)}", file=sys.stderr)
    else:
        subscription_list = available_subscriptions
        if args.verbose:
            sub_names = [s['name'] for s in subscription_list]
            print(f"Processing All Subscriptions ({len(subscription_list)}): {', '.join(sub_names)}",
                  file=sys.stderr)

    # Check if we have valid subscriptions
    if not subscription_list:
        if args.verbose:
            print("\nError: No valid subscriptions to process", file=sys.stderr)
        print(json.dumps([]))
        if subscription_errors:
            print(json.dumps(subscription_errors), file=sys.stderr)
        sys.exit(0)

    # Build filter
    filter_config = build_filter(args.service, args.resource_group, args.location, args.tags)

    # Process each subscription
    final_output = []

    for subscription in subscription_list:
        sub_name = subscription['name']
        sub_id = subscription['subscriptionId']

        if args.verbose:
            print(f"\nProcessing Subscription: {sub_name}", file=sys.stderr)

        # Get cost data
        result = get_cost_data(sub_id, sub_name, args.start_date, args.end_date,
                               args.granularity, args.metric, filter_config, args.verbose)

        if 'error' in result:
            if args.verbose:
                print(f"Warning: Azure CLI Error for subscription '{sub_name}': {result['error']}",
                      file=sys.stderr)
            subscription_errors.append({
                'subscription': sub_name,
                'error': result['error']
            })

        subscription_data = result['data']

        # Count results
        result_count = len(subscription_data.get('resultsByTime', []))
        if args.verbose:
            print(f"Found {result_count} time periods", file=sys.stderr)
            if result_count > 0:
                groups_in_first = len(subscription_data['resultsByTime'][0].get('groups', []))
                print(f"Groups in first period: {groups_in_first}", file=sys.stderr)

        # Convert to camelCase
        camel_data = to_camel_case(subscription_data)
        results_by_time = camel_data.get('resultsByTime', [])

        # Replace end date with original only for the last period.
        # Earlier periods keep their natural API bucket boundaries.
        if args.start_date != original_end_date and results_by_time:
            last = results_by_time[-1]
            if 'timePeriod' in last:
                last['timePeriod']['end'] = original_end_date

        # Build service breakdown from already-fetched data (no duplicate API call).
        # When --service is not set, the main query already groups by ServiceName.
        service_breakdown = {}
        if not args.service:
            service_breakdown = compute_service_breakdown(results_by_time)
            if args.verbose:
                print(f"Service breakdown: {len(service_breakdown)} services found", file=sys.stderr)

        # Calculate total and average cost
        total_cost, average_cost = compute_totals(results_by_time)

        # Calculate monthly cost breakdown
        monthly_costs = compute_monthly_costs(results_by_time)

        camel_data['metric'] = args.metric
        camel_data['monthlyCosts'] = monthly_costs
        camel_data['averageCost'] = round(average_cost, 2)
        camel_data['totalCost'] = round(total_cost, 2)

        # Add message if no data
        if not results_by_time and 'error' not in result:
            camel_data['message'] = 'No cost has been incurred for the given period of time'

        # Add service breakdown if available (sort once and reuse)
        sorted_service_breakdown = None
        if service_breakdown:
            sorted_service_breakdown = sorted(service_breakdown.items(), key=lambda x: x[1], reverse=True)
            camel_data['serviceBreakdown'] = {k: round(v, 2) for k, v in sorted_service_breakdown}

        final_output.append(camel_data)

        if args.verbose:
            print(f"Total cost: ${total_cost:.2f}", file=sys.stderr)
            print(f"Average cost per period: ${average_cost:.2f}", file=sys.stderr)
            if sorted_service_breakdown:
                print(f"Services found: {len(sorted_service_breakdown)}", file=sys.stderr)
                for svc, cost in sorted_service_breakdown[:5]:
                    print(f"  - {svc}: ${cost:.2f}", file=sys.stderr)

    # Summary
    if args.verbose:
        print("\nSummary:", file=sys.stderr)
        subscriptions_with_data = len([s for s in final_output if len(s.get('resultsByTime', [])) > 0])
        subscriptions_without_data = len([s for s in final_output if len(s.get('resultsByTime', [])) == 0])
        print(f"  Subscriptions with data: {subscriptions_with_data}", file=sys.stderr)
        print(f"  Subscriptions without data: {subscriptions_without_data}", file=sys.stderr)
        print(f"  Subscriptions with errors: {len(subscription_errors)}", file=sys.stderr)

    # Save to file if requested
    if args.output:
        if args.verbose:
            print(f"\nWriting output to: {args.output}", file=sys.stderr)

        complete_output = {
            'data': final_output,
            'errors': subscription_errors
        }

        with open(args.output, 'w') as f:
            json.dump(complete_output, f, indent=2)

        if args.verbose:
            print(f"Done. Report saved to {args.output}", file=sys.stderr)

    # Output data to stdout
    print(json.dumps(final_output, indent=2))

    # Output errors to stderr
    if subscription_errors:
        print(json.dumps(subscription_errors, indent=2), file=sys.stderr)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Azure Monitor Metrics Script with Subscription Name Support

Fetches and filters Azure Monitor metrics for any Azure service, with support
for resolving subscription names to IDs.
"""

import argparse
import json
import subprocess
import sys
from typing import List, Optional, Dict

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.monitor import MonitorManagementClient

def resolve_subscription_name_to_id(subscription_name: str) -> Optional[str]:
    """Resolve subscription name to subscription ID using Azure CLI."""
    try:
        # Use Azure CLI to get subscriptions (only returns accessible ones)
        cmd = ['az', 'account', 'list', '--output', 'json']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        subscriptions = json.loads(result.stdout)

        for sub in subscriptions:
            # Match subscription name (case-insensitive)
            if sub.get('name', '').lower() == subscription_name.lower():
                return sub.get('id')

        return None
    except subprocess.CalledProcessError as e:
        print(f"Error resolving subscription name: {e.stderr}", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing subscription list: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error resolving subscription name: {e}", file=sys.stderr)
        return None

def get_resource_groups(subscription_id: Optional[str] = None) -> List[str]:
    """Get all resource groups in the subscription using Azure SDK."""
    try:
        if not subscription_id:
            print("Error: Subscription ID is required for SDK-based resource group lookup.", file=sys.stderr)
            return []

        credential = DefaultAzureCredential()
        resource_client = ResourceManagementClient(credential, subscription_id)

        resource_groups = []
        for rg in resource_client.resource_groups.list():
            resource_groups.append(rg.name)

        return resource_groups
    except Exception as e:
        print(f"Error getting resource groups: {e}", file=sys.stderr)
        return []

def get_resources_in_group(resource_group: str, subscription_id: Optional[str] = None, service_type: Optional[str] = None) -> List[Dict]:
    """Get all resources in a resource group using Azure SDK, optionally filtered by service type."""
    try:
        if not subscription_id:
            print("Error: Subscription ID is required for SDK-based resource lookup.", file=sys.stderr)
            return []

        credential = DefaultAzureCredential()
        resource_client = ResourceManagementClient(credential, subscription_id)

        # Service type mapping
        service_type_map = {
            'vm': 'Microsoft.Compute/virtualMachines',
            'sqldb': 'Microsoft.Sql/servers/databases',
            'webapp': 'Microsoft.Web/sites',
            'storage': 'Microsoft.Storage/storageAccounts',
            'cosmos': 'Microsoft.DocumentDB/databaseAccounts',
            'aks': 'Microsoft.ContainerService/managedClusters'
        }

        resources = []
        for resource in resource_client.resources.list_by_resource_group(resource_group):
            resource_dict = {
                'id': resource.id,
                'name': resource.name,
                'type': resource.type,
                'location': resource.location
            }

            # Filter by service type if specified
            if service_type:
                resource_type = service_type_map.get(service_type.lower())
                if resource_type and resource.type == resource_type:
                    resources.append(resource_dict)
            else:
                resources.append(resource_dict)

        return resources
    except Exception as e:
        print(f"Error getting resources in group {resource_group}: {e}", file=sys.stderr)
        return []

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Azure Monitor Metrics Script with Subscription Name Support.'
    )

    # Required parameters
    parser.add_argument('--service', required=True, help='Azure service type (e.g., vm, sqldb, webapp, storage, cosmos, aks)')
    parser.add_argument('--resource-group', help='Azure resource group name (optional, queries all resource groups if not specified)')

    # Optional parameters
    parser.add_argument('--metric', help='Azure Monitor metric name (e.g., "Percentage CPU", "dtu_used")')
    parser.add_argument('--resource', help='Specific resource name (optional)')
    parser.add_argument('--tags', help='Filter resources by Azure tags (format: Key1=Value1,Key2=Value2)')
    parser.add_argument('--duration', default='1h', help='Time range to query (default: 1h)')
    parser.add_argument('--start-date', help='Start date in YYYY-MM-DD format (requires --end-date)')
    parser.add_argument('--end-date', help='End date in YYYY-MM-DD format (requires --start-date)')
    parser.add_argument('--threshold', help='Filter values by condition (e.g., >80, <20)')
    parser.add_argument('--top', type=int, default=0, help='Return only top N highest values (default: 0 = all values)')
    parser.add_argument('--aggregation', default='Average', choices=['Average', 'Total', 'Maximum', 'Minimum', 'Count'],
                        help='Aggregation type (default: Average)')
    parser.add_argument('--subscription-name', help='Specify the subscription name (case-insensitive)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')

    return parser.parse_args()

def main():
    """Main execution function."""
    args = parse_arguments()

    # Resolve subscription name to ID if provided
    subscription_id = None
    if args.subscription_name:
        subscription_id = resolve_subscription_name_to_id(args.subscription_name)
        if not subscription_id:
            print(f"Error: Subscription name '{args.subscription_name}' not found.", file=sys.stderr)
            sys.exit(1)
        if args.verbose:
            print(f"Resolved subscription name '{args.subscription_name}' to ID '{subscription_id}'", file=sys.stderr)

    # Determine resource groups to query
    if args.resource_group:
        resource_groups = [args.resource_group]
    else:
        resource_groups = get_resource_groups(subscription_id)
        if not resource_groups:
            print("Error: No resource groups found.", file=sys.stderr)
            sys.exit(1)
        if args.verbose:
            print(f"Querying {len(resource_groups)} resource groups", file=sys.stderr)

    # Query metrics for each resource group
    all_metrics = []
    for rg in resource_groups:
        if args.verbose:
            print(f"Querying resource group: {rg}", file=sys.stderr)

        # Get resources in the resource group
        resources = get_resources_in_group(rg, subscription_id, args.service)

        if not resources:
            if args.verbose:
                print(f"No resources found in resource group {rg}", file=sys.stderr)
            continue

        if args.verbose:
            print(f"Found {len(resources)} resources in {rg}", file=sys.stderr)

        # Query metrics for each resource
        for resource in resources:
            resource_id = resource.get('id')
            resource_name = resource.get('name')

            if args.verbose:
                print(f"Querying resource: {resource_name}", file=sys.stderr)

            # Build Azure CLI command
            cmd = [
                'az', 'monitor', 'metrics', 'list',
                '--resource', resource_id,
                '--aggregation', args.aggregation
            ]

            # Add metric if specified
            if args.metric:
                cmd.extend(['--metrics', args.metric])

            if args.start_date and args.end_date:
                cmd.extend(['--start-time', args.start_date, '--end-time', args.end_date])
            elif args.duration:
                cmd.extend(['--interval', args.duration])

            if args.verbose:
                print(f"Executing command: {' '.join(cmd)}", file=sys.stderr)

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                metrics = json.loads(result.stdout)
                if metrics and 'value' in metrics:
                    # Add resource context to metrics
                    for metric in metrics['value']:
                        metric['resourceGroup'] = rg
                        metric['resourceName'] = resource_name
                        metric['resourceId'] = resource_id
                    all_metrics.extend(metrics['value'])
            except subprocess.CalledProcessError as e:
                if args.verbose:
                    print(f"Error querying resource {resource_name}: {e.stderr}", file=sys.stderr)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON response for resource {resource_name}: {e}", file=sys.stderr)

    # Output results
    if all_metrics:
        print(json.dumps(all_metrics, indent=2))
    else:
        output = {
            "message": "No metrics found for the specified criteria",
            "service": args.service,
            "metric": args.metric or 'Percentage CPU',
            "resource_groups": resource_groups,
            "subscription_name": args.subscription_name if args.subscription_name else None,
            "metrics": []
        }
        print(json.dumps(output, indent=2))

if __name__ == '__main__':
    main()

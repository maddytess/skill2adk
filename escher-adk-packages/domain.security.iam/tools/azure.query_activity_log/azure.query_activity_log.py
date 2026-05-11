#!/usr/bin/env python3
"""
Azure Activity Log Audit Script with Subscription Name Support

This script queries Azure Activity Logs with support for both single and
multiple resource providers, and allows resolving subscription names to IDs.
"""

import argparse
import json
import subprocess
import sys
from typing import List, Dict, Optional

from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient

def resolve_subscription_name_to_id(subscription_name: str) -> Optional[str]:
    """Resolve subscription name to subscription ID using Azure SDK."""
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)

        # List all subscriptions across all accessible tenants
        subscriptions = list(subscription_client.subscriptions.list())

        for sub in subscriptions:
            # Match subscription name (case-insensitive)
            if sub.display_name.lower() == subscription_name.lower():
                return sub.subscription_id

        return None
    except Exception as e:
        print(f"Error resolving subscription name: {e}", file=sys.stderr)
        return None

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Azure Activity Log Audit Script with Subscription Name Support.'
    )

    # Required parameters
    parser.add_argument('--start-time', required=True, help='ISO 8601 timestamp (e.g., 2025-01-01T00:00:00Z)')
    parser.add_argument('--resource-providers', required=True, help='Comma-separated list of resource providers')

    # Optional parameters
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

    # Split resource providers
    resource_providers = args.resource_providers.split(',')
    if args.verbose:
        print(f"Resource providers: {resource_providers}", file=sys.stderr)

    # Query each provider
    results = []
    for provider in resource_providers:
        if args.verbose:
            print(f"Querying provider: {provider}", file=sys.stderr)

        # Build Azure CLI command
        cmd = [
            'az', 'monitor', 'activity-log', 'list',
            '--start-time', args.start_time,
            '--namespace', provider
        ]

        if subscription_id:
            cmd.extend(['--subscription', subscription_id])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            provider_results = json.loads(result.stdout)
            results.extend(provider_results)
        except subprocess.CalledProcessError as e:
            print(f"Error querying provider {provider}: {e.stderr}", file=sys.stderr)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON response for provider {provider}: {e}", file=sys.stderr)

    # Output results
    if results:
        print(json.dumps(results, indent=2))
    else:
        output = {
            "message": "No activity log events found for the specified criteria",
            "start_time": args.start_time,
            "resource_providers": resource_providers,
            "subscription_name": args.subscription_name if args.subscription_name else None,
            "events": []
        }
        print(json.dumps(output, indent=2))

if __name__ == '__main__':
    main()

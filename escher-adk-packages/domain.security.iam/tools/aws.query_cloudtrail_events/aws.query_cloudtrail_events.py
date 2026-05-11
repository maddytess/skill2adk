#!/usr/bin/env python3
"""
AWS CloudTrail Audit Script (LLM-Ready) - Python Version
"""

import argparse
import boto3
import json
import sys
from datetime import datetime, timezone
from botocore.exceptions import ClientError


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg, verbose):
    if verbose:
        print(f"[DEBUG] {msg}", file=sys.stderr)


def parse_args():
    parser = argparse.ArgumentParser(description="AWS CloudTrail Audit Tool")

    # Required
    parser.add_argument("--profile", required=True, help="AWS profile name")
    parser.add_argument("--start-time", required=True, help="ISO start time (UTC)")
    parser.add_argument("--event-source", "--source", required=True, dest="event_source", help="AWS service event source")

    # Optional
    parser.add_argument("--end-time", default=utc_now(), help="ISO end time (UTC)")
    parser.add_argument("--username")
    parser.add_argument("--resource-name")
    parser.add_argument("--resource-type")
    parser.add_argument("--event-name")
    parser.add_argument("--ip")
    parser.add_argument("--error-code")
    parser.add_argument("--region")
    parser.add_argument("--format", choices=["full", "compact"], default="compact")
    parser.add_argument("--max-results", "--limit", type=int, default=25, dest="max_results", help="Maximum number of results to return")
    parser.add_argument("--verbose", action="store_true")

    return parser.parse_args()


def build_lookup_attributes(args, verbose):
    attrs = []

    if args.username:
        attrs.append({"AttributeKey": "Username", "AttributeValue": args.username})
        log(f"Filter: Username={args.username}", verbose)

    if args.resource_name:
        attrs.append({"AttributeKey": "ResourceName", "AttributeValue": args.resource_name})
        log(f"Filter: ResourceName={args.resource_name}", verbose)

    if args.event_name:
        attrs.append({"AttributeKey": "EventName", "AttributeValue": args.event_name})
        log(f"Filter: EventName={args.event_name}", verbose)

    # REQUIRED
    attrs.append({"AttributeKey": "EventSource", "AttributeValue": args.event_source})
    log(f"Filter: EventSource={args.event_source}", verbose)

    return attrs


def lookup_cloudtrail_events(args):
    session = boto3.Session(profile_name=args.profile)
    # Default to us-east-1 if no region specified or configured in profile
    region = args.region or session.region_name or 'us-east-1'
    log(f"Using region: {region}", args.verbose)
    client = session.client("cloudtrail", region_name=region)

    lookup_attrs = build_lookup_attributes(args, args.verbose)

    events = []
    paginator = client.get_paginator("lookup_events")

    try:
        for page in paginator.paginate(
            LookupAttributes=lookup_attrs,
            StartTime=datetime.fromisoformat(args.start_time.replace("Z", "+00:00")),
            EndTime=datetime.fromisoformat(args.end_time.replace("Z", "+00:00")),
        ):
            events.extend(page.get("Events", []))

            if args.max_results > 0 and len(events) >= args.max_results:
                events = events[: args.max_results]
                break

    except ClientError as e:
        print(json.dumps({
            "error": "CloudTrail lookup failed",
            "details": str(e)
        }))
        sys.exit(1)

    return events


def apply_post_filters(events, args):
    filtered = []

    for e in events:
        cloudtrail_event = json.loads(e.get("CloudTrailEvent", "{}"))

        if args.resource_type:
            resources = e.get("Resources", [])
            if not any(r.get("ResourceType") == args.resource_type for r in resources):
                continue

        if args.ip and cloudtrail_event.get("sourceIPAddress") != args.ip:
            continue

        if args.error_code and cloudtrail_event.get("errorCode") != args.error_code:
            continue

        filtered.append(e)

    return filtered


def format_events(events, mode):
    if mode == "full":
        # For full mode, convert datetime objects to ISO format strings
        formatted = []
        for e in events:
            event_copy = e.copy()
            if "EventTime" in event_copy and isinstance(event_copy["EventTime"], datetime):
                event_copy["EventTime"] = event_copy["EventTime"].isoformat()
            formatted.append(event_copy)
        return formatted

    compact = []
    for e in events:
        ce = json.loads(e.get("CloudTrailEvent", "{}"))

        compact.append({
            "event": e.get("EventName"),
            "time": e.get("EventTime").isoformat() if e.get("EventTime") else None,
            "user": e.get("Username"),
            "service": e.get("EventSource"),
            "read_only": e.get("ReadOnly"),
            "resources": e.get("Resources") or None,
            "source_ip": ce.get("sourceIPAddress"),
            "region": ce.get("awsRegion"),
            "error": ce.get("errorCode"),
        })

    return compact


def main():
    args = parse_args()

    log("Validating parameters", args.verbose)
    log(f"Start Time: {args.start_time}", args.verbose)
    log(f"End Time: {args.end_time}", args.verbose)

    events = lookup_cloudtrail_events(args)
    log(f"Events fetched: {len(events)}", args.verbose)

    events = apply_post_filters(events, args)
    log(f"Events after filtering: {len(events)}", args.verbose)

    formatted = format_events(events, args.format)

    print(json.dumps(formatted, indent=2))


if __name__ == "__main__":
    main()

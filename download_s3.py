#!/usr/bin/env python3
"""Download contents of s3://escher-adk-packages/ to ./escher-adk-packages/.

Uses an AWS profile from ~/.aws/config (SSO-aware). Pass --profile to pick one;
defaults to AWS_PROFILE env var or "default".
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, TokenRetrievalError

BUCKET = "escher-adk-packages"
DEFAULT_DEST = Path(__file__).parent / "escher-adk-packages"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", default=os.environ.get("AWS_PROFILE", "default"),
                   help="AWS profile name from ~/.aws/config")
    p.add_argument("--prefix", default="", help="Only download keys under this prefix")
    p.add_argument("--dest", type=Path, default=DEFAULT_DEST,
                   help="Local destination directory")
    return p.parse_args()


def download_bucket(profile: str, prefix: str, dest: Path) -> int:
    session = boto3.Session(profile_name=profile)
    s3 = session.client("s3")
    paginator = s3.get_paginator("list_objects_v2")

    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    total_bytes = 0

    for page in paginator.paginate(Bucket=BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"):
                continue
            local = dest / key
            local.parent.mkdir(parents=True, exist_ok=True)
            print(f"  {key} ({obj['Size']:,} B)")
            s3.download_file(BUCKET, key, str(local))
            count += 1
            total_bytes += obj["Size"]

    print(f"\nDone: {count} object(s), {total_bytes:,} bytes -> {dest}")
    return count


def main() -> int:
    args = parse_args()
    print(f"Profile: {args.profile}  Bucket: s3://{BUCKET}/{args.prefix}")
    print(f"Dest:    {args.dest}\n")
    try:
        download_bucket(args.profile, args.prefix, args.dest)
    except TokenRetrievalError:
        print(f"\nSSO token expired. Run: aws sso login --profile {args.profile}",
              file=sys.stderr)
        return 2
    except NoCredentialsError:
        print(f"\nNo credentials for profile '{args.profile}'. "
              f"Run: aws sso login --profile {args.profile}", file=sys.stderr)
        return 2
    except ClientError as e:
        print(f"\nAWS error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

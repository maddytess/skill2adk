"""skill2adk command-line entry point."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from .generator import write_package
from .inference import DEFAULT_MAX_RETRIES, InferenceConfig, infer_package
from .ingest import ingest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="skill2adk",
        description="Convert agentskills.io / Anthropic SKILL.md skills "
                    "into an Escher ADK package using Claude.",
    )
    p.add_argument("source",
                   help="Local skill directory, parent directory of multiple skill dirs, "
                        "or a github URL (https://github.com/owner/repo[/tree/branch/path]).")
    p.add_argument("--domain", required=True,
                   help="Domain name (e.g. 'security', 'billing', 'documents'). "
                        "Becomes domain.{domain}.{name}.")
    p.add_argument("--out", type=Path, default=Path.cwd() / "out",
                   help="Output directory; the package is written under <out>/<agent_id>/. "
                        "Default: ./out")
    p.add_argument("--retries", type=int, default=None,
                   help="Per-call retry budget. Falls back to SKILL2ADK_MAX_RETRIES "
                        f"in .env, then to {DEFAULT_MAX_RETRIES}.")
    p.add_argument("--api-key",
                   help="Override CLAUDE_API_KEY / ANTHROPIC_API_KEY from .env.")
    p.add_argument("--env-file", type=Path, default=Path(".env"),
                   help="Path to .env file (default: ./.env).")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress per-call usage logging.")
    args = p.parse_args(argv)

    if args.env_file.exists():
        load_dotenv(args.env_file)
    elif args.env_file != Path(".env"):
        print(f"warning: --env-file {args.env_file} not found", file=sys.stderr)

    retries = args.retries if args.retries is not None else int(
        os.environ.get("SKILL2ADK_MAX_RETRIES", DEFAULT_MAX_RETRIES)
    )

    print(f"Ingesting: {args.source}")
    try:
        corpus = ingest(args.source)
    except (FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"  {len(corpus.skills)} skill(s): {[s.name for s in corpus.skills]}")

    print(f"Inferring (domain={args.domain}, model=claude-opus-4-7, retries={retries})…")
    config = InferenceConfig(
        domain=args.domain,
        api_key=args.api_key,
        max_retries=retries,
        verbose=not args.quiet,
    )
    try:
        inferred = infer_package(corpus, config)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"  agent_id={inferred.agent_registry.agent_id}")
    print(f"  skills={len(inferred.skills)}  tools={len(inferred.tools)}  "
          f"guardrails={len(inferred.guardrails)}")

    pkg_dir = write_package(inferred, corpus, args.out)
    print(f"\nPackage written: {pkg_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

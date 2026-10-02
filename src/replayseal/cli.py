"""Offline evidence inspection; commands never load or execute recorded tools."""
import argparse
import json
import sys
from . import verify, compare, export_bundle, IntegrityError


def main(argv=None):
    parser = argparse.ArgumentParser(prog="replayseal", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("verify", help="verify content hashes, sequence and causal references")
    check.add_argument("path")
    check.add_argument("--expected-root")
    diff = commands.add_parser("diff", help="explain the first divergence without printing payloads")
    diff.add_argument("left")
    diff.add_argument("right")
    bundle = commands.add_parser("export", help="export a ZIP with a standalone verifier")
    bundle.add_argument("path")
    bundle.add_argument("destination")
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            evidence = verify(args.path, args.expected_root)
            result = {"verified": True, "root": evidence["manifest"]["root"], "events": len(evidence["events"])}
        elif args.command == "diff":
            result = compare(args.left, args.right)
        else:
            result = {"exported": True, "root": export_bundle(args.path, args.destination)}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 1 if args.command == "diff" and not result["equal"] else 0
    except (IntegrityError, OSError, ValueError) as error:
        # Paths and payload-bearing exceptions from the filesystem must not escape to stderr.
        print(json.dumps({"error": type(error).__name__, "message": "operation failed; verify input evidence and destination"}), file=sys.stderr)
        return 2

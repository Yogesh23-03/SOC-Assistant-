"""
Standalone CLI Executor for Target VM (M2 Deliverable).
Can be executed directly on the target Ubuntu VM or inside WSL2 to apply
iptables containment rules after verifying a signed approval token.

Usage:
  python -m backend.cli_executor --token '{"proposal_id": "...", ...}'
  python -m backend.cli_executor --file approval_token.json
  python -m backend.cli_executor --list
  python -m backend.cli_executor --expire
"""

import argparse
import json
import sys
from typing import Optional

from backend.executor import (
    execute_approved_action,
    expire_active_blocks,
    list_active_blocks,
)


def main():
    parser = argparse.ArgumentParser(
        description="SOC Assistant Target VM Firewall Executor. "
                    "Validates cryptographically signed approval tokens before applying iptables rules."
    )
    parser.add_argument("--token", type=str, help="Raw JSON string of the signed approval token")
    parser.add_argument("--file", type=str, help="Path to file containing signed approval token JSON")
    parser.add_argument("--dry-run", action="store_true", help="Simulate iptables commands without applying them")
    parser.add_argument("--list", action="store_true", help="List currently active firewall blocks")
    parser.add_argument("--expire", action="store_true", help="Expire and unblock any overdue firewall rules")

    args = parser.parse_args()

    # Subcommand: List Active Blocks
    if args.list:
        blocks = list_active_blocks()
        print(f"[*] Active Firewall Blocks ({len(blocks)}):")
        for b in blocks:
            print(f"    - Target: {b['target']} | Proposal: {b['proposal_id']} | Expires: {b['expires_at']}")
        return

    # Subcommand: Expire Overdue Rules
    if args.expire:
        expired = expire_active_blocks(dry_run=args.dry_run)
        print(f"[*] Expired and unblocked {len(expired)} rules: {expired}")
        return

    # Subcommand: Apply Token
    token_json_str: Optional[str] = None
    if args.token:
        token_json_str = args.token
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            token_json_str = f.read()

    if not token_json_str:
        parser.print_help()
        sys.exit(1)

    try:
        token_data = json.loads(token_json_str)
    except json.JSONDecodeError as exc:
        print(f"[-] Error: Invalid JSON token payload: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        result = execute_approved_action(token_data, dry_run=args.dry_run)
        print("[+] Containment Action Executed Successfully:")
        print(json.dumps(result, indent=2))
    except (PermissionError, ValueError, RuntimeError) as err:
        print(f"[-] Execution Refused: {err}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

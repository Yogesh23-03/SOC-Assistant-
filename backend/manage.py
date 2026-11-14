"""Trusted-terminal session provisioning. Tokens are never written to project files."""
import argparse
from backend.security import create_analyst_token


def main():
    parser = argparse.ArgumentParser(description='Issue a short-lived analyst token from a trusted backend terminal.')
    parser.add_argument('analyst_id')
    parser.add_argument('--minutes', type=int, default=120)
    args = parser.parse_args()
    if not 1 <= args.minutes <= 1440 or not 2 <= len(args.analyst_id.strip()) <= 64:
        parser.error('Use a 2-64 character identity and a lifetime of 1-1440 minutes')
    print(create_analyst_token(args.analyst_id.strip(), expires_in_minutes=args.minutes))


if __name__ == '__main__':
    main()

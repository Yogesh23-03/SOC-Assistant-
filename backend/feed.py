"""Read a lab auth.log or a JSON alert dataset and send authenticated webhooks.

This is an alert source only. It never generates attacks or executes containment.
The token is read from SOC_ANALYST_TOKEN, never from command-line arguments.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import httpx

PATTERN = re.compile(r'(?:Failed password|Invalid user|Accepted password).*? from (\d+\.\d+\.\d+\.\d+)')


def auth_alert(line, host, sequence=''):
    match = PATTERN.search(line)
    if not match:
        return None
    try:
        ipaddress.IPv4Address(match.group(1))
    except ValueError:
        return None
    return dict(alert_id='auth-' + hashlib.sha256((host + sequence + line).encode()).hexdigest()[:20],
                timestamp=datetime.now(timezone.utc).isoformat(), source_ip=match.group(1),
                rule_name='SSH authentication activity', host=host, severity='medium', log_text=line[:2000])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--auth-log', type=Path)
    source.add_argument('--dataset', type=Path)
    parser.add_argument('--backend', default='http://127.0.0.1:8000')
    parser.add_argument('--host', default='server-01')
    parser.add_argument('--follow', action='store_true')
    args = parser.parse_args()
    url = urlparse(args.backend)
    if url.scheme != 'https' and not (url.scheme == 'http' and url.hostname in ('127.0.0.1', 'localhost')):
        parser.error('Use HTTPS for remote backends; HTTP is allowed only on localhost')
    token = os.getenv('SOC_ANALYST_TOKEN', '').strip()
    if not token:
        parser.error('Set SOC_ANALYST_TOKEN to a short-lived analyst token')
    with httpx.Client(base_url=args.backend, headers={'Authorization': f'Bearer {token}'}, timeout=120, follow_redirects=False) as client:
        def submit(alert):
            response = client.post('/api/alerts', json=alert)
            if response.status_code == 401:
                raise SystemExit('Session expired; issue a fresh SOC_ANALYST_TOKEN')
            response.raise_for_status()
            print(f"{alert['alert_id']}: {response.json()['status']}")
        if args.dataset:
            from schemas.models import Alert
            for raw in json.loads(args.dataset.read_text(encoding='utf-8-sig'))['alerts']:
                submit({k: v for k, v in raw.items() if k in Alert.model_fields})
        else:
            # Follow by byte offset; handle truncation and rotation. Preserve partial lines.
            position = 0
            identity = None
            partial = ''
            while True:
                stat = args.auth_log.stat()
                current_identity = (stat.st_dev, stat.st_ino)
                if identity != current_identity or stat.st_size < position:
                    position, partial = 0, ''
                identity = current_identity
                with args.auth_log.open('r', encoding='utf-8', errors='replace') as stream:
                    stream.seek(position)
                    text = stream.read()
                    position = stream.tell()
                rows = (partial + text).splitlines(keepends=True)
                partial = ''
                for line in rows:
                    if args.follow and not line.endswith('\n'):
                        partial = line
                        continue
                    alert = auth_alert(line, args.host, str(position))
                    if alert:
                        submit(alert)
                if not args.follow:
                    break
                time.sleep(1)


if __name__ == '__main__':
    main()

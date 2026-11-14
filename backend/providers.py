"""Read-only threat-intelligence providers with explicit live mode and SQLite cache.

API contracts: https://docs.abuseipdb.com/#check-endpoint
https://docs.virustotal.com/reference/ip-info
"""
import ipaddress
import json
import os
import time
import httpx
from backend.database import get_db
from tools import readonly


def reputation(ip, db_path=None, client=None):
    address = ipaddress.IPv4Address(ip)
    if not address.is_global:
        return dict(ip=ip, reputation='unknown', score=None, reports=0,
                    source='local-policy', note='Non-public address; no external query sent')
    results = []
    for provider, key_name in [('abuseipdb', 'ABUSEIPDB_API_KEY'), ('virustotal', 'VIRUSTOTAL_API_KEY')]:
        key = os.getenv(key_name, '').strip()
        if not key:
            continue
        with get_db(db_path) as conn:
            cached = conn.execute('SELECT * FROM intel_cache WHERE provider=? AND indicator=?', (provider, ip)).fetchone()
        ttl = int(os.getenv('SOC_INTEL_CACHE_SECONDS', '86400'))
        if cached and time.time() - cached['fetched_at'] < ttl:
            results.append(dict(json.loads(cached['payload']), cached=True))
            continue
        try:
            get = client.get if client else httpx.get
            if provider == 'abuseipdb':
                response = get('https://api.abuseipdb.com/api/v2/check',
                               params={'ipAddress': ip, 'maxAgeInDays': 90}, headers={'Key': key, 'Accept': 'application/json'}, timeout=8)
                response.raise_for_status()
                data = response.json()['data']
                score, reports = int(data['abuseConfidenceScore']), int(data['totalReports'])
            else:
                response = get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}', headers={'x-apikey': key}, timeout=8)
                response.raise_for_status()
                stats = response.json()['data']['attributes']['last_analysis_stats']
                reports = int(stats.get('malicious', 0)) + int(stats.get('suspicious', 0))
                score = round(100 * reports / max(1, sum(stats.values())))
            result = dict(provider=provider, score=score, reports=reports, cached=False, stale=False)
            with get_db(db_path) as conn:
                conn.execute('INSERT OR REPLACE INTO intel_cache VALUES (?, ?, ?, ?)', (provider, ip, json.dumps(result), time.time()))
            results.append(result)
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            if cached:
                results.append(dict(json.loads(cached['payload']), cached=True, stale=True, error='Provider unavailable; stale cache'))
            else:
                results.append(dict(provider=provider, score=None, reports=0, error='Provider unavailable', stale=False))
    scored = [r for r in results if r.get('score') is not None]
    score = max((r['score'] for r in scored), default=None)
    return dict(ip=ip, reputation='unknown' if score is None else 'malicious' if score >= 50 else 'suspicious' if score > 0 else 'no-reports',
                score=score, reports=sum(r['reports'] for r in scored), source='live-providers', providers=results)


def tool_runner(name, ip, db_path=None):
    if os.getenv('SOC_DATA_MODE', 'fixture') != 'live':
        return readonly.run_tool(name, ip)
    if name not in ('search_logs', 'threat_intel'):
        return json.dumps(dict(ok=False, tool=name, error='Tool is not allowed'))
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return json.dumps(dict(ok=False, tool=name, error='Invalid IPv4 address'))
    if name == 'threat_intel':
        result = reputation(ip, db_path)
    else:
        with get_db(db_path) as conn:
            rows = conn.execute('SELECT alert_json FROM case_runs ORDER BY started_at DESC LIMIT 500').fetchall()
        lines = []
        for row in rows:
            log = json.loads(row['alert_json']).get('log_text', '')
            lines.extend(line[:2000] for line in log.splitlines() if ip in line)
        result = dict(ip=ip, lines=lines[:20], hits=len(lines), source='persisted-ingested-logs')
    return json.dumps(dict(ok=True, tool=name, result=result))

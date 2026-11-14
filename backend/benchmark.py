"""Reproducible pipeline evaluation. Offline mode validates plumbing, not AI accuracy.

Live mode must be explicitly selected and may consume provider quota. No executor
is imported or invoked by this tool.
"""
import argparse
import json
import statistics
import time
from pathlib import Path
from types import SimpleNamespace
from agents.llm import LLM, Settings
from agents.pipeline import run_pipeline
from schemas.models import Alert

BASE = Path(__file__).resolve().parent.parent


def fixture_llm(expected):
    replies = [dict(label=expected, confidence=.9, reasoning='Scripted fixture verdict', explanation='Offline wiring check')]
    if expected != 'false_positive':
        replies += [None, dict(action='escalate', target='manual-review', reason='Scripted fixture proposal', explanation='No firewall execution')]
    def create(**kwargs):
        content = replies.pop(0)
        message = SimpleNamespace(content=json.dumps(content) if content else 'No further lookups', tool_calls=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    return LLM(Settings(api_key='offline-only', model='scripted-fixture', max_retries=0), client=client)


def summarize(rows, mode):
    labelled = [r for r in rows if r['expected'] is not None]
    fp = [r for r in labelled if r['expected'] == 'false_positive']
    attacks = [r for r in labelled if r['expected'] != 'false_positive']
    matrix = {}
    for row in labelled:
        key = f"{row['expected']} -> {row['predicted']}"
        matrix[key] = matrix.get(key, 0) + 1
    return dict(mode=mode, measured_model_accuracy=round(sum(r['expected'] == r['predicted'] for r in labelled) / len(labelled), 4) if mode == 'live' and labelled else None,
                alerts=len(rows), labelled_alerts=len(labelled),
                false_positive_auto_close_rate=sum(r['predicted'] == 'false_positive' for r in fp) / len(fp) if mode == 'live' and fp else None,
                unsafe_auto_close_count=sum(r['predicted'] == 'false_positive' for r in attacks) if mode == 'live' else None,
                median_alert_to_proposal_seconds=statistics.median([r['seconds'] for r in rows if r['action'] != 'none']) if any(r['action'] != 'none' for r in rows) else None,
                execution_claims=sum(r['executed'] for r in rows), confusion_matrix=matrix,
                scope='Pipeline outputs only; does not measure real firewall actions or browser latency', rows=rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['offline', 'live'], default='offline')
    parser.add_argument('--dataset', type=Path, default=BASE / 'data/sample_alerts.json')
    parser.add_argument('--labels', type=Path, default=BASE / 'data/evaluation_labels.json')
    parser.add_argument('--limit', type=int, default=0)
    parser.add_argument('--delay', type=float, default=2)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    alerts = json.loads(args.dataset.read_text(encoding='utf-8-sig'))['alerts']
    labels = json.loads(args.labels.read_text(encoding='utf-8-sig'))
    rows = []
    live_llm = LLM() if args.mode == 'live' else None
    for raw in alerts[:args.limit or None]:
        payload = {k: v for k, v in raw.items() if k in Alert.model_fields}
        expected = labels.get(payload['alert_id'])
        start = time.perf_counter()
        result = run_pipeline(payload, live_llm if args.mode == 'live' else fixture_llm(expected or 'suspicious'))
        proposal = result.get('proposal') or {}
        rows.append(dict(alert_id=payload['alert_id'], expected=expected, predicted=result['verdict']['label'],
                         seconds=round(time.perf_counter() - start, 4), action=proposal.get('action', 'none'), executed=proposal.get('executed', False)))
        if args.mode == 'live' and args.delay > 0:
            time.sleep(args.delay)
    report = summarize(rows, args.mode)
    report['model'] = live_llm.settings.model if live_llm else 'scripted-fixture (not model evaluation)'
    output = args.output or BASE / f'results/benchmark_{args.mode}.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    lines = ['# SOC benchmark', f"Mode: {report['mode']}", f"Model: {report['model']}",
             f"Alerts: {report['alerts']}", f"Measured model accuracy: {report['measured_model_accuracy']}",
             f"False-positive auto-close rate: {report['false_positive_auto_close_rate']}",
             f"Unsafe auto-closes: {report['unsafe_auto_close_count']}",
             f"Median alert-to-proposal seconds: {report['median_alert_to_proposal_seconds']}",
             f"Execution claims in model outputs: {report['execution_claims']}", '', report['scope'], '',
             'Offline labels are scripted. Do not present offline results as model accuracy.', '',
             '| Case | Expected | Predicted | Action | Seconds |', '|---|---|---|---|---|']
    lines += [f"| {r['alert_id']} | {r['expected']} | {r['predicted']} | {r['action']} | {r['seconds']} |" for r in rows]
    output.with_suffix('.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'Saved {output.name} and {output.with_suffix(".md").name}')


if __name__ == '__main__':
    main()

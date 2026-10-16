"""Foreground agenda calls through this body's existing home owner adapter.

Payload is JSON on stdin. The installed publisher owns credential handling.
This helper starts no model, inbox listener or background service.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--publisher', required=True, type=Path,
                        help='The receiving installed daimon-home scripts/home.py')
    parser.add_argument('--binding', type=Path,
                        default=Path(os.environ.get('XDG_CONFIG_HOME', Path.home()/'.config'))/'daimon-home/binding.json')
    parser.add_argument('action', choices=['state','init','project-create','task-create','task-edit',
        'task-update','observations','observation-add','calendar-account','calendar-sync','calendar-skip','calendar-disconnect'])
    args = parser.parse_args()
    data = sys.stdin.read(65537)
    if len(data) > 65536:
        raise ValueError('Agenda request too large')
    payload = json.loads(data or '{}')
    if not isinstance(payload, dict):
        raise ValueError('JSON object required')
    spec = importlib.util.spec_from_file_location('receiving_home_publisher', args.publisher.resolve())
    publisher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(publisher)
    binding = json.loads(args.binding.read_text())
    result = publisher.owner_request(binding, 'agenda-'+args.action, payload)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        print(json.dumps({'error': str(error)}), file=sys.stderr)
        raise SystemExit(1)

"""Finite opt-in authority for the retained synthetic portal admission journey.

Use the existing signed TCP authority and atomic registrar-set transition. Keep
all original registrars and holder history; never copy signing custody or add a
second transport to work around a fixture configuration.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from clusterctl import being_seed
from clusterctl.admission import AdmissionAuthority, AdmissionTCPServer
from clusterctl.fences import Ed25519Signer
from clusterctl.production_fences import ProductionFenceStore


def prepare(state: Path, *, key: Path, key_id: str, registrars: dict[str, str],
            receipt: Path) -> AdmissionAuthority:
    before = ProductionFenceStore(state, signer=None, key_id=None,
        verifier_only=True).holder_registrar_position()
    current = {row['key_id']:row['public_key'] for row in before['registrars'] if row['state'] == 'active'}
    if not current or any(registrars.get(name) != public for name, public in current.items()):
        raise ValueError('preserve every original active synthetic registrar')
    authority = AdmissionAuthority(state, signer=Ed25519Signer(key, key_id),
        holder_registrars=current)
    transition = None
    if current != registrars:
        transition = authority.transition_registrars(registrars, expected_generation=before['generation'])
    after = authority.registrar_position()
    if {row['key_id']:row['public_key'] for row in after['registrars'] if row['state'] == 'active'} != registrars:
        raise ValueError('the selected synthetic registrar set was not observed')
    value = dict(schema='cluster-synthetic-registrar-selection/v1', before=before,
        transition=transition, after=after, model_turns_started=0, production_effects=0)
    if not receipt.exists():
        being_seed._write(receipt, value)
    elif being_seed._read(receipt)['after'] != after:
        raise ValueError('preserve the retained registrar transition receipt')
    return authority


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--key-id', required=True)
    parser.add_argument('--registrar', action='append', required=True, help='key-id=public-key-file')
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()
    selected = {}
    for row in args.registrar:
        name, filename = row.split('=', 1)
        if name in selected:
            raise ValueError('duplicate registrar')
        selected[name] = Path(filename).read_text(encoding='ascii').strip()
    authority = prepare(args.state, key=args.key, key_id=args.key_id,
        registrars=selected, receipt=args.receipt)
    with AdmissionTCPServer(('127.0.0.1', args.port), authority) as server:
        print(json.dumps(dict(ready=True, registrar_count=len(selected))), flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()

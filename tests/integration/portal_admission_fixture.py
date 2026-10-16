"""Prepare a retained, opt-in native Matrix admission fixture.

This is test setup, never a production enrollment entrypoint. A supported new
synthetic seed supplies real frozen input; the ordinary worker owns all stages.
No models, accounts, Telegram bots or SSH keys are created. Existing member
identities and their private state are not copied.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace

from clusterctl import being_seed, onboarding_code_successor, onboarding_consent, onboarding_input, onboarding_release
from clusterctl.onboarding import JobStore, digest, private_directory
from clusterctl.onboarding_custody import GRANT_SCHEMA, ROLES
from clusterctl.onboarding_group_coordinator import SCHEMA as GROUP_SCHEMA
from clusterctl.onboarding_host import HostBackend, HostConfig
from clusterctl.operation_journal import OperationJournal
from tests.test_onboarding import plan as fixture_plan

NAME = 'q227-native-join'
PROFILE = 'q227-native'


def incus(*arguments: str, value: dict | None = None) -> str:
    return subprocess.run(['incus', *arguments],
        input=None if value is None else json.dumps(value), text=True,
        capture_output=True, check=True, timeout=120).stdout


def retain(path: Path, value: dict) -> None:
    if path.exists():
        if being_seed._read(path) != value:
            raise ValueError('preserve the existing fixture selection')
    else:
        being_seed._write(path, value)


def prepare(root: Path, *, existing_host: Path, artifact: Path, source_observation: Path,
            admission_config: Path) -> dict:
    if os.geteuid() != 0:
        raise ValueError('this isolated fixture requires its root host controller')
    original = HostConfig.load(existing_host)
    if not original.qualification:
        raise ValueError('production host configurations are excluded')
    # A shared group requires the real managed admission backend, even before
    # an operation is selected. Validate it before allocating a guest or grants.
    from clusterctl.onboarding_managed import ManagedRuntime
    if not admission_config.is_absolute():
        raise ValueError('an absolute isolated managed admission config is required')
    ManagedRuntime(SimpleNamespace(config=SimpleNamespace(admission=admission_config)))
    root = private_directory(root, create=True)
    # Reject the earlier incomplete fixture before producing any new state.
    if (root/'plan.json').exists() and being_seed._read(root/'plan.json')['name'] != NAME:
        raise ValueError('preserve the earlier incomplete fixture; use the supported seed fixture')
    selected = json.loads(artifact.read_bytes())
    source_code = Path(selected['code'])
    code_digest = selected['runtime_digest']
    onboarding_release.verify(source_code, code_digest, uid=1000)
    public = Path('/opt/daimon-cluster-qualification')
    public.mkdir(mode=0o755, exist_ok=True)
    if public.stat().st_uid != 0 or public.stat().st_mode & 0o022:
        raise ValueError('trusted fixture code parent required')
    code = public/code_digest
    if not code.exists():
        shutil.copytree(source_code, code)
    onboarding_release.verify(code, code_digest, uid=0)
    onboarding_code_successor.verify(code, code_digest, original.code,
        original.release_digest, uid=0)
    observation = json.loads(source_observation.read_bytes())
    tribe = observation['group']['tribe_ref']
    intake = private_directory(root/'intake', create=True)
    being_seed.create(intake, dict(name=NAME, label='Synthetic native admission qualification',
        mode='new', browser=False, soul='Synthetic disposable Matrix integration fixture. No human history.'),
        owner='q227-lab', key=str(uuid.uuid5(uuid.NAMESPACE_URL, str(root)+'/'+NAME)))
    being_seed.prepare(intake, NAME, None, owner='q227-lab')
    inputs = private_directory(root/'inputs', create=True)
    captured = onboarding_input.capture(intake/'being-seeds'/NAME/'received', inputs/NAME,
        source_uid=0, resume=True, seed_mode='new')
    plan = {**fixture_plan(name=NAME, owner='q227-lab', browser=False),
        'release_digest':original.release_digest, 'seed_digest':captured['seed_digest']}
    scope = dict(schema='cluster-native-admission-fixture/v1', synthetic=True,
        name=NAME, instance='dm-'+NAME, original_host_sha256=digest(being_seed._read(existing_host)),
        plan_digest=digest(plan), code_digest=code_digest, tribe_ref=tribe,
        pre_matrix_context_memory='supported new synthetic seed; actual worker', model_turns_started=0)
    retain(root/'scope.json', scope)
    retain(root/'plan.json', plan)

    profiles = json.loads(incus('profile', 'list', '--format=json'))
    expected = dict(description='Isolated native Matrix admission qualification',
        config={'limits.cpu':'2', 'limits.memory':'1536MiB'},
        devices=dict(eth0=dict(type='none'),
            root=dict(type='disk', pool=original.pool, path='/')))
    actual = next((row for row in profiles if row['name'] == PROFILE), None)
    if actual is None:
        incus('profile', 'create', PROFILE)
        incus('profile', 'edit', PROFILE, value=expected)
        actual = next(row for row in json.loads(incus('profile', 'list', '--format=json'))
            if row['name'] == PROFILE)
    if any(actual[key] != value for key, value in expected.items()):
        raise ValueError('preserve the existing nonmatching fixture profile')

    config = being_seed._read(existing_host)
    # Reuse only the qualified image, pool and public receiving code. Every
    # mutable input, grant, queue and custody belongs to this synthetic fixture.
    for field in ('jobs', 'grants', 'progress', 'views', 'custody', 'custody_grants'):
        config[field] = str(private_directory(root/field, create=True))
    config.update(profile=PROFILE, runtime_code=str(code), runtime_digest=code_digest,
        inputs=str(inputs), consent_state=str(intake), consent_uid=0,
        group_admission=str(root/'group.json'), admission=str(admission_config))
    journal = OperationJournal(root/'journal')
    group = dict(schema=GROUP_SCHEMA, tribe_ref=tribe, journal=str(journal.path.parent),
        owners={NAME:dict(profile='guest', plan=plan,
            candidate=dict(code=str(code), digest=code_digest),
            root='/home/agent/.local/state/daimon-onboarding/'+NAME+'/matrix/package/runtime')},
        admissions={})
    retain(root/'group.json', group)
    retain(root/'host.json', config)
    retain(Path(config['grants'])/(NAME+'.json'),
        dict(schema='cluster-onboarding-host-grant/v1', plan=plan, revoked=False))
    retain(Path(config['custody_grants'])/(NAME+'.json'),
        dict(schema=GRANT_SCHEMA, plan_digest=digest(plan), ceremony='first-matrix-identity',
            execution_uid=0, source_binding_digest=digest(scope),
            owner_instruction_digest=digest(scope), roles=ROLES, revoked=False))
    proposal = onboarding_consent.review(plan, (original.code/'inheritance.md').read_text())
    onboarding_consent.Reviews(Path(config['progress']), worker_uid=0).publish(proposal)
    parent = private_directory(Path(config['consent_state'])/'being-seeds', create=True)
    decision_dir = private_directory(parent/NAME, create=True)
    decision = onboarding_consent._expected(proposal,
        dict(review_digest=proposal['review_digest'], inheritance_approved=True, matrix_identity_mode='first'))
    retain(decision_dir/('consent-'+proposal['review_digest']+'.json'), decision)
    backend = HostBackend(HostConfig.load(root/'host.json'))
    store = JobStore(backend.config.jobs)

    store.submit(plan, backend)
    row = store._load(NAME)
    return dict(prepared=True, name=NAME, instance='dm-'+NAME, stage=row['stage'],
        host_config=str(root/'host.json'), code_digest=code_digest,
        registered_group=False, model_turns_started=0, production_effects=0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--existing-host', type=Path, required=True)
    parser.add_argument('--artifact', type=Path, required=True)
    parser.add_argument('--source-observation', type=Path, required=True)
    parser.add_argument('--admission-config', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.root, existing_host=args.existing_host,
        artifact=args.artifact, source_observation=args.source_observation,
        admission_config=args.admission_config), sort_keys=True))


if __name__ == '__main__':
    main()

"""Resumable routine receiving maintenance over the existing owner controllers.

The root coordinator owns only protected public selections and child references.
Source custody, SDK and lifecycle journal remain under the receiving owner. No
model, global Stop, worker pause or arbitrary command callback is provided.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from . import being_seed, onboarding_code_successor, onboarding_release, onboarding_sdk
from .onboarding import OnboardingError, digest, refusal_diagnostic
from .operation_journal import OperationJournal
from .onboarding_owner_control import PUBLIC_ERRORS as OWNER_PUBLIC_ERRORS

SCHEMA = 'cluster-receiving-maintenance/v1'
MODULE = 'clusterctl.receiving_maintenance'

# Disclosure is based on known public codes, never spelling of exception text.
PUBLIC_ERRORS = OWNER_PUBLIC_ERRORS | frozenset({
    'receiving_maintenance_binding_required', 'receiving_maintenance_child_conflict',
    'receiving_maintenance_owner_required', 'receiving_maintenance_preparation_required',
    'receiving_maintenance_preservation_required', 'receiving_maintenance_action_required',
    'receiving_maintenance_owner_refused', 'receiving_maintenance_root_required',
    'receiving_maintenance_completed_job_required', 'receiving_maintenance_host_changed',
    'receiving_maintenance_current_roster_required',
    'qualified_receiving_observer_required', 'receiving_source_configuration_changed',
    'receiving_source_owner_binding_required', 'receiving_required_cohort_changed',
    'receiving_cohort_predecessor_changed', 'receiving_sender_precondition_changed',
    'host_authorization_required', 'qualified_onboarding_candidate_mount_required',
    'qualified_guest_bootstrap_candidate_required',
})


def public_error(error: Exception) -> str:
    if isinstance(error, (OnboardingError, being_seed.SeedError)) and str(error) in PUBLIC_ERRORS:
        return str(error)
    diagnostic = refusal_diagnostic(error, stage='receiving-maintenance')['code']
    return diagnostic if diagnostic != 'unclassified_refusal' else 'receiving_maintenance_owner_refused'



def _path(value) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute() or '..' in Path(value).parts:
        raise OnboardingError('receiving_maintenance_binding_required')
    return Path(value)


def _artifact(value: dict) -> tuple[Path, str]:
    if (not isinstance(value, dict) or set(value) != {'code', 'code_digest'}
            or re.fullmatch('[0-9a-f]{64}', value.get('code_digest', '')) is None):
        raise OnboardingError('receiving_maintenance_binding_required')
    return _path(value['code']), value['code_digest']


def validate(spec: dict) -> dict:
    if (not isinstance(spec, dict) or set(spec) != {'schema', 'name', 'journal', 'host_config',
            'candidate', 'observer', 'source', 'guests'} or spec['schema'] != SCHEMA
            or not isinstance(spec['name'], str) or re.fullmatch('[a-z0-9][a-z0-9-]{0,63}', spec['name']) is None
            or not isinstance(spec['guests'], dict) or not 1 <= len(spec['guests']) <= 64
            or any(re.fullmatch('[a-z0-9][a-z0-9-]{0,30}', name) is None or name == 'source'
                   for name in spec['guests'])):
        raise OnboardingError('receiving_maintenance_binding_required')
    candidate = spec['candidate']
    if (not isinstance(candidate, dict) or set(candidate) != {'code', 'code_digest',
            'manifest_path', 'manifest_digest', 'expires_at_ms'}
            or re.fullmatch('[0-9a-f]{64}', candidate.get('manifest_digest', '')) is None
            or type(candidate.get('expires_at_ms')) is not int or not 0 < candidate['expires_at_ms'] < 2**53):
        raise OnboardingError('receiving_maintenance_binding_required')
    _artifact({key: candidate[key] for key in ('code', 'code_digest')})
    _artifact(spec['observer'])
    _path(candidate['manifest_path'])
    for name in ('journal', 'host_config'):
        _path(spec[name])
    source = spec['source']
    if (not isinstance(source, dict) or set(source) != {'uid', 'gid', 'home', 'config',
            'config_sha256', 'unit', 'root', 'socket', 'bootstrap_venv', 'bootstrap_imports',
            'journal', 'transaction', 'tooling'}
            or any(type(source.get(key)) is not int or not 0 < source[key] < 2**32 for key in ('uid', 'gid'))
            or re.fullmatch('[0-9a-f]{64}', source.get('config_sha256', '')) is None):
        raise OnboardingError('receiving_maintenance_binding_required')
    for name in ('home', 'config', 'unit', 'root', 'socket', 'bootstrap_venv',
                 'bootstrap_imports', 'journal', 'transaction'):
        _path(source[name])
    for guest in spec['guests'].values():
        if not isinstance(guest, dict) or set(guest) != {'grant', 'tooling'}:
            raise OnboardingError('receiving_maintenance_binding_required')
        _path(guest['grant'])
    from .onboarding_owner_client import validate_tooling_recipe
    for profile in (source, *spec['guests'].values()):
        validate_tooling_recipe(profile['tooling'])
    return copy.deepcopy(spec)


def current_roster(observed: dict) -> str:
    """Routine preservation requires the already migrated signed group view."""
    roster = observed.get('runtime_status', {}).get('receiving', {}).get('rosters', {}).get('tribe')
    if (not isinstance(roster, dict) or roster.get('schema') != 'dm.runtime.tribe-roster/v1'
            or not isinstance(roster.get('roster_sha256'), str)
            or re.fullmatch('[0-9a-f]{64}', roster['roster_sha256']) is None):
        raise OnboardingError('receiving_maintenance_current_roster_required')
    return roster['roster_sha256']


def _sdk(code: Path, fingerprint: str) -> tuple[dict, dict]:
    onboarding_release.verify(code, fingerprint, uid=0)
    parameters = onboarding_code_successor.sdk_parameters(code, uid=0)
    if not parameters:
        raise OnboardingError('qualified_receiving_observer_required')
    return onboarding_sdk.verify(code, uid=0, **parameters), parameters


def _owner_paths(spec: dict, *, observer: bool) -> tuple[Path, Path, Path]:
    selection = spec['observer'] if observer else spec['candidate']
    code, fingerprint = _artifact({key: selection[key] for key in ('code', 'code_digest')})
    sdk, _ = _sdk(code, fingerprint)
    generation = _path(spec['source']['home']) / '.local/share/daimon-matrix/sdk' / digest(sdk)
    # Derive only; the root coordinator must not stat/open the owner's SDK.
    return code, generation / 'venv', generation / 'runtime-imports'


def _source_row(journal: OperationJournal, spec: dict):
    target = 'source-bootstrap:maintenance:' + digest(spec)
    row = journal.latest_for_idempotency_key(
        'receiving-update:' + target + ':' + spec['candidate']['manifest_digest'])
    if row is None:
        return None
    if (row['expected_precondition'].get('maintenance_binding') != digest(spec)
            or row['intent']['runtime_call']['manifest_digest'] != spec['candidate']['manifest_digest']
            or row['state'] in {'degraded', 'compensated', 'completed'}):
        raise OnboardingError('receiving_maintenance_child_conflict')
    return row


def resume_source(controller, *, timeout_seconds: float = 60) -> dict:
    """Never replay quiescence/publication after an acknowledged selection."""
    row = controller._row()[0]
    effects = (row['runtime_observation'] or {}).get('source_bootstrap', {})
    if any(key in effects for key in ('start_intent', 'controlled_loaded')) and 'unit_selected' not in effects:
        raise OnboardingError('receiving_maintenance_child_conflict')
    if 'unit_selected' not in effects:
        if 'quiesced' not in effects:
            controller.quiesce(timeout_seconds=timeout_seconds)
        controller.publish()
    # start observes an already active candidate after a lost response. It
    # revalidates retained controlled_loaded, never stops a replacement process.
    return controller.start(timeout_seconds=timeout_seconds)


def source_worker(spec: dict, action: str) -> dict:
    """Run only after dropping to the configured non-root receiving owner."""
    spec = validate(spec)
    source_binding, candidate = spec['source'], spec['candidate']
    if (os.geteuid(), os.getegid()) != (source_binding['uid'], source_binding['gid']):
        raise OnboardingError('receiving_maintenance_owner_required')
    observer, fingerprint = _artifact(spec['observer'])
    if Path(__file__).resolve().parents[1] != observer:
        raise OnboardingError('qualified_receiving_observer_required')
    _sdk(observer, fingerprint)
    if action == 'prepare-sdk':
        installed = set()
        for selection in (spec['observer'], candidate):
            code, code_digest = _artifact({key: selection[key] for key in ('code', 'code_digest')})
            selected_sdk, parameters = _sdk(code, code_digest)
            if digest(selected_sdk) in installed:
                continue
            installed.add(digest(selected_sdk))
            venv = onboarding_sdk.install(_path(source_binding['home']), code, code_digest,
                code_uid=0, **parameters)
            onboarding_sdk.runtime_imports(venv, code, code_uid=0, **parameters)
        return {'sdk_prepared': True, 'services_changed': 0}
    code, venv, imports = _owner_paths(spec, observer=True)
    _, parameters = _sdk(code, fingerprint)
    if Path(sys.prefix) != venv or not onboarding_sdk.startup_context(venv, imports, code):
        raise OnboardingError('qualified_runtime_context_required')
    onboarding_sdk.qualified_startup(venv, code, code_digest=fingerprint, code_uid=0, **parameters)
    settings = being_seed._read(_path(source_binding['config']))
    if digest(settings) != source_binding['config_sha256']:
        raise OnboardingError('receiving_source_configuration_changed')
    from .onboarding_source import Source
    from .onboarding_service import MatrixUserService
    from .onboarding_receiving_update import (SourceBootstrapController, freeze_source_bootstrap,
                                              prepare_source_bootstrap)
    source = Source(settings, code=_path(candidate['code']), code_uid=0,
                    code_digest=candidate['code_digest'])
    if source.root != _path(source_binding['root']):
        raise OnboardingError('receiving_source_configuration_changed')
    manager = MatrixUserService(_path(source_binding['unit']))
    journal = OperationJournal(_path(source_binding['journal']))
    row = _source_row(journal, spec)
    if row is None:
        if action != 'prepare':
            raise OnboardingError('receiving_maintenance_preparation_required')
        # Lookup above deliberately precedes fresh observations/timestamps.
        request = prepare_source_bootstrap(source, home=_path(source_binding['home']),
            code=_path(candidate['code']), code_digest=candidate['code_digest'],
            config=_path(source_binding['config']), manifest_path=_path(candidate['manifest_path']),
            manifest_digest=candidate['manifest_digest'], transaction=_path(source_binding['transaction']),
            expires_at_ms=candidate['expires_at_ms'], code_uid=0, manifest_uid=0)
        frozen = freeze_source_bootstrap(source, manager)
        if frozen.get('mode') != 'preserve':
            raise OnboardingError('receiving_maintenance_preservation_required')
        row = onboarding_code_successor.plan_update(journal, manifest_digest=candidate['manifest_digest'],
            target='source-bootstrap:maintenance:' + digest(spec),
            expected_precondition={'source_bootstrap': frozen, 'maintenance_binding': digest(spec)},
            intended_transition={'source_bootstrap': request}, audit_identity={'actor': 'receiving-maintenance'})
    selected_group = row['intended_transition']['source_bootstrap']['qualification']['group']['selected']
    if selected_group.get('socket') != source_binding['socket']:
        raise OnboardingError('receiving_source_configuration_changed')
    reference = dict(operation_id=row['operation_id'], journal=source_binding['journal'])
    if action == 'prepare':
        return dict(reference=reference, frozen=row['expected_precondition']['source_bootstrap'],
                    request=row['intended_transition']['source_bootstrap'])
    if action != 'execute':
        raise OnboardingError('receiving_maintenance_action_required')
    loaded = resume_source(SourceBootstrapController(journal, row['operation_id'], source, manager))
    return dict(reference=reference, loaded=loaded)


def _response(result, *, deadline_ns: int) -> dict:
    if time.monotonic_ns() >= deadline_ns:
        raise OnboardingError('receiving_owner_deadline_expired')
    if result.returncode:
        for line in result.stderr.splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if (isinstance(value, dict) and set(value) == {'error'} and isinstance(value['error'], str)
                    and public_error(OnboardingError(value['error'])) == value['error']):
                raise OnboardingError(value['error'])
        raise OnboardingError('receiving_maintenance_owner_refused')
    if len(result.stdout.encode()) > being_seed.MAX_SELECTION:
        raise OnboardingError('receiving_maintenance_owner_refused')
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or 'error' in value:
        raise OnboardingError('receiving_maintenance_owner_refused')
    return value


class SourceMaintenanceClient:
    """Root adapter whose private interpreter is entered only after UID drop."""

    def __init__(self, spec: dict):
        self.spec = validate(spec)

    def call(self, action: str) -> dict:
        if action not in {'prepare-sdk', 'prepare', 'execute'}:
            raise OnboardingError('receiving_maintenance_action_required')
        source = self.spec['source']
        code, fingerprint = _artifact(self.spec['observer'])
        _sdk(code, fingerprint)
        info = _path(source['config']).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077
                or (info.st_uid, info.st_gid) != (source['uid'], source['gid'])):
            raise OnboardingError('receiving_source_owner_binding_required')
        if action == 'prepare-sdk':
            venv, imports = _path(source['bootstrap_venv']), _path(source['bootstrap_imports'])
        else:
            _, venv, imports = _owner_paths(self.spec, observer=True)
        argv = onboarding_sdk.runtime_command(venv, imports, code, MODULE, ['--owner', action])
        budget = 1800 if action == 'prepare-sdk' else 180
        deadline = time.monotonic_ns() + budget * 1_000_000_000
        result = subprocess.run(argv, input=json.dumps(self.spec), text=True, capture_output=True,
            timeout=budget, user=source['uid'], group=source['gid'], extra_groups=(),
            env={'PATH': os.defpath, 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
        return _response(result, deadline_ns=deadline)



def expected_owner(observed: dict) -> dict:
    status = observed.get('runtime_status', observed)
    loaded, application = status['loaded_runtime'], status['loaded_application']
    return dict(process=observed['process'], server=loaded['local_origin'],
        admission_parent=observed.get('admission_parent'), selection=dict(
            receiving_code=loaded['qualified_startup']['code_digest'],
            matrix_sdk=loaded['qualified_startup']['matrix_wheel_sha256'],
            runtime_bundle_sha256=loaded['runtime_bundle_sha256'],
            application_sha256=application['application_sha256'],
            publication_sha256=application['publication_sha256'],
            visibility_installation_sha256=application['visibility']['installation_sha256']))


class PinnedOwnerClient:
    """Maintain one observed process with the approved short owner-control CLI.

    Body tooling/lifecycle APIs remain on the body selection. Observation and
    controls execute the separately approved observer; their replies still have
    to match the authenticated actual body/process, not the observer startup.
    """

    def __init__(self, base, observer: dict, expected: dict, *, body_code: Path):
        self.base, self.observer, self.expected = base, copy.deepcopy(observer), copy.deepcopy(expected)
        self.body_code = body_code
        self.time_namespace = os.readlink('/proc/self/ns/time')

    def __getattr__(self, name):
        return getattr(self.base, name)

    @property
    def deadline_ns(self):
        return self.base.deadline_ns

    @deadline_ns.setter
    def deadline_ns(self, value):
        self.base.deadline_ns = value

    def _call(self, *, command=None, path=None, expires_at_ms=None, native_tooling=None,
              require_admitted=False) -> dict:
        from .onboarding_receiving_update import GuestGroupClient
        guest = isinstance(self.base, GuestGroupClient)
        if expires_at_ms is not None and require_admitted != guest:
            raise OnboardingError('receiving_control_parent_changed')
        code, fingerprint = _artifact(self.observer)
        sdk, _ = _sdk(code, fingerprint)
        deadline = time.monotonic_ns() + int(self.base.timeout_seconds * 1_000_000_000)
        if self.deadline_ns is not None:
            deadline = min(deadline, self.deadline_ns)
        if deadline <= time.monotonic_ns():
            raise OnboardingError('receiving_owner_deadline_expired')
        options = {}
        if guest:
            backend, plan = self.base.backend, self.base.plan
            if not backend.authorize(plan, digest(plan)) or not backend._ceremony(plan).authorize(plan):
                raise OnboardingError('host_authorization_required')
            vector = (code, fingerprint)
            code, _, mounts = backend._runtime_paths(plan, backend._receiving_base(plan), candidate=vector)
            if not backend._mounted(plan, mounts, deadline_ns=deadline):
                raise OnboardingError('qualified_onboarding_candidate_mount_required')
            generation = Path('/home/agent/.local/share/daimon-matrix/sdk') / digest(sdk)
        else:
            info = self.base.config.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077
                    or (info.st_uid, info.st_gid) != (self.base.owner_uid, self.base.owner_gid)):
                raise OnboardingError('receiving_source_owner_binding_required')
            generation = self.base.venv.parent.parent / digest(sdk)
            options = dict(user=self.base.owner_uid, group=self.base.owner_gid, extra_groups=())
        arguments = ['--root', str(self.root), '--socket', str(self.socket), '--deadline-ns', str(deadline),
                     '--time-namespace', self.time_namespace]
        payload = {'expected': self.expected}
        if expires_at_ms is not None:
            arguments += ['--identity-expires-at-ms', str(expires_at_ms), '--code', str(self.body_code)]
            if native_tooling is not None:
                body = self.base.candidate if guest else (self.base.code, self.base.code_digest)
                body_sdk, _ = _sdk(*body)
                arguments += ['--body-venv', str(generation.parent / digest(body_sdk) / 'venv')]
            if guest:
                arguments += ['--require-admitted']
            payload['native_tooling'] = native_tooling
        elif command is None:
            arguments += ['--observe-only']
        else:
            arguments += ['--path', str(path)]
            payload['command'] = command
        argv = onboarding_sdk.runtime_command(generation / 'venv', generation / 'runtime-imports',
            code, 'clusterctl.onboarding_owner_control', arguments)
        if guest:
            result = backend._dispatch(plan, ['exec', backend.instance(plan), '--user', '1000',
                '--group', '1000', '--', *argv], input_data=json.dumps(payload), deadline_ns=deadline)
            # _dispatch already enforces the host deadline and command status.
            result = SimpleNamespace(returncode=0, stdout=result, stderr='')
        else:
            remaining = (deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise OnboardingError('receiving_owner_deadline_expired')
            result = subprocess.run(argv, input=json.dumps(payload), text=True, capture_output=True,
                timeout=remaining, env={'PATH': os.defpath, 'LANG': 'C.UTF-8',
                                       'PYTHONDONTWRITEBYTECODE': '1'}, **options)
        return _response(result, deadline_ns=deadline)

    def status(self):
        return self._call()

    def prepare_apply_control(self, command: dict, path: Path):
        return self._call(command=command, path=path)

    def qualified_identity(self, *, expires_at_ms: int, require_admitted: bool = False,
                           native_tooling: dict | None = None):
        return self._call(expires_at_ms=expires_at_ms, require_admitted=require_admitted,
                          native_tooling=native_tooling)


class ReceivingMaintenance:
    """One root operation links existing Source, guest and cohort transactions."""

    def __init__(self, spec: dict):
        from .onboarding_host import HostBackend, HostConfig
        self.spec = validate(spec)
        self.config_path = _path(spec['host_config'])
        self.backend = HostBackend(HostConfig.load(self.config_path))
        if self.backend.config.code is None:
            raise OnboardingError('qualified_receiving_observer_required')
        self.journal = OperationJournal(_path(spec['journal']))
        self.source = SourceMaintenanceClient(spec)
        self.body = _artifact({key: spec['candidate'][key] for key in ('code', 'code_digest')})
        self.observer = _artifact(spec['observer'])
        self.plans = {}
        from .onboarding import JobStore
        store = JobStore(self.backend.config.jobs)
        for name, profile in spec['guests'].items():
            grant = _path(profile['grant'])
            if grant != self.backend.config.grants / (name + '.json'):
                raise OnboardingError('receiving_maintenance_binding_required')
            plan = being_seed._read(grant)['plan']
            job = store._load(name)
            if job['state'] != 'complete' or job['plan'] != plan or not self.backend.authorize(plan, digest(plan)):
                raise OnboardingError('receiving_maintenance_completed_job_required')
            self.plans[name] = plan
        for code, fingerprint in (self.body, self.observer):
            onboarding_code_successor.verify(code, fingerprint, self.backend.config.code,
                self.backend.config.release_digest, uid=0)
            _sdk(code, fingerprint)
        row = onboarding_code_successor.plan_update(self.journal,
            manifest_digest=spec['candidate']['manifest_digest'],
            target='receiving-maintenance:' + spec['name'] + ':' + digest(spec),
            expected_precondition={'maintenance_spec': spec},
            intended_transition={'maintenance_binding': digest(spec)},
            audit_identity={'actor': 'receiving-maintenance'})
        self.operation_id = row['operation_id']

    def _effects(self) -> dict:
        row = self.journal.get(self.operation_id)
        if row is None or row['expected_precondition'] != {'maintenance_spec': self.spec}:
            raise OnboardingError('receiving_maintenance_binding_required')
        return (row['runtime_observation'] or {}).get('maintenance', {})

    def _record(self, name: str, value: dict) -> dict:
        row = self.journal.get(self.operation_id)
        if row is None:
            raise OnboardingError('receiving_maintenance_binding_required')
        observed = copy.deepcopy(row['runtime_observation'] or {})
        effects = observed.setdefault('maintenance', {})
        if name in effects and effects[name] != value:
            raise OnboardingError('receiving_maintenance_child_conflict')
        effects[name] = value
        self.journal.advance(self.operation_id, row['state'], runtime_observation=observed,
                             expected_runtime_observation=row['runtime_observation'])
        return value

    def _mounted_sdk(self, plan: dict, vector: tuple[Path, str]) -> None:
        backend = self.backend
        _, _, mounts = backend._runtime_paths(plan, backend._receiving_base(plan), candidate=vector)
        if not backend._mounted(plan, mounts):
            for name, device in mounts.items():
                if device.get('readonly') != 'true':
                    raise OnboardingError('qualified_onboarding_candidate_mount_required')
                backend._dispatch(plan, ['config', 'device', 'add', backend.instance(plan), name,
                    device['type'], *[key + '=' + value for key, value in device.items() if key != 'type']],
                    timeout_seconds=20)
        if not backend._mounted(plan, mounts):
            raise OnboardingError('qualified_onboarding_candidate_mount_required')
        ready = backend._target_call(plan, 'sdk-prepare', candidate=vector)
        if ready.get('ready') is not True:
            raise OnboardingError('qualified_guest_bootstrap_candidate_required')

    def _base_owners(self, *, observer: bool) -> dict:
        from .onboarding_receiving_update import GuestGroupClient, SourceGroupClient
        source = self.spec['source']
        selection = self.observer if observer else self.body
        code, fingerprint = selection
        sdk, _ = _sdk(code, fingerprint)
        generation = _path(source['home']) / '.local/share/daimon-matrix/sdk' / digest(sdk)
        owners: dict = {'source': SourceGroupClient(config=_path(source['config']),
            config_sha256=source['config_sha256'], owner_uid=source['uid'], owner_gid=source['gid'],
            code=code, code_digest=fingerprint, code_uid=0, venv=generation / 'venv',
            imports=generation / 'runtime-imports', root=_path(source['root']),
            socket_path=_path(source['socket']), timeout_seconds=60,
            lifecycle_journal=_path(source['journal']))}
        prepared = self._effects()
        for name, plan in self.plans.items():
            frozen = prepared['guest:' + name]['frozen']
            root = Path(frozen['owner']['group']['selected']['socket']).parent
            owners[name] = GuestGroupClient(self.backend, plan, selection, root=root, timeout_seconds=60)
        return owners

    def _owners(self, observed: dict) -> dict:
        bases = self._base_owners(observer=False)
        owners = {}
        for name, base in bases.items():
            code = self.body[0] if name == 'source' else self.backend._runtime_paths(
                self.plans[name], self.backend._receiving_base(self.plans[name]), candidate=self.body)[0]
            owners[name] = PinnedOwnerClient(base, self.spec['observer'], expected_owner(observed[name]), body_code=code)
        return owners

    def prepare(self) -> dict:
        from .onboarding_host import RUNTIME_SELECTION_KEYS
        from .onboarding_receiving_update import prepare_guest_bootstrap, freeze_senders, _manifest
        candidate = self.spec['candidate']
        with self.journal.mutation_lock(self.operation_id):
            effects = self._effects()
            if 'cohort' in effects:
                return self.status()
            if candidate['expires_at_ms'] <= time.time_ns() // 1_000_000:
                raise OnboardingError('receiving_preservation_authorization_expired')
            manifest = _manifest(_path(candidate['manifest_path']), candidate['manifest_digest'], uid=0)
            if 'source' not in effects:
                self.source.call('prepare-sdk')
                self._record('source', self.source.call('prepare'))
            for name, plan in self.plans.items():
                if 'guest:' + name in self._effects():
                    continue
                for vector in dict.fromkeys((self.body, self.observer)):
                    self._mounted_sdk(plan, vector)
                frozen, request = prepare_guest_bootstrap(self.backend, plan, candidate=self.body,
                    manifest_path=_path(candidate['manifest_path']), manifest_digest=candidate['manifest_digest'],
                    expires_at_ms=candidate['expires_at_ms'], timeout_seconds=60, manifest_uid=0)
                if frozen['owner'].get('mode') != 'preserve':
                    raise OnboardingError('receiving_maintenance_preservation_required')
                self._record('guest:' + name, {'frozen': frozen, 'request': request})
            effects = self._effects()
            # Freeze originals only after artifact preparation, before revocation
            # or any lifecycle effect. Exact retry reuses these retained vectors.
            if 'before' not in effects:
                originals = {name: owner.status() for name, owner in self._base_owners(observer=True).items()}
                self._record('before', originals)
            originals = self._effects()['before']
            roster = current_roster(originals['source'])
            owners = self._owners(originals)
            tribe = originals['source']['runtime_status']['loaded_application']['tribe']['policy']['tribe_ref']
            senders = freeze_senders(owners, tribe_ref=tribe)
            required = {(row['being_ref'], row['embodiment_id']) for row in manifest['required_receivers']}
            actual = {(row['being_ref'], row['server']['embodiment_id']) for row in senders}
            if required != actual or len(required) != len(owners):
                raise OnboardingError('receiving_required_cohort_changed')
            settings = being_seed._read(self.config_path)
            runtime = {key: value for key, value in settings.items() if key in RUNTIME_SELECTION_KEYS}
            # Other bodies/future admission retain their existing global default.
            runtime['runtime_by_name'] = {**runtime.get('runtime_by_name', {}),
                **{name: {'runtime_code': str(self.body[0]), 'runtime_digest': self.body[1]} for name in self.plans}}
            resulting = {**{key: value for key, value in settings.items() if key not in RUNTIME_SELECTION_KEYS}, **runtime}
            previous, recipes = {}, {}
            for name in owners:
                before = expected_owner(originals[name])
                previous[name] = before['selection']
                receiver = next((row for row in manifest['required_receivers'] if
                    row['embodiment_id'] == before['server']['embodiment_id']), None)
                if receiver is None or receiver['expected_selection_sha256'] != digest(previous[name]):
                    raise OnboardingError('receiving_cohort_predecessor_changed')
                prepared = self._effects()['source' if name == 'source' else 'guest:' + name]
                frozen = prepared['frozen'] if name == 'source' else prepared['frozen']['owner']
                predecessor = frozen['predecessor']
                if predecessor['process'] != before['process']:
                    raise OnboardingError('receiving_sender_precondition_changed')
                if name == 'source':
                    reference = prepared['reference']
                    checked = prepared['request']['qualification']['prepared']
                else:
                    child = onboarding_code_successor.plan_update(self.journal,
                        manifest_digest=candidate['manifest_digest'], target='guest-bootstrap:maintenance:' + self.spec['name'] + ':' + name,
                        expected_precondition=dict(host_config=str(self.config_path), host_configuration=resulting,
                            host_config_sha256=digest(resulting), guest_bootstraps={name: prepared['frozen']},
                            receiving_observer=self.spec['observer']),
                        intended_transition={'guest_bootstraps': {name: prepared['request']}},
                        audit_identity={'actor': 'receiving-maintenance'})
                    reference = {'operation_id': child['operation_id']}
                    checked = prepared['request']['prepared']
                    self._record('child:' + name, reference)
                if checked['being_ref'] != receiver['being_ref']:
                    raise OnboardingError('receiving_required_cohort_changed')
                selected = {**previous[name], 'receiving_code': self.body[1], 'matrix_sdk': checked['matrix_wheel_sha256']}
                profile = self.spec['source'] if name == 'source' else self.spec['guests'][name]
                recipes[name] = dict(profile='source' if name == 'source' else 'guest', selection=selected,
                    prepared=checked, lifecycle_operation_id=reference['operation_id'], tooling=profile['tooling'])
            activation = dict(manifest_path=candidate['manifest_path'], manifest_uid=0, roster_sha256=roster,
                expires_at_ms=candidate['expires_at_ms'], observation_window_ms=60000, receivers=recipes)
            row = onboarding_code_successor.plan_update(self.journal, manifest_digest=candidate['manifest_digest'],
                target='receiving:maintenance:' + self.spec['name'],
                expected_precondition=dict(senders=senders, receiver_selections=previous, tribe_ref=tribe,
                    host_config=str(self.config_path), host_configuration=settings, host_config_sha256=digest(settings)),
                intended_transition={'host_runtime': runtime, 'cohort_activation': activation},
                audit_identity={'actor': 'receiving-maintenance'})
            self._record('cohort', {'operation_id': row['operation_id']})
            return self.status()

    def apply(self) -> dict:
        from .onboarding_host import HostBackend, HostConfig
        from .onboarding_receiving_update import CohortController, GuestBootstrapController
        with self.journal.mutation_lock(self.operation_id):
            effects = self._effects()
            if 'cohort' not in effects:
                raise OnboardingError('receiving_maintenance_preparation_required')
            cohort_id = effects['cohort']['operation_id']
            # The original-process barrier must be consumed before replacement.
            if 'host-selected' not in effects:
                controller = CohortController(self.journal, cohort_id, self._owners(effects['before']))
                controller.revoke_senders()
                self._record('host-selected', controller.apply_host_selection(self.config_path))
            # Resume may follow a separately changed selector. Check the whole
            # retained result before ANY lifecycle effect, not at the first guest.
            from .onboarding_host import RUNTIME_SELECTION_KEYS
            cohort = self.journal.get(cohort_id)
            if cohort is None:
                raise OnboardingError('receiving_maintenance_child_conflict')
            original = cohort['expected_precondition']['host_configuration']
            selected = {**{key: value for key, value in original.items() if key not in RUNTIME_SELECTION_KEYS},
                        **cohort['intended_transition']['host_runtime']}
            if being_seed._read(self.config_path) != selected:
                raise OnboardingError('receiving_maintenance_host_changed')
            self.backend = HostBackend(HostConfig.load(self.config_path))
            if 'loaded:source' not in self._effects():
                self._record('loaded:source', self.source.call('execute')['loaded'])
            for name in self.plans:
                if 'loaded:' + name in self._effects():
                    continue
                reference = self._effects()['child:' + name]
                lifecycle = GuestBootstrapController(self.journal, reference['operation_id'], self.backend, name)
                self._record('loaded:' + name, lifecycle.execute(timeout_seconds=60))
            loaded = {name: self._effects()['loaded:' + name] for name in ('source', *self.plans)}
            controller = CohortController(self.journal, cohort_id, self._owners(loaded))
            controller.reconcile_tooling()
            # activate owns partial/full selection reconciliation; never replay
            # its preparation/revoke barrier after a positive selection.
            result = controller.activate()
            if 'receiving-selected' not in self._effects():
                self._record('receiving-selected', result)
            return self.status()

    def status(self) -> dict:
        effects = self._effects()
        return dict(operation_id=self.operation_id,
            phase='receiving-selected' if 'receiving-selected' in effects else 'prepared' if 'cohort' in effects else 'preparing',
            loaded=sorted(name.removeprefix('loaded:') for name in effects if name.startswith('loaded:')),
            prepared_receivers=sorted(name.removeprefix('guest:') for name in effects if name.startswith('guest:')),
            communication='unobserved', worker_paused=False)

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--owner', choices=('prepare-sdk', 'prepare', 'execute'))
    mode.add_argument('--spec', type=Path)
    parser.add_argument('action', nargs='?', choices=('prepare', 'apply', 'status'))
    args = parser.parse_args(argv)
    operation = None
    try:
        if args.owner:
            if args.action is not None:
                raise OnboardingError('receiving_maintenance_action_required')
            raw = sys.stdin.buffer.read(being_seed.MAX_SELECTION + 1)
            if len(raw) > being_seed.MAX_SELECTION:
                raise OnboardingError('receiving_maintenance_binding_required')
            result = source_worker(json.loads(raw), args.owner)
        else:
            if os.geteuid() != 0 or args.action is None:
                raise OnboardingError('receiving_maintenance_root_required')
            raw = onboarding_release.regular(args.spec, uid=0)
            if args.spec.stat().st_mode & 0o077:
                raise OnboardingError('receiving_maintenance_binding_required')
            spec = validate(json.loads(raw))
            if args.action == 'status':
                journal = OperationJournal.existing(_path(spec['journal']))
                target = 'receiving-maintenance:' + spec['name'] + ':' + digest(spec)
                row = None if journal is None else journal.latest_for_idempotency_key(
                    'receiving-update:' + target + ':' + spec['candidate']['manifest_digest'])
                result = dict(phase='unplanned', communication='unobserved', worker_paused=False)
                if row is not None:
                    effects = (row['runtime_observation'] or {}).get('maintenance', {})
                    result.update(operation_id=row['operation_id'],
                        phase='receiving-selected' if 'receiving-selected' in effects else
                              'prepared' if 'cohort' in effects else 'preparing')
            else:
                operation = ReceivingMaintenance(spec)
                result = operation.prepare() if args.action == 'prepare' else operation.apply()
        print(json.dumps(result))
        return 0
    except Exception as error:
        code = public_error(error)
        if args.spec is not None:
            busy = code == 'seed_operation_in_progress'
            print(json.dumps(dict(phase='busy' if busy else 'uncertain', code=code,
                operation_id=None if operation is None else operation.operation_id,
                resume='same-spec', worker_paused=False)))
            return 75 if busy else 1
        print(json.dumps({'error': code}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

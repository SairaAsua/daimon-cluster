"""Protected portal binding and native preparation in the existing worker.

The receiving operation owns admission. This caller runs outside JobStore.tick,
retains public observations in that operation and never treats a selected app as
completed receiving acceptance. No inbox attention, model or extra queue exists.
"""
from __future__ import annotations

import copy
import math
import re
import time
import uuid
from contextlib import ExitStack, contextmanager
from pathlib import Path

from . import being_seed
from .onboarding import JobStore, Observation, OnboardingError, digest, private_directory, validate_plan
from .operation_journal import JournalConflict, OperationJournal

SCHEMA = 'cluster-onboarding-group-coordinator/v1'
CALLER_SCHEMA = 'cluster-portal-group-admission/v1'
SOURCE_FIELDS = frozenset({'config', 'config_sha256', 'owner_uid', 'owner_gid', 'code',
    'code_digest', 'code_uid', 'venv', 'imports', 'root', 'socket_path', 'lifecycle_journal'})
SOURCE_PATHS = frozenset({'config', 'code', 'venv', 'imports', 'root', 'socket_path', 'lifecycle_journal'})


def _path(value) -> bool:
    return isinstance(value, str) and Path(value).is_absolute() and '..' not in Path(value).parts


def configuration(path: Path) -> dict:
    """Read only a host-owner-controlled, closed map; never intake or labels."""
    value = being_seed._read(path, limit=being_seed.MAX_SELECTION)
    try:
        if (set(value) != {'schema', 'tribe_ref', 'journal', 'owners', 'admissions'}
                or value['schema'] != SCHEMA or not _path(value['journal'])
                or not isinstance(value['tribe_ref'], str) or not value['tribe_ref']
                or not isinstance(value['owners'], dict) or not 1 <= len(value['owners']) <= 256
                or not isinstance(value['admissions'], dict) or len(value['admissions']) > 256):
            raise ValueError
        for name, owner in value['owners'].items():
            if not isinstance(name, str) or not being_seed.NAME.fullmatch(name) or not isinstance(owner, dict):
                raise ValueError
            if owner.get('profile') == 'source':
                if (set(owner) != SOURCE_FIELDS | {'profile'}
                        or any(not _path(owner[key]) for key in SOURCE_PATHS)
                        or any(type(owner[key]) is not int or owner[key] <= 0 for key in ('owner_uid', 'owner_gid'))
                        or type(owner['code_uid']) is not int or owner['code_uid'] < 0
                        or any(re.fullmatch('[0-9a-f]{64}', owner[key]) is None
                               for key in ('config_sha256', 'code_digest'))):
                    raise ValueError
            elif owner.get('profile') == 'guest':
                if (set(owner) != {'profile', 'plan', 'candidate', 'root'}
                        or not _path(owner['root']) or not isinstance(owner['candidate'], dict)
                        or set(owner['candidate']) != {'code', 'digest'}
                        or not _path(owner['candidate']['code'])
                        or re.fullmatch('[0-9a-f]{64}', owner['candidate']['digest']) is None
                        or validate_plan(owner['plan'])['name'] != name):
                    raise ValueError
            else:
                raise ValueError
        for key, operation in value['admissions'].items():
            if (not isinstance(key, str) or re.fullmatch('[0-9a-f]{64}', key) is None
                    or not isinstance(operation, str) or not 1 <= len(operation) <= 240):
                raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_coordinator_configuration_required') from None
    return value


class GroupCoordinator:
    """Join an exact stored job to its already approved receiving operation."""

    def __init__(self, backend):
        self.backend = backend
        self.path = backend.config.group_admission
        self.settings = configuration(self.path)
        self.store = JobStore(backend.config.jobs)

    def _binding(self, plan: dict):
        if configuration(self.path) != self.settings:
            raise OnboardingError('onboarding_group_coordinator_configuration_changed')
        operation_id = self.settings['admissions'].get(digest(plan))
        journal = OperationJournal.existing(Path(self.settings['journal']))
        if operation_id is None or journal is None:
            return None
        row = journal.get(operation_id)
        if row is None:
            return None
        before, after = row['expected_precondition'], row['intended_transition']
        admission = after.get('cohort_admission')
        caller = after.get('portal_admission')
        if (row['operation'] != 'receiving-update' or row['state'] in {'degraded', 'compensated'}
                or row['intent_hash'] != digest(row['intent'])
                or row['target'] != 'receiving:' + self.settings['tribe_ref']
                or before.get('tribe_ref') != self.settings['tribe_ref']
                or row['intent'].get('runtime_call', {}).get('precondition_digest') != digest(before)
                or row['intent'].get('runtime_call', {}).get('transition_digest') != digest(after)
                or not isinstance(admission, dict) or admission.get('tribe_ref') != self.settings['tribe_ref']
                or not isinstance(admission.get('receivers'), dict) or plan['name'] not in admission['receivers']
                or any(plan['name'] == item.get('name') for item in before.get('senders', []))
                or not set(admission['receivers']) <= set(self.settings['owners'])
                or not isinstance(caller, dict) or set(caller) != {
                    'schema', 'plan_digest', 'matrix_operation_id', 'owners_sha256'}
                or caller != dict(schema=CALLER_SCHEMA, plan_digest=digest(plan),
                    matrix_operation_id=JobStore.operation_id(digest(plan), 'matrix'),
                    owners_sha256=digest({name: self.settings['owners'][name] for name in admission['receivers']}))):
            raise OnboardingError('onboarding_group_admission_binding_changed')
        entrant = admission['receivers'][plan['name']]
        selected = self.settings['owners'][plan['name']]
        if (selected['profile'] != 'guest' or selected['plan'] != plan
                or entrant.get('root') != selected['root']
                or entrant.get('candidate', {}).get('code') != selected['candidate']['code']
                or entrant.get('recipe', {}).get('prepared', {}).get('code_digest') != selected['candidate']['digest']):
            raise OnboardingError('onboarding_group_admission_binding_changed')
        return journal, row, admission

    def observe(self, plan: dict) -> Observation:
        selected = self._binding(plan)
        if selected is None:
            return Observation('waiting', reason='group_admission_required')
        _journal, row, _admission = selected
        # Only the completed receiving transaction can release the normal
        # stage's actual managed-presence check. Native preparation is not it.
        if row['state'] != 'completed':
            return Observation('waiting', reason='group_admission_pending')
        return Observation('complete', dict(verified=True, identity_verified=True))

    def _owners(self, admission: dict) -> dict:
        from .onboarding_receiving_update import GuestGroupClient, SourceGroupClient
        owners: dict[str, GuestGroupClient | SourceGroupClient] = {}
        for name in sorted(admission['receivers']):
            owner: GuestGroupClient | SourceGroupClient
            row = self.settings['owners'][name]
            if row['profile'] == 'source':
                options: dict = {key: Path(row[key]) if key in SOURCE_PATHS else row[key] for key in SOURCE_FIELDS}
                owner = SourceGroupClient(**options)
            else:
                owner = GuestGroupClient(self.backend, row['plan'],
                    (Path(row['candidate']['code']), row['candidate']['digest']), root=Path(row['root']))
            approved = admission['receivers'][name]
            selected_code = row['code'] if row['profile'] == 'source' else row['candidate']['code']
            selected_digest = row['code_digest'] if row['profile'] == 'source' else row['candidate']['digest']
            if ((str(owner.root), str(owner.socket)) != (approved['root'], approved['socket'])
                    or row['profile'] != approved['recipe']['profile']
                    or selected_code != approved['candidate']['code']
                    or selected_digest != approved['recipe']['prepared']['code_digest']):
                raise OnboardingError('onboarding_group_admission_binding_changed')
            owners[name] = owner
        return owners

    @contextmanager
    def _job_scope(self, plan: dict):
        with ExitStack() as locks:
            locks.enter_context(being_seed._locked(private_directory(self.store.root)))
            for name in self.store.names():
                locks.enter_context(being_seed._locked(private_directory(self.store.directory(name))))
            record = self.store._load(plan['name'])
            if (record['plan'] != plan or not self.backend.authorize(plan, digest(plan))
                    or not self.backend._consented(plan, stage='matrix')
                    or self.backend._decision(plan) is None or not self.backend._ceremony(plan).authorize(plan)):
                raise OnboardingError('host_authorization_required')
            yield record

    def _retain(self, journal, row: dict, key: str, value: dict) -> dict:
        current = journal.get(row['operation_id'])
        observations = copy.deepcopy(current['runtime_observation'] or {})
        admission = observations.setdefault('portal_admission', {})
        if key in admission:
            if admission[key] != value:
                raise JournalConflict('portal admission evidence changed')
            return current
        admission[key] = value
        return journal.advance(row['operation_id'], current['state'], runtime_observation=observations,
            expected_runtime_observation=current['runtime_observation'])

    def advance(self, name: str, *, timeout_seconds: float = 30) -> dict | None:
        """Prepare the exact native endpoint before any irreversible admission.

        Social publication/lifecycle/communication remain separate retained
        receiving phases. This preparation cannot mark the operation complete.
        """
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 60:
            raise OnboardingError('receiving_host_deadline_required')
        deadline = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
        def remaining():
            value = (deadline - time.monotonic_ns()) / 1_000_000_000
            if value <= 0:
                raise OnboardingError('receiving_host_deadline_expired')
            return value
        record = self.store._load(name)
        if record['stage'] != 'matrix':
            return None
        plan = record['plan']
        bound = self._binding(plan)
        if bound is None:
            return None
        journal, row, admission = bound
        with journal.mutation_lock(row['operation_id']):
            with self._job_scope(plan) as record:
                current_binding = self._binding(plan)
                if current_binding is None:
                    return None
                _journal, row, admission = current_binding
                if record['stage'] != 'matrix' or row['state'] == 'completed':
                    return None
                retained = (row['runtime_observation'] or {}).get('portal_admission', {})
                native_prepared = isinstance(retained.get('native_ready'), dict)
                expired = time.time_ns() // 1_000_000 >= admission['activation']['expires_at_ms']
                if expired:
                    request = retained.get('controller_intent')
                    if (not native_prepared or 'physical_ready' not in retained
                            or not isinstance(request, dict)
                            or not (request.get('mode') == 'preserve'
                                    or 'controller_stage' in retained)):
                        raise OnboardingError('receiving_preservation_authorization_expired')
                    # Owner stage/publish already supports exact historical
                    # completion after expiry. Its original fixed request is
                    # unchanged; native validation refuses any fresh effect.
                else:
                    deadline = min(deadline, time.monotonic_ns() +
                        (admission['activation']['expires_at_ms'] - time.time_ns() // 1_000_000) * 1_000_000)
                candidate = (Path(self.settings['owners'][name]['candidate']['code']),
                    self.settings['owners'][name]['candidate']['digest'])
                if not native_prepared and not self.backend.prepare_group_target(plan, candidate, deadline_ns=deadline):
                    return None
                owners = self._owners(admission)
                from .onboarding_receiving_update import CohortController
                cohort = CohortController(journal, row['operation_id'], owners)
                cohort._row()
                row = self._retain(journal, row, 'native_intent', dict(
                    plan_digest=digest(plan), cohort_intent_sha256=digest(row['intent']),
                    owners_sha256=row['intended_transition']['portal_admission']['owners_sha256']))
            # Public owner/bootstrap helpers can take their own job scopes.
            # Never call them under JobStore.tick or the job locks above.
            with ExitStack() as scopes:
                for owner in owners.values():
                    scopes.enter_context(cohort._owner_deadline(owner, deadline))
                if not native_prepared:
                    readiness = {}
                    for current in sorted(owners):
                        recipe = admission['receivers'][current]['recipe']['tooling']
                        if recipe['profile'] == 'matrix-only':
                            continue
                        owner = owners[current]
                        endpoint = Path(recipe['native_endpoint'])
                        if current == name:
                            # Reobserve the exact manager state before a lost-start
                            # retry. A generic SDK/socket failure cannot restart it.
                            with self._job_scope(plan):
                                self._binding(plan)
                                self.backend._attach_telegram(plan, deadline_ns=deadline)
                                budget = dict(deadline_ns=deadline,
                                    authorization_expires_at_ms=admission['activation']['expires_at_ms'])
                                native = self.backend._telegram_command(plan, 'native-observe', **budget)
                                if native.get('native_state') not in {'absent', 'inactive', 'active'}:
                                    return dict(operation_id=row['operation_id'], native_prepared=False,
                                        receiving_readiness='unobserved')
                                if native['native_state'] != 'active':
                                    self._retain(journal, row, 'native_dispatch', dict(plan_digest=digest(plan)))
                                    self.backend._telegram_command(plan, 'native-install', **budget)
                                self.backend._telegram_probe(plan, **budget)
                        observed = owner.preflight_native(endpoint)
                        readiness[current] = observed
                        remaining()
                    # A later invocation observes the endpoint afresh; do not
                    # overwrite retained process evidence with a newer process.
                    current = journal.get(row['operation_id'])
                    if 'native_ready' not in (current['runtime_observation'] or {}).get('portal_admission', {}):
                        self._retain(journal, current, 'native_ready', readiness)
                    remaining()
                self._prepare_body(plan, journal, row, admission, candidate, deadline_ns=deadline,
                    historical_only=expired)
                remaining()
                return dict(operation_id=row['operation_id'], native_prepared=True,
                    physical_prepared=True, controller_prepared=True, receiving_readiness='unobserved')

    def _prepare_body(self, plan, journal, row, admission, candidate, *, deadline_ns: int,
                      historical_only: bool = False) -> None:
        """Prepare the new holder/controller before freezing social context.

        These owner-only calls take guest locks, not host job locks. Existing
        members are untouched. Later managed first-load owns a separate scope.
        """
        from .onboarding_managed import ManagedRuntime
        def remaining():
            value = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
            if value <= 0:
                raise OnboardingError('receiving_host_deadline_expired')
            return value
        def retained():
            return (journal.get(row['operation_id'])['runtime_observation'] or {}).get('portal_admission', {})
        with self._job_scope(plan):
            self._binding(plan)
            remaining()
            managed = ManagedRuntime(self.backend)
            expected = managed._expected(plan)
            approved = admission['receivers'][plan['name']]
            if any(expected[key] != approved[key] for key in ('being_ref', 'embodiment_id')):
                raise OnboardingError('onboarding_group_admission_binding_changed')
            intent = dict(plan_digest=digest(plan), admission_settings_sha256=digest(managed.settings),
                coordinates=expected)
            self._retain(journal, row, 'physical_intent', intent)
            if 'physical_ready' not in retained():
                if historical_only:
                    raise OnboardingError('receiving_preservation_authorization_expired')
                profile = managed.prepare_admission(plan, candidate=candidate, deadline_ns=deadline_ns,
                    authorization_expires_at_ms=admission['activation']['expires_at_ms'])
                self._retain(journal, row, 'physical_ready', dict(profile_sha256=digest(profile)))
            else:
                existing_profile = managed._profile(plan)
                if existing_profile is None or retained()['physical_ready'] != dict(profile_sha256=digest(existing_profile)):
                    raise OnboardingError('existing_onboarding_service_profile_preserved')
                profile = existing_profile
            remaining()
            if 'controller_prepared' in retained():
                return
            request = retained().get('controller_intent')
            if request is None:
                if historical_only:
                    raise OnboardingError('receiving_preservation_authorization_expired')
                frozen = self.backend._target_call(plan, 'receiving-bootstrap-freeze', candidate=candidate,
                    bootstrap_timeout_seconds=remaining(), bootstrap_initial=True)
                expected = profile['enrollment']
                approved = admission['receivers'][plan['name']]
                if (frozen['plan_digest'] != digest(plan) or frozen['code_digest'] != candidate[1]
                        or frozen['being_ref'] != approved['being_ref']
                        or frozen['being_ref'] != expected['being_ref']
                        or any(frozen['origin'].get(key) != expected[key]
                               for key in ('body_ref', 'embodiment_id', 'incarnation_id'))
                        or frozen['origin']['embodiment_id'] != approved['embodiment_id']
                        or frozen['predecessor'] is not None or frozen['group'] is not None
                        or frozen['group_sha256'] != digest({'group': None})
                        or frozen['mode'] not in {'issue', 'preserve', 'renew'}):
                    raise OnboardingError('receiving_guest_bootstrap_initial_required')
                expires = admission['activation']['expires_at_ms']
                if frozen['mode'] == 'preserve':
                    expires = min(expires, frozen['preservation']['not_after_ms'])
                elif frozen['mode'] == 'renew':
                    expires = min(expires, frozen['renewal_not_after_ms'])
                if time.time_ns() // 1_000_000 >= expires:
                    raise OnboardingError('receiving_preservation_authorization_expired')
                request = dict(schema='cluster-guest-owner-initial/v1',
                    operation_id=str(uuid.uuid5(uuid.NAMESPACE_URL, 'cluster:portal:initial:' +
                        row['operation_id'] + ':' + digest(plan))),
                    **{key: frozen[key] for key in ('plan_digest', 'genesis_digest', 'code_digest',
                        'runtime_sha256', 'group_sha256', 'predecessor', 'mode', 'preservation')},
                    expires_at_ms=expires)
                self._retain(journal, row, 'controller_intent', request)
            staged = retained().get('controller_stage')
            if staged is None:
                if historical_only and request['mode'] != 'preserve':
                    raise OnboardingError('receiving_preservation_authorization_expired')
                staged = self.backend._target_call(plan, 'receiving-bootstrap-stage', candidate=candidate,
                    bootstrap_timeout_seconds=remaining(), bootstrap_request=request)
                if (staged.get('operation_id') != request['operation_id']
                        or staged.get('schema') != ('cluster-receiving-owner-preserved/v1'
                            if request['mode'] == 'preserve' else 'cluster-guest-owner-bootstrap-ready/v1')
                        or request['mode'] != 'preserve' and re.fullmatch('[0-9a-f]{64}', staged.get('ready_sha256', '')) is None):
                    raise OnboardingError('receiving_guest_bootstrap_ready_required')
                self._retain(journal, row, 'controller_stage', staged)
            result = staged
            if request['mode'] != 'preserve':
                result = self.backend._target_call(plan, 'receiving-bootstrap-publish', candidate=candidate,
                    bootstrap_timeout_seconds=remaining(), bootstrap_request=request,
                    bootstrap_ready_sha256=staged['ready_sha256'])
                if (result.get('schema') != 'cluster-guest-owner-bootstrap-publication/v1'
                        or result.get('operation_id') != request['operation_id']
                        or result.get('ready_sha256') != staged['ready_sha256']
                        or re.fullmatch('[0-9a-f]{64}', result.get('runtime_sha256', '')) is None):
                    raise OnboardingError('receiving_guest_bootstrap_ready_required')
            self._retain(journal, row, 'controller_prepared', result)
            remaining()

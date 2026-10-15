"""Worker reconciliation of configured admission, guest service and registry."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import hashlib
import json
import math
from pathlib import Path
import time

from . import being_seed, onboarding_admission, onboarding_mounts
from .admission import AdmissionEndpoint
from .onboarding_registry import OwnerRegistry
from .fences import Ed25519Signer
from .onboarding import JobStore, Observation, OnboardingError, digest, private_directory
from .onboarding_service import UNIT
from .production_fences import ed25519_fingerprint


class ManagedRuntime:
    def __init__(self, backend):
        self.backend = backend
        config = backend.config
        self.settings = being_seed._read(config.admission)
        value = self.settings
        fields = {'schema', 'host_port', 'guest_port', 'authority_key_id', 'authority_public_key',
                  'registrar_key_id', 'registrar_key', 'registry', 'state', 'visibility_installation'}
        if (set(value) - {'messaging_application'} != fields or value['schema'] != 'cluster-onboarding-managed-runtime/v1'
                or any(type(value[key]) is not int or not 1 <= value[key] <= 65535
                       for key in ('host_port', 'guest_port'))
                or any(not isinstance(value[key], str) or not value[key]
                       for key in ('authority_key_id', 'registrar_key_id'))):
            raise OnboardingError('invalid_onboarding_managed_configuration')
        ed25519_fingerprint(value['authority_public_key'])
        for key in ('registrar_key', 'registry', 'state'):
            if not isinstance(value[key], str) or not Path(value[key]).is_absolute():
                raise OnboardingError('invalid_onboarding_managed_configuration')
        self.registry = OwnerRegistry(Path(value['registry']))
        self.state = private_directory(Path(value['state']))
        visibility = value['visibility_installation']
        if visibility is not None and (not isinstance(visibility, str)
                or not Path(visibility).is_absolute() or '..' in Path(visibility).parts
                or not Path(visibility).is_relative_to('/home/agent')):
            raise OnboardingError('invalid_onboarding_managed_configuration')

        app = value.get('messaging_application')
        if app is not None and (visibility is None or not isinstance(app, str)
                or not Path(app).is_absolute() or '..' in Path(app).parts
                or not Path(app).is_relative_to('/home/agent')):
            raise OnboardingError('invalid_onboarding_managed_configuration')

    def _ready(self, plan: dict) -> bool:
        return self._selection(plan)[1] is not None or (
            self.backend.config.qualification and plan['name'].startswith('qualify-'))

    def _selection(self, plan: dict) -> tuple[str | None, str | None]:
        if getattr(self.backend.config, 'peer', None) is not None:
            from .onboarding_peer_host import PeerHost
            return PeerHost(self.backend).application(plan) or (None, None)
        return self.settings.get('messaging_application'), self.settings['visibility_installation']

    def _expected(self, plan: dict) -> dict:
        return self.backend._ceremony(plan).admission_coordinates(plan)

    def _proxy(self) -> dict:
        return dict(type='proxy', bind='instance', listen='tcp:127.0.0.1:' + str(self.settings['guest_port']),
                    connect='tcp:127.0.0.1:' + str(self.settings['host_port']))

    def _check_proxy(self, plan: dict, *, deadline_ns: int | None = None) -> bool:
        if deadline_ns is None:
            rows, _ = self.backend._inventory()
        else:
            rows = json.loads(self.backend._dispatch(plan, ['list', '--format=json'], deadline_ns=deadline_ns))
            if (not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
                    or sum(row.get('name') == self.backend.instance(plan) for row in rows) != 1):
                raise OnboardingError('invalid_onboarding_environment_observation')
        row = next(row for row in rows if row.get('name') == self.backend.instance(plan))
        current = row.get('expanded_devices', {}).get('onboarding-admission')
        if current is not None and current != self._proxy():
            raise OnboardingError('foreign_onboarding_admission_proxy_preserved')
        return current is not None

    def _registered(self, expected: dict) -> bool:
        identifier = expected['embodiment_id']
        rows = self.registry.load()['embodiments']
        existing = rows.get(identifier)
        if existing is not None:
            if (existing.get('body_ref') != expected['body_ref']
                    or existing.get('hosting') != 'external-owner' or existing.get('status') != 'running'
                    or existing.get('current_incarnation_id') != expected['incarnation_id']
                    or sum(item.get('incarnation_id') == expected['incarnation_id']
                           and item.get('stopped_at_ms') is None for item in existing.get('incarnations', [])) != 1):
                raise OnboardingError('existing_onboarding_registry_preserved')
            return True
        if any(row.get('body_ref') == expected['body_ref'] or any(
                item.get('incarnation_id') == expected['incarnation_id'] for item in row.get('incarnations', []))
                for row in rows.values()):
            raise OnboardingError('existing_onboarding_registry_preserved')
        return False

    def _profile(self, plan: dict) -> dict | None:
        root = self.state / digest(plan)
        private_directory(root, create=True)
        path = root / 'confirmed.json'
        if not path.exists():
            return None
        value = being_seed._read(path)
        endpoint = dict(transport='tcp-authenticated', host='127.0.0.1', port=self.settings['guest_port'])
        if (value.get('schema') != 'cluster-onboarding-admission-profile/v1'
                or value.get('plan_digest') != digest(plan) or value.get('endpoint') != endpoint
                or value.get('authority_key_id') != self.settings['authority_key_id']
                or value.get('authority_public_key') != self.settings['authority_public_key']
                or any(value.get('enrollment', {}).get(key) != expected
                       for key, expected in self._expected(plan).items())):
            raise OnboardingError('existing_onboarding_service_profile_preserved')
        return value

    def observe(self, plan: dict) -> Observation:
        if not self._ready(plan):
            return Observation('waiting', reason='backend_unavailable')
        expected = self._expected(plan)
        registered = self._registered(expected)
        configuration = self._profile(plan)
        if configuration is None or not self._check_proxy(plan):
            return Observation('absent', safe_to_execute=True)
        properties = self.backend._dispatch(plan, ['exec', self.backend.instance(plan), '--', 'systemctl',
            'show', UNIT, '--property=ActiveState', '--property=MainPID'])
        values = dict(line.split('=', 1) for line in properties.splitlines() if '=' in line)
        if values.get('ActiveState') != 'active' or not values.get('MainPID', '').isdigit():
            return Observation('absent', safe_to_execute=True)
        presence = self.backend._target_call(plan, 'admitted-running')
        if (presence.get('schema') != 'cluster-onboarding-runtime-presence/v1'
                or presence.get('plan_digest') != digest(plan)
                or any(presence.get('origin', {}).get(key) != expected[key]
                       for key in ('body_ref', 'embodiment_id', 'incarnation_id'))
                or presence.get('process', {}).get('pid') == int(values['MainPID'])):
            raise OnboardingError('onboarding_managed_presence_rejected')
        if not registered:
            return Observation('absent', safe_to_execute=True)
        return Observation('complete', dict(verified=True, identity_verified=True))

    def prepare_admission(self, plan: dict) -> dict:
        """Enroll the existing native holder without selecting or starting a service.

        Initial shared-group admission needs this profile before its owner
        context is frozen. Group publication and managed service startup follow
        separately; neither a profile nor a registry row proves a loaded body.
        The normal execute path reuses these same durable proposals and retries.
        """
        expected = self._expected(plan)
        self._registered(expected)  # Preserve foreign canonical state before enrollment.
        if not self._check_proxy(plan):
            proxy = self._proxy()
            self.backend._dispatch(plan, ['config', 'device', 'add', self.backend.instance(plan),
                'onboarding-admission', 'proxy', *[key + '=' + value for key, value in proxy.items() if key != 'type']])
        configuration = self._profile(plan)
        root = self.state / digest(plan)
        if configuration is None:
            candidate = root / 'candidate.json'
            configuration = being_seed._read(candidate) if candidate.exists() else None
            registered = (configuration is not None and self.backend._target_call(plan, 'admission-check',
                profile=configuration).get('registered') is True)
            if not registered:
                request = self.backend._target_call(plan, 'admission-prepare')
                registrar = Ed25519Signer(self.settings['registrar_key'], self.settings['registrar_key_id'])
                configuration = onboarding_admission.profile(plan, request, expected, registrar,
                    endpoint=AdmissionEndpoint.network('127.0.0.1', self.settings['guest_port']),
                    authority_key_id=self.settings['authority_key_id'],
                    authority_public_key=self.settings['authority_public_key'])
                # Preserve every signed proposal; the pointer is only local progress.
                being_seed._write(root / ('profile-' + digest(configuration) + '.json'), configuration)
                being_seed._write(candidate, configuration)
                if self.backend._target_call(plan, 'admission-enroll', profile=configuration) != {'registered': True}:
                    raise OnboardingError('onboarding_admission_not_current')
            assert configuration is not None
            being_seed._write(root / 'confirmed.json', configuration)
        assert configuration is not None
        onboarding_mounts.prepare_matrix_public(self.backend.config.views, plan, {'admission.json': configuration})
        return configuration

    def execute(self, plan: dict) -> None:
        if not self._ready(plan):
            raise OnboardingError('onboarding_visibility_selection_required')
        self.prepare_admission(plan)
        expected = self._expected(plan)
        _, code, _ = self.backend._guest_paths(plan)
        runtime_code, runtime_args, _ = self.backend._runtime_paths(plan, code)
        launcher = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                    'from clusterctl.onboarding_service import main;raise SystemExit(main())')
        application, visibility = self._selection(plan)
        selection = (['--receive-only'] if visibility is None else ['--visibility-installation', visibility])
        if application is not None:
            selection += ['--messaging-application', application]
        self.backend._dispatch(plan, ['exec', self.backend.instance(plan), '--', 'python3', '-B', '-I', '-c',
            launcher, str(runtime_code), '--code', str(code), *runtime_args, '--plan', '/home/agent/.onboarding-input/plan.json', *selection])
        # Observe authenticated, admitted presence before committing canonical state.
        presence = self.backend._target_call(plan, 'admitted-running')
        origin = presence['origin']
        if any(origin.get(key) != expected[key] for key in ('body_ref', 'embodiment_id', 'incarnation_id')):
            raise OnboardingError('onboarding_managed_presence_rejected')
        self.registry.adopt_running(**{key: expected[key] for key in ('body_ref', 'embodiment_id', 'incarnation_id')})

    @contextmanager
    def _initial_scope(self, plan: dict, cohort):
        """Reuse operation -> jobs ownership for first load and steady selection."""
        with ExitStack() as locks:
            locks.enter_context(cohort.journal.mutation_lock(cohort.operation_id))
            jobs = private_directory(self.backend.config.jobs)
            locks.enter_context(being_seed._locked(jobs))
            store = JobStore(jobs)
            for job in store.names():
                locks.enter_context(being_seed._locked(private_directory(store.directory(job))))
            if store._load(plan['name'])['plan'] != plan or not self.backend.authorize(plan, digest(plan)):
                raise OnboardingError('receiving_initial_plan_changed')
            yield

    def execute_initial(self, plan: dict, cohort, *, timeout_seconds: float = 30) -> dict:
        """Retain a first native load in the existing admission operation.

        Invoke outside JobStore.tick: operation -> jobs parent -> job locks is
        the same ownership order as the maintained replacement controller.
        No sender is enabled here; full cohort adoption remains separate.
        """
        from .onboarding_receiving_update import (
            GuestBootstrapController, _manifest, guest_loaded_observation, preflight,
            preservation_authorization,
        )
        from .onboarding_service import command, unit_content
        from .operation_journal import JournalConflict
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 60:
            raise OnboardingError('receiving_host_deadline_required')
        deadline = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
        def remaining():
            result = (deadline - time.monotonic_ns()) / 1_000_000_000
            if result <= 0:
                raise OnboardingError('receiving_host_deadline_expired')
            return result

        with self._initial_scope(plan, cohort):
            name = plan['name']
            row = cohort._row()
            admission = cohort._admission(row)
            if (admission is None or name not in admission['receivers']
                    or name in {sender['name'] for sender in row['expected_precondition']['senders']}):
                raise OnboardingError('receiving_initial_admission_required')
            approved = admission['receivers'][name]
            vector = Path(approved['candidate']['code']), approved['recipe']['prepared']['code_digest']
            prepared = approved['recipe']['prepared']
            bounds = admission['activation']
            _manifest(Path(bounds['manifest_path']), row['intent']['runtime_call']['manifest_digest'],
                uid=bounds['manifest_uid'])
            checked = preflight(vector[0], vector[1], Path(bounds['manifest_path']),
                row['intent']['runtime_call']['manifest_digest'], being_ref=approved['being_ref'],
                embodiment_id=approved['embodiment_id'], code_uid=approved['candidate']['code_uid'],
                manifest_uid=bounds['manifest_uid'])
            if any(prepared.get(key) != value for key, value in checked.items()):
                raise OnboardingError('receiving_initial_candidate_changed')
            configuration = self._profile(plan)
            expected = self._expected(plan)
            self._registered(expected)
            if configuration is None or not self._check_proxy(plan, deadline_ns=deadline):
                raise OnboardingError('receiving_initial_admission_profile_required')

            def effects():
                return (cohort._row()['runtime_observation'] or {}).get('initial_managed', {}).get(name, {})

            def record(key, value):
                current = cohort._row()
                observations = dict(current['runtime_observation'] or {})
                receivers = dict(observations.get('initial_managed', {}))
                retained = dict(receivers.get(name, {}))
                if key in retained:
                    if retained[key] != value:
                        raise JournalConflict('receiving initial managed effect changed')
                    return retained[key]
                retained[key] = value
                receivers[name] = retained
                observations['initial_managed'] = receivers
                cohort.journal.advance(cohort.operation_id, current['state'], runtime_observation=observations,
                    expected_runtime_observation=current['runtime_observation'])
                return value

            binding = dict(schema='cluster-managed-initial-binding/v1', plan_digest=digest(plan),
                admission_sha256=digest(admission), profile_sha256=digest(configuration),
                receiver=approved, origin=expected)
            intent = effects().get('intent')
            if intent is None:
                with ExitStack() as observations:
                    for sender in row['expected_precondition']['senders']:
                        observations.enter_context(cohort._owner_deadline(cohort.owners[sender['name']], deadline))
                    cohort.require_revocation_barrier()
                owner = self.backend._target_call(plan, 'receiving-bootstrap-freeze', candidate=vector,
                    bootstrap_timeout_seconds=remaining(), bootstrap_initial_service=True)
                startup = owner['observer_startup']
                if (owner['predecessor'] is not None or owner['being_ref'] != approved['being_ref']
                        or owner['origin'] != {key: expected[key] for key in (
                            'body_ref', 'embodiment_id', 'incarnation_id')}
                        or owner['origin']['embodiment_id'] != approved['embodiment_id']
                        or owner['group']['selected']['tribe_ref'] != admission['tribe_ref']
                        or owner['group']['selected']['socket'] != approved['socket']
                        or any(startup.get(key) != value for key, value in dict(code_digest=vector[1],
                            matrix_commit=prepared['matrix_revision'], sdk_digest=prepared['sdk_digest'],
                            matrix_wheel_sha256=prepared['matrix_wheel_sha256'], reader=prepared['reader']).items())):
                    raise OnboardingError('receiving_initial_owner_changed')
                base = self.backend._receiving_base(plan)
                code, _, _ = self.backend._runtime_paths(plan, base, candidate=vector)
                selected = owner['group']['selected']
                frozen_owner = {key: value for key, value in owner.items() if key != 'observer_startup'}
                initial_context = dict(schema='cluster-initial-start-context/v1',
                    owner_sha256=digest(frozen_owner), profile_sha256=digest(configuration),
                    not_after_ms=bounds['expires_at_ms'])
                argv = command(base, receive_only=False, runtime_code=code, runtime_digest=vector[1],
                    visibility=Path(selected['visibility']), messaging_application=Path(selected['application']),
                    expected_initial_context=initial_context)
                native_id = GuestBootstrapController(cohort.journal, cohort.operation_id, self.backend, name)._native_operation_id()
                request = dict(schema='cluster-guest-service-initial/v1', operation_id=native_id,
                    plan_digest=digest(plan), predecessor=None, argv=argv, not_after_ms=bounds['expires_at_ms'])
                intent = record('intent', dict(binding=binding, owner=frozen_owner, request=request,
                    unit_sha256=hashlib.sha256(unit_content(argv)).hexdigest()))
            if intent['binding'] != binding:
                raise OnboardingError('receiving_initial_binding_changed')
            if name in (cohort._row()['runtime_observation'] or {}).get('initial_steady', {}):
                self._complete_initial_locked(plan, cohort, deadline=deadline)
                return effects()['controlled_loaded']
            def root_call(action, *, fresh_effect=False, **kwargs):
                budget = remaining()
                if fresh_effect:
                    budget = min(budget, (bounds['expires_at_ms'] - time.time_ns() // 1_000_000) / 1000)
                    if budget <= 0:
                        raise OnboardingError('receiving_preservation_authorization_expired')
                return self.backend._guest_service_call(plan, action, candidate=vector,
                    timeout_seconds=budget, **kwargs)
            validated = root_call('bootstrap-validate', request=intent['request'])
            dispatch_state = validated.get('dispatch_state')
            if dispatch_state not in {'not-dispatched', 'intent-retained', 'started-recorded'}:
                raise OnboardingError('receiving_initial_dispatch_unobserved')
            record('validated', {key: value for key, value in validated.items() if key != 'dispatch_state'})
            if dispatch_state == 'not-dispatched':
                preservation_authorization(intent['owner']['preservation'], bounds['expires_at_ms'])
            if 'selected' not in effects():
                record('selected', root_call('bootstrap-select', fresh_effect=dispatch_state == 'not-dispatched',
                    request=intent['request']))
            if dispatch_state == 'not-dispatched':
                current = self.backend._target_call(plan, 'receiving-bootstrap-freeze', candidate=vector,
                    bootstrap_timeout_seconds=remaining(), bootstrap_initial_service=True)
                if {key: value for key, value in current.items() if key != 'observer_startup'} != intent['owner']:
                    raise OnboardingError('receiving_initial_owner_changed')
                # Selection can consume the remaining authority horizon. A
                # retained start intent, in contrast, is never fresh permission.
                preservation_authorization(intent['owner']['preservation'], bounds['expires_at_ms'])
            # The root primitive observes a retained first invocation after a
            # lost reply. Repeating this exact call never repeats StartUnit.
            started = record('started', root_call('bootstrap-start', fresh_effect=dispatch_state == 'not-dispatched',
                request=intent['request']))
            if (started.get('schema') != 'cluster-guest-service-initial-start/v1'
                    or started['service']['unit_sha256'] != intent['unit_sha256']
                    or effects()['selected']['selected_sha256'] != intent['unit_sha256']):
                raise OnboardingError('receiving_initial_service_changed')
            observed = self.backend._target_call(plan, 'admitted-running', candidate=vector,
                observation_timeout_seconds=remaining(), require_loaded=True)
            root = root_call('bootstrap-inspect', owner_observation={key: observed[key]
                for key in ('process', 'admission_parent')})
            if (root['service'] != started['service']
                    or observed['admission_parent'] != started['admission_parent']):
                raise OnboardingError('receiving_initial_service_changed')
            result = dict(schema='cluster-guest-initial-loaded/v1', **guest_loaded_observation(
                observed, root, intent['owner'], dict(runtime_digest=vector[1], prepared=prepared),
                expected_runtime=intent['owner']['runtime_sha256'], unit_sha256=intent['unit_sha256'],
                manager=started['service']['manager'], dropins=started['service'].get('dropins', {}),
                initial_observation='controlled_loaded' not in effects()))
            remaining()
            record('controlled_loaded', result)
            remaining()
            self.registry.adopt_running(**{key: expected[key] for key in ('body_ref', 'embodiment_id', 'incarnation_id')})
            remaining()
            return result

    def complete_initial(self, plan: dict, cohort, *, timeout_seconds: float = 30) -> dict:
        """Select ordinary restart policy only after qualified cohort activation.

        Retain a committed physical handoff before rechecking receiving proof;
        a lost/expired later observation cannot turn it into another first start.
        Communication acceptance and portal completion remain separate.
        """
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 60:
            raise OnboardingError('receiving_host_deadline_required')
        deadline = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
        with self._initial_scope(plan, cohort):
            return self._complete_initial_locked(plan, cohort, deadline=deadline)

    def _complete_initial_locked(self, plan: dict, cohort, *, deadline: int) -> dict:
        from .onboarding_service import unit_content
        from .onboarding_receiving_update import guest_loaded_observation
        from .operation_journal import JournalConflict
        name = plan['name']
        def remaining():
            seconds = (deadline - time.monotonic_ns()) / 1_000_000_000
            if seconds <= 0:
                raise OnboardingError('receiving_host_deadline_expired')
            return seconds

        row = cohort._row()
        activation_plan, manifest = cohort._activation(row)
        activation = (row['runtime_observation'] or {}).get('cohort_activation')
        if (activation is None or set(row['runtime_observation'].get('sender_selections', {})) != set(cohort.owners)):
            raise OnboardingError('receiving_cohort_selection_required')
        initial = cohort._initial_lifecycle(row, name, activation_plan['receivers'][name])
        intent, loaded = initial['intent'], initial['controlled_loaded']
        approved = cohort._admission(row)['receivers'][name]
        vector = Path(approved['candidate']['code']), approved['recipe']['prepared']['code_digest']
        argv = intent['request']['argv']
        index = argv.index('--initial-context-json')
        steady_sha256 = hashlib.sha256(unit_content(argv[:index] + argv[index + 2:])).hexdigest()

        def root_call(action, **options):
            return self.backend._guest_service_call(plan, action, candidate=vector,
                timeout_seconds=remaining(), **options)

        def effect():
            return (cohort._row()['runtime_observation'] or {}).get('initial_steady', {}).get(name, {})

        def record(key, value):
            current = cohort._row()
            observations = dict(current['runtime_observation'] or {})
            steady = dict(observations.get('initial_steady', {}))
            receiver = dict(steady.get(name, {}))
            if key in receiver and receiver[key] != value:
                raise JournalConflict('receiving initial steady effect changed')
            receiver[key] = value
            steady[name] = receiver
            observations['initial_steady'] = steady
            cohort.journal.advance(cohort.operation_id, current['state'], runtime_observation=observations,
                expected_runtime_observation=current['runtime_observation'])
            remaining()
            return value

        def confirmed():
            with ExitStack() as scopes:
                scopes.enter_context(cohort._observation_scope())
                for owner in cohort.owners.values():
                    scopes.enter_context(cohort._owner_deadline(owner, deadline))
                current = cohort._row()
                if 'cohort_reassessment' in (current['runtime_observation'] or {}):
                    raise OnboardingError('receiving_cohort_reassessment_required')
                return cohort._confirmed_selection(current, activation_plan, manifest, activation)

        owner_observation = {key: loaded[key] for key in ('process', 'admission_parent')}
        physical = root_call('bootstrap-inspect', owner_observation=owner_observation)
        selected_sha256 = physical['service']['unit_sha256']
        if selected_sha256 not in {intent['unit_sha256'], steady_sha256}:
            raise OnboardingError('receiving_initial_service_changed')
        request = effect().get('intent')
        if selected_sha256 == intent['unit_sha256']:
            observed_at_ms = time.time_ns() // 1_000_000
            selection = confirmed()
            remaining()
            if request is None:
                request = record('intent', dict(schema='cluster-guest-service-steady/v1',
                    operation_id=intent['request']['operation_id'], plan_digest=digest(plan),
                    initial_request_sha256=digest(intent['request']), cohort_selection_sha256=digest(selection),
                    **owner_observation, not_after_ms=min(intent['request']['not_after_ms'],
                        observed_at_ms + activation_plan['observation_window_ms'])))
            elif request['cohort_selection_sha256'] != digest(selection):
                raise OnboardingError('receiving_cohort_selection_changed')
        elif request is None:
            raise OnboardingError('receiving_initial_steady_intent_required')
        if (request['initial_request_sha256'] != digest(intent['request'])
                or request['operation_id'] != intent['request']['operation_id']
                or request['plan_digest'] != digest(plan)
                or any(request[key] != value for key, value in owner_observation.items())):
            raise OnboardingError('receiving_initial_binding_changed')
        # Root observes an already selected exact steady unit after expiry. A
        # still-guarded unit requires its original finite request horizon.
        selected = root_call('bootstrap-steady', request=request)
        if (selected.get('schema') != 'cluster-guest-service-steady-selection/v1'
                or selected['request_sha256'] != digest(request)
                or selected['service']['unit_sha256'] != steady_sha256
                or selected['selected']['previous_sha256'] != intent['unit_sha256']
                or any(selected[key] != value for key, value in owner_observation.items())):
            raise OnboardingError('receiving_initial_service_changed')
        # Retain the physical receipt before post-selection qualification.
        try:
            record('selected', selected)
            if 'cohort_reassessment' in (cohort._row()['runtime_observation'] or {}):
                raise OnboardingError('receiving_cohort_reassessment_required')
            observed = self.backend._target_call(plan, 'admitted-running', candidate=vector,
                observation_timeout_seconds=remaining(), require_loaded=True)
            root = root_call('bootstrap-inspect', owner_observation={key: observed[key]
                for key in ('process', 'admission_parent')})
            current_load = guest_loaded_observation(observed, root, intent['owner'],
                dict(runtime_digest=vector[1], prepared=approved['recipe']['prepared']),
                expected_runtime=intent['owner']['runtime_sha256'], unit_sha256=steady_sha256,
                manager=selected['service']['manager'], dropins=selected['service'].get('dropins', {}),
                initial_observation=False)
            if any(current_load[key] != value for key, value in loaded.items() if key != 'schema'):
                raise OnboardingError('receiving_initial_service_changed')
            selection = confirmed()
            if digest(selection) != request['cohort_selection_sha256']:
                raise OnboardingError('receiving_cohort_selection_changed')
            remaining()
            return record('completed', dict(schema='cluster-managed-initial-steady/v1',
                initial_sha256=digest(loaded), selected_sha256=steady_sha256,
                cohort_selection_sha256=digest(selection), loaded=current_load,
                receiving_readiness='qualified-local-projection', communication_acceptance='unobserved'))
        except (OnboardingError, OSError, KeyError, ValueError, TypeError):
            current = cohort._row()
            observations = dict(current['runtime_observation'] or {})
            if 'cohort_reassessment' not in observations:
                # Persist the repair obligation even when the invocation's
                # budget no longer permits contacting any receiving owner.
                observations['cohort_reassessment'] = {}
                cohort.journal.advance(cohort.operation_id, current['state'], runtime_observation=observations,
                    expected_runtime_observation=current['runtime_observation'])
                try:
                    with ExitStack() as scopes:
                        for owner in cohort.owners.values():
                            scopes.enter_context(cohort._owner_deadline(owner, deadline))
                        cohort._fence_partial_activation(activation)
                except (OnboardingError, OSError):
                    pass  # The retained reassessment remains explicitly pending.
            raise

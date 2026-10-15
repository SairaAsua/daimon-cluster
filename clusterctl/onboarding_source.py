"""Owner-local Source group hosting, observation and retained directed repair.

The caller coordinates the existing daemon lifecycle. Offline operations acquire
its real writer lock; online relationship requests use its authenticated base
socket. Both retain existing Body custody, never read an inbox, and never create
Root authority or synthesize participant signatures.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from . import being_seed, onboarding_peer, onboarding_release
from .onboarding import OnboardingError, digest, private_directory
from .onboarding_views import serve_views


class Source:
    def __init__(self, settings: dict, *, code: Path | None = None, code_uid: int = 0,
                 code_digest: str | None = None, qualified_startup: dict | None = None):
        if (not isinstance(settings, dict) or set(settings) != {'schema', 'runtime_root', 'password_file',
                'native_visibility', 'outputs', 'applications'} or settings['schema'] != 'cluster-onboarding-source/v1'
                or any(not isinstance(settings[key], str) or not Path(settings[key]).is_absolute()
                       for key in ('runtime_root', 'password_file', 'native_visibility', 'outputs'))
                or not isinstance(settings['applications'], list) or len(settings['applications']) > 16):
            raise OnboardingError('invalid_onboarding_source_configuration')
        for key in ('runtime_root', 'password_file', 'native_visibility', 'outputs'):
            being_seed._path(Path(settings[key]))
        self.settings = settings
        self.root = private_directory(Path(settings['runtime_root']))
        self.outputs = private_directory(Path(settings['outputs']), create=True)
        self.visibility = Path(settings['native_visibility'])
        self.code = code or Path(__file__).resolve().parents[1]
        self.code_uid = code_uid
        self.code_digest = code_digest
        self.qualified_startup = qualified_startup
        self._tool = None

    @property
    def tool(self):
        # Group serving does not run the archived two-party ceremony. Preserve
        # that ceremony's exact SDK/tool guards when it is actually requested.
        if self._tool is None:
            self._tool = onboarding_peer.native(self.code, uid=self.code_uid)
        return self._tool

    def _reader(self):
        from daimon_matrix.messaging_config import protected_read
        return bytearray(protected_read(Path(self.settings['password_file'])))

    def _load(self, *, signed: bool, relationship_authorities: dict | None = None):
        from daimon_matrix import daemon, native_egress, runtime
        def clock():
            return time.time_ns() // 1_000_000
        options = ({'egress_factory': daemon._visibility_factory(self.visibility, clock=clock)} if signed else
                   {'egress': native_egress.closed_visibility(clock=clock, catalog_mode='migrate')})
        bundle = being_seed._read(self.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
        authorities = onboarding_peer.approved_group_authorities(self.root, self.outputs / 'tribe', bundle)
        if relationship_authorities is not None:
            from .onboarding_group_admission import merge_authorities
            authorities = merge_authorities(authorities, relationship_authorities)
        if authorities:
            options['relationship_authorities'] = authorities
        return runtime.load_runtime(self.root, 'runtime.json', self._reader, clock=clock,
            **({} if self.qualified_startup is None else {'qualified_startup': self.qualified_startup}),
            **options)

    @contextmanager
    def writer(self):
        from daimon_matrix.daemon import acquire_lock
        descriptor = acquire_lock(self.root)
        try:
            yield
        finally:
            os.close(descriptor)

    def directory(self, plan_digest: str) -> Path:
        import re
        if not isinstance(plan_digest, str) or not re.fullmatch(r'[0-9a-f]{64}', plan_digest):
            raise OnboardingError('approved_onboarding_peer_required')
        return private_directory(self.outputs / plan_digest, create=True)

    def group_relationship(self, value: dict, *, offline: bool = False,
                           authority_closure: dict | None = None,
                           deadline_ns: int | None = None) -> dict:
        """The qualified owner route supplies approval; no peer text grants it."""
        from .onboarding_group_admission import (
            check_retained_ledger, command, load_owner_runtime, owner_authorities, relationship_request,
        )
        value = command(value)
        journal = self.outputs / 'group-admission'
        if not offline:
            if authority_closure:
                raise OnboardingError('onboarding_group_relationship_writer_required')
            return relationship_request(self.root, journal, value, deadline_ns=deadline_ns)
        with self.writer():
            check_retained_ledger(self.root, journal, value)
            authorities = owner_authorities(self.root, self.outputs / 'tribe', journal,
                                            value['operation_id'], authority_closure or {})
            hosted = load_owner_runtime(self.root, self._reader, authorities=authorities,
                                        qualified_startup=self.qualified_startup)
            return relationship_request(self.root, journal, value, offline=hosted, deadline_ns=deadline_ns)

    def group_publication(self, value: dict, *, authority_closure: dict,
                          deadline_ns: int | None = None) -> dict:
        from .onboarding_receiving_update import source_bootstrap_group
        from .onboarding_group_admission import (
            check_snapshot_context, load_owner_runtime, owner_authorities, publication_command, publication_request,
        )
        value = publication_command(value)
        journal = self.outputs / 'group-admission'
        group = self.outputs / 'tribe'
        with self.writer():
            check_snapshot_context(journal, value)
            authorities = owner_authorities(self.root, group, journal, value['operation_id'], authority_closure)
            hosted = load_owner_runtime(self.root, self._reader, authorities=authorities,
                                        qualified_startup=self.qualified_startup)
            return publication_request(hosted, group, journal, value, deadline_ns=deadline_ns,
                snapshot=lambda: source_bootstrap_group(self, being_seed._read(
                    self.root / 'runtime.json', limit=being_seed.MAX_SELECTION)))

    def offer(self, plan_digest: str, peer: dict, endpoints: list[str]) -> dict:
        self.tool.verify_identity(peer)
        directory = self.directory(plan_digest)
        with self.writer():
            runtime = self._load(signed=True)
            bundle = self.tool.read_public(self.root / 'runtime.json')
            path = self.tool.offer(runtime, bundle, peer, directory, endpoints, self.visibility)
            return self.tool.read_public(path)

    def finish(self, plan_digest: str, response: dict) -> dict:
        from daimon_matrix.messaging_config import config_digest
        from daimon_matrix.operator_messaging import _reissue_installation
        directory = self.directory(plan_digest)
        with self.writer():
            before = self.tool.read_public(self.visibility)
            # Migration-mode loading registers native catalogs without changing
            # their journals/proof keys and cannot serve or release an egress.
            # The maintained additional-link operation migrates only app catalogs.
            runtime = self._load(signed=False)
            try:
                path = self.tool.finish(runtime, self.root, bytes(self._reader()), response,
                                        directory, additional_link=True)
            finally:
                # A lost ACK after bundle publication must still leave the native
                # daemon restartable against its unchanged signed disclosure.
                current = self._load(signed=False)
                _reissue_installation(current, self.visibility,
                    application_sha256=config_digest(self.tool.read_public(self.root / 'runtime.json')))
            after = self.tool.read_public(self.visibility)
            if any(after['document'][field] != before['document'][field]
                   for field in ('disclosure', 'secrets', 'telegram_qualification')):
                raise OnboardingError('existing_onboarding_source_visibility_preserved')
            # Validate the ORIGINAL controller and every native catalog with its
            # ORIGINAL proof key before returning a usable app to the host.
            restored = self._load(signed=True)
            restored.egress.validate_registered_catalogs()
            return self.tool.read_public(path)

    def views(self) -> list:
        from daimon_matrix.chat_host import application_view
        base = self._load(signed=True)
        views = [base]
        group = onboarding_peer.approved_group_application(base, self.outputs / 'tribe')
        if group is not None:
            view = application_view(base, Path(group['directory']), Path(group['visibility']))
            return [base, replace(view, socket_path=self.outputs / group['socket'])]
        seen = set()
        for fingerprint in self.settings['applications']:
            directory = self.directory(fingerprint)
            ready = self.tool.read_public(directory / 'ready.json')
            if (ready['runtime_root'] != str(self.root) or ready['app_directory'] != str(directory / 'application')
                    or ready['visibility_installation'] != str(directory / 'visibility/installation.json')):
                raise OnboardingError('current_onboarding_source_application_required')
            view = application_view(base, directory / 'application', directory / 'visibility/installation.json')
            socket_name = 'peer-' + fingerprint[:12] + '.sock'
            if socket_name in seen:
                raise OnboardingError('onboarding_runtime_listener_collision')
            seen.add(socket_name)
            socket = self.outputs / socket_name
            if len(os.fsencode(socket)) > 107:
                raise OnboardingError('onboarding_runtime_socket_path_too_long')
            views.append(replace(view, socket_path=socket))
        return views

    def register(self, config: Path, unit: Path, original_sha256: str, python: Path, fingerprint: str) -> None:
        from .onboarding_service import selection_lock
        with selection_lock(unit):
            self._register_locked(config, unit, original_sha256, python, fingerprint)

    def _register_locked(self, config: Path, unit: Path, original_sha256: str,
                         python: Path, fingerprint: str) -> None:
        """Retain all unit settings and original bytes; replace only its entry point.

        The host pins the original owner unit. This owner-local operation may
        append an accepted application; a retry cannot reset preceding links.
        """
        import hashlib
        from daimon_matrix.keystore import _atomic_write
        from .onboarding_release import regular
        settings = being_seed._read(config)
        if settings != self.settings:
            raise OnboardingError('existing_onboarding_source_configuration_preserved')
        original = self.outputs / ('native-unit-' + original_sha256)
        if not original.exists():
            raw = regular(unit, uid=os.geteuid())
            if hashlib.sha256(raw).hexdigest() != original_sha256 or raw.count(b'\nExecStart=') != 1:
                raise OnboardingError('existing_onboarding_source_service_preserved')
            _atomic_write(original, raw)
        raw = regular(original, uid=os.geteuid())
        if hashlib.sha256(raw).hexdigest() != original_sha256:
            raise OnboardingError('existing_onboarding_source_service_preserved')
        from . import onboarding_code_successor, onboarding_sdk
        parameters = onboarding_code_successor.sdk_parameters(self.code, uid=self.code_uid)
        if parameters:
            if self.code_digest is None:
                raise OnboardingError('qualified_onboarding_source_runtime_required')
            onboarding_release.verify(self.code, self.code_digest, uid=self.code_uid)
            venv = python.parent.parent
            imports = onboarding_sdk.runtime_imports(venv, self.code,
                code_uid=self.code_uid, **parameters)
            command = onboarding_sdk.runtime_command(venv, imports, self.code,
                'clusterctl.onboarding_source', ['--config', str(config),
                                               '--code-digest', self.code_digest])
        else:
            launcher = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                        'from clusterctl.onboarding_source import main;raise SystemExit(main())')
            command = [str(python), '-B', '-I', '-c', launcher, str(self.code), '--config', str(config)]
        argv = command
        def selection(arguments):
            encoded = ' '.join(json.dumps(arg.replace('%', '%%').replace('$', '$$')) for arg in arguments)
            return b'\n'.join(('ExecStart=' + encoded).encode() if line.startswith(b'ExecStart=') else line
                              for line in raw.split(b'\n'))
        candidate = selection(argv)
        current = regular(unit, uid=os.geteuid())
        if current not in (raw, candidate):
            import shlex
            try:
                previous = shlex.split(next(line[len('ExecStart='):] for line in current.decode().splitlines()
                                           if line.startswith('ExecStart=')))
                if len(previous) != len(argv) or previous[:5] != argv[:5] or previous[6:] != argv[6:]:
                    raise ValueError
                previous_code = Path(previous[5])
                if not previous_code.is_absolute() or selection(previous) != current:
                    raise ValueError
                regular(previous_code / 'clusterctl/onboarding_source.py', uid=self.code_uid)
                import ast
                adapter = ast.parse(regular(previous_code / 'clusterctl/onboarding_peer.py', uid=self.code_uid))
                declared = next(ast.literal_eval(statement.value) for statement in adapter.body
                    if isinstance(statement, ast.Assign) and any(isinstance(target, ast.Name)
                        and target.id == 'TOOL_SHA256' for target in statement.targets))
                tool = regular(previous_code / 'clusterctl/onboarding_peer_native.py', uid=self.code_uid)
                if declared != hashlib.sha256(tool).hexdigest():
                    raise ValueError
            except (ValueError, StopIteration, UnicodeError, OSError, OnboardingError):
                raise OnboardingError('existing_onboarding_source_service_preserved') from None
        # Validate both retained controllers and the new signed app BEFORE
        # selecting its service. Publication order remains safe after lost ACK.
        if fingerprint not in settings['applications']:
            settings = {**settings, 'applications': [*settings['applications'], fingerprint]}
        self.settings = settings
        self.views()
        being_seed._write(config, settings)
        _atomic_write(unit, candidate)

    def serve(self, stop: threading.Event, *, ready_descriptor: int | None = None) -> None:
        with self.writer():
            serve_views(self.views(), stop, ready_descriptor=ready_descriptor)

    def observe(self, *, require_loaded: bool = False, deadline_ns: int | None = None) -> dict:
        """Authenticate actual selected listeners without loading another runtime.

        A receiving controller must request loaded evidence explicitly. Legacy
        callers retain their old probe, clearly outside receiving qualification.
        Neither branch claims admission, delivery or positive reader selection.
        """
        from contextlib import ExitStack
        import hashlib
        from types import SimpleNamespace
        from daimon_matrix.canonical import canonical_bytes
        from daimon_matrix.client import ClientConfig, LocalClient
        from daimon_matrix.operator_capabilities import host_capability_profile
        from .onboarding_target import document
        from .owner_process import ConnectedProcessObserver

        connected = 'connection_observer' in getattr(LocalClient, '__dataclass_fields__', {})
        if require_loaded and not connected:
            raise OnboardingError('qualified_onboarding_client_required')
        if deadline_ns is not None and 'deadline_ns' not in getattr(LocalClient, '__dataclass_fields__', {}):
            raise OnboardingError('qualified_onboarding_deadline_client_required')
        with ExitStack() as ownership:
            observer = ownership.enter_context(ConnectedProcessObserver()) if connected else None
            options = {} if observer is None else {'connection_observer': observer}
            sockets = {}

            def client(path: Path, config_path: Path, key_path: Path):
                remaining = 40 if deadline_ns is None else (deadline_ns - time.monotonic_ns()) / 1_000_000_000
                if remaining <= 0:
                    raise OnboardingError('onboarding_observation_deadline_expired')
                sockets[path] = path.lstat()
                key = bytearray(onboarding_release.regular(key_path, uid=os.geteuid()))
                config = ClientConfig.load(config_path, key)
                return LocalClient(path, config, timeout_seconds=40,
                    **({} if deadline_ns is None else {'deadline_ns': deadline_ns}), **options)

            native = client(self.root / 'matrix.sock', self.root / 'client.json', self.root / 'client.key')
            base = native.runtime_status()[1]
            if base.get('ok') is not True:
                raise OnboardingError('onboarding_runtime_not_ready')
            bundle = document(self.root / 'runtime.json')
            group = onboarding_peer.observed_group(SimpleNamespace(root=self.outputs, package=self.outputs),
                bundle, socket_root=self.outputs)
            application_status = None
            if group is not None:
                if observer is not None:
                    role = host_capability_profile('status')
                    directory = self.root / role['client_directory']
                    hosted = client(Path(group['socket']), directory / role['client_config_filename'],
                                    directory / role['client_key_filename'])
                    response = hosted.runtime_status()[1]
                    if response.get('ok') is not True or response['server'] != base['server']:
                        raise OnboardingError('onboarding_daemon_origin_conflict')
                    application_status = response['result']
                else:
                    directory = Path(group['application'])
                    hosted = client(Path(group['socket']), directory / 'client.json', directory / 'client.key')
                    if hosted.invoke('messaging.send', {})[1].get('error', {}).get('code') != 'invalid_params':
                        raise OnboardingError('onboarding_runtime_not_ready')
            elif require_loaded:
                raise OnboardingError('qualified_onboarding_group_required')
            else:
                # Explicit retained directed applications remain independently
                # observable; they never stand in for a missing selected group.
                for fingerprint in self.settings['applications']:
                    directory = self.directory(fingerprint) / 'application'
                    hosted = client(self.outputs / ('peer-' + fingerprint[:12] + '.sock'),
                                    directory / 'client.json', directory / 'client.key')
                    if hosted.invoke('messaging.send', {})[1].get('error', {}).get('code') != 'invalid_params':
                        raise OnboardingError('onboarding_runtime_not_ready')
            loaded_base = base['result'].get('loaded_runtime')
            if observer is not None:
                observer.verify()
                process = observer.process
                if process is None:
                    raise OnboardingError('onboarding_daemon_responder_conflict')
                for status in (base['result'], application_status):
                    loaded = None if status is None else status.get('loaded_runtime')
                    if loaded is not None and loaded.get('process_id') != process['pid']:
                        raise OnboardingError('onboarding_daemon_responder_conflict')
                if application_status is not None and (
                        application_status.get('loaded_runtime') != loaded_base):
                    raise OnboardingError('onboarding_loaded_base_conflict')
            if require_loaded:
                loaded_application = None if application_status is None else application_status.get('loaded_application')
                if (not isinstance(loaded_base, dict) or not loaded_base.get('qualified_startup')
                        or not isinstance(loaded_application, dict)
                        or loaded_application.get('loaded_base_sha256') != hashlib.sha256(canonical_bytes(loaded_base)).hexdigest()):
                    raise OnboardingError('qualified_onboarding_loaded_view_required')
            for path, before in sockets.items():
                after = path.lstat()
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise OnboardingError('onboarding_daemon_socket_changed')
            if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
                raise OnboardingError('onboarding_observation_deadline_expired')
            return dict(running=True, applications=[] if group else self.settings['applications'], group=group,
                base_runtime_status=base['result'], runtime_status=application_status,
                process=None if observer is None else observer.process,
                responder_association='same-connection' if observer is not None else 'legacy-probe',
                receiving_readiness='unobserved')

    def receiving_observation(self, *, expires_at_ms: int | None = None,
                              deadline_ns: int | None = None) -> dict:
        from .onboarding_receiving_update import OwnerGroupClient
        observed = self.observe(require_loaded=True,
            **({} if deadline_ns is None else {'deadline_ns': deadline_ns}))
        with OwnerGroupClient(self.root, Path(observed['group']['socket']), deadline_ns=deadline_ns) as owner:
            current = (owner.status() if expires_at_ms is None else
                owner.qualified_identity(expires_at_ms=expires_at_ms, require_admitted=False))
            if (current['process'] != observed['process']
                    or current['server'] != observed['runtime_status']['local_origin']
                    or any(current['runtime_status'].get(key) != observed['runtime_status'].get(key)
                           for key in ('loaded_runtime', 'loaded_application'))):
                raise OnboardingError('receiving_source_process_changed')
            return {**current, 'group': observed['group']}

    def receiving_control(self, action: str, path: Path, *, command: dict | None = None,
                          deadline_ns: int | None = None) -> dict:
        from .onboarding_receiving_update import owner_control
        observed = (self.observe(require_loaded=True) if deadline_ns is None else
            self.observe(require_loaded=True, deadline_ns=deadline_ns))
        if deadline_ns is None:
            return owner_control(self.root, observed['group'], observed, action, path, command=command)
        return owner_control(self.root, observed['group'], observed, action, path,
            command=command, deadline_ns=deadline_ns)

    def receiving_lifecycle(self, journal_path: Path, operation_id: str) -> dict:
        """Project only this Source's retained lifecycle; no service/native RPC."""
        from .operation_journal import OperationJournal
        from .onboarding_receiving_update import admission_lifecycle_projection
        journal = OperationJournal.existing(being_seed._path(journal_path))
        row = None if journal is None else journal.get(operation_id)
        if row is None or row['operation'] != 'receiving-update':
            raise OnboardingError('receiving_source_lifecycle_unobserved')
        before, after = row['expected_precondition'], row['intended_transition']
        call = row['intent'].get('runtime_call', {})
        frozen = before.get('source_bootstrap', {})
        qualification = after.get('source_bootstrap', {}).get('qualification', {})
        if (call.get('precondition_digest') != digest(before)
                or call.get('transition_digest') != digest(after)
                or frozen.get('settings_sha256') != digest(self.settings)
                or not isinstance(frozen.get('predecessor'), dict)
                or not isinstance(qualification.get('code'), str)
                or type(qualification.get('code_uid')) is not int
                or qualification.get('config') is None
                or being_seed._read(Path(qualification['config'])) != self.settings):
            raise OnboardingError('receiving_source_lifecycle_conflict')
        effects = (row['runtime_observation'] or {}).get('source_bootstrap', {})
        # Never export intents, control capabilities, custody or another Source.
        projected = dict(operation_id=operation_id, operation='receiving-update',
            expected_precondition={'source_bootstrap': {'predecessor': {
                key: frozen['predecessor'].get(key) for key in ('process', 'server')}}},
            intended_transition={'source_bootstrap': {'qualification': {
                key: qualification[key] for key in ('code', 'code_uid')}}},
            runtime_observation={'source_bootstrap': {
                key: effects[key] for key in ('quiesced', 'controlled_loaded') if key in effects}})
        admission = admission_lifecycle_projection(row, profile='source')
        if admission is not None:
            projected['admission'] = admission
        return dict(schema='cluster-receiving-source-lifecycle/v1',
            source_config_sha256=digest(self.settings), lifecycle=projected)

    def receiving_lifecycle_action(self, journal_path: Path, operation_id: str, action: str, *, deadline_ns: int) -> dict:
        """Execute only the protected operation through the existing user unit."""
        from .operation_journal import OperationJournal
        from .onboarding_service import MatrixUserService
        from .onboarding_receiving_update import SourceBootstrapController
        if action not in {'quiesce', 'preserve', 'derive', 'start', 'quiescence'}:
            raise OnboardingError('receiving_source_lifecycle_conflict')
        journal = OperationJournal.existing(being_seed._path(journal_path))
        row = None if journal is None else journal.get(operation_id)
        if row is None or row['operation'] != 'receiving-update':
            raise OnboardingError('receiving_source_lifecycle_unobserved')
        frozen = row['expected_precondition'].get('source_bootstrap', {})
        if frozen.get('settings_sha256') != digest(self.settings) or not isinstance(frozen.get('unit'), str):
            raise OnboardingError('receiving_source_lifecycle_conflict')
        controller = SourceBootstrapController(journal, operation_id, self, MatrixUserService(Path(frozen['unit'])))
        if action != 'quiescence' and (frozen.get('mode') != 'preserve'
                or 'admission_link' not in row['intended_transition'].get('source_bootstrap', {})):
            raise OnboardingError('receiving_admission_prepared_controller_required')
        # Resolve no caller-supplied argv, unit or candidate: the controller
        # consumes the original journal and revalidates its exact qualification.
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if not 0 < remaining <= 60:
            raise OnboardingError('onboarding_observation_deadline_expired')
        if action == 'preserve':
            result = controller.publish(deadline_ns=deadline_ns)
        elif action == 'derive':
            result = controller.retain_admission_group(timeout_seconds=remaining, deadline_ns=deadline_ns)
        elif action == 'quiesce':
            result = controller.quiesce(timeout_seconds=remaining, deadline_ns=deadline_ns)
        elif action == 'start':
            result = controller.start(timeout_seconds=remaining, deadline_ns=deadline_ns)
        else:
            result = controller.observe_quiescence(timeout_seconds=remaining, deadline_ns=deadline_ns)
        if time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('onboarding_observation_deadline_expired')
        return dict(schema='cluster-receiving-source-lifecycle-effect/v1', source_config_sha256=digest(self.settings),
            operation_id=operation_id, action=action, result=result)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--ready-fd', type=int)
    parser.add_argument('--code-digest')
    parser.add_argument('--code-owner', type=int, default=0)
    parser.add_argument('--observe', action='store_true')
    parser.add_argument('--require-loaded', action='store_true')
    control = parser.add_mutually_exclusive_group()
    control.add_argument('--prepare-control', type=Path)
    control.add_argument('--apply-control', type=Path)
    control.add_argument('--prepare-apply-control', type=Path)
    parser.add_argument('--control-command', type=Path)
    parser.add_argument('--owner-status', action='store_true')
    parser.add_argument('--qualified-identity', action='store_true')
    parser.add_argument('--identity-expires-at-ms', type=int)
    parser.add_argument('--native-tooling-json')
    parser.add_argument('--observation-deadline-ns', type=int)
    parser.add_argument('--expected-config-sha256')
    parser.add_argument('--receiving-lifecycle')
    parser.add_argument('--lifecycle-action', choices=('quiesce', 'preserve', 'derive', 'start', 'quiescence'))
    parser.add_argument('--operation-journal', type=Path)
    parser.add_argument('--group-request', type=Path)
    args = parser.parse_args(argv)
    try:
        from . import onboarding_code_successor, onboarding_sdk
        code = Path(__file__).resolve().parents[1]
        if args.code_owner < 0:
            raise OnboardingError('qualified_source_code_owner_required')
        controlling = any(path is not None for path in (args.prepare_control, args.apply_control, args.prepare_apply_control))
        lifecycle = args.receiving_lifecycle is not None
        grouping = args.group_request is not None
        if args.native_tooling_json is not None and (not args.qualified_identity
                or len(args.native_tooling_json.encode()) > 65536):
            raise OnboardingError('receiving_native_tooling_recipe_required')
        receiving = args.owner_status or args.qualified_identity or controlling or lifecycle or grouping
        if (sum((args.observe, args.owner_status, args.qualified_identity, controlling, lifecycle, grouping)) > 1
                or lifecycle != (args.operation_journal is not None)
                or args.lifecycle_action is not None and not lifecycle
                or lifecycle and (args.ready_fd is not None or args.require_loaded)
                or args.qualified_identity != (args.identity_expires_at_ms is not None)
                or args.identity_expires_at_ms is not None and not 0 < args.identity_expires_at_ms < 2**53
                or (args.owner_status or args.qualified_identity or grouping) and (args.ready_fd is not None or args.require_loaded)
                or args.expected_config_sha256 is not None and not receiving
                or args.observation_deadline_ns is not None and not receiving):
            raise OnboardingError('invalid_receiving_control_request')
        if (args.owner_status or args.qualified_identity or lifecycle or grouping) and args.observation_deadline_ns is None:
            args.observation_deadline_ns = time.monotonic_ns() + 30_000_000_000
        def accept_deadline():
            if args.observation_deadline_ns is not None and time.monotonic_ns() >= args.observation_deadline_ns:
                raise OnboardingError('onboarding_observation_deadline_expired')
        if args.observation_deadline_ns is not None and not 0 < args.observation_deadline_ns - time.monotonic_ns() <= 60_000_000_000:
            raise OnboardingError('onboarding_observation_deadline_expired')
        if (controlling and (args.observe or args.require_loaded or args.ready_fd is not None)
                or (args.prepare_control is not None or args.prepare_apply_control is not None) != (args.control_command is not None)):
            raise OnboardingError('invalid_receiving_control_request')
        stdin_command = None
        if args.control_command == Path('-'):
            raw = sys.stdin.buffer.read(being_seed.MAX_SELECTION + 1)
            if len(raw) > being_seed.MAX_SELECTION:
                raise OnboardingError('invalid_receiving_control_request')
            stdin_command = json.loads(raw)
            if not isinstance(stdin_command, dict):
                raise OnboardingError('invalid_receiving_control_request')
        accept_deadline()
        parameters = onboarding_code_successor.sdk_parameters(code, uid=args.code_owner)
        if receiving and not parameters:
            raise OnboardingError('qualified_onboarding_source_observer_required')
        if args.require_loaded and (not args.observe or not parameters):
            raise OnboardingError('qualified_onboarding_source_observer_required')
        if parameters and args.code_digest is None:
            raise OnboardingError('qualified_onboarding_source_runtime_required')
        startup = (onboarding_sdk.qualified_startup(Path(sys.prefix), code,
            code_digest=args.code_digest, code_uid=args.code_owner, **parameters) if parameters else None)
        accept_deadline()
        settings = being_seed._read(args.config)
        if args.expected_config_sha256 is not None and digest(settings) != args.expected_config_sha256:
            raise OnboardingError('receiving_source_configuration_changed')
        accept_deadline()
        source = Source(settings, code=code, code_uid=args.code_owner, code_digest=args.code_digest,
                        qualified_startup=startup)
        if grouping:
            from .onboarding_group_admission import request_packet
            if args.group_request == Path('-'):
                raw = sys.stdin.buffer.read(being_seed.MAX_SELECTION + 1)
                if len(raw) > being_seed.MAX_SELECTION:
                    raise OnboardingError('onboarding_group_relationship_command_required')
                packet = json.loads(raw)
            else:
                packet = being_seed._read(args.group_request, limit=being_seed.MAX_SELECTION)
            packet = request_packet(packet)
            if 'action' in packet['command']:
                result = source.group_publication(packet['command'], authority_closure=packet['authority_closure'],
                    deadline_ns=args.observation_deadline_ns)
            else:
                result = source.group_relationship(packet['command'], offline=packet['offline'],
                    authority_closure=packet['authority_closure'], deadline_ns=args.observation_deadline_ns)
            print(json.dumps(result))
            return 0
        if lifecycle:
            accept_deadline()
            result = (source.receiving_lifecycle(args.operation_journal, args.receiving_lifecycle)
                if args.lifecycle_action is None else source.receiving_lifecycle_action(
                    args.operation_journal, args.receiving_lifecycle, args.lifecycle_action,
                    deadline_ns=args.observation_deadline_ns))
            accept_deadline()
            print(json.dumps(result))
            return 0
        if controlling:
            action = 'receiving-control-prepare' if args.prepare_control is not None else 'receiving-control-apply'
            path = args.prepare_control if args.prepare_control is not None else args.apply_control
            if args.prepare_apply_control is not None:
                action, path = 'receiving-control-prepare-apply', args.prepare_apply_control
            if args.control_command == Path('-'):
                command = stdin_command
            else:
                command = (None if args.control_command is None
                    else being_seed._read(args.control_command, limit=being_seed.MAX_SELECTION))
            accept_deadline()
            result = source.receiving_control(action, path, command=command,
                **({} if args.observation_deadline_ns is None else {'deadline_ns': args.observation_deadline_ns}))
            accept_deadline()
            print(json.dumps(result))
            return 0
        if args.owner_status or args.qualified_identity:
            result = source.receiving_observation(expires_at_ms=args.identity_expires_at_ms,
                deadline_ns=args.observation_deadline_ns)
            if args.native_tooling_json is not None:
                from .onboarding_owner_client import observe_selected_tooling
                if startup is None:
                    raise OnboardingError('qualified_native_peer_tool_required')
                result['native_tooling'] = observe_selected_tooling(json.loads(args.native_tooling_json),
                    code=code, startup=startup, code_uid=args.code_owner, deadline_ns=args.observation_deadline_ns,
                    receiving=result)
            accept_deadline()
            print(json.dumps(result))
            return 0
        if args.observe:
            if args.ready_fd is not None:
                raise OnboardingError('invalid_source_observation_request')
            print(json.dumps(source.observe(require_loaded=args.require_loaded)))
            return 0
        stop = threading.Event()
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, lambda *_: stop.set())
        source.serve(stop, ready_descriptor=args.ready_fd)
        return 0
    except Exception:
        # No paths, custody, token values or raw native errors in service logs.
        print(json.dumps({'error': 'native_onboarding_source_refused'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())


def child() -> int:
    """Drop privilege before reading Body custody; return only public ceremony data."""
    try:
        config = being_seed._path(Path(sys.argv[1]))
        owner = json.loads(sys.argv[2])
        action = sys.argv[3]
        info = config.stat()
        if (os.geteuid() != 0 or action not in {'offer', 'finish', 'register', 'observe'}
                or [info.st_uid, info.st_gid, info.st_dev, info.st_ino] != owner or info.st_mode & 0o077):
            return 1
        raw = sys.stdin.buffer.read(1_048_577)
        if len(raw) > 1_048_576:
            return 1
        request = json.loads(raw)
        os.setgroups([])
        os.setgid(owner[1])
        os.setuid(owner[0])
        source = Source(being_seed._read(config))
        if action == 'offer':
            with source.writer():
                group = onboarding_peer.approved_group_application(source._load(signed=True), source.outputs / 'tribe')
            if group is not None:
                raise OnboardingError('onboarding_group_enrollment_required')
            value = source.offer(request['plan_digest'], request['peer'], request['endpoints'])
        elif action == 'finish':
            value = source.finish(request['plan_digest'], request['response'])
        elif action == 'register':
            source.register(config, Path(request['unit']), request['unit_sha256'], Path(request['python']), request['plan_digest'])
            value = {'registered': True}
        else:
            if (set(request) - {'require_loaded'}
                    or 'require_loaded' in request and type(request['require_loaded']) is not bool):
                raise OnboardingError('invalid_source_observation_request')
            value = source.observe(require_loaded=request.get('require_loaded') is True)
        print(json.dumps(value))
        return 0
    except Exception:
        return 1

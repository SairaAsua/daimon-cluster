"""Verify shared group selection before managed receiving admission.

Normal onboarding requires the existing signed Tribe group, without per-pair
enrollment or proxies. Missing group admission remains an explicit deployment
gap. Historical Source/member setup is available only through the separately
requested ``repair_directed`` route; its service effects are not the group flow.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from . import being_seed, onboarding_local_body, onboarding_peer, onboarding_release
from .onboarding import OnboardingError, digest, private_directory


class PeerHost:
    def __init__(self, backend):
        self.backend = backend
        value = being_seed._read(backend.config.peer)
        fields = {'schema', 'source_config', 'source_uid', 'source_gid', 'source_settings_digest',
            'source_being_ref', 'source_unit', 'source_unit_sha256', 'source_python', 'state', 'port_base'}
        if (set(value) != fields or value['schema'] != 'cluster-onboarding-peer-host/v1'
                or any(type(value[key]) is not int or value[key] < 0 for key in ('source_uid', 'source_gid'))
                or type(value['port_base']) is not int or not 1024 <= value['port_base'] <= 65503
                or any(not isinstance(value[key], str) or not Path(value[key]).is_absolute()
                       for key in ('source_config', 'source_unit', 'source_python', 'state'))
                or any(not isinstance(value[key], str) or not re.fullmatch(r'[0-9a-f]{64}', value[key])
                       for key in ('source_settings_digest', 'source_unit_sha256'))
                or not isinstance(value['source_being_ref'], str)
                or not re.fullmatch(r'dm:being:v1:[A-Za-z0-9_-]{43}', value['source_being_ref'])
                or not re.fullmatch(r'daimon-matrix-[a-z0-9-]+\.service', Path(value['source_unit']).name)):
            raise OnboardingError('invalid_onboarding_peer_configuration')
        self.settings = value
        self.state = private_directory(Path(value['state']))
        self.source_config = Path(value['source_config'])
        self._source_settings()

    def _source_settings(self) -> dict:
        value = json.loads(onboarding_release.regular(self.source_config, uid=self.settings['source_uid']))
        info = self.source_config.stat()
        if (info.st_mode & 0o077 or info.st_gid != self.settings['source_gid']
                or digest({key: item for key, item in value.items() if key != 'applications'}) != self.settings['source_settings_digest']):
            raise OnboardingError('existing_onboarding_source_configuration_preserved')
        return value

    def _source(self, action: str, request: dict) -> dict:
        self._source_settings()
        info = self.source_config.stat()
        owner = [info.st_uid, info.st_gid, info.st_dev, info.st_ino]
        launcher = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                    'from clusterctl.onboarding_source import child;raise SystemExit(child())')
        return self._run([sys.executable, '-B', '-I', '-c', launcher, str(Path(__file__).resolve().parents[1]),
            str(self.source_config), json.dumps(owner), action], request)

    def _run(self, argv: list[str], request: dict | None = None) -> dict:
        try:
            result = subprocess.run(argv, input=None if request is None else json.dumps(request).encode(),
                capture_output=True, timeout=60, check=False,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8',
                     'LD_LIBRARY_PATH': str(Path(sys.base_prefix) / 'lib')})
            if result.returncode or len(result.stdout) > 1_048_576:
                raise OnboardingError('native_onboarding_source_unavailable')
            return json.loads(result.stdout) if request is not None else {}
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            raise OnboardingError('native_onboarding_source_unavailable') from None

    def _service(self, action: str) -> None:
        import pwd
        user = pwd.getpwuid(self.settings['source_uid']).pw_name
        environment = ['XDG_RUNTIME_DIR=/run/user/' + str(self.settings['source_uid']),
            'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(self.settings['source_uid']) + '/bus']
        arguments = [action] if action == 'daemon-reload' else [action, Path(self.settings['source_unit']).name]
        self._run(['/usr/sbin/runuser', '-u', user, '--', 'env', *environment, 'systemctl', '--user', *arguments])

    def _ports(self, plan: dict) -> tuple[int, int]:
        fingerprint = digest(plan)
        with being_seed._locked(self.state):
            path = self.state / 'ports.json'
            leases = being_seed._read(path) if path.exists() else {}
            if fingerprint not in leases:
                if len(leases) >= 16:
                    raise OnboardingError('onboarding_peer_capacity_required')
                leases[fingerprint] = dict(name=plan['name'], owner=plan['owner'], index=len(leases))
                being_seed._write(path, leases)
            row = leases[fingerprint]
            if row['name'] != plan['name'] or row['owner'] != plan['owner']:
                raise OnboardingError('approved_onboarding_peer_required')
            first = self.settings['port_base'] + 2 * row['index']
            return first, first + 1

    def _proxy_values(self, plan: dict) -> dict:
        source, target = self._ports(plan)
        return {'onboarding-peer-source': dict(type='proxy', bind='instance',
                    listen=f'tcp:127.0.0.1:{source}', connect=f'tcp:127.0.0.1:{source}'),
                'onboarding-peer-receiver': dict(type='proxy', bind='host',
                    listen=f'tcp:127.0.0.1:{target}', connect=f'tcp:127.0.0.1:{target}')}

    def _proxies(self, plan: dict, *, install: bool = False) -> bool:
        expected = self._proxy_values(plan)
        rows, _ = self.backend._inventory()
        own = next(row for row in rows if row['name'] == self.backend.instance(plan))
        ready = True
        for name, value in expected.items():
            current = own.get('expanded_devices', {}).get(name)
            if current is not None and current != value:
                raise OnboardingError('foreign_onboarding_peer_proxy_preserved')
            # Host listeners are global; a second body's claim is a collision.
            if any(device.get('type') == 'proxy' and device.get('bind', 'host') == 'host'
                    and device.get('listen') == value['listen']
                    for row in rows if row['name'] != own['name']
                    for device in row.get('expanded_devices', {}).values()):
                raise OnboardingError('onboarding_runtime_listener_collision')
            if current is None:
                ready = False
                if install:
                    self.backend._dispatch(plan, ['config', 'device', 'add', own['name'], name, 'proxy',
                        *[key + '=' + item for key, item in value.items() if key != 'type']])
        return ready

    def _identity(self, plan: dict) -> dict:
        # Reconcile newly submitted local authority before every acceptance.
        # Participant reports cannot substitute a hosted Root already published.
        directory = private_directory(self.state / digest(plan), create=True)
        path = directory / 'identity.json'
        identity = being_seed._read(path) if path.exists() else self.backend._target_call(plan, 'peer-identity')
        tool = onboarding_peer.native(Path(__file__).resolve().parents[1])
        authority = tool.verify_identity(identity)
        expected = self.backend._ceremony(plan).admission_coordinates(plan)
        if authority.state.being_ref != expected['being_ref'] or any(
                identity['document']['origin'].get(key) != expected[key]
                for key in ('body_ref', 'embodiment_id', 'incarnation_id')):
            raise OnboardingError('existing_onboarding_target_preserved')
        state = self.backend.config.consent_state
        progress = self.backend.config.progress
        if state is not None and progress is not None:
            requests = onboarding_local_body.Requests(progress)
            try:
                request = requests.read(plan['name'], owner=plan['owner'])
            except FileNotFoundError:
                request = None
            if request is not None:
                local = onboarding_local_body.worker_identity(state, request,
                    intake_uid=self.backend.config.consent_uid)
                if local is not None and local['document']['authority']['manifest']['being_ref'] != authority.state.being_ref:
                    raise OnboardingError('existing_identity_conflict')
        if not path.exists():
            being_seed._write(path, identity)
        return identity

    def application(self, plan: dict) -> tuple[str, str] | None:
        observed = self.backend._matrix_command(plan, 'observe')
        group = observed.get('group')
        if group is not None:
            root = '/home/agent/.local/state/daimon-onboarding/' + plan['name'] + '/matrix/tribe'
            if (observed['phase'] != 'v8' or set(group) != {
                    'tribe_ref', 'application', 'visibility', 'socket', 'channel_id'}
                    or group['application'] != root + '/application'
                    or group['visibility'] != root + '/visibility/installation.json'
                    or group['socket'] != root.removesuffix('/tribe') + '/package/runtime/tribe.sock'
                    or group['channel_id'] != 'tribe'):
                raise OnboardingError('approved_onboarding_group_required')
            return group['application'], group['visibility']
        return None

    def directed_application(self, plan: dict) -> tuple[str, str] | None:
        """Inspect explicitly requested historical directed repair only.

        Worker group selection never calls this route or interprets its retained
        pair receipt as shared Tribe admission.
        """
        self._identity(plan)
        path = self.state / digest(plan) / 'complete.json'
        if not path.exists() or not self._proxies(plan):
            return None
        complete = being_seed._read(path)
        if complete != dict(schema='cluster-onboarding-peer-complete/v1', plan_digest=digest(plan),
                source_being_ref=self.settings['source_being_ref']):
            raise OnboardingError('approved_onboarding_peer_required')
        try:
            status = self._source('observe', {})
        except OnboardingError as error:
            if str(error) != 'native_onboarding_source_unavailable':
                raise
            return None
        if status.get('running') is not True or digest(plan) not in status.get('applications', []):
            return None
        observed = self.backend._matrix_command(plan, 'observe')
        if (observed['phase'] != 'v8' or observed['receipt'].get('peer_being_ref') != self.settings['source_being_ref']):
            raise OnboardingError('native_onboarding_peer_incomplete')
        root = '/home/agent/.local/state/daimon-onboarding/' + plan['name'] + '/matrix/peer'
        return root + '/application', root + '/visibility/installation.json'

    def execute(self, plan: dict) -> None:
        lifecycle = private_directory(self.state / 'source-lifecycle', create=True)
        # Different approved jobs share one Source writer/service. Serialize
        # that finite ceremony, without serializing independent guest stages.
        with being_seed._locked(lifecycle):
            self._execute(plan)

    def _execute(self, plan: dict) -> None:
        selected = self.application(plan)
        group_root = '/home/agent/.local/state/daimon-onboarding/' + plan['name'] + '/matrix/tribe'
        if selected == (group_root + '/application', group_root + '/visibility/installation.json'):
            return
        # Automated onboarding never declares a founder/member Tribe or builds
        # pair proxies. A missing signed group is an explicit deployment gap.
        raise OnboardingError('onboarding_group_enrollment_required')

    def repair_directed(self, plan: dict) -> None:
        """Legacy explicit directed repair; never called by the worker.

        This preserves retained recovery journals for an operator requesting
        that exact repair. It does not implement same-Tribe enrollment.
        """
        lifecycle = private_directory(self.state / 'source-lifecycle', create=True)
        with being_seed._locked(lifecycle):
            self._repair_directed(plan)

    def _repair_directed(self, plan: dict) -> None:
        self._approved(plan)
        peer = self._identity(plan)
        directory = private_directory(self.state / digest(plan), create=True)
        self._proxies(plan, install=True)
        source, target = self._ports(plan)
        # Cache every public boundary before advancing. The native owner tool
        # preserves encrypted proposals, local custody and signed drafts itself.
        response_path = directory / 'response.json'
        self._approved(plan)
        self._service('stop')
        try:
            if response_path.exists():
                response = being_seed._read(response_path)
            else:
                self._approved(plan)
                packet = self._source('offer', dict(plan_digest=digest(plan), peer=peer,
                    endpoints=[f'http://127.0.0.1:{source}', f'http://127.0.0.1:{target}']))
                signer = onboarding_peer.native(Path(__file__).resolve().parents[1]).verify_identity(packet['sender_identity'])
                if signer.state.being_ref != self.settings['source_being_ref']:
                    raise OnboardingError('approved_onboarding_peer_required')
                response = self.backend._target_call(plan, 'peer-accept', peer_packet=packet,
                    peer_being_ref=self.settings['source_being_ref'])
                being_seed._write(response_path, response)
            self._approved(plan)
            self._source('finish', dict(plan_digest=digest(plan), response=response))
            self._approved(plan)
            self._source('register', dict(plan_digest=digest(plan), unit=self.settings['source_unit'],
                unit_sha256=self.settings['source_unit_sha256'], python=self.settings['source_python']))
            self._service('daemon-reload')
        finally:
            self._service('start')
        being_seed._write(directory / 'complete.json', dict(schema='cluster-onboarding-peer-complete/v1',
            plan_digest=digest(plan), source_being_ref=self.settings['source_being_ref']))

    def _approved(self, plan: dict) -> None:
        if not self.backend.authorize(plan, digest(plan)):
            raise OnboardingError('host_authorization_required')

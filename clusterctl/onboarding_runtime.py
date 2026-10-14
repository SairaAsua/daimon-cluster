"""Native receiving daemon under shared admission and kernel process observation.

The parent retains the physical holder/session. Its private inherited socket
supplies read-only body snapshots to the child; no holder or authority custody
crosses that socket. Neither side reads Matrix inboxes or starts model turns.
"""
from __future__ import annotations

import json
import os
import selectors
import select
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from .onboarding import OnboardingError
from .onboarding_admission import ReceivingHolder
from .owner_process import ProcessPresence

MAX_FRAME = 4096
# Real receiving histories can take longer than five seconds to authenticate.
# Readiness still requires the actual native READY pipe under current admission.
READY_TIMEOUT_S = 60


def serve(target, profile: dict, *, receive_only=False, visibility_installation=None, messaging_application=None, ready_descriptor=None):
    """Run the admitted parent as a service, retaining its ephemeral session."""
    holder = ReceivingHolder(target)
    client = holder.configured_client(profile)
    # Persisted authority enrollment survives service/profile expiry. Probe its
    # binding first instead of trying an expired enrollment on every restart.
    holder.ensure_enrolled(profile, enroll=True)
    owned = AdmittedDaemon(target,client)
    stopping = threading.Event()
    def request_stop(_number,_frame):
        stopping.set()
    signal.signal(signal.SIGTERM,request_stop)
    signal.signal(signal.SIGINT,request_stop)
    try:
        owned.start(receive_only=receive_only,visibility_installation=visibility_installation,
                    messaging_application=messaging_application)
        if ready_descriptor is not None:
            os.write(ready_descriptor,b'READY\n')
            os.close(ready_descriptor)
        while not stopping.wait(0.25) and owned.process.poll() is None:
            pass
        return 0 if stopping.is_set() else 1
    finally:
        owned.close()


def receive(connection: socket.socket) -> dict:
    header = bytearray()
    while len(header) < 4:
        chunk = connection.recv(4 - len(header))
        if not chunk:
            raise OnboardingError("onboarding_runtime_channel_closed")
        header.extend(chunk)
    size = int.from_bytes(header, "big")
    if not 1 <= size <= MAX_FRAME:
        raise OnboardingError("onboarding_runtime_frame_rejected")
    raw = bytearray()
    while len(raw) < size:
        chunk = connection.recv(size - len(raw))
        if not chunk:
            raise OnboardingError("onboarding_runtime_channel_closed")
        raw.extend(chunk)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise OnboardingError("onboarding_runtime_frame_rejected")
    return value


def send(connection: socket.socket, value: dict) -> None:
    raw = json.dumps(value, separators=(",", ":")).encode()
    if not 1 <= len(raw) <= MAX_FRAME:
        raise OnboardingError("onboarding_runtime_frame_rejected")
    connection.sendall(len(raw).to_bytes(4, "big") + raw)


class AdmittedDaemon:
    def __init__(self, target, client):
        self.target, self.client = target, client
        self.supervisor = None
        self.presence = None
        self.process = None
        self.connection = None
        self.thread = None
        self.stop = threading.Event()
        self.origin = target.observe()["receipt"]["origin"]

    def snapshot(self, request: dict) -> dict:
        from daimon_matrix.cluster import validate_body_snapshot
        fields = {"body_ref", "embodiment_id", "incarnation_id", "evaluated_at_ms"}
        if set(request) != fields or any(request[key] != self.origin[key] for key in fields - {"evaluated_at_ms"}):
            raise OnboardingError("onboarding_runtime_origin_rejected")
        at_ms = request["evaluated_at_ms"]
        now = time.time_ns() // 1_000_000
        if type(at_ms) is not int or not 0 <= at_ms <= now or now - at_ms > 5000:
            raise OnboardingError("onboarding_runtime_time_rejected")
        if self.presence is None or self.supervisor is None:
            raise OnboardingError("onboarding_runtime_not_ready")
        self.presence.verify()
        current = self.supervisor.verify_current(minimum_remaining_s=1)
        if current is None:
            raise OnboardingError("onboarding_admission_not_current")
        self.presence.verify()
        # Admission controls execution. No writable resource has been adopted
        # through this adapter; curator mutations remain unavailable.
        value = dict(schema="dm.cluster-body-snapshot/v1", body_ref=request["body_ref"],
            embodiment_id=request["embodiment_id"], incarnation_id=request["incarnation_id"],
            observed_at_ms=at_ms, state="running", resource_fences=[])
        return validate_body_snapshot(value, **request)

    def _serve(self):
        while not self.stop.is_set():
            try:
                readable, _, _ = select.select([self.connection], [], [], 0.25)
                if not readable:
                    continue
                request = receive(self.connection)
                try:
                    result = self.snapshot(request)
                    response = dict(ok=True, result=result)
                except Exception:
                    response = dict(ok=False)
                send(self.connection, response)
            except (OSError, ValueError):
                if (not self.stop.is_set() and self.supervisor is not None
                        and not self.supervisor.shutdown_requested and self.process.poll() is None):
                    self.supervisor.force_stop("body-observer-unavailable")
                return

    def start(self, *, receive_only=False, visibility_installation=None, messaging_application=None):
        if receive_only == (visibility_installation is not None):
            raise OnboardingError("onboarding_visibility_selection_required")
        if messaging_application is not None and receive_only:
            raise OnboardingError("onboarding_visibility_selection_required")
        parent, child = socket.socketpair()
        parent.settimeout(5)
        ready_read, ready_write = os.pipe()
        self.connection = parent
        launcher = ("import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
                    "from clusterctl.onboarding_runtime import child_main;"
                    "raise SystemExit(child_main(Path(sys.argv[2]),json.loads(sys.argv[3]),"
                    "json.loads(sys.argv[4]),int(sys.argv[5]),int(sys.argv[6]),int(sys.argv[7]),"
                    "sys.argv[8]=='true',Path(sys.argv[9]) if sys.argv[9] else None,"
                    "Path(sys.argv[10]) if sys.argv[10] else None,int(sys.argv[11]),sys.argv[12]))")
        def spawn():
            environment = {'PATH':os.defpath, 'LANG':'C.UTF-8', 'HOME':str(self.target.home),
                'LD_LIBRARY_PATH':str(Path(sys.base_prefix)/'lib')}
            if 'DM_TRIBU_REFERENCE_DIRECTORY' in os.environ:
                environment['DM_TRIBU_REFERENCE_DIRECTORY'] = os.environ['DM_TRIBU_REFERENCE_DIRECTORY']
            arguments = [str(self.target.home), json.dumps(self.target.plan),
                json.dumps(self.target.genesis), str(child.fileno()), str(ready_write), str(os.getpid()),
                'true' if receive_only else 'false', str(visibility_installation) if visibility_installation else '',
                str(messaging_application) if messaging_application else '', str(self.target.code_uid),
                self.target.code_digest]
            from . import onboarding_code_successor, onboarding_sdk
            parameters = onboarding_code_successor.sdk_parameters(self.target.code, uid=self.target.code_uid)
            if parameters:
                # This parent already runs the selected SDK. Derive/check the
                # same closed paths before a fresh child can execute site hooks.
                venv = Path(sys.prefix)
                imports = onboarding_sdk.runtime_imports(venv, self.target.code,
                    code_uid=self.target.code_uid, **parameters)
                child_launcher = '''import sys
from pathlib import Path
sys.prefix = sys.exec_prefix = sys.argv.pop(1)
imports = sys.argv.pop(1)
code = sys.argv.pop(1)
sys.path[:0] = [code, imports]
sys.dont_write_bytecode = True
sys.pycache_prefix = imports + '/.disabled-bytecode'
from clusterctl.onboarding_runtime import child_main
import json
raise SystemExit(child_main(Path(sys.argv[1]), json.loads(sys.argv[2]), json.loads(sys.argv[3]),
    int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]), sys.argv[7]=='true',
    Path(sys.argv[8]) if sys.argv[8] else None, Path(sys.argv[9]) if sys.argv[9] else None,
    int(sys.argv[10]), sys.argv[11]))
'''
                command = [str(venv / 'bin/python'), '-B', '-I', '-S', '-c', child_launcher,
                           str(venv), str(imports), str(self.target.code), *arguments]
            else:
                command = [sys.executable, '-B', '-I', '-c', launcher,
                           str(Path(__file__).resolve().parents[1]), *arguments]
            self.process = subprocess.Popen(command,
                pass_fds=(child.fileno(), ready_write), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=environment)
            pid = self.process.pid
            try:
                self.presence = ProcessPresence(dict(uid=os.geteuid(), pid=pid,
                    start_ticks=int((Path('/proc')/str(pid)/'stat').read_text().rpartition(')')[2].split()[19]),
                    boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()))
                return self.process
            except BaseException:
                # A callback failure must stop its child before launch releases
                # admission; no unobserved process may outlive that lease.
                if self.process.poll() is None:
                    self.process.kill()
                self.process.wait(timeout=5)
                raise
        try:
            self.supervisor = ReceivingHolder(self.target).launch(self.client, spawn)
            child.close()
            os.close(ready_write)
            ready_write = -1
            self.thread = threading.Thread(target=self._serve, name='onboarding-body-observer', daemon=True)
            self.thread.start()
            with selectors.DefaultSelector() as selector:
                selector.register(ready_read, selectors.EVENT_READ)
                if not selector.select(READY_TIMEOUT_S) or os.read(ready_read, 16) != b'READY\n':
                    raise OnboardingError('onboarding_runtime_not_ready')
            if self.supervisor.verify_current(minimum_remaining_s=1) is None:
                raise OnboardingError('onboarding_admission_not_current')
            return self.target.running()
        except BaseException:
            self.close()
            raise
        finally:
            child.close()
            os.close(ready_read)
            if ready_write >= 0:
                os.close(ready_write)

    def close(self):
        if self.supervisor is not None:
            self.supervisor.request_shutdown()
        if self.process is not None:
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.supervisor is not None:
            self.supervisor.thread.join(timeout=10)
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=6)
        if self.connection is not None:
            self.connection.close()
        if self.presence is not None:
            self.presence.close()


def child_main(home, plan, genesis, descriptor, ready_descriptor, guardian_pid,
               receive_only, visibility_installation, messaging_application=None, code_uid=0,
               code_digest=None):
    # The parent checks its own tree, but only this child can attest its boot.
    # Do this before importing Matrix or opening Body custody.
    from . import onboarding_sdk, onboarding_code_successor
    code = Path(__file__).resolve().parents[1]
    parameters = onboarding_code_successor.sdk_parameters(code, uid=code_uid)
    startup = (onboarding_sdk.qualified_startup(Path(sys.prefix), code, code_uid=code_uid,
        code_digest=code_digest or plan['release_digest'], **parameters) if parameters else None)
    from daimon_matrix import daemon, runtime, native_egress
    from .onboarding_target import Target
    target = Target(home, plan, genesis, code_uid=code_uid, code_digest=code_digest,
                    qualified_startup=startup)
    if target.observe()['phase'] != 'v8' or os.getppid() != guardian_pid:
        raise OnboardingError('onboarding_runtime_parent_rejected')
    stopping = threading.Event()
    connection = socket.socket(fileno=descriptor)
    connection.settimeout(5)
    rpc_lock = threading.Lock()
    def body_reader(body_ref, embodiment_id, incarnation_id, evaluated_at_ms):
        with rpc_lock:
            send(connection, dict(body_ref=body_ref, embodiment_id=embodiment_id,
                incarnation_id=incarnation_id, evaluated_at_ms=evaluated_at_ms))
            response = receive(connection)
        if set(response) != {'ok','result'} or response['ok'] is not True:
            raise OnboardingError('onboarding_runtime_observation_unavailable')
        return response['result']
    def guardian():
        while not stopping.wait(0.25):
            if os.getppid() != guardian_pid:
                os._exit(1)
    monitor = threading.Thread(target=guardian, name='onboarding-runtime-guardian', daemon=True)
    monitor.start()
    lock = daemon.acquire_lock(target.package/'runtime')
    try:
        if receive_only == (visibility_installation is not None):
            raise OnboardingError('onboarding_visibility_selection_required')
        def clock():
            return time.time_ns() // 1_000_000
        if messaging_application is not None and receive_only:
            raise OnboardingError('onboarding_visibility_selection_required')
        if messaging_application is not None:
            # The receiving native catalogs were initialized before enrollment.
            # The peer app owns a separate signed controller, not their key.
            options = dict(egress=native_egress.closed_visibility(clock=clock))
        else:
            options = (dict(egress=native_egress.closed_visibility(clock=clock)) if receive_only else
                   dict(egress_factory=daemon._visibility_factory(visibility_installation, clock=clock)))
        hosted = runtime.load_runtime(target.package/'runtime', 'runtime.json', target._reader,
            clock=clock, body_reader=body_reader,
            **({} if startup is None else {'qualified_startup': startup}), **options)
        from .onboarding_peer import group_application
        group = group_application(target, hosted)
        if group is not None:
            # Reuse the same admitted daemon, native lock and visibility adapter.
            # A group selection replaces bootstrap/default pair apps, not history.
            messaging_application = Path(group['directory'])
            visibility_installation = Path(group['visibility'])
        if messaging_application is not None:
            from dataclasses import replace
            from daimon_matrix.chat_host import application_view
            peer = application_view(hosted, messaging_application, visibility_installation)
            peer = replace(peer, socket_path=hosted.state_root /
                ('peer.sock' if group is None else group['socket']))
        def request_stop(_number, _frame):
            stopping.set()
        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        if messaging_application is not None:
            from .onboarding_views import serve_views
            from .onboarding_peer import additional_applications
            extras = [] if group is not None else [replace(
                application_view(hosted, Path(row['directory']), Path(row['visibility'])),
                socket_path=hosted.state_root / row['socket'])
                for row in additional_applications(target)]
            serve_views([hosted, peer, *extras], stopping, ready_descriptor=ready_descriptor)
        else:
            daemon.serve_forever(hosted, stop=stopping, ready_descriptor=ready_descriptor)
        return 0
    finally:
        stopping.set()
        connection.close()
        os.close(lock)

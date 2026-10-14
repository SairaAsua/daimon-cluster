"""Real native receiving daemon under actual signed TCP admission supervision."""
import tempfile
import subprocess
import sys
import os
import select
import json
import uuid
import time
from pathlib import Path

import pytest
from daimon_matrix.client import ClientConfig, LocalClient

from clusterctl.admission import AdmissionAuthority, AdmissionEndpoint, AdmissionTCPServer, serve_in_thread
from clusterctl.production_fences import create_holder_enrollment
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_admission import ReceivingHolder, enrollment, profile
from clusterctl.onboarding_custody import document
from clusterctl.onboarding_runtime import AdmittedDaemon
from clusterctl.onboarding_target import Target
from tests.test_admission import _key
from tests.test_onboarding_target import receiving


def test_actual_receiving_scope_reports_running_only_under_current_shared_lease(tmp_path):
    ceremony, plan, blank = receiving(tmp_path)
    ceremony.prepare(plan, identity_mode='first')
    with tempfile.TemporaryDirectory(prefix='dm-') as short:
        target = Target(Path(short), plan, blank.genesis)
        target.activate(ceremony.authorize_target(plan, target.prepare()))
        target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
        holder = ReceivingHolder(target)
        registrar = _key(tmp_path/'host/registrar.pem','registrar')
        signer = _key(tmp_path/'host/authority.pem','authority')
        authority = AdmissionAuthority(tmp_path/'authority', signer=signer,
            holder_registrars={registrar.key_id:registrar.public_key})
        server = AdmissionTCPServer(('127.0.0.1',0),authority)
        thread = serve_in_thread(server)
        endpoint = AdmissionEndpoint.network('127.0.0.1',server.server_address[1])
        def client():
            return holder.client(endpoint, authority_key_id=signer.key_id, authority_public_key=signer.public_key)
        first = client()
        first.enroll(enrollment(plan,holder.request(),ceremony.admission_coordinates(plan),registrar))
        root = target.package/'runtime'
        observer = LocalClient(root/'matrix.sock',ClientConfig.load(root/'client.json',bytearray((root/'client.key').read_bytes())))
        origin = target.observe()['receipt']['origin']
        custody = (root/'custody.json').read_bytes()
        runtime = (root/'runtime.json').read_bytes()
        pids = []
        try:
            for _ in range(2):
                owned = client()
                admitted = AdmittedDaemon(target,owned)
                try:
                    presence = admitted.start(receive_only=True)
                    pids.append(presence['process']['pid'])
                    assert presence['origin'] == origin
                    me = observer.scope_me()[1]
                    assert me['ok'] is True and me['result']['body']['state'] == 'running'
                    assert me['result']['origin'] == origin
                    assert target.running(admitted=True)['process']['pid'] == presence['process']['pid']
                    assert admitted.supervisor.verify_current(minimum_remaining_s=1) is not None
                    request = {key:origin[key] for key in ('body_ref','embodiment_id','incarnation_id')}
                    request['evaluated_at_ms'] = time.time_ns()//1_000_000
                    with pytest.raises(OnboardingError,match='origin_rejected'):
                        admitted.snapshot({**request,'body_ref':'foreign'})
                    assert admitted.snapshot(request)['state'] == 'running'
                finally:
                    admitted.close()
                assert owned.current() is None
                assert admitted.presence.descriptor == -1
                with pytest.raises(OSError):
                    target.running()
                assert (root/'custody.json').read_bytes() == custody
                assert (root/'runtime.json').read_bytes() == runtime
            revoked = client()
            admitted = AdmittedDaemon(target,revoked)
            try:
                admitted.start(receive_only=True)
                with admitted.supervisor._client_lock:
                    revoked.release()
                unavailable = observer.scope_me()[1]
                assert unavailable['ok'] is False
                admitted.process.wait(timeout=8)
                assert admitted.process.returncode != 0
            finally:
                admitted.close()
            assert revoked.current() is None
            configuration = profile(plan,holder.request(),ceremony.admission_coordinates(plan),registrar,
                endpoint=endpoint,authority_key_id=signer.key_id,authority_public_key=signer.public_key)
            # The authority already remembers the exact holder binding. An old
            # enrollment document must not prevent a legitimate service restart.
            public = holder.prepare()
            configuration['enrollment'] = create_holder_enrollment(registrar,
                holder_key_id=public['holder_key_id'],holder_pubkey=public['holder_pubkey'],
                issued_ms=time.time_ns()//1_000_000-10_000,ttl_s=1,nonce=str(uuid.uuid4()),
                **public['coordinates'])
            reader,writer = os.pipe()
            launch = ("import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
                      "from clusterctl.onboarding_target import Target;"
                      "from clusterctl.onboarding_runtime import serve;"
                      "raise SystemExit(serve(Target(Path(sys.argv[2]),json.loads(sys.argv[3]),"
                      "json.loads(sys.argv[4])),json.loads(sys.argv[5]),receive_only=True,"
                      "ready_descriptor=int(sys.argv[6])))")
            parent = subprocess.Popen([sys.executable,'-B','-I','-c',launch,str(Path(__file__).resolve().parents[1]),
                str(target.home),json.dumps(plan),json.dumps(target.genesis),json.dumps(configuration),str(writer)],
                pass_fds=(writer,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            os.close(writer)
            try:
                assert select.select([reader],[],[],10)[0]
                assert os.read(reader,16) == b'READY\n'
                assert observer.scope_me()[1]['result']['body']['state'] == 'running'
                child_pid = target.running()['process']['pid']
                parent.kill()
                parent.wait(timeout=5)
                deadline = time.monotonic()+3
                while time.monotonic()<deadline:
                    try:
                        with open('/proc/'+str(child_pid)+'/stat') as state:
                            exited = state.read().rpartition(')')[2].split()[0] in {'Z','X','x'}
                        if exited:
                            break
                    except FileNotFoundError:
                        break
                    time.sleep(0.05)
                else:
                    pytest.fail('native daemon outlived its admission parent')
                assert parent.returncode != 0
            finally:
                os.close(reader)
                if parent.poll() is None:
                    parent.kill()
                parent.wait(timeout=5)
            assert pids[0] != pids[1]
            assert document(target.root/'admission/holder.json')['coordinates'] == ceremony.admission_coordinates(plan)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

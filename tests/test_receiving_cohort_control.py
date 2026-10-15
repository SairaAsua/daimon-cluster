"""Cohort state-machine faults with fake senders and real selector/journal.

These cases prove durable orchestration, not native RPC or receiving readiness.
Native owner RPC/fence qualification is a separate actual integration boundary.
"""
import copy
import hashlib
import os
import time
import uuid
from pathlib import Path

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.onboarding_receiving_update import CohortController, GuestGroupClient, OwnerGroupClient, apply_host_selection, freeze_senders, preflight, receiving_identity, verify_receiving_identity
from clusterctl.operation_journal import OperationJournal
from tests.test_receiving_host_selection import fixture as host_fixture


def identity_fixture():
    origin = dict(body_ref='codex:fixture:eko', embodiment_id='body:eko', incarnation_id='incarnation:eko')
    status = dict(being_ref='being:eko', manifest_hash='a'*64, local_origin=origin)
    scope = dict(schema='dm.scope.me/v1', being_ref=status['being_ref'], manifest_hash=status['manifest_hash'],
        origin=origin, evaluated_at_ms=100, credential_ref='credential:eko',
        incarnation_authorization_ref='authorization:eko', body={**origin, 'state': 'running'},
        heads={'private': 'excluded'}, effective={'private': 'excluded'}, body_capabilities=['excluded'])
    return dict(ok=True, server=origin, result=scope), status, origin


def test_current_identity_projection_excludes_ledger_and_capability_data():
    response, status, origin = identity_fixture()
    result = receiving_identity(response, status, origin)
    assert result['credential_ref'] == 'credential:eko'
    assert result['incarnation_authorization_ref'] == 'authorization:eko'
    assert not {'body', 'heads', 'effective', 'body_capabilities'} & set(result)
    result['origin']['embodiment_id'] = 'changed'
    assert origin['embodiment_id'] == 'body:eko'


def test_source_identity_does_not_invent_a_cluster_admission_requirement():
    response, status, origin = identity_fixture()
    response['result']['body'] = None
    assert receiving_identity(response, status, origin, require_admitted=False)['origin'] == origin
    with pytest.raises(OnboardingError, match='receiving_identity_admission_conflict'):
        receiving_identity(response, status, origin)


@pytest.fixture(params=[False, True], ids=['v1', 'v2-until-revoked'])
def signed_receiving_identity(tmp_path, request):
    from daimon_matrix.canonical import canonical_bytes
    from daimon_matrix.weave import BeingManifest
    from tests.test_onboarding_target import receiving
    ceremony, plan, target = receiving(tmp_path)
    target.activate(ceremony.authorize_target(plan, target.prepare()))
    if request.param:
        target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
    bundle = target.document_bundle()
    # Receiving runtime bundle hashing uses Matrix's Unicode canonical codec,
    # not the separate Cluster operation digest codec.
    bundle['ledger'] = 'mémoire-synthétique.sqlite3'
    origin = bundle['local_origin']
    manifest = bundle['manifest']
    member = next(row for row in manifest['embodiments'] if
                  (row['embodiment_id'], row['incarnation_id']) ==
                  (origin['embodiment_id'], origin['incarnation_id']))
    identity = dict(being_ref=manifest['being_ref'], manifest_hash=BeingManifest.from_value(manifest).digest,
        origin=origin, credential_ref=member['embodiment_credential_id'],
        incarnation_authorization_ref=member['incarnation_authorization_id'])
    observed = dict(server=origin, process={'pid': os.getpid()}, identity=identity,
        runtime_status=dict(being_ref=identity['being_ref'], manifest_hash=identity['manifest_hash'],
            local_origin=origin, loaded_runtime=dict(runtime_bundle_sha256=hashlib.sha256(canonical_bytes(bundle)).hexdigest(),
                process_id=os.getpid(), runtime_id=bundle['runtime_id'], local_origin=origin)))
    return bundle, observed


def test_signed_public_bundle_current_validity_without_loading_custody(signed_receiving_identity, monkeypatch):
    from daimon_matrix.canonical import canonical_bytes
    bundle, observed = signed_receiving_identity
    horizon = time.time_ns() // 1_000_000 + 300000
    result = verify_receiving_identity(bundle, observed, expires_at_ms=horizon)
    assert result['identity'] == observed['identity']
    assert result['runtime_bundle_sha256'] == hashlib.sha256(canonical_bytes(bundle)).hexdigest()
    assert 0 < result['expires_at_ms'] <= horizon
    assert not {'signing_key', 'credentials', 'capabilities', 'keystore'} & set(result)
    for fields in (('identity', 'origin'), ('runtime_status', 'local_origin'),
                   ('runtime_status', 'loaded_runtime', 'local_origin')):
        changed = copy.deepcopy(observed)
        row = changed
        for key in fields[:-1]:
            row = row[key]
        row[fields[-1]] = None
        with pytest.raises(OnboardingError, match='loaded_bundle_conflict'):
            verify_receiving_identity(bundle, changed, expires_at_ms=horizon)
    # Verification can consume a short horizon. It must not return expired
    # evidence merely because the initial clock sample was still valid.
    from clusterctl import onboarding_receiving_update as updates
    from types import SimpleNamespace
    instants = iter((result['verified_at_ms'], horizon + 1))
    monkeypatch.setattr(updates, 'time', SimpleNamespace(time_ns=lambda: next(instants) * 1_000_000))
    with pytest.raises(OnboardingError, match='horizon_expired'):
        verify_receiving_identity(bundle, observed, expires_at_ms=horizon)


def test_reselected_public_bundle_is_not_the_loaded_identity(signed_receiving_identity):
    bundle, observed = signed_receiving_identity
    bundle['runtime_label'] = 'another-selected-label'
    with pytest.raises(OnboardingError, match='loaded_bundle_conflict'):
        verify_receiving_identity(bundle, observed, expires_at_ms=time.time_ns() // 1_000_000 + 300000)


def test_current_validity_uses_the_actual_signed_lifetime(signed_receiving_identity, monkeypatch):
    from clusterctl import onboarding_receiving_update as updates
    from types import SimpleNamespace
    bundle, observed = signed_receiving_identity
    credential = next(row for row in bundle['credentials']
                      if row['artifact_id'] == observed['identity']['credential_ref'])
    if 'validity' in credential['body']:
        assert credential['body']['validity']['mode'] == 'until-revoked'
        later = time.time_ns() // 1_000_000 + 3600000
        monkeypatch.setattr(updates, 'time', SimpleNamespace(time_ns=lambda: later * 1_000_000))
        verified = verify_receiving_identity(bundle, observed, expires_at_ms=later + 1000)
        assert verified['credential_validity']['mode'] == 'until-revoked'
        assert verified['expires_at_ms'] == later + 1000
    else:
        expired = credential['body']['valid_until_ms'] + 1
        monkeypatch.setattr(updates, 'time', SimpleNamespace(time_ns=lambda: expired * 1_000_000))
        # The original first-body credential ends at the protocol's maximum
        # instant; its successor request is then outside the finite time domain.
        error = 'horizon_expired' if expired + 1000 >= 2**53 else 'public_verification_failed'
        with pytest.raises(OnboardingError, match=error):
            verify_receiving_identity(bundle, observed, expires_at_ms=expired + 1000)


@pytest.mark.parametrize('part', ['server', 'origin', 'being_ref', 'manifest_hash', 'body',
                                  'credential_ref', 'incarnation_authorization_ref', 'evaluated_at_ms'])
def test_identity_projection_refuses_unbound_or_missing_current_admission(part):
    response, status, origin = identity_fixture()
    response = copy.deepcopy(response)
    if part == 'server':
        response['server']['embodiment_id'] = 'another-body'
    elif part == 'body':
        response['result']['body']['state'] = 'stopped'
    elif part == 'evaluated_at_ms':
        response['result'][part] = True
    else:
        response['result'][part] = None
    with pytest.raises(OnboardingError, match='receiving_identity_admission_conflict'):
        receiving_identity(response, status, origin)


class FakeOwner:
    def __init__(self, root, name):
        self.root = root
        self.socket = root / 'tribe.sock'
        self.requests = {}
        self.effects = 0
        self.process = dict(uid=1, pid=2, start_ticks=3, boot_id='fixture')
        self.being = 'being:' + name
        self.server = dict(embodiment_id='body:' + name)
        self.gate = dict(process_instance_id=name, process_id=2, channel_id='tribe',
            controlled=True, context_sha256='a'*64, head='b'*64, phase='unselected',
            operation_id=None, release_digest=None, request_sha256=None, readers=[])

    def status(self):
        return copy.deepcopy(dict(process=self.process, server=self.server, gate=self.gate,
            runtime_status={'being_ref': self.being, 'local_origin': self.server,
                'loaded_application': {'tribe': {'policy': {'tribe_ref': 'tribe:fixture'}}}}))

    def prepare_control(self, command, path):
        if path in self.requests:
            assert self.requests[path] == command
        else:
            self.requests[path] = copy.deepcopy(command)
            path.parent.mkdir(mode=0o700, exist_ok=True)
            being_seed._write(path, {'command': command})

    def apply_control(self, path):
        command = self.requests[path]
        request = digest(command)
        if self.gate['request_sha256'] != request:
            if self.gate['phase'] == 'revoke' and self.gate['operation_id'] != command['operation_id']:
                raise OnboardingError('receiving_control_operation_reserved')
            assert self.gate['head'] == command['expected_head']
            self.effects += 1
            self.gate = {**self.gate, **{k: v for k, v in command.items() if k != 'expected_head'},
                'head': digest([self.gate['head'], request]), 'request_sha256': request}
        return {**self.status(), 'request_sha256': request, 'request_id': request,
                'command_sha256': digest(command)}


def test_guest_owner_adapter_keeps_private_request_paths_receiving_local(monkeypatch):
    from types import SimpleNamespace
    from tests.test_onboarding import plan
    calls = []
    root = Path('/not-mounted-on-host/receiving/runtime')
    origin = dict(body_ref='body:eko', embodiment_id='embodiment:eko', incarnation_id='incarnation:eko')
    gate = dict(controlled=True, process_id=123, phase='revoke', head='a'*64)
    loaded = dict(process_id=123, local_origin=origin)
    status = dict(local_origin=origin, loaded_runtime=loaded, loaded_application={'view':'fixture'},
                  receiving={'channels':{'tribe':gate}})
    def call(_plan, action, **arguments):
        calls.append((action, arguments))
        if action == 'admitted-running':
            return dict(responder_association='same-connection', admission_parent={'pid':122},
                group={'socket':str(root/'tribe.sock')}, group_runtime_status=status,
                runtime_status={'loaded_runtime':loaded}, process={'pid':123}, origin=origin)
        return dict(request_sha256='b'*64)
    native_exists = Path.exists
    def no_host_private_access(path):
        if path == root or root in path.parents:
            pytest.fail('host inspected a guest-private path')
        return native_exists(path)
    monkeypatch.setattr(Path, 'exists', no_host_private_access)
    guest = GuestGroupClient(SimpleNamespace(_target_call=call), plan(), (Path('/candidate'),'c'*64), root=root)
    assert guest.status()['server'] == origin
    private = root/'receiving-control'/'request.json'
    assert guest.prepare_control({'phase':'revoke','readers':[]}, private)['request_sha256'] == 'b'*64
    assert guest.apply_control(private)['request_sha256'] == 'b'*64
    assert [action for action,_ in calls] == ['admitted-running','receiving-control-prepare','receiving-control-apply']
    assert calls[1][1]['control_value'] == {'phase':'revoke','readers':[]}
    assert all(options['observation_timeout_seconds'] == 30 for _,options in calls)


def test_late_durable_prepare_keeps_exact_request_without_reporting_success(tmp_path, monkeypatch):
    from clusterctl import onboarding_receiving_update as module
    root = tmp_path/'owner'
    root.mkdir(mode=0o700)
    clock = [10]
    monkeypatch.setattr(module.time,'monotonic_ns',lambda:clock[0])
    owner = OwnerGroupClient(root, root/'tribe.sock', deadline_ns=100)
    command = dict(channel_id='tribe',process_instance_id='fixture',expected_head='a'*64,phase='revoke')
    monkeypatch.setattr(owner,'status',lambda:dict(gate={'process_instance_id':'fixture','head':'a'*64},process={},server={}))
    authored = []
    class Client:
        def prepare(self, method, params):
            authored.append(True)
            return dict(method=method,params=params,request_id='one-retained-request')
    monkeypatch.setattr(owner,'_client',lambda _role:Client())
    durable = owner._durable_control
    def late(path):
        durable(path)
        clock[0]=101
    monkeypatch.setattr(owner,'_durable_control',late)
    private = root/'receiving-control'/'revoke.json'
    with pytest.raises(OnboardingError,match='deadline_expired'):
        owner.prepare_control(command,private)
    retained = private.read_bytes()
    owner.deadline_ns=200
    assert owner.prepare_control(command,private)['request_id'] == 'one-retained-request'
    assert private.read_bytes() == retained and authored == [True]


def fixture(tmp_path):
    path, original, runtime, _old_journal, _identifier = host_fixture(tmp_path)
    owners = {}
    for name in ('eko', 'oliva'):
        root = tmp_path / name
        root.mkdir(mode=0o700)
        owners[name] = FakeOwner(root, name)
    senders = freeze_senders(owners, tribe_ref='tribe:fixture')
    journal = OperationJournal(tmp_path / 'cohort-journal')
    row = plan_update(journal, manifest_digest='a'*64, target='receiving:tribe-fixture',
        expected_precondition=dict(host_config=str(path), host_configuration=original,
            host_config_sha256=digest(original), senders=senders),
        intended_transition={'host_runtime': runtime}, audit_identity={'actor': 'fixture'})
    return path, original, runtime, owners, journal, row['operation_id']


def activation_fixture(tmp_path, *, replacement=False, exit_observed=True, profile='source', assessment_fault=None):
    """Fake RPC/import/load seams; actual protected manifest and journal."""
    from types import MethodType
    from tests.test_receiving_update_preflight import fixture as reader_fixture, call as qualify_reader
    _, _, _, owners, _, _ = fixture(tmp_path)
    reader_root=tmp_path/'reader'
    reader_root.mkdir()
    code,code_digest,_,reader_path,reader_manifest,_=reader_fixture(reader_root)
    baseline=qualify_reader(code,code_digest,reader_path,reader_manifest)
    reader=baseline['reader']
    until = time.time_ns() // 1_000_000 + 300000
    epochs = ['1'*64,'2'*64,'3'*64]
    recipes, before, required = {}, {}, []
    for name, owner in owners.items():
        owner.server['incarnation_id'] = 'incarnation:'+name
        startup = dict(code_digest=code_digest,matrix_commit=baseline['matrix_revision'],
            matrix_wheel_sha256=baseline['matrix_wheel_sha256'],sdk_digest=baseline['sdk_digest'],
            reader=reader,process_id=owner.process['pid'],startup_instance_id=name)
        owner.loaded = dict(process_id=owner.process['pid'], qualified_startup=startup,
            runtime_bundle_sha256='f'*64,authority_epoch={'accepted_manifest_hashes':epochs})
        owner.application = dict(loaded_view_sha256='9'*64,application_sha256='a'*64,
            tribe={'policy':{'tribe_ref':'tribe:fixture'}},
            publication_sha256='b'*64,shared_relationships=True,communication_store_role='ledger',
            shared_stores={'ledger':{'schema_versions':{'communication':4}}},
            visibility=dict(catalog_mode='validate',catalog_validation='validated',release_enabled=True,
                installation_sha256='4'*64,catalog_schema_version=1),
            authorities={who.being:{'accepted_manifest_hashes':epochs,'active_manifest_hash':epochs[0],
                'active_control_head':'control:fixture'} for who in owners.values()})
        owner.roster = dict(schema='dm.runtime.tribe-roster/v1',roster_sha256='5'*64,
                            required_authority_epochs=epochs)
        owner.identity = dict(being_ref=owner.being,manifest_hash=epochs[0],credential_ref='credential:'+name)
        owner.parent = dict(uid=1,pid=1,start_ticks=2,boot_id='fixture')
        original_status = owner.status
        def status(self, original=original_status):
            result = original()
            result['runtime_status'].update(loaded_runtime=copy.deepcopy(self.loaded),
                loaded_application=copy.deepcopy(self.application),
                receiving={'features':['signed-roster-cas/v1'],'rosters':{'tribe':copy.deepcopy(self.roster)}})
            return result
        owner.status = MethodType(status,owner)
        def qualified(self, *, expires_at_ms, require_admitted):
            assert require_admitted == (profile == 'guest')
            return {**self.status(),'identity':copy.deepcopy(self.identity),
                **({'admission_parent':copy.deepcopy(self.parent)} if require_admitted else {}),
                'verified_identity':dict(identity=copy.deepcopy(self.identity),runtime_bundle_sha256='f'*64,
                                         authority_control_head='control:fixture',
                                         expires_at_ms=expires_at_ms)}
        owner.qualified_identity=MethodType(qualified,owner)
        selection=dict(receiving_code=code_digest,matrix_sdk=baseline['matrix_wheel_sha256'],runtime_bundle_sha256='f'*64,
            application_sha256='a'*64,publication_sha256='b'*64,visibility_installation_sha256='4'*64)
        before[name]={'old':name}
        required.append(dict(being_ref=owner.being,embodiment_id=owner.server['embodiment_id'],
                             expected_selection_sha256=digest(before[name])))
        recipes[name]=dict(profile=profile,selection=selection)
    authorities=[dict(being_ref=who.being,manifest_hash=epochs[0],control_head='control:fixture')
                 for who in owners.values()]
    manifest=dict(schema='dm.receiving-release/v1',
        artifacts={'receiving_code':code_digest,'matrix_sdk':baseline['matrix_wheel_sha256']},required_receivers=required,
        provenance={**reader_manifest['provenance']},contract=copy.deepcopy(reader['contract']),
        authorities={'current':authorities,'candidate':copy.deepcopy(authorities)})
    manifest_path=tmp_path/'activation-manifest.json'
    being_seed._write(manifest_path,manifest)
    journal=OperationJournal(tmp_path/'activation-journal')
    frozen_senders = freeze_senders(owners,tribe_ref='tribe:fixture')
    # Separate actual lifecycle observations are required for each receiver.
    for name, owner in owners.items():
        recipes[name]['prepared']=preflight(code,code_digest,manifest_path,digest(manifest),
            being_ref=owner.being,embodiment_id=owner.server['embodiment_id'],
            code_uid=os.geteuid(),manifest_uid=os.geteuid())
        previous = owner.status()
        if profile == 'guest':
            previous['admission_parent'] = copy.deepcopy(owner.parent)
        if replacement:
            owner.process = {**owner.process, 'start_ticks': owner.process['start_ticks'] + 1}
            owner.parent = {**owner.parent, 'start_ticks': owner.parent['start_ticks'] + 1}
            owner.gate = {**owner.gate, 'process_instance_id': name + ':replacement'}
        loaded = dict(process=owner.process,loaded_runtime=owner.loaded,loaded_application=owner.application)
        if profile == 'source':
            precondition={'source_bootstrap':{'predecessor':previous}}
            effects={'source_bootstrap':{'quiesced':dict(process=previous['process'],
                exit_observed=exit_observed,writer_available=True),'controlled_loaded':loaded}}
        else:
            precondition={'guest_bootstraps':{name:{'owner':{'origin':previous['server'],
                'predecessor':{'process':previous['process'],'admission_parent':previous['admission_parent']}}}}}
            loaded['admission_parent']=owner.parent
            effects={'guest_bootstraps':{name:{'quiesced':dict(schema='cluster-guest-service-quiescence/v1',
                process=previous['process'],admission_parent=previous['admission_parent'],
                exits={'process':exit_observed,'admission_parent':exit_observed}),'controlled_loaded':loaded}}}
        life=plan_update(journal,manifest_digest=digest(manifest),target='lifecycle:'+name,
            expected_precondition=precondition,
            intended_transition=({'source_bootstrap':{'qualification':{'code':str(code),'code_uid':os.geteuid()}}}
                if profile=='source' else {'guest_bootstraps':{name:{'runtime_code':str(code),'code_uid':os.geteuid()}}}),
            audit_identity={'actor':'fixture'})
        journal.advance(life['operation_id'],'runtime-dispatching',runtime_observation=effects)
        recipes[name]['lifecycle_operation_id']=life['operation_id']
        recipes[name]['prepared']['release_digest']=digest(manifest)
    if assessment_fault == 'unsupported':
        manifest['contract']['capabilities']=sorted([*manifest['contract']['capabilities'],'unsupported-fixture/v1'])
        being_seed._write(manifest_path,manifest)
        for recipe in recipes.values():
            recipe['prepared']['release_digest']=digest(manifest)
    elif assessment_fault is not None:
        recipes['eko']['prepared']['assessment'][assessment_fault]='0'*64
    row=plan_update(journal,manifest_digest=digest(manifest),target='receiving:activation-fixture',
        expected_precondition=dict(senders=frozen_senders,receiver_selections=before),
        intended_transition={'cohort_activation':dict(manifest_path=str(manifest_path),manifest_uid=os.geteuid(),
            roster_sha256='5'*64,expires_at_ms=until,observation_window_ms=60000,receivers=recipes)},
        audit_identity={'actor':'fixture'})
    controller=CohortController(journal,row['operation_id'],owners)
    if replacement:
        # Model the retained original revoke before the separately observed
        # bootstrap replacement. No ACK from the replacement substitutes it.
        observations = {}
        for sender in frozen_senders:
            owner = owners[sender['name']]
            process, gate = owner.process, owner.gate
            owner.process, owner.gate = sender['process'], sender['gate']
            owner.effects = 0
            # Revoke the frozen original while the other frozen sender is also
            # represented below through its actual journal ACK.
            control_id = str(uuid.uuid5(uuid.NAMESPACE_URL,'receiving-control:'+row['operation_id']))
            command=dict(process_instance_id=owner.gate['process_instance_id'],channel_id='tribe',
                expected_head=owner.gate['head'],operation_id=control_id,release_digest=digest(manifest),phase='revoke',readers=[])
            path=owner.root/'receiving-control'/(control_id+'-revoke.json')
            owner.prepare_control(command,path)
            observations[sender['name']]=owner.apply_control(path)
            owner.process, owner.gate = process, gate
        journal.advance(row['operation_id'],'runtime-dispatching',runtime_observation={'sender_revocations':observations})
    else:
        controller.revoke_senders()
    return controller,owners,journal,row['operation_id']


@pytest.mark.parametrize('profile',['source','guest'])
def test_observed_replacements_get_fresh_fences_without_replacing_old_acks(tmp_path,profile):
    controller,owners,journal,identifier=activation_fixture(tmp_path,replacement=True,profile=profile)
    before=copy.deepcopy(journal.get(identifier)['runtime_observation']['sender_revocations'])
    first=controller.activate()
    after=journal.get(identifier)['runtime_observation']
    assert after['sender_revocations']==before
    assert set(after['sender_replacements'])==set(owners)
    assert all(owner.effects==3 for owner in owners.values())
    assert controller.activate()==first
    assert all(owner.effects==3 for owner in owners.values())


@pytest.mark.parametrize('profile',['source','guest'])
def test_replacement_without_old_exit_evidence_cannot_enable_any_sender(tmp_path,profile):
    controller,owners,_,_=activation_fixture(tmp_path,replacement=True,exit_observed=False,profile=profile)
    with pytest.raises(OnboardingError,match='replacement_unobserved'):
        controller.activate()
    assert all(owner.effects==1 and owner.gate['phase']=='unselected' for owner in owners.values())



def test_guest_replacement_requires_frozen_authenticated_origin(tmp_path):
    controller, owners, journal, identifier = activation_fixture(tmp_path, replacement=True, profile='guest')
    row = journal.get(identifier)
    recipe = row['intended_transition']['cohort_activation']['receivers']['eko']
    lifecycle = journal.get(recipe['lifecycle_operation_id'])
    lifecycle['expected_precondition']['guest_bootstraps']['eko']['owner']['origin']['embodiment_id'] = 'different-body'
    original = journal.get
    def changed(operation_id):
        return lifecycle if operation_id == recipe['lifecycle_operation_id'] else original(operation_id)
    journal.get = changed
    with pytest.raises(OnboardingError, match='replacement_unobserved'):
        controller.activate()
    assert all(owner.effects == 1 and owner.gate['phase'] == 'unselected' for owner in owners.values())


def test_source_cohort_uses_owner_lifecycle_for_adoption_and_replacement(tmp_path, monkeypatch):
    controller, owners, journal, identifier = activation_fixture(tmp_path, replacement=True)
    recipes = journal.get(identifier)['intended_transition']['cohort_activation']['receivers']
    records = {name: journal.get(recipe['lifecycle_operation_id']) for name, recipe in recipes.items()}
    calls = []
    for name, owner in owners.items():
        def inspect(operation_id, selected=name):
            calls.append((selected, operation_id))
            assert operation_id == recipes[selected]['lifecycle_operation_id']
            return copy.deepcopy(records[selected])
        owner.lifecycle_operation = inspect
    local_get = journal.get
    foreign = {recipe['lifecycle_operation_id'] for recipe in recipes.values()}
    def root_get(operation_id):
        assert operation_id not in foreign, 'root coordinator attempted owner journal lookup'
        return local_get(operation_id)
    monkeypatch.setattr(journal, 'get', root_get)
    first = controller.activate()
    assert set(name for name, _ in calls) == set(owners)
    assert len(calls) == len(owners)
    assert all(owner.gate['phase'] == 'select' for owner in owners.values())
    assert controller.activate() == first
    assert len(calls) == 2 * len(owners), 'next invocation must reread owner proof'
    assert controller._lifecycle_projections is None
    def unavailable(operation_id):
        raise OnboardingError('receiving_source_owner_unavailable')
    owners['eko'].lifecycle_operation = unavailable
    with pytest.raises(OnboardingError, match='owner_unavailable'):
        controller.activate()
    assert controller._lifecycle_projections is None


def test_owner_lifecycle_failure_never_uses_a_stale_local_copy(tmp_path):
    controller, owners, _, _ = activation_fixture(tmp_path, replacement=True)
    def unavailable(operation_id):
        raise OnboardingError('receiving_source_owner_unavailable')
    owners['eko'].lifecycle_operation = unavailable
    with pytest.raises(OnboardingError, match='owner_unavailable'):
        controller.activate()
    assert all(owner.gate['phase'] == 'unselected' for owner in owners.values())


def test_competing_activation_cannot_leak_owner_projection_into_next_invocation(
    tmp_path, monkeypatch,
):
    import threading
    from clusterctl.operation_journal import JournalConflict
    controller, _, _, _ = activation_fixture(tmp_path)
    entered, release = threading.Event(), threading.Event()
    completed = []

    def action():
        retained = controller._lifecycle_projections
        assert retained == {}
        entered.set()
        assert release.wait(5)
        assert controller._lifecycle_projections is retained
        return {'completed': True}

    monkeypatch.setattr(controller, '_activate', action)
    worker = threading.Thread(target=lambda: completed.append(controller.activate()))
    worker.start()
    try:
        assert entered.wait(5)
        with pytest.raises(JournalConflict, match='mutation is in progress'):
            controller.activate()
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive() and completed == [{'completed': True}]
    assert controller._lifecycle_projections is None
    monkeypatch.setattr(controller, '_activate', lambda: controller._lifecycle_projections == {})
    assert controller.activate() is True
    assert controller._lifecycle_projections is None


def test_lost_replacement_revoke_reply_reconciles_exact_request(tmp_path,monkeypatch):
    controller,owners,journal,identifier=activation_fixture(tmp_path,replacement=True)
    apply=owners['oliva'].apply_control
    lost=[True]
    def lose(path):
        result=apply(path)
        if lost[0]:
            lost[0]=False
            raise OSError('synthetic replacement revoke reply loss')
        return result
    monkeypatch.setattr(owners['oliva'],'apply_control',lose)
    with pytest.raises(OSError):
        controller.activate()
    retained=copy.deepcopy(journal.get(identifier)['runtime_observation']['sender_replacements'])
    assert 'accepted' not in retained['oliva']
    assert all(owner.effects==2 for owner in owners.values())
    controller.activate()
    assert all(owner.effects==3 for owner in owners.values())
    assert journal.get(identifier)['runtime_observation']['sender_replacements']['eko']==retained['eko']


def test_completed_observation_window_covers_the_first_receiver_too(tmp_path,monkeypatch):
    from clusterctl import onboarding_receiving_update as module
    from types import SimpleNamespace
    controller,owners,journal,identifier=activation_fixture(tmp_path)
    activation=controller.prepare_activation()
    row=journal.get(identifier)
    plan,manifest=controller._activation(row)
    instant=[time.time_ns()//1_000_000]
    qualify=owners['oliva'].qualified_identity
    def slow_last(**options):
        instant[0]+=plan['observation_window_ms']+1
        return qualify(**options)
    monkeypatch.setattr(owners['oliva'],'qualified_identity',slow_last)
    monkeypatch.setattr(module,'time',SimpleNamespace(time_ns=lambda:instant[0]*1_000_000,monotonic_ns=time.monotonic_ns))
    with pytest.raises(OnboardingError,match='activation_changed'):
        controller._current_activation(row,plan,manifest,activation)
    assert all(owner.effects==1 for owner in owners.values())


@pytest.mark.parametrize('fault',['unsupported','release_digest','reader_sha256'])
def test_current_release_cannot_reuse_an_unbound_compatible_assessment(tmp_path,fault):
    controller,owners,_,_=activation_fixture(tmp_path,assessment_fault=fault)
    with pytest.raises(OnboardingError,match='incompatible_receiving_reader|preflight_changed'):
        controller.activate()
    assert all(owner.effects==1 and owner.gate['phase']=='revoke' for owner in owners.values())
    controller.reconcile_reassessment()
    assert all(owner.gate['phase']=='select' and owner.gate['readers']==[] for owner in owners.values())
    assert_new_operation_can_revoke(owners)


@pytest.mark.parametrize('stage',['query','prepare','apply','final-query'])
def test_slow_observation_or_control_cannot_report_fresh_activation(tmp_path,monkeypatch,stage):
    from clusterctl import onboarding_receiving_update as module
    from types import SimpleNamespace
    controller,owners,_,_=activation_fixture(tmp_path)
    base_ms=time.time_ns()//1_000_000
    elapsed=[0]
    monkeypatch.setattr(module,'time',SimpleNamespace(
        time_ns=lambda:(base_ms*1_000_000+elapsed[0]),monotonic_ns=lambda:elapsed[0]))
    def consume_window():
        elapsed[0]+=60_001_000_000
    if stage=='query':
        qualify=owners['eko'].qualified_identity
        def slow(**options):
            result=qualify(**options)
            consume_window()
            return result
        monkeypatch.setattr(owners['eko'],'qualified_identity',slow)
    elif stage in {'prepare','apply'}:
        attribute='prepare_control' if stage=='prepare' else 'apply_control'
        original=getattr(owners['oliva'],attribute)
        def slow(*arguments):
            result=original(*arguments)
            if arguments[-1].name.endswith('-select.json'):
                consume_window()
            return result
        monkeypatch.setattr(owners['oliva'],attribute,slow)
    else:
        fresh=set()
        for name,owner in owners.items():
            qualify=owner.qualified_identity
            def record(*,who=name,original=qualify,**options):
                result=original(**options)
                if all(item.gate['phase']=='select' for item in owners.values()):
                    fresh.add(who)
                if fresh==set(owners):
                    consume_window()
                return result
            monkeypatch.setattr(owner,'qualified_identity',record)
    with pytest.raises(OnboardingError,match='observation_expired|activation_changed'):
        controller.activate()
    assert all(owner.gate['readers']==[] for owner in owners.values())


def test_roster_drift_during_native_select_repairs_prior_positive_sender(tmp_path,monkeypatch):
    controller,owners,journal,identifier=activation_fixture(tmp_path)
    prepare=owners['oliva'].prepare_control
    apply=owners['oliva'].apply_control
    def drift(command,path):
        result=prepare(command,path)
        if command['readers']:
            owners['oliva'].roster['roster_sha256']='8'*64
        return result
    def native_cas(path):
        if owners['oliva'].requests[path]['readers']:
            raise OnboardingError('receiving_control_not_accepted')
        return apply(path)
    monkeypatch.setattr(owners['oliva'],'prepare_control',drift)
    monkeypatch.setattr(owners['oliva'],'apply_control',native_cas)
    with pytest.raises(OnboardingError,match='not_accepted'):
        controller.activate()
    assert all(owner.gate['readers']==[] for owner in owners.values())
    assert set(journal.get(identifier)['runtime_observation']['cohort_reassessment'])==set(owners)
    assert_new_operation_can_revoke(owners)


@pytest.mark.parametrize('missing',['process','gate','request_sha256','command_sha256'])
def test_malformed_select_completion_keeps_effect_and_repairs_conservatively(tmp_path,monkeypatch,missing):
    controller,owners,journal,identifier=activation_fixture(tmp_path)
    apply=owners['oliva'].apply_control
    def malformed(path):
        result=apply(path)
        if path.name.endswith('-select.json'):
            result.pop(missing)
        return result
    monkeypatch.setattr(owners['oliva'],'apply_control',malformed)
    with pytest.raises(OnboardingError,match='selection_uncertain'):
        controller.activate()
    assert all(owner.gate['readers']==[] for owner in owners.values())
    assert set(journal.get(identifier)['runtime_observation']['cohort_reassessment'])==set(owners)
    assert_new_operation_can_revoke(owners)


@pytest.mark.parametrize('fault',['offline','epoch','roster','selection','catalog','lifecycle'])
def test_required_receiver_failure_blocks_first_positive_selection(tmp_path,monkeypatch,fault):
    controller,owners,_,_=activation_fixture(tmp_path)
    owner=owners['oliva']
    if fault=='offline':
        monkeypatch.setattr(owner,'qualified_identity',lambda **_:(_ for _ in ()).throw(OSError('synthetic offline')))
    elif fault=='epoch':
        owner.loaded['authority_epoch']['accepted_manifest_hashes']=[]
        for authority in owner.application['authorities'].values():
            authority['accepted_manifest_hashes']=['1'*64]
    elif fault=='roster':
        owner.roster['roster_sha256']='8'*64
    elif fault=='selection':
        owner.application['publication_sha256']='8'*64
    elif fault=='catalog':
        owner.application['visibility']['catalog_validation']='pending'
    else:
        owner.process['start_ticks']+=1
    with pytest.raises((OnboardingError,OSError)):
        controller.activate()
    assert all(owner.effects==1 and owner.gate['phase']=='revoke' for owner in owners.values())


def test_all_required_adoption_precedes_select_and_exact_retry_keeps_expiries(tmp_path):
    controller,owners,journal,identifier=activation_fixture(tmp_path)
    first=controller.activate()
    assert first['receiving_readiness']=='qualified-local-projection'
    assert first['communication_acceptance']=='unobserved'
    assert len(first['readers'])==2 and all(owner.effects==2 for owner in owners.values())
    assert controller.activate()==first
    assert all(owner.effects==2 for owner in owners.values())
    assert set(journal.get(identifier)['runtime_observation']['sender_selections'])==set(owners)


def test_partial_select_lost_reply_resumes_exact_same_vector(tmp_path,monkeypatch):
    controller,owners,journal,identifier=activation_fixture(tmp_path)
    apply=owners['oliva'].apply_control
    lost=[True]
    def lose(path):
        result=apply(path)
        if lost[0]:
            lost[0]=False
            raise OSError('synthetic selected reply loss')
        return result
    monkeypatch.setattr(owners['oliva'],'apply_control',lose)
    with pytest.raises(OSError):
        controller.activate()
    retained=copy.deepcopy(journal.get(identifier)['runtime_observation']['cohort_activation'])
    assert set(journal.get(identifier)['runtime_observation']['sender_selections'])=={'eko'}
    assert all(owner.effects==2 for owner in owners.values())
    assert controller.activate()['readers']==retained['readers']
    assert journal.get(identifier)['runtime_observation']['cohort_activation']==retained
    assert all(owner.effects==2 for owner in owners.values())


def test_changed_proof_after_partial_activation_fences_and_retains_reassessment(tmp_path,monkeypatch):
    controller,owners,journal,identifier=activation_fixture(tmp_path)
    apply=owners['eko'].apply_control
    def mutate(path):
        result=apply(path)
        if path.name.endswith('-select.json'):
            owners['oliva'].roster['roster_sha256']='8'*64
        return result
    monkeypatch.setattr(owners['eko'],'apply_control',mutate)
    with pytest.raises(OnboardingError,match='roster_unready'):
        controller.activate()
    assert owners['eko'].gate['readers']==[] and owners['eko'].effects==4
    assert owners['oliva'].effects==2 and owners['oliva'].gate['readers']==[]
    repair=journal.get(identifier)['runtime_observation']['cohort_reassessment']
    assert repair['eko']['state']=='disabled'
    with pytest.raises(OnboardingError,match='reassessment_required'):
        controller.activate()
    assert controller.reconcile_reassessment()==repair
    assert_new_operation_can_revoke(owners)


def assert_new_operation_can_revoke(owners):
    """Mirror native operation-reservation behavior, never grant readers."""
    for owner in owners.values():
        identifier=str(uuid.uuid4())
        command=dict(process_instance_id=owner.gate['process_instance_id'],channel_id='tribe',
            expected_head=owner.gate['head'],operation_id=identifier,release_digest='a'*64,phase='revoke',readers=[])
        path=owner.root/'receiving-control'/(identifier+'-revoke.json')
        owner.prepare_control(command,path)
        assert owner.apply_control(path)['gate']['operation_id']==identifier


def test_expired_all_revoked_stage_clears_reservations_without_positive_grants(tmp_path,monkeypatch):
    from clusterctl import onboarding_receiving_update as module
    from types import SimpleNamespace
    controller,owners,journal,identifier=activation_fixture(tmp_path)
    retained=controller.prepare_activation()
    expired=max(item['expires_at_ms'] for item in retained['readers'])+1
    monkeypatch.setattr(module,'time',SimpleNamespace(time_ns=lambda:expired*1_000_000,monotonic_ns=time.monotonic_ns))
    with pytest.raises(OnboardingError,match='observation_expired'):
        controller.activate()
    assert all(owner.effects==2 and owner.gate['readers']==[] for owner in owners.values())
    assert set(journal.get(identifier)['runtime_observation']['cohort_reassessment'])==set(owners)
    assert_new_operation_can_revoke(owners)


def test_expired_vector_cannot_renew_its_reader_horizon(tmp_path,monkeypatch):
    from clusterctl import onboarding_receiving_update as module
    from types import SimpleNamespace
    controller,owners,journal,identifier=activation_fixture(tmp_path)
    first=controller.activate()
    expired=max(item['expires_at_ms'] for item in first['readers'])+1
    monkeypatch.setattr(module,'time',SimpleNamespace(time_ns=lambda:expired*1_000_000,monotonic_ns=time.monotonic_ns))
    with pytest.raises(OnboardingError,match='observation_expired'):
        controller.activate()
    assert journal.get(identifier)['runtime_observation']['cohort_activation']['readers']==first['readers']
    assert all(owner.gate['readers']==[] for owner in owners.values())


def test_changed_process_cannot_reuse_retained_lifecycle_or_select_ack(tmp_path):
    controller,owners,_,_=activation_fixture(tmp_path)
    controller.activate()
    owners['oliva'].process['start_ticks']+=1
    with pytest.raises(OnboardingError,match='lifecycle_unobserved'):
        controller.activate()
    assert owners['eko'].gate['readers']==[]


@pytest.mark.parametrize('part', ['being_ref', 'local_origin'])
def test_frozen_sender_identity_requires_the_authenticated_status_binding(tmp_path, monkeypatch, part):
    root = tmp_path / 'owner'
    root.mkdir(mode=0o700)
    owner = FakeOwner(root, 'source')
    status = owner.status()
    status['runtime_status'][part] = None if part == 'being_ref' else {'embodiment_id': 'another-body'}
    monkeypatch.setattr(owner, 'status', lambda: status)
    with pytest.raises(OnboardingError, match='owner_identity_conflict'):
        freeze_senders({'source': owner}, tribe_ref='tribe:fixture')
    assert owner.effects == 0 and owner.requests == {}


def test_incomplete_barrier_and_direct_selector_bypass_have_no_file_effect(tmp_path):
    path, original, _, owners, journal, identifier = fixture(tmp_path)
    controller = CohortController(journal, identifier, owners)
    with pytest.raises(OnboardingError, match='barrier_incomplete'):
        controller.apply_host_selection(path)
    with pytest.raises(OnboardingError, match='barrier_required'):
        apply_host_selection(journal, identifier, path)
    assert being_seed._read(path) == original
    assert journal.get(identifier)['state'] == 'planned'
    assert all(owner.effects == 0 for owner in owners.values())


def test_all_frozen_revocations_precede_actual_selector_and_exact_retry(tmp_path):
    path, original, runtime, owners, journal, identifier = fixture(tmp_path)
    controller = CohortController(journal, identifier, owners)
    barrier = controller.revoke_senders()
    assert set(barrier['sender_revocations']) == set(owners)
    assert being_seed._read(path) == original
    assert all(owner.effects == 1 for owner in owners.values())
    assert controller.apply_host_selection(path)['selected']
    assert being_seed._read(path) == {**original, **runtime}
    assert controller.revoke_senders() == barrier
    assert controller.apply_host_selection(path)['selected']
    assert all(owner.effects == 1 for owner in owners.values())
    assert set(journal.get(identifier)['runtime_observation']) == {'sender_revocations', 'host_selection'}


def test_partial_revocation_loss_resumes_without_repeating_the_first_effect(tmp_path, monkeypatch):
    path, original, _, owners, journal, identifier = fixture(tmp_path)
    controller = CohortController(journal, identifier, owners)
    apply = owners['oliva'].apply_control
    lost = True
    def lose_reply(path):
        nonlocal lost
        result = apply(path)
        if lost:
            lost = False
            raise OSError('synthetic control reply lost after effect')
        return result
    monkeypatch.setattr(owners['oliva'], 'apply_control', lose_reply)
    with pytest.raises(OSError):
        controller.revoke_senders()
    assert set(journal.get(identifier)['runtime_observation']['sender_revocations']) == {'eko'}
    assert all(owner.effects == 1 for owner in owners.values())
    assert being_seed._read(path) == original
    with pytest.raises(OnboardingError, match='barrier_incomplete'):
        controller.apply_host_selection(path)
    restored = CohortController(journal, identifier, owners)
    restored.revoke_senders()
    assert all(owner.effects == 1 for owner in owners.values())
    assert restored.apply_host_selection(path)['selected']


@pytest.mark.parametrize('changed', ['process', 'gate', 'readers'])
def test_durable_old_ack_cannot_pass_a_changed_current_sender(tmp_path, changed):
    path, original, _, owners, journal, identifier = fixture(tmp_path)
    controller = CohortController(journal, identifier, owners)
    controller.revoke_senders()
    if changed == 'process':
        owners['eko'].process['start_ticks'] += 1
    elif changed == 'gate':
        owners['eko'].gate['head'] = 'f'*64
    else:
        owners['eko'].gate['readers'] = [{'fixture': 'enabled'}]
    with pytest.raises(OnboardingError, match='barrier_changed'):
        controller.apply_host_selection(path)
    assert being_seed._read(path) == original


def test_another_owner_locator_cannot_rebind_the_frozen_sender_vector(tmp_path):
    path, original, _, owners, journal, identifier = fixture(tmp_path)
    owners['eko'].socket = Path('/other/tribe.sock')
    with pytest.raises(OnboardingError, match='vector_invalid'):
        CohortController(journal, identifier, owners).revoke_senders()
    assert being_seed._read(path) == original
    assert all(owner.effects == 0 for owner in owners.values())


@pytest.mark.parametrize('failed_directory', ['control', 'root'])
def test_failed_request_publication_is_completed_before_native_control(tmp_path, monkeypatch, failed_directory):
    """Fault actual fsync after rename; fake RPC distinguishes effect ordering."""
    from daimon_matrix.local_api import request_hash
    root = tmp_path / 'owner'
    root.mkdir(mode=0o700)
    owner = OwnerGroupClient(root, root / 'tribe.sock')
    path = root / 'receiving-control' / 'revoke.json'
    command = dict(channel_id='tribe', process_instance_id='fixture', expected_head='b'*64,
                   phase='revoke', operation_id='fixture', release_digest='a'*64, readers=[])
    gate = dict(command, head=command['expected_head'], request_sha256=None)
    calls = []
    prepared = []
    monkeypatch.setattr(owner, 'status', lambda: dict(gate=copy.deepcopy(gate), process={}, server={}))

    class FakeClient:
        def prepare(self, method, params):
            prepared.append(True)
            return dict(method=method, params=params, request_id='fixture-request')

        def send(self, request):
            calls.append(request)
            gate['request_sha256'] = request_hash(request)
            return {'ok': True}

    monkeypatch.setattr(owner, '_client', lambda role: FakeClient())
    actual_sync = os.fsync
    fault = True
    syncs = []
    target = path.parent if failed_directory == 'control' else root

    def fail_sync(descriptor):
        location = os.readlink('/proc/self/fd/' + str(descriptor))
        syncs.append(location)
        if location == str(target) and fault:
            raise OSError('synthetic directory fsync failure')
        return actual_sync(descriptor)

    monkeypatch.setattr(os, 'fsync', fail_sync)
    with pytest.raises(OSError, match='fsync failure'):
        owner.prepare_control(command, path)
    raw = path.read_bytes()  # Rename happened, but the durable boundary failed.
    with pytest.raises(OSError, match='fsync failure'):
        owner.prepare_control(command, path)
    with pytest.raises(OSError, match='fsync failure'):
        owner.apply_control(path)
    assert not calls and len(prepared) == 1 and path.read_bytes() == raw

    fault = False
    start = len(syncs)
    owner.prepare_control(command, path)
    assert syncs[start:] == [str(path), str(path.parent), str(root)]
    owner.apply_control(path)
    assert len(calls) == 1 and len(prepared) == 1 and path.read_bytes() == raw


@pytest.mark.parametrize('changed', ['none', 'counts', 'process', 'loaded', 'gate'])
def test_owner_adapter_rechecks_actual_loaded_connection_before_control(tmp_path, monkeypatch, changed):
    from clusterctl import onboarding_receiving_update as receiving
    current = dict(process={'pid': 123}, gate={'head': 'original'}, runtime_status={
        'loaded_runtime': {'base': 'actual'}, 'loaded_application': {'view': 'actual'},
        'counts': {'rows': 1}, 'receiving': {'channels': {'tribe': {'head': 'original'}}}})
    observed = dict(process=copy.deepcopy(current['process']),
        runtime_status=copy.deepcopy(current['runtime_status']), responder_association='same-connection')
    calls = []
    class FakeClient:
        def __init__(self, *_):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def status(self):
            return current
        def apply_control(self, path):
            calls.append(path)
            return {'applied': True}
    monkeypatch.setattr(receiving, 'OwnerGroupClient', FakeClient)
    if changed == 'process':
        current['process']['pid'] += 1
    elif changed == 'loaded':
        current['runtime_status']['loaded_application']['view'] = 'other'
    elif changed == 'gate':
        current['gate']['head'] = 'other'
    elif changed == 'counts':
        current['runtime_status']['counts']['rows'] += 1
    group = dict(channel_id='tribe', socket=str(tmp_path / 'tribe.sock'))
    path = tmp_path / 'revoke.json'
    if changed in {'none', 'counts'}:
        assert receiving.owner_control(tmp_path, group, observed, 'receiving-control-apply', path) == {'applied': True}
        assert calls == [path]
    else:
        with pytest.raises(OnboardingError, match='process_changed'):
            receiving.owner_control(tmp_path, group, observed, 'receiving-control-apply', path)
        assert calls == []


def test_completed_cohort_retry_observes_without_repreparing_native_controls(tmp_path, monkeypatch):
    controller, owners, _, _ = activation_fixture(tmp_path)
    first = controller.activate()
    effects = {name: owner.effects for name, owner in owners.items()}
    def refuse(*args, **kwargs):
        pytest.fail('completed selection retry prepared or applied another control')
    observations = {name: 0 for name in owners}
    for name, owner in owners.items():
        monkeypatch.setattr(owner, 'prepare_control', refuse)
        monkeypatch.setattr(owner, 'apply_control', refuse)
        original = owner.status
        def status(selected=name, query=original):
            observations[selected] += 1
            return query()
        monkeypatch.setattr(owner, 'status', status)
    assert controller.activate() == first
    assert {name: owner.effects for name, owner in owners.items()} == effects
    assert observations == {name: 1 for name in owners}, 'reuse same-round qualified gate'


def test_cohort_preparation_reuses_its_authenticated_round_for_barrier(tmp_path, monkeypatch):
    controller, owners, _, _ = activation_fixture(tmp_path)
    observations = {name: 0 for name in owners}
    for name, owner in owners.items():
        original = owner.status
        def status(selected=name, query=original):
            observations[selected] += 1
            assert observations[selected] == 1, 'barrier must reuse the qualified gate'
            return query()
        monkeypatch.setattr(owner, 'status', status)
    assert len(controller.prepare_activation()['readers']) == len(owners)
    assert observations == {name: 1 for name in owners}


def test_completed_cohort_retry_changed_gate_still_fences_forward(tmp_path):
    controller, owners, journal, identifier = activation_fixture(tmp_path)
    first = controller.activate()
    owners['eko'].gate['head'] = '9' * 64
    with pytest.raises(OnboardingError, match='selection_changed'):
        controller.activate()
    assert journal.get(identifier)['runtime_observation']['cohort_activation']['readers'] == first['readers']
    assert all(owner.gate['readers'] == [] for owner in owners.values())
    assert_new_operation_can_revoke(owners)

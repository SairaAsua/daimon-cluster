"""Native owner requests retain real relationship effects across interrupted ACKs."""
import copy
import os
import time
import uuid
from dataclasses import replace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_group_admission import command, public_authorities, relationship_request, request_packet
from clusterctl.onboarding_target import Target, document
from tests import test_onboarding_group_authorities as group_fixtures

group_source = group_fixtures.group_source


def closure(bundle):
    from daimon_matrix.operator_rebirth import AUTHORITY_SCHEMA
    return {bundle['manifest']['being_ref']: dict(authority=dict(schema=AUTHORITY_SCHEMA,
        **{key: bundle[key] for key in ('manifest', 'control_artifacts', 'control_head',
                                      'credentials', 'incarnations')}), history=bundle['authority_history'])}


def invitation(source, peer_bundle):
    from daimon_matrix.canonical import b64url
    from daimon_matrix.relationships import INVITATION_SCHEMA, invitation_id
    selected = being_seed._read(source.outputs / 'tribe/selection.json')['document']
    bundle = being_seed._read(source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    nonce = b64url(os.urandom(32))
    invitee = peer_bundle['manifest']['being_ref']
    now = time.time_ns() // 1_000_000
    payload = dict(schema=INVITATION_SCHEMA, tribe_ref=selected['tribe_ref'], founder_epoch=0,
        founder_being_ref=bundle['manifest']['being_ref'], invitee_being_ref=invitee, nonce=nonce,
        invitation_id=invitation_id(tribe=selected['tribe_ref'], founder_epoch=0,
            invitee_being_ref=invitee, nonce=nonce), issued_at_ms=now, expires_at_ms=now + 86_400_000)
    return dict(operation_id=str(uuid.uuid4()), step='invite', method='tribe.invite', params=dict(payload=payload))


def test_protected_social_phase_resumes_partial_native_distribution(group_source, tmp_path, monkeypatch):
    """Real native Roots/RPC/journal; physical quiescence is an explicit seam."""
    from types import SimpleNamespace
    from clusterctl import onboarding_group_admission as social
    from clusterctl.onboarding_code_successor import plan_update
    from clusterctl.onboarding_group_admission import membership_recipe
    from clusterctl.onboarding_receiving_update import CohortController
    from clusterctl.operation_journal import OperationJournal

    source, first, _peer, peer_bundle, _old = group_source
    target = Target(tmp_path / 'candidate/guest', first.plan,
        document(tmp_path / 'candidate/custody' / digest(first.plan) / 'genesis.json'))
    founder_bundle = first.document_bundle()
    native = source._load(signed=False)
    declaration = next(row for row in native.service.relationships.store.events() if row['kind'] == 'matrix/tribe-declaration')
    invitation_payload = invitation(source, peer_bundle)['params']['payload']
    operation = str(uuid.uuid4())
    roots = {'founder': source.root, 'entrant': target.package / 'runtime'}
    original_identity = {name: {file: (root/file).read_bytes() for file in ('runtime.json', 'custody.json')}
                         for name, root in roots.items()}
    bundles = {'founder': founder_bundle, 'entrant': peer_bundle}
    closure_all = {**closure(founder_bundle), **closure(peer_bundle)}
    pins = {}
    for name, owner in (('founder', source), ('entrant', target)):
        pins[name] = owner.group_publication(dict(operation_id=operation, step='context',
            action='context-preview', params={}), authority_closure={ref: item for ref, item in closure_all.items()
                if ref != bundles[name]['manifest']['being_ref']})['owner_context_sha256']
    receivers = {name: dict(being_ref=bundles[name]['manifest']['being_ref'],
        embodiment_id=bundles[name]['local_origin']['embodiment_id'], root=str(root), socket=str(root/'tribe.sock'),
        candidate=dict(code=str(tmp_path/'qualified-code'), code_uid=0),
        recipe=dict(profile='source' if name == 'founder' else 'guest',
            prepared=dict(being_ref=bundles[name]['manifest']['being_ref'],
                embodiment_id=bundles[name]['local_origin']['embodiment_id'], code_digest='a'*64,
                matrix_wheel_sha256='b'*64), tooling={'profile': 'matrix-only'})) for name, root in roots.items()}
    sender = dict(name='founder', root=str(source.root), socket=str(source.root/'tribe.sock'),
        being_ref=founder_bundle['manifest']['being_ref'], server=founder_bundle['local_origin'], process={}, gate={})
    admission = dict(schema='cluster-receiving-admission/v1', tribe_ref=invitation_payload['tribe_ref'],
        entrant=dict(being_ref=peer_bundle['manifest']['being_ref'],
            embodiment_ids=[peer_bundle['local_origin']['embodiment_id']]), receivers=receivers,
        activation=dict(manifest_path=str(tmp_path/'manifest.json'), manifest_uid=0,
            expires_at_ms=invitation_payload['expires_at_ms'], observation_window_ms=1000))
    recipe = dict(schema='cluster-membership-admission/v1', operation_id=operation,
        founder_owner='founder', entrant_owner='entrant', authority_closure=closure_all,
        governance=[declaration], invitation=invitation_payload, membership_sequence=0,
        previous_membership_terminal_ref=None, acceptance_not_after_ms=invitation_payload['expires_at_ms'], owner_contexts=pins)
    assert membership_recipe(recipe, admission, [sender]) == recipe
    for changed in ({**recipe, 'founder_owner': 'entrant'}, {**recipe, 'authority_closure': closure(peer_bundle)},
                    {**recipe, 'membership_sequence': 1}, {**recipe, 'governance': [declaration, declaration]},
                    {**recipe, 'invitation': {**invitation_payload, 'nonce': 'invalid'}},
                    {**recipe, 'extra': 'unapproved'}):
        with pytest.raises(OnboardingError, match='membership_recipe_required'):
            membership_recipe(changed, admission, [sender])
    calls, fault = [], {'accept': False, 'ingest': False, 'barrier': 'revoked-original'}
    from daimon_matrix.service import HostedWeave
    handle = HostedWeave.handle

    def native_response_loss(self, value):
        result = handle(self, value)
        if value['method'] == 'tribe.membership.accept' and fault['accept']:
            fault['accept'] = False
            raise OSError('synthetic lost membership acceptance response')
        return result

    monkeypatch.setattr(HostedWeave, 'handle', native_response_loss)

    class Owner:
        deadline_ns = None
        def __init__(self, name, local):
            self.name, self.local, self.root, self.socket = name, local, roots[name], roots[name]/'tribe.sock'
        def group_relationship(self, value, **options):
            calls.append((self.name, copy.deepcopy(value)))
            assert self.deadline_ns > time.monotonic_ns()
            result = self.local.group_relationship(value, **options)
            if self.name == 'founder' and value['step'] == 'membership-acceptance' and fault['ingest']:
                fault['ingest'] = False
                raise OSError('synthetic lost acceptance intake response')
            return result

    owners = {'founder': Owner('founder', source), 'entrant': Owner('entrant', target)}
    journal = OperationJournal(tmp_path/'social-phase')
    row = plan_update(journal, manifest_digest='f'*64, target='receiving:'+admission['tribe_ref'],
        expected_precondition=dict(tribe_ref=admission['tribe_ref'], senders=[sender],
            receiver_selections={name: None for name in owners}),
        intended_transition=dict(cohort_admission=admission,
            portal_admission=dict(schema='cluster-portal-group-admission/v2', social=recipe)),
        audit_identity={'actor': 'synthetic-host'})
    cohort = CohortController(journal, row['operation_id'], owners)
    monkeypatch.setattr(cohort, 'require_revocation_barrier', lambda: dict(
        schema='cluster-receiving-admission-barrier/v1', current_senders={'founder': {'state': fault['barrier']}}))
    with pytest.raises(OnboardingError, match='quiescence_required'):
        cohort.admit_membership(deadline_ns=time.monotonic_ns()+30_000_000_000)
    assert calls == [] and journal.get(row['operation_id'])['runtime_observation'] is None
    fault.update(barrier='stopped', accept=True)
    with pytest.raises(OSError, match='lost membership acceptance response'):
        cohort.admit_membership(deadline_ns=time.monotonic_ns()+30_000_000_000)
    commands = journal.get(row['operation_id'])['runtime_observation']['membership_admission']['requests']
    frozen_accept = copy.deepcopy(commands['entrant']['membership-accept']['command'])
    assert commands['entrant']['membership-accept']['result'] is None
    # Expiry must not generate a different accepted_at_ms or invitation. Native
    # owner retries still use their actual retained authenticated response.
    monkeypatch.setattr(social, 'time', SimpleNamespace(monotonic_ns=time.monotonic_ns,
        time_ns=lambda: (recipe['acceptance_not_after_ms']+1)*1_000_000))
    load = social.load_owner_runtime

    def late_owner_load(root, *args, **options):
        hosted = load(root, *args, **options)
        if root == roots['entrant']:
            return replace(hosted, service=replace(hosted.service,
                clock=lambda: recipe['acceptance_not_after_ms']+1))
        return hosted

    monkeypatch.setattr(social, 'load_owner_runtime', late_owner_load)
    fault['ingest'] = True
    with pytest.raises(OSError, match='lost acceptance intake response'):
        cohort.admit_membership(deadline_ns=time.monotonic_ns()+30_000_000_000)
    retained = journal.get(row['operation_id'])
    assert retained['state'] == 'planned'
    commands = retained['runtime_observation']['membership_admission']['requests']
    accepted = commands['entrant']['membership-accept']['result']['result']['event']
    assert commands['entrant']['membership-accept']['command'] == frozen_accept
    assert commands['founder']['membership-acceptance']['result'] is None
    count_before = len(calls)
    result = cohort.admit_membership(deadline_ns=time.monotonic_ns()+30_000_000_000)
    assert result['schema'] == 'cluster-native-membership-admission/v1'
    assert result['receiving_readiness'] == 'unobserved' and result['acceptance'] == accepted
    assert all(value['step'] not in {'membership-invite', 'membership-accept'} for _, value in calls[count_before:])
    row = journal.get(row['operation_id'])
    assert row['runtime_observation']['membership_admission']['requests']['entrant']['membership-accept']['command'] == frozen_accept
    count_before = len(calls)
    monkeypatch.setattr(cohort, 'require_revocation_barrier', lambda: pytest.fail('completed social phase repeated a physical barrier'))
    assert cohort.admit_membership(deadline_ns=time.monotonic_ns()+30_000_000_000) == result
    assert len(calls) == count_before and row['state'] == 'planned'
    assert not (roots['entrant']/'matrix.sock').exists()
    assert all(owner.deadline_ns is None for owner in owners.values())
    assert {name: {file: (root/file).read_bytes() for file in ('runtime.json', 'custody.json')}
            for name, root in roots.items()} == original_identity
    # A stale supplied lineage cannot authorize a second sequence-0 acceptance
    # (or another invite) against the actual already-joined native stores.
    guard = dict(schema='cluster-membership-authoring-precondition/v1',
        **{key: recipe['invitation'][key] for key in ('tribe_ref', 'founder_being_ref', 'founder_epoch', 'invitee_being_ref')},
        membership_sequence=0, previous_membership_terminal_ref=None,
        active_members=[founder_bundle['manifest']['being_ref']],
        not_after_ms=recipe['acceptance_not_after_ms']+60_000)
    ledger_events = {name: load(root, (source if name == 'founder' else target)._reader,
        authorities=social.public_authorities(bundles[name], {ref: item for ref, item in closure_all.items()
            if ref != bundles[name]['manifest']['being_ref']})).service.ledger.events() for name, root in roots.items()}
    fresh_invite = invitation(source, peer_bundle)
    for local, value, authority, extra in (
        (source, fresh_invite, closure(peer_bundle), {'offline': True}),
        (target, {**frozen_accept, 'operation_id': str(uuid.uuid4())}, closure(founder_bundle), {}),
    ):
        with pytest.raises(OnboardingError, match='membership_precondition_changed'):
            local.group_relationship(value, authority_closure=authority, membership_precondition=guard, **extra)
    # Authorization must retain a known acceptance if the clock goes back;
    # a historical display view would hide it and allow a conflicting event.
    with monkeypatch.context() as patch:
        def rollback_load(*args, **options):
            hosted = load(*args, **options)
            return replace(hosted, service=replace(hosted.service,
                clock=lambda: recipe['invitation']['issued_at_ms']))
        patch.setattr(social, 'load_owner_runtime', rollback_load)
        with pytest.raises(OnboardingError, match='membership_precondition_changed'):
            target.group_relationship({**frozen_accept, 'operation_id': str(uuid.uuid4())},
                authority_closure=closure(founder_bundle), membership_precondition=guard)
    # Expensive owner preparation must not allow absent first execution after
    # the fixed bound. The actual native writer observes its own late clock.
    expired = {**guard, 'not_after_ms': recipe['acceptance_not_after_ms']}
    with pytest.raises(OnboardingError, match='acceptance_expired'):
        target.group_relationship({**frozen_accept, 'operation_id': str(uuid.uuid4())},
            authority_closure=closure(founder_bundle), membership_precondition=expired)
    assert {name: load(root, (source if name == 'founder' else target)._reader,
        authorities=social.public_authorities(bundles[name], {ref: item for ref, item in closure_all.items()
            if ref != bundles[name]['manifest']['being_ref']})).service.ledger.events() for name, root in roots.items()} == ledger_events


def test_owner_refuses_expired_unsubmitted_membership_without_refreshing_frame(group_source, monkeypatch):
    from clusterctl import onboarding_group_admission as social
    from daimon_matrix.local_api import request_hash
    from daimon_matrix.service import HostedWeave
    source, _first, _peer, peer_bundle, _old = group_source
    base = source._load(signed=False)
    value = invitation(source, peer_bundle)
    guard = dict(schema='cluster-membership-authoring-precondition/v1',
        **{key: value['params']['payload'][key] for key in ('tribe_ref', 'founder_being_ref', 'founder_epoch', 'invitee_being_ref')},
        membership_sequence=0, previous_membership_terminal_ref=None,
        active_members=[value['params']['payload']['founder_being_ref']],
        not_after_ms=time.time_ns()//1_000_000+60_000)
    journal = source.outputs/'group-admission'
    events = base.service.ledger.events()
    with monkeypatch.context() as patch:
        def absent(self, request):
            raise OSError('synthetic stop before native dispatch')
        patch.setattr(HostedWeave, 'handle', absent)
        with source.writer(), pytest.raises(OSError, match='stop before native dispatch'):
            relationship_request(source.root, journal, value, offline=base, membership_precondition=guard)
    path = journal/value['operation_id']/'invite.json'
    frame = being_seed._read(path)['request']
    assert not any(row['request_id'] == frame['request_id'] for row in base.service.ledger.rpc_requests())
    load = social.load_owner_runtime
    def late_load(*args, **options):
        hosted = load(*args, **options)
        return replace(hosted, service=replace(hosted.service, clock=lambda: guard['not_after_ms']+1))
    monkeypatch.setattr(social, 'load_owner_runtime', late_load)
    with pytest.raises(OnboardingError, match='acceptance_expired'):
        source.group_relationship(value, offline=True, authority_closure=closure(peer_bundle), membership_precondition=guard)
    retained = being_seed._read(path)
    assert retained['request'] == frame and retained['retired_requests'] == [] and retained['response'] is None
    assert base.service.ledger.events() == events
    # Pending is uncertain, including a possible committed local event; it is
    # never treated as permission to refresh or perform a new expired action.
    with source.writer():
        base.service.ledger.begin_rpc(client_id=frame['client_id'], request_id=frame['request_id'],
            request_hash=request_hash(frame), method=frame['method'])
    with pytest.raises(OnboardingError, match='native_uncertain'):
        source.group_relationship(value, offline=True, authority_closure=closure(peer_bundle), membership_precondition=guard)
    assert being_seed._read(path) == retained and base.service.ledger.events() == events
    # The second current-state reduction may consume the remaining monotonic
    # budget. It must not fall through to the native effect afterwards.
    from types import SimpleNamespace
    clock, checks = [0], [0]
    check = social.check_membership_precondition
    def exhausted(hosted, value, **options):
        check(hosted, value, **options)
        checks[0] += 1
        if checks[0] == 2:
            clock[0] = 2_000_000
    monkeypatch.setattr(social, 'time', SimpleNamespace(time_ns=time.time_ns, monotonic_ns=lambda: clock[0]))
    monkeypatch.setattr(social, 'check_membership_precondition', exhausted)
    with source.writer(), pytest.raises(OnboardingError, match='relationship_deadline_expired'):
        relationship_request(source.root, journal, invitation(source, peer_bundle), offline=base,
            membership_precondition=guard, deadline_ns=1_000_000)
    assert checks[0] == 2 and base.service.ledger.events() == events


@pytest.mark.parametrize('profile', ['source', 'target'])
def test_retained_owner_context_recovers_lagging_selector_without_relaxing_serving(group_source, profile):
    from daimon_matrix.canonical import canonical_bytes
    from daimon_matrix.keystore import _atomic_write
    from daimon_matrix.messaging_config import config_digest, create_binding, read_publication, validate_shape
    from daimon_matrix.operator_messaging import _publication
    source, target, _peer, peer_bundle, _old = group_source
    base = source._load(signed=False)
    request = invitation(source, peer_bundle)
    group = source.outputs / 'tribe'
    journal = source.outputs / 'group-admission'
    if profile == 'target':
        destination = target.root / 'tribe'
        group.rename(destination)
        group = destination
        selected = being_seed._read(group / 'selection.json')['document']
        selected.update(directory=str(group / 'application'),
                        visibility=str(group / 'visibility/installation.json'))
        being_seed._write(group / 'selection.json',
            dict(document=selected, binding=create_binding(base, selected)))
        journal = target.root / 'group-admission'

    def submit(value, authorities):
        options = {} if expected[0] is None else {'expected_context_sha256': expected[0]}
        if profile == 'source':
            return source.group_relationship(value, offline=True, authority_closure=authorities, **options)
        return target.group_relationship(value, authority_closure=authorities, **options)

    def observe():
        return source._load(signed=False) if profile == 'source' else target.observe()

    supplied = closure(peer_bundle)
    expected = [None]
    first = submit(request, supplied)
    assert first['status'] == 'recorded'
    context = journal / request['operation_id'] / 'owner/context.json'
    retained = context.read_bytes()
    expected[0] = digest(being_seed._read(context))
    events = base.service.ledger.events()
    selector = (group / 'selection.json').read_bytes()
    before = {name: (source.root / name).read_bytes() for name in ('runtime.json', 'custody.json')}

    # Inject a genuine owner-signed application drift, leaving its selector
    # behind. SDK additive-publication correctness is qualified separately;
    # this isolates the owner-loader recovery boundary using real signatures.
    app, metadata = read_publication(base, group / 'application')
    predecessor = config_digest(app)
    app['tribe']['policy']['max_ttl_ms'] -= 1
    validate_shape(app)
    _atomic_write(metadata / 'application.json', canonical_bytes(app))
    _atomic_write(metadata / 'binding.json', canonical_bytes(create_binding(base, app)))
    _atomic_write(group / 'application/publication.json', _publication(base, app, '.', predecessor))
    assert read_publication(base, group / 'application')[0] == app
    with pytest.raises(OnboardingError, match='approved_onboarding_group_required'):
        observe()

    assert submit(request, supplied) == first
    assert context.read_bytes() == retained and base.service.ledger.events() == events
    assert (group / 'selection.json').read_bytes() == selector
    assert read_publication(base, group / 'application')[0] == app
    assert {name: (source.root / name).read_bytes() for name in before} == before
    with pytest.raises(OnboardingError, match='owner_context_conflict'):
        submit(request, {})
    fresh = {**request, 'operation_id': str(uuid.uuid4())}
    with pytest.raises(OnboardingError, match='approved_onboarding_group_required'):
        submit(fresh, supplied)
    assert not (journal / fresh['operation_id'] / 'owner/context.json').exists()
    with pytest.raises(OnboardingError, match='approved_onboarding_group_required'):
        observe()


def test_owner_context_requires_complete_approved_closure_before_private_load(group_source, monkeypatch):
    source, _target, _peer, peer_bundle, _old = group_source
    request = invitation(source, peer_bundle)
    monkeypatch.setattr(source, '_reader', lambda: pytest.fail('incomplete closure reached custody'))
    with pytest.raises(OnboardingError, match='owner_context_incomplete'):
        source.group_relationship(request, offline=True, authority_closure={})
    journal = source.outputs / 'group-admission' / request['operation_id']
    assert not (journal / 'owner/context.json').exists()
    assert not (journal / 'invite.json').exists()


def test_owner_context_lost_durability_reply_resumes_before_native_dispatch(group_source, monkeypatch):
    from clusterctl import onboarding_group_admission as admission
    source, _target, _peer, peer_bundle, _old = group_source
    request = invitation(source, peer_bundle)
    base = source._load(signed=False)
    events = base.service.ledger.events()
    original_sync = admission._sync
    original_reader = source._reader

    def lost_reply(path):
        original_sync(path)
        raise OSError('synthetic lost owner-context durability reply')

    monkeypatch.setattr(admission, '_sync', lost_reply)
    monkeypatch.setattr(source, '_reader', lambda: pytest.fail('owner context was not durable'))
    with pytest.raises(OSError, match='owner-context durability'):
        source.group_relationship(request, offline=True, authority_closure=closure(peer_bundle))
    path = source.outputs / 'group-admission' / request['operation_id'] / 'owner/context.json'
    retained = path.read_bytes()
    assert base.service.ledger.events() == events
    synced = []

    def observed_sync(path):
        original_sync(path)
        synced.append(path)

    monkeypatch.setattr(admission, '_sync', observed_sync)
    def reader():
        assert path.parent in synced
        return original_reader()
    monkeypatch.setattr(source, '_reader', reader)
    assert source.group_relationship(request, offline=True,
        authority_closure=closure(peer_bundle))['status'] == 'recorded'
    assert path.read_bytes() == retained
    assert len(base.service.ledger.events()) == len(events) + 1


def test_source_and_offline_newcomer_record_real_membership_without_running_group(group_source, tmp_path, monkeypatch):
    from daimon_matrix.relationships import MEMBERSHIP_ACCEPTANCE_SCHEMA
    source, first, _peer_authority, peer_bundle, _old = group_source
    target = Target(tmp_path / 'candidate/guest', first.plan,
        document(tmp_path / 'candidate/custody' / digest(first.plan) / 'genesis.json'))
    before = {root: {name: (root / name).read_bytes() for name in ('runtime.json', 'custody.json')}
              for root in (source.root, target.package / 'runtime')}
    request = invitation(source, peer_bundle)
    tribe_ref = request['params']['payload']['tribe_ref']
    peer_ref = peer_bundle['manifest']['being_ref']
    snapshot = dict(operation_id=request['operation_id'], step='membership-before',
        method='relationship.snapshot', params=dict(tribe_ref=tribe_ref, at_ms=None))
    initial = source.group_relationship(snapshot, offline=True, authority_closure=closure(peer_bundle))
    assert initial['status'] == 'recorded'
    assert initial['result']['tribe_ref'] == tribe_ref
    assert not any(row['principal_id'] == peer_ref for row in initial['result']['members'])
    # The actual founder uses the Target/guest profile here: hosting role does
    # not choose who may invite. Native social authority chooses that role.
    invited = first.group_relationship(request, authority_closure=closure(peer_bundle))
    assert invited['status'] == 'recorded' and invited['native_error'] is None
    event = invited['result']['event']
    assert first.group_relationship(request, authority_closure=closure(peer_bundle)) == invited
    base = source._load(signed=False)
    declaration = next(row for row in base.service.relationships.store.events() if row['kind'] == 'matrix/tribe-declaration')
    authorities = closure(first.document_bundle())
    for step, value in (('declaration', declaration), ('invitation', event)):
        ingested = target.group_relationship(dict(operation_id=request['operation_id'], step=step,
            method='relationship.event.ingest', params=dict(event=value)), authority_closure=authorities)
        assert ingested['status'] == 'recorded'
    invited_view = target.group_relationship(snapshot, authority_closure=authorities)
    assert invited_view['status'] == 'recorded'
    assert not any(row['principal_id'] == peer_ref for row in invited_view['result']['members'])
    acceptance = dict(operation_id=request['operation_id'], step='accept', method='tribe.membership.accept',
        params=dict(payload=dict(schema=MEMBERSHIP_ACCEPTANCE_SCHEMA,
            tribe_ref=request['params']['payload']['tribe_ref'], founder_epoch=0,
            invitation_ref=dict(event_id=event['event_id'], event_hash=event['content_hash']),
            invitee_being_ref=peer_bundle['manifest']['being_ref'], membership_sequence=0,
            previous_membership_terminal_ref=None, accepted_at_ms=time.time_ns() // 1_000_000)))
    accepted = target.group_relationship(acceptance, authority_closure=authorities)
    assert accepted['status'] == 'recorded' and accepted['result']['event']['origin'] == peer_bundle['local_origin']
    assert target.group_relationship(acceptance, authority_closure=authorities) == accepted
    source.group_relationship(dict(operation_id=request['operation_id'], step='acceptance',
        method='relationship.event.ingest', params=dict(event=accepted['result']['event'])),
        offline=True, authority_closure=closure(peer_bundle))
    hosted = source._load(signed=False, relationship_authorities=public_authorities(
        first.document_bundle(), closure(peer_bundle)))
    view = hosted.service.relationships.store.view(at_ms=time.time_ns() // 1_000_000,
        card_verifier=hosted.service.relationships.card_verifier)
    tribe = view.tribes[request['params']['payload']['tribe_ref']]
    assert tribe['memberships'][peer_bundle['manifest']['being_ref']]['state'] == 'active'
    # Native intake being recorded is not membership proof. Query the actual
    # reducer through the same authenticated route on both owner profiles.
    # The before-step remains a historical observation after acceptance.
    assert source.group_relationship(snapshot, offline=True, authority_closure=closure(peer_bundle)) == initial
    assert target.group_relationship(snapshot, authority_closure=authorities) == invited_view
    snapshot = {**snapshot, 'step': 'membership-after'}
    from daimon_matrix.service import HostedWeave
    handle = HostedWeave.handle
    events = hosted.service.ledger.events()

    def lost_snapshot_response(self, value):
        result = handle(self, value)
        if value['method'] == 'relationship.snapshot':
            raise OSError('synthetic lost snapshot response')
        return result

    with monkeypatch.context() as patch:
        patch.setattr(HostedWeave, 'handle', lost_snapshot_response)
        with pytest.raises(OSError, match='lost snapshot response'):
            source.group_relationship(snapshot, offline=True, authority_closure=closure(peer_bundle))
    current = source.group_relationship(snapshot, offline=True, authority_closure=closure(peer_bundle))
    newcomer = target.group_relationship(snapshot, authority_closure=authorities)
    for result in (current, newcomer):
        assert result['status'] == 'recorded'
        assert result['result']['tribe_ref'] == tribe_ref
        member = next(row for row in result['result']['members'] if row['principal_id'] == peer_ref)
        assert member['state'] == 'active'
        assert member['membership_ref'] == accepted['result']['event']['event_id']
        assert result['result']['verified_at_ms'] >= initial['result']['verified_at_ms']
    assert source.group_relationship(snapshot, offline=True, authority_closure=closure(peer_bundle)) == current
    assert hosted.service.ledger.events() == events
    assert not (target.package / 'runtime/matrix.sock').exists()
    assert not (target.root / 'tribe/selection.json').exists()
    for root, original in before.items():
        assert {name: (root / name).read_bytes() for name in original} == original
    with target._runtime_writer(), pytest.raises(BlockingIOError):
        target.group_relationship(acceptance, authority_closure=authorities)


def test_lost_native_reply_retries_original_stale_frame_without_another_event(group_source, monkeypatch):
    from daimon_matrix.service import HostedWeave
    source, _target, _peer, peer_bundle, _old = group_source
    base = source._load(signed=False)
    request = invitation(source, peer_bundle)
    journal = source.outputs / 'group-admission'
    path = journal / request['operation_id'] / 'invite.json'
    original = HostedWeave.handle

    def lost(self, value):
        original(self, value)
        raise OSError('synthetic lost native response')

    monkeypatch.setattr(HostedWeave, 'handle', lost)
    with source.writer(), pytest.raises(OSError, match='synthetic lost'):
        relationship_request(source.root, journal, request, offline=base)
    frame = being_seed._read(path)['request']
    events = base.service.ledger.events()
    assert any(row['request_id'] == frame['request_id'] and row['state'] == 'completed'
               for row in base.service.ledger.rpc_requests())
    monkeypatch.setattr(HostedWeave, 'handle', original)
    late = replace(base, service=replace(base.service, clock=lambda: frame['issued_at_ms'] + 61_000))
    with source.writer():
        result = relationship_request(source.root, journal, request, offline=late)
    assert result['status'] == 'recorded'
    retained = being_seed._read(path)
    assert retained['request'] == frame and retained['retired_requests'] == []
    assert base.service.ledger.events() == events
    changed = copy.deepcopy(request)
    changed['params']['payload']['expires_at_ms'] += 1
    with source.writer(), pytest.raises(OnboardingError, match='request_conflict'):
        relationship_request(source.root, journal, changed, offline=late)
    retained['response']['auth']['value'] = 'A' * 43
    being_seed._write(path, retained)
    with source.writer(), pytest.raises(ValueError, match='invalid_local_response'):
        relationship_request(source.root, journal, request, offline=late)


def test_expired_unsubmitted_frame_renews_only_after_exclusive_native_absence(group_source, monkeypatch):
    from daimon_matrix.service import HostedWeave
    source, _target, _peer, peer_bundle, _old = group_source
    base = source._load(signed=False)
    request = invitation(source, peer_bundle)
    journal = source.outputs / 'group-admission'
    path = journal / request['operation_id'] / 'invite.json'
    original = HostedWeave.handle

    def not_submitted(self, value):
        raise OSError('synthetic stop before native dispatch')

    monkeypatch.setattr(HostedWeave, 'handle', not_submitted)
    with source.writer(), pytest.raises(OSError, match='synthetic stop'):
        relationship_request(source.root, journal, request, offline=base)
    frame = being_seed._read(path)['request']
    assert not any(row['request_id'] == frame['request_id'] for row in base.service.ledger.rpc_requests())
    monkeypatch.setattr(HostedWeave, 'handle', original)
    late = replace(base, service=replace(base.service, clock=lambda: frame['issued_at_ms'] + 61_000))
    with source.writer():
        result = relationship_request(source.root, journal, request, offline=late)
    retained = being_seed._read(path)
    assert result['status'] == 'recorded' and retained['retired_requests'] == [frame]
    assert retained['request']['request_id'] == frame['request_id']
    assert retained['request']['issued_at_ms'] == frame['issued_at_ms'] + 61_000
    assert retained['request'] != frame
    assert len([row for row in base.service.ledger.rpc_requests() if row['request_id'] == frame['request_id']]) == 1
    # A different native row is not absence and must never refresh the frame.
    conflicting = invitation(source, peer_bundle)
    monkeypatch.setattr(HostedWeave, 'handle', not_submitted)
    with source.writer(), pytest.raises(OSError, match='synthetic stop'):
        relationship_request(source.root, journal, conflicting, offline=base)
    path = journal / conflicting['operation_id'] / 'invite.json'
    saved = being_seed._read(path)
    frame = saved['request']
    with source.writer():
        base.service.ledger.begin_rpc(client_id=frame['client_id'], request_id=frame['request_id'],
            request_hash='0' * 64, method=frame['method'])
    late = replace(base, service=replace(base.service, clock=lambda: frame['issued_at_ms'] + 61_000))
    monkeypatch.setattr(HostedWeave, 'handle', original)
    with source.writer(), pytest.raises(OnboardingError, match='request_conflict'):
        relationship_request(source.root, journal, conflicting, offline=late)
    assert being_seed._read(path) == saved


def test_closed_commands_and_packets_reject_unrelated_methods_and_paths():
    value = dict(operation_id=str(uuid.uuid4()), step='invite', method='tribe.invite', params={})
    assert command(value) == value
    for invalid in ({**value, 'step': '../escape'}, {**value, 'method': 'messaging.send'},
                    {**value, 'operation_id': True}, {**value, 'extra': True}):
        with pytest.raises(OnboardingError, match='command_required'):
            command(invalid)
    for invalid in ({'command': value}, dict(command=value, offline=1, authority_closure={}),
                    dict(command=value, offline=True, authority_closure={}, extra=True)):
        with pytest.raises(OnboardingError, match='command_required'):
            request_packet(invalid)
    assert request_packet(dict(command=value, offline=True, authority_closure={}))['command'] == value
    bounded = dict(command=value, offline=True, authority_closure={}, expected_context_sha256='a'*64)
    assert request_packet(bounded) == bounded
    for invalid in (None, True, '', 'A'*64, 'a'*63):
        with pytest.raises(OnboardingError, match='command_required'):
            request_packet({**bounded, 'expected_context_sha256': invalid})
    with pytest.raises(OnboardingError, match='command_required'):
        request_packet({**bounded, 'offline': False})


def test_missing_or_replaced_ledger_cannot_turn_uncertainty_into_absence(group_source, monkeypatch):
    from daimon_matrix.ledger import Ledger
    from daimon_matrix.service import HostedWeave, ServiceError
    source, _target, _peer, peer_bundle, _old = group_source
    base = source._load(signed=False)
    request = invitation(source, peer_bundle)
    journal = source.outputs / 'group-admission'
    path = journal / request['operation_id'] / 'invite.json'

    def not_submitted(self, value):
        raise OSError('synthetic stop before dispatch')

    monkeypatch.setattr(HostedWeave, 'handle', not_submitted)
    with source.writer(), pytest.raises(OSError, match='synthetic stop'):
        relationship_request(source.root, journal, request, offline=base)
    retained = being_seed._read(path)
    ledger = base.service.ledger.path
    saved = ledger.with_name(ledger.name + '.saved')
    reader = source._reader
    monkeypatch.setattr(source, '_reader', lambda: pytest.fail('missing/replaced ledger reached private runtime load'))
    ledger.rename(saved)
    try:
        with pytest.raises(FileNotFoundError):
            source.group_relationship(request, offline=True)
        assert not ledger.exists() and being_seed._read(path) == retained
        ledger.write_bytes(b'foreign replacement must not initialize')
        ledger.chmod(0o600)
        with pytest.raises(OnboardingError, match='ledger_changed'):
            source.group_relationship(request, offline=True)
        assert ledger.read_bytes() == b'foreign replacement must not initialize'
        assert being_seed._read(path) == retained
    finally:
        ledger.unlink(missing_ok=True)
        saved.rename(ledger)
    monkeypatch.setattr(source, '_reader', reader)
    original = Ledger.rpc_requests

    def removed_after_inventory(self):
        rows = original(self)
        self.path.rename(saved)
        return rows

    monkeypatch.setattr(Ledger, 'rpc_requests', removed_after_inventory)
    late = replace(base, service=replace(base.service,
        clock=lambda: retained['request']['issued_at_ms'] + 61_000))
    try:
        with source.writer(), pytest.raises(ServiceError, match='loaded_store_replaced'):
            relationship_request(source.root, journal, request, offline=late)
        assert not ledger.exists() and being_seed._read(path) == retained
    finally:
        saved.rename(ledger)

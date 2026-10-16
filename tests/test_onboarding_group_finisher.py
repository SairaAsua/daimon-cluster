"""Actual worker/job/journal/cohort join with explicit native/manager seams.

Existing native social, publication, first-load and activation suites qualify
those producers. These cases qualify caller recovery, not installed admission.
"""
import copy
import time
import uuid
from types import SimpleNamespace

import pytest

from clusterctl import being_seed, onboarding_group_coordinator as module, onboarding_receiving_update as updates
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.onboarding_group_coordinator import GroupCoordinator
from clusterctl.onboarding_worker import Worker
from clusterctl.operation_journal import OperationJournal
from tests.test_onboarding_group_coordinator import fixture  # noqa: F401
from tests.test_receiving_cohort_control import admission_child_fixture


@pytest.fixture
def full(fixture, monkeypatch, request):  # noqa: F811 - imported shared pytest fixture
    f = fixture
    before, transition = copy.deepcopy(f.row['expected_precondition']), copy.deepcopy(f.row['intended_transition'])
    admission = transition['cohort_admission']
    old = {item['name'] for item in before['senders']}
    settings = getattr(request,'param',{})
    selected = copy.deepcopy(f.selected)
    profiles = {name:'guest' for name in old}
    if settings.get('source'):
        profiles['eko'] = 'source'
        admission['receivers']['eko']['recipe']['profile'] = 'source'
        f.activation['receivers']['eko']['profile'] = 'source'
        owner = f.owners['eko']
        candidate = admission['receivers']['eko']['candidate']
        selected['owners']['eko'] = dict(profile='source',config=str(owner.root/'source.json'),
            config_sha256='a'*64,owner_uid=1000,owner_gid=1000,code=candidate['code'],
            code_digest=admission['receivers']['eko']['recipe']['prepared']['code_digest'],code_uid=0,
            venv=str(owner.root/'sdk/venv'),imports=str(owner.root/'sdk/imports'),root=str(owner.root),
            socket_path=str(owner.socket),lifecycle_journal=str(owner.root/'journal'))
    if 'window_ms' in settings:
        admission['activation']['observation_window_ms'] = settings['window_ms']
    if 'channel' in settings:
        for item in admission['receivers'].values():
            item['recipe']['tooling']['tribe_channel'] = settings['channel']
    social = dict(operation_id=str(uuid.uuid4()), founder_owner='eko', entrant_owner='newcomer',
        authority_closure={owner.being:{} for owner in f.owners.values()}, owner_contexts={name:'4'*64 for name in f.owners})
    transition['portal_admission'].update(schema=module.SOCIAL_CALLER_SCHEMA, social=social,owners_sha256=digest(selected['owners']))
    transition['admission_preparations'] = {name:dict(profile=profiles[name], steps=dict(
        application='application', visibility='visibility', selection='selection', snapshot='child-snapshot'),
        **(dict(home=str(f.owners[name].root),unit=str(f.owners[name].root/'matrix.service')) if profiles[name] == 'source' else {})) for name in old}
    transition['admission_publications'] = {'synthetic':'fixed-approved-native-recipe'}
    def sender(name):
        return dict(owner=name, **{key:admission['receivers'][name][key] for key in ('being_ref','embodiment_id')})
    scope = dict(schema=module.COMMUNICATION_SCHEMA, expires_at_ms=admission['activation']['expires_at_ms'],
        group=dict(sender=sender('eko'), text='Group check'),
        direct=dict(sender=sender('newcomer'), text='Directed check', destination=dict(kind='being', being_ref=f.owners['eko'].being)),
        reply=dict(sender=sender('newcomer'), text='Connected reply', parent='group'))
    transition['admission_communication'] = scope
    before['host_config'] = str(f.store.root.parent/'host.json')
    journal = OperationJournal(f.store.root.parent/'full-caller')
    row = plan_update(journal, manifest_digest=f.row['intent']['runtime_call']['manifest_digest'], target=f.row['target'],
        expected_precondition=before, intended_transition=transition, audit_identity={'actor':'synthetic-host'})
    selected.update(journal=str(journal.path.parent), admissions={digest(f.plans['newcomer']):row['operation_id']})
    being_seed._write(f.path, selected)
    # Governance validation/native issuance are explicit seams already covered
    # by native membership/publication suites; this fixture has no signing keys.
    monkeypatch.setattr('clusterctl.onboarding_group_admission.membership_recipe', lambda value,*a:copy.deepcopy(value))
    monkeypatch.setattr('clusterctl.onboarding_group_admission.publication_recipe', lambda value,*a:copy.deepcopy(value))
    monkeypatch.setattr(module, 'communication_recipe', lambda value,*a:copy.deepcopy(value))
    calls, children, snapshots, messages = [], {}, {}, {}
    active_journal = [journal]
    fault = dict(phase=None, lost=False, echo=True, busy=False, restarted=False, reply_echo=True)
    def lose(phase):
        if fault['phase'] == phase and not fault['lost']:
            fault['lost'] = True
            raise OSError('synthetic lost '+phase+' response')
    def retain(key, value):
        selected_journal = active_journal[0]
        current = selected_journal.get(row['operation_id'])
        observations = copy.deepcopy(current['runtime_observation'] or {})
        observations[key] = value
        selected_journal.advance(row['operation_id'], current['state'], runtime_observation=observations,
            expected_runtime_observation=current['runtime_observation'])
    def child_effect(name, key, value):
        child_id = children[name]['recipe']['lifecycle_operation_id']
        current = active_journal[0].get(child_id)
        observations = copy.deepcopy(current['runtime_observation'])
        if profiles[name] == 'source':
            observations['source_bootstrap'][key] = value
        else:
            observations['guest_bootstraps'][name][key] = value
        active_journal[0].advance(child_id, current['state'], runtime_observation=observations)
    def loaded(name):
        approved = admission['receivers'][name]
        prepared = approved['recipe']['prepared']
        return dict(process=copy.deepcopy(f.owners[name].process),
            admission_parent=dict(uid=1,pid=1,start_ticks=2,boot_id='fixture'), loaded_runtime=dict(
            runtime_bundle_sha256='a'*64, qualified_startup=dict(code_digest=prepared['code_digest'],
                matrix_wheel_sha256=prepared['matrix_wheel_sha256'])),
            loaded_application=dict(application_sha256='b'*64, publication_sha256='c'*64,
                visibility=dict(installation_sha256='d'*64)))
    for name,owner in f.owners.items():
        owner.backend = f.backend
        state = dict(stopped=False, loaded=None)
        owner.test_state = state
        original = owner.status
        def status(*, owner=owner, original=original, state=state):
            if state['stopped']:
                raise OnboardingError('synthetic_stopped')
            result = original()
            if state['loaded']:
                result['runtime_status'].update(loaded_runtime=copy.deepcopy(state['loaded']['loaded_runtime']),
                    loaded_application=copy.deepcopy(state['loaded']['loaded_application']),
                    receiving=dict(rosters=dict(tribe=dict(schema='dm.runtime.tribe-roster/v1', roster_sha256='5'*64))))
                result['admission_parent'] = dict(uid=1,pid=1,start_ticks=2,boot_id='fixture')
            return result
        owner.status = status
    def prepare(_backend, value, selected_journal, request, **options):
        active_journal[0] = selected_journal
        name = value['name']
        if name not in children:
            cohort = updates.CohortController(selected_journal, row['operation_id'], f.owners)
            result = admission_child_fixture(f.store.root.parent, profile=profiles[name], name=name, with_group=False, with_exit=False,
                setup=(cohort,f.owners,selected_journal,row,f.activation))
            children[name] = dict(recipe=result[4], effects=result[6])
        return dict(schema='cluster-'+profiles[name]+'-admission-prepared/v1', operation_id=children[name]['recipe']['lifecycle_operation_id'],
            request_sha256=digest(request), cohort_operation_id=row['operation_id'], cohort_intent_sha256=digest(row['intent']),
            receiving_readiness='unobserved')
    monkeypatch.setattr(updates, 'prepare_guest_admission', prepare)
    if settings.get('source'):
        f.owners['eko'].prepare_admission_lifecycle = lambda request:prepare(f.backend,f.plans['eko'],active_journal[0],request)
    def schema(request, **options):
        if request['action'] == 'context-preview':
            return dict(owner_context_sha256='6'*64, predecessor_selection_sha256=None,
                communication_plan=dict(target_version=4, plan_sha256='8'*64))
        return dict(schema='cluster-group-publication-result/v1', **{key:request[key] for key in ('operation_id','step','action')},
            status='recorded', receiving_readiness='unobserved', migration=dict(target_version=4, source_plan_sha256='8'*64))
    f.owners['newcomer'].group_publication = schema
    class Controller:
        def __init__(self, _journal, operation, backend, name):
            active_journal[0] = _journal
            assert operation == children[name]['recipe']['lifecycle_operation_id']
            self.name = name
        def quiesce(self, **options):
            calls.append('quiesce-'+self.name)
            f.owners[self.name].test_state['stopped'] = True
            result = children[self.name]['effects']['quiesced']
            child_effect(self.name, 'quiesced', result)
            return result
        def preserve(self, **options):
            calls.append('preserve-'+self.name)
            return {'preserved':True}
        def retain_admission_group(self, **options):
            calls.append('derive-'+self.name)
            value = children[self.name]['effects']['admission_group']
            child_effect(self.name, 'admission_group', value)
            return value
        def execute(self, **options):
            name, owner = self.name, f.owners[self.name]
            if owner.test_state['loaded'] is None:
                calls.append('load-'+name)
                owner.process = {**owner.process, 'start_ticks':owner.process['start_ticks']+1}
                owner.gate = {**owner.gate, 'phase':'unselected', 'process_instance_id':name+':replacement', 'readers':[]}
                owner.test_state.update(stopped=False, loaded=loaded(name))
                child_effect(name, 'controlled_loaded', owner.test_state['loaded'])
            lose('load-'+name)
            return owner.test_state['loaded']
        def observe_quiescence(self, **options):
            exited = children[self.name]['effects']['quiesced']
            return dict(schema=('cluster-source-bootstrap-quiescence/v1' if profiles[self.name] == 'source'
                    else 'cluster-guest-service-quiescence-observation/v1'), process=exited['process'],
                exit_sha256=digest(exited), service=dict(manager=dict(ActiveState='inactive',SubState='dead',MainPID='0')))
    monkeypatch.setattr(updates, 'GuestBootstrapController', Controller)
    if settings.get('source'):
        def source_action(operation,action):
            controller = Controller(active_journal[0],operation,f.backend,'eko')
            return {'quiesce':controller.quiesce,'preserve':controller.preserve,
                'derive':controller.retain_admission_group,'start':controller.execute,
                'quiescence':controller.observe_quiescence}[action]()
        f.owners['eko'].lifecycle_action = source_action
    def membership(cohort, **options):
        active_journal[0] = cohort.journal
        current = journal.get(row['operation_id'])
        if 'membership_admission' not in (current['runtime_observation'] or {}):
            cohort.require_revocation_barrier()
            calls.append('membership')
            result = {'schema':'cluster-native-membership-admission/v1'}
            retain('membership_admission', dict(recipe_sha256=digest(social),result=result,result_sha256=digest(result)))
        return journal.get(row['operation_id'])['runtime_observation']['membership_admission']['result']
    monkeypatch.setattr(updates.CohortController, 'admit_membership', membership)
    def publish(cohort, **options):
        active_journal[0] = cohort.journal
        current = journal.get(row['operation_id'])
        if 'group_publication' in (current['runtime_observation'] or {}):
            return current['runtime_observation']['group_publication']['result']
        cohort.require_revocation_barrier()
        calls.append('publication')
        requests = {}
        for name,owner in f.owners.items():
            group = dict(selected=dict(channel_id='tribe',tribe_ref='tribe:fixture',socket=str(owner.socket),
                application=str(owner.root/'application'),visibility=str(owner.root/'visibility')),
                application_sha256='b'*64,publication_sha256='c'*64,installation_sha256='d'*64)
            snapshots[name] = dict(group=group)
            if name in children:
                requests[name] = {}
                publications = children[name]['effects']['admission_group']['snapshot']['publications']
                for action,key in (('application','application'),('visibility-publish','visibility'),('selection','selection')):
                    command = {'action':action,'owner':name}
                    publications[action]['command_sha256'] = digest(command)
                    requests[name][key] = dict(command=command,result=publications[action]['result'])
        result = dict(schema='cluster-admission-group-publications/v1',snapshots=snapshots)
        membership = current['runtime_observation']['membership_admission']
        retain('group_publication',dict(result=result,result_sha256=digest(result),requests=requests,
            recipe_sha256=digest(transition['admission_publications']),membership_sha256=membership['result_sha256']))
        lose('publication')
        return result
    monkeypatch.setattr(updates.CohortController, 'publish_admission_group', publish)
    def initial(self, value, cohort, **options):
        active_journal[0] = cohort.journal
        name = value['name']
        owner = f.owners[name]
        if owner.test_state['loaded'] is None:
            calls.append('initial-load')
            owner.test_state['loaded'] = loaded(name)
            retain('initial_managed',{name:dict(intent=dict(owner=dict(origin=owner.server)),controlled_loaded=owner.test_state['loaded'])})
        lose('initial-load')
        return owner.test_state['loaded']
    monkeypatch.setattr(type(f.managed),'execute_initial',initial)
    f.owners['newcomer'].prepare_attachment = lambda request,**options: calls.append('attachment') or {'prepared':True}
    def activate(cohort):
        active_journal[0] = cohort.journal
        current = journal.get(row['operation_id'])['runtime_observation']
        if 'sender_selections' in current:
            if fault['restarted']:
                raise OnboardingError('receiving_cohort_selection_changed')
            return current['portal_admission']['activation_ready']
        calls.append('activation')
        records = {name:{'observed':name} for name in f.owners}
        readers = [{'being_ref':owner.being,'embodiment_id':owner.server['embodiment_id'],
            'expires_at_ms':admission['activation']['expires_at_ms']} for owner in f.owners.values()]
        retain('cohort_activation',dict(records=records,readers=readers,evidence_sha256=digest(records)))
        selections = {name:{'selected':name} for name in f.owners}
        retain('sender_selections',selections)
        retain('native_tooling',{name:{'configured':True} for name in f.owners})
        return dict(schema='cluster-receiving-cohort-selection/v1',operation_id=row['operation_id'],
            sender_selections=selections,readers=readers,evidence_sha256=digest(records))
    monkeypatch.setattr(updates.CohortController,'activate',activate)
    def steady(self,value,cohort,**options):
        active_journal[0] = cohort.journal
        phases = journal.get(row['operation_id'])['runtime_observation']['portal_admission']
        result = dict(schema='cluster-managed-initial-steady/v1', initial_sha256=digest(f.owners['newcomer'].test_state['loaded']),
            cohort_selection_sha256=digest(phases['activation_ready']))
        if 'initial_steady' not in journal.get(row['operation_id'])['runtime_observation']:
            calls.append('steady')
            retain('initial_steady',{'newcomer':{'completed':result}})
        lose('steady')
        return result
    monkeypatch.setattr(type(f.managed),'complete_initial',steady)
    for name,owner in f.owners.items():
        def messaging(method,parameters,*,name=name,owner=owner,**options):
            send_id = parameters['send_id']
            if method == 'messaging_delivery':
                if send_id not in messages:
                    raise OnboardingError('receiving_communication_unobserved')
                response = copy.deepcopy(messages[send_id])
                echo = fault['echo'] and (fault['reply_echo'] or response['result']['response_context'] is None)
                response['result']['visibility'].update(echo_state='confirmed' if echo else 'pending')
                return response
            if send_id in messages:
                calls.append('resume-'+method)
                if fault['busy']:
                    for leg in messages[send_id]['result']['semantic']['legs']:
                        leg['state'] = 'delivered'
                    fault['busy'] = False
                return copy.deepcopy(messages[send_id])
            assert send_id not in messages, 'an uncertain send must be inspected, never reauthored'
            calls.append(method)
            author = dict(being_ref=owner.being,embodiment_id=owner.server['embodiment_id'])
            parent = next((response['result'] for response in messages.values()
                if response['result']['message_id'] == parameters.get('message_id')),None)
            target = parameters.get('destination')
            audience = [dict(membership_ref='membership:'+other,being_ref=who.being,embodiment_id=who.server['embodiment_id'])
                for other,who in f.owners.items() if target is None or who.being == target['being_ref']]
            result = dict(schema='dm.tribe.direct-delivery/v1' if target else 'dm.tribe.delivery/v1',
                send_id=send_id,message_id=str(uuid.uuid4()),message_hash=digest(parameters),tribe_ref='tribe:fixture',author=author,
                thread_id=parent['thread_id'] if parent else parameters['thread_id'],
                response_context=(dict(message_id=parent['message_id'],message_hash=parent['message_hash'],
                    sender_being_ref=parent['author']['being_ref'],sender_embodiment_id=parent['author']['embodiment_id']) if parent else None),
                visibility=dict(echo_state='confirmed' if fault['echo'] else 'pending',part_count=2,confirmed_parts=2),audience=audience,
                semantic=dict(legs=[]))
            if target:
                result['destination'] = target
            for item in audience:
                result['semantic']['legs'].append(dict(recipient_id=item['membership_ref'],receipt_origin_embodiment_id=item['embodiment_id'],
                    message_id=result['message_id'],thread_id=result['thread_id'],state='delivered',
                    terminal_receipt_event_id=str(uuid.uuid4()),terminal_receipt_hash='a'*64))
            if fault['busy']:
                for leg in result['semantic']['legs']:
                    leg['state'] = 'pending'
            if parent is not None and not fault['reply_echo']:
                result['visibility']['echo_state'] = 'pending'
            messages[send_id] = dict(schema='dm.local.response/v1',ok=True,error=None,result=result)
            lose('message')
            return copy.deepcopy(messages[send_id])
        owner.messaging = messaging
    observe = f.stages.observe
    f.stages.observe = lambda value,stage,operation: (GroupCoordinator(f.backend).observe(value) if stage == 'matrix'
        else observe(value,stage,operation))
    worker = Worker(f.store,lambda:f.stages,advance_group_admission=lambda name:GroupCoordinator(f.backend).advance(name))
    return SimpleNamespace(f=f,journal=journal,row=row,calls=calls,fault=fault,messages=messages,worker=worker)


@pytest.mark.parametrize('lost_phase',[None,'publication','load-eko','initial-load','steady','message'])
def test_full_worker_join_resumes_exact_effects_and_releases_only_complete_admission(full,lost_phase):
    x = full
    x.fault['phase'] = lost_phase
    first = x.worker._tick('newcomer')
    if lost_phase:
        assert first['state'] == 'attention-required'
        assert x.journal.get(x.row['operation_id'])['state'] != 'completed'
        retry = x.worker._tick('newcomer')
        assert retry['state'] != 'attention-required'
    current = x.journal.get(x.row['operation_id'])
    assert current['state'] == 'completed'
    assert GroupCoordinator(x.f.backend).observe(x.f.plans['newcomer']).state == 'complete'
    assert len(x.messages) == 3
    for phase in ('membership','publication','load-eko','load-oliva','initial-load','attachment','activation','steady'):
        assert x.calls.count(phase) == 1
    count = len(x.calls)
    assert GroupCoordinator(x.f.backend).advance('newcomer') is None
    assert len(x.calls) == count
    # A forged completed marker without the closure must not release the job.
    changed = copy.deepcopy(current['runtime_observation'])
    changed['portal_admission'].pop('communication-reply')
    x.journal.advance(current['operation_id'],'completed',runtime_observation=changed)
    with pytest.raises(OnboardingError,match='completion_unobserved'):
        GroupCoordinator(x.f.backend).observe(x.f.plans['newcomer'])


def test_unconfirmed_echo_waits_then_uses_only_delivery_inspection(full):
    x = full
    x.fault['echo'] = False
    x.worker._tick('newcomer')
    assert x.journal.get(x.row['operation_id'])['state'] != 'completed'
    assert len(x.messages) == 1
    x.fault['echo'] = True
    x.worker._tick('newcomer')
    assert x.journal.get(x.row['operation_id'])['state'] == 'completed'
    assert len(x.messages) == 3
    assert x.calls.count('activation') == 1


def test_pending_native_fanout_resumes_same_request_within_original_scope(full):
    x = full
    x.fault['busy'] = True
    x.worker._tick('newcomer')
    assert len(x.messages) == 1
    assert x.journal.get(x.row['operation_id'])['state'] != 'completed'
    original_id = next(iter(x.messages))
    x.worker._tick('newcomer')
    assert x.journal.get(x.row['operation_id'])['state'] == 'completed'
    assert original_id in x.messages and len(x.messages) == 3
    assert x.calls.count('resume-messaging_send') == 1
    assert x.calls.count('messaging_send') == 2


@pytest.mark.parametrize('full', [dict(channel='membership/tribe')], indirect=True)
def test_full_caller_routes_technical_checks_through_the_approved_public_alias(full):
    """Use the real SDK alias validator/normalizer at the owner boundary."""
    from daimon_matrix.agent_chat import MULTI_SCHEMA, checked_arguments, _link_arguments
    x = full
    binding = dict(schema=MULTI_SCHEMA, incoming_channels=['membership/tribe'],
        outgoing_channels=['membership/tribe'])
    routed = []
    for owner in x.f.owners.values():
        original = owner.messaging
        def messaging(method, parameters, *, original=original, **options):
            checked = checked_arguments(binding, method, parameters)
            alias, normalized = _link_arguments(method, checked)
            assert alias == 'membership'
            routed.append((method, copy.deepcopy(parameters)))
            return original(method, normalized, **options)
        owner.messaging = messaging
    x.fault['echo'] = False
    x.worker._tick('newcomer')
    x.fault['echo'] = True
    x.worker._tick('newcomer')
    current = x.journal.get(x.row['operation_id'])
    assert current['state'] == 'completed'
    assert len(x.messages) == 3
    assert {'messaging_send', 'messaging_delivery', 'messaging_reply'} <= {method for method, _ in routed}
    assert all(params['channel_id'] == 'membership/tribe' for _, params in routed)
    assert next(params for method, params in routed if method == 'messaging_reply')['received_channel_id'] == 'membership/tribe'
    # Alias selection is presentation/routing. The retained native request IDs
    # and reply context stay on the same canonical group.
    phases = current['runtime_observation']['portal_admission']
    assert all(phases['communication-intent-'+step]['parameters']['channel_id'] == 'tribe'
        for step in ('group', 'direct', 'reply'))


def test_restarted_receiver_cannot_borrow_an_old_selection_for_new_speech(full):
    x = full
    x.fault['echo'] = False
    x.worker._tick('newcomer')
    assert len(x.messages) == 1
    x.fault.update(echo=True,restarted=True)
    assert x.worker._tick('newcomer')['state'] == 'attention-required'
    assert len(x.messages) == 1
    assert x.journal.get(x.row['operation_id'])['state'] != 'completed'
    x.fault['restarted'] = False
    x.worker._tick('newcomer')
    assert x.journal.get(x.row['operation_id'])['state'] == 'completed'


def test_late_final_proof_completes_without_renewing_or_reauthoring(full,monkeypatch):
    x = full
    x.fault['reply_echo'] = False
    x.worker._tick('newcomer')
    assert len(x.messages) == 3
    assert x.journal.get(x.row['operation_id'])['state'] != 'completed'
    count = len(x.calls)
    expiry = x.row['intended_transition']['cohort_admission']['activation']['expires_at_ms']
    monkeypatch.setattr(module,'time',SimpleNamespace(monotonic_ns=time.monotonic_ns,time_ns=lambda:(expiry+1)*1_000_000))
    x.fault.update(reply_echo=True,restarted=True)
    x.worker._tick('newcomer')
    assert x.journal.get(x.row['operation_id'])['state'] == 'completed'
    assert len(x.calls) == count and len(x.messages) == 3


@pytest.mark.parametrize('full',[{'source':True}],indirect=True)
@pytest.mark.parametrize('lost_phase',[None,'load-eko'])
def test_source_owner_lifecycle_joins_the_same_worker_group_operation(full,lost_phase):
    test_full_worker_join_resumes_exact_effects_and_releases_only_complete_admission(full,lost_phase)


@pytest.mark.parametrize('full',[{'window_ms':5}],indirect=True)
def test_authoring_round_reuse_expires_with_the_original_observation_window(full,monkeypatch):
    x = full
    clock = [time.monotonic_ns()]
    monkeypatch.setattr(module,'time',SimpleNamespace(monotonic_ns=lambda:clock[0],time_ns=time.time_ns))
    observations = []
    activate = updates.CohortController.activate
    def observed(cohort):
        if 'sender_selections' in (cohort._row()['runtime_observation'] or {}):
            observations.append(clock[0])
        return activate(cohort)
    monkeypatch.setattr(updates.CohortController,'activate',observed)
    for owner in x.f.owners.values():
        original = owner.messaging
        def delayed(method,parameters,*,original=original,**options):
            result = original(method,parameters,**options)
            if method != 'messaging_delivery':
                clock[0] += 6_000_000
            return result
        owner.messaging = delayed
    x.worker._tick('newcomer')
    assert x.journal.get(x.row['operation_id'])['state'] == 'completed'
    assert len(observations) == 3

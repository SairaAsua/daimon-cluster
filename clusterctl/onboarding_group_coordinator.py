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
SOCIAL_CALLER_SCHEMA = 'cluster-portal-group-admission/v2'
SOURCE_FIELDS = frozenset({'config', 'config_sha256', 'owner_uid', 'owner_gid', 'code',
    'code_digest', 'code_uid', 'venv', 'imports', 'root', 'socket_path', 'lifecycle_journal'})
SOURCE_PATHS = frozenset({'config', 'code', 'venv', 'imports', 'root', 'socket_path', 'lifecycle_journal'})
COMMUNICATION_SCHEMA = 'cluster-admission-communication/v1'
COMPLETION_SCHEMA = 'cluster-portal-group-completion/v1'


def _path(value) -> bool:
    return isinstance(value, str) and Path(value).is_absolute() and '..' not in Path(value).parts


def communication_recipe(value: dict, row: dict, admission: dict) -> dict:
    """The protected operation explicitly selects its finite technical speech.

    This is an execution opt-in, not interruption consent. Old preparation-only
    operations cannot acquire effects by observing a later SDK or worker.
    """
    from daimon_matrix.tribe_conversation import direct_destination
    try:
        social = row['intended_transition']['portal_admission']['social']
        founder, entrant = social['founder_owner'], social['entrant_owner']
        if (set(value) != {'schema', 'expires_at_ms', 'group', 'direct', 'reply'}
                or value['schema'] != COMMUNICATION_SCHEMA
                or type(value['expires_at_ms']) is not int
                or not 0 < value['expires_at_ms'] <= admission['activation']['expires_at_ms']):
            raise ValueError
        for step, name in (('group', founder), ('direct', entrant), ('reply', entrant)):
            item = value[step]
            if (set(item) != {'sender', 'text'} | ({'destination'} if step == 'direct' else {'parent'} if step == 'reply' else set())
                    or item['sender'] != dict(owner=name, **{key:admission['receivers'][name][key]
                        for key in ('being_ref', 'embodiment_id')})
                    or not isinstance(item['text'], str) or not 1 <= len(item['text']) <= 2048):
                raise ValueError
        destination = direct_destination(value['direct']['destination'])
        if (destination != value['direct']['destination']
                or destination['being_ref'] != admission['receivers'][founder]['being_ref']
                or destination['kind'] == 'body' and destination['embodiment_id'] != admission['receivers'][founder]['embodiment_id']
                or value['reply']['parent'] != 'group'):
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_communication_scope_required') from None
    return copy.deepcopy(value)


def communication_result(response: dict, intent: dict, *, tribe_ref: str, parent: dict | None = None) -> dict:
    """Qualify authenticated projections; author retention is never uptake."""
    try:
        result = response['result']
        parameters = intent['parameters']
        direct = intent['step'] == 'direct'
        if (intent['step'] not in {'group', 'direct', 'reply'}
                or (intent['step'] == 'reply') != (parent is not None)
                or parameters.get('channel_id') != 'tribe'
                or response.get('schema') != 'dm.local.response/v1' or response.get('ok') is not True
                or response.get('error') is not None or not isinstance(result, dict)
                or result.get('schema') != ('dm.tribe.direct-delivery/v1' if direct else 'dm.tribe.delivery/v1')
                or result['send_id'] != parameters['send_id'] or result['tribe_ref'] != tribe_ref
                or result['author'] != {key:intent['sender'][key] for key in ('being_ref', 'embodiment_id')}
                or str(uuid.UUID(result['message_id'])) != result['message_id']
                or re.fullmatch('[0-9a-f]{64}', result['message_hash']) is None):
            raise ValueError
        if parent is None:
            if result['thread_id'] != parameters['thread_id'] or result['response_context'] is not None:
                raise ValueError
        elif (parameters.get('message_id') != parent['message_id']
                or parameters.get('received_channel_id') != 'tribe'
                or result['thread_id'] != parent['thread_id'] or result['response_context'] != dict(
                message_id=parent['message_id'], message_hash=parent['message_hash'],
                sender_being_ref=parent['author']['being_ref'], sender_embodiment_id=parent['author']['embodiment_id'])):
            raise ValueError
        visibility = result['visibility']
        if (not isinstance(visibility, dict) or visibility.get('echo_state') != 'confirmed'
                or type(visibility.get('part_count')) is not int or visibility['part_count'] <= 0
                or visibility.get('confirmed_parts') != visibility['part_count']):
            raise ValueError
        if direct:
            target = parameters['destination']
            if (any(result.get('destination', {}).get(key) != value for key,value in target.items())
                    or any(item['being_ref'] != target['being_ref']
                        or target['kind'] == 'body' and item['embodiment_id'] != target['embodiment_id']
                        for item in result['audience'])):
                raise ValueError
        elif 'destination' in result:
            raise ValueError
        audience = {(item['membership_ref'], item['embodiment_id']):item for item in result['audience']}
        if len(audience) != len(result['audience']):
            raise ValueError
        inbound = []
        for leg in result['semantic']['legs']:
            item = audience.get((leg['recipient_id'], leg['receipt_origin_embodiment_id']))
            if item is None or leg['message_id'] != result['message_id'] or leg['thread_id'] != result['thread_id']:
                raise ValueError
            if (leg['state'] == 'delivered' and (item['being_ref'], item['embodiment_id']) !=
                    (result['author']['being_ref'], result['author']['embodiment_id'])):
                if (str(uuid.UUID(leg['terminal_receipt_event_id'])) != leg['terminal_receipt_event_id']
                        or re.fullmatch('[0-9a-f]{64}', leg['terminal_receipt_hash']) is None):
                    raise ValueError
                inbound.append(dict(being_ref=item['being_ref'], embodiment_id=item['embodiment_id'],
                    receipt_id=leg['terminal_receipt_event_id'], receipt_sha256=leg['terminal_receipt_hash']))
        return dict(message_id=result['message_id'], message_hash=result['message_hash'],
            thread_id=result['thread_id'], author=result['author'], response_context=result['response_context'],
            visibility=visibility, inbound=inbound, response_sha256=digest(response))
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('receiving_communication_unobserved') from None


def loaded_selection(loaded: dict) -> dict:
    """Use the same six observed pins as the existing receiving adopter."""
    try:
        runtime, application = loaded['loaded_runtime'], loaded['loaded_application']
        startup = runtime['qualified_startup']
        value = dict(receiving_code=startup['code_digest'], matrix_sdk=startup['matrix_wheel_sha256'],
            runtime_bundle_sha256=runtime['runtime_bundle_sha256'], application_sha256=application['application_sha256'],
            publication_sha256=application['publication_sha256'],
            visibility_installation_sha256=application['visibility']['installation_sha256'])
        if any(not isinstance(item, str) or re.fullmatch('[0-9a-f]{64}', item) is None for item in value.values()):
            raise ValueError
        return value
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_load_unobserved') from None


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
                or not isinstance(caller, dict)):
            raise OnboardingError('onboarding_group_admission_binding_changed')
        expected: dict = dict(schema=CALLER_SCHEMA, plan_digest=digest(plan),
            matrix_operation_id=JobStore.operation_id(digest(plan), 'matrix'),
            owners_sha256=digest({name: self.settings['owners'][name] for name in admission['receivers']}))
        if caller.get('schema') == SOCIAL_CALLER_SCHEMA:
            from .onboarding_group_admission import membership_recipe
            expected.update(schema=SOCIAL_CALLER_SCHEMA, social=membership_recipe(
                caller.get('social', {}), admission, before.get('senders', [])))
        if caller != expected:
            raise OnboardingError('onboarding_group_admission_binding_changed')
        preparations = after.get('admission_preparations')
        if preparations is not None:
            old = {item['name'] for item in before.get('senders', [])}
            if (caller['schema'] != SOCIAL_CALLER_SCHEMA or not isinstance(preparations, dict)
                    or set(preparations) != old):
                raise OnboardingError('onboarding_group_admission_preparations_required')
            for name, preparation in preparations.items():
                profile = self.settings['owners'][name]['profile']
                fields = {'profile', 'steps'} | ({'unit', 'home'} if profile == 'source' else set())
                if (not isinstance(preparation, dict) or set(preparation) != fields
                        or preparation['profile'] != profile or not isinstance(preparation['steps'], dict)
                        or set(preparation['steps']) != {'application', 'visibility', 'selection', 'snapshot'}
                        or any(not isinstance(step, str) or re.fullmatch('[a-z][a-z0-9-]{0,79}', step) is None
                               for step in preparation['steps'].values())
                        or len(set(preparation['steps'].values())) != 4
                        or profile == 'source' and any(not _path(preparation[key]) for key in ('unit', 'home'))
                        or profile == 'guest' and not _path(before.get('host_config'))):
                    raise OnboardingError('onboarding_group_admission_preparations_required')
        if 'admission_publications' in after:
            from .onboarding_group_admission import publication_recipe
            if caller['schema'] != SOCIAL_CALLER_SCHEMA:
                raise OnboardingError('onboarding_group_publication_recipe_required')
            publication_recipe(after['admission_publications'], admission, caller['social'],
                before['senders'], preparations)
        if 'admission_communication' in after:
            if (caller['schema'] != SOCIAL_CALLER_SCHEMA or preparations is None
                    or 'admission_publications' not in after
                    or any(item['recipe']['tooling']['profile'] != 'codex' for item in admission['receivers'].values())):
                raise OnboardingError('onboarding_group_finisher_scope_required')
            communication_recipe(after['admission_communication'], row, admission)
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
        _journal, row, admission = selected
        # Only the completed receiving transaction can release the normal
        # stage's actual managed-presence check. Native preparation is not it.
        if row['state'] != 'completed':
            return Observation('waiting', reason='group_admission_pending')
        if (row.get('result') != self._completion(row, admission)
                or (row['runtime_observation'] or {}).get('portal_admission', {}).get('completed') != row['result']):
            raise OnboardingError('onboarding_group_completion_unobserved')
        return Observation('complete', dict(verified=True, identity_verified=True))

    def selection(self, plan: dict) -> tuple[dict, dict, dict]:
        """A locator is usable only after this admission's complete closure."""
        bound = self._binding(plan)
        if bound is None or bound[1]['state'] != 'completed':
            raise OnboardingError('onboarding_group_admission_pending')
        self.observe(plan)
        _journal, row, admission = bound
        approved = admission['receivers'][plan['name']]
        group = row['runtime_observation']['group_publication']['result']['snapshots'][plan['name']]['group']['selected']
        if (group.get('channel_id') != 'tribe' or group.get('socket') != approved['socket']
                or group.get('tribe_ref') != admission['tribe_ref']):
            raise OnboardingError('receiving_native_tooling_group_changed')
        return row, approved, group

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

    def _completion(self, row: dict, admission: dict) -> dict:
        """Revalidate historical closure without restarting or renewing effects."""
        try:
            observations = row['runtime_observation'] or {}
            phases = observations['portal_admission']
            scope = communication_recipe(row['intended_transition']['admission_communication'], row, admission)
            names = set(admission['receivers'])
            old = {item['name'] for item in row['expected_precondition']['senders']}
            caller = row['intended_transition']['portal_admission']
            entrant = caller['social']['entrant_owner']
            intent = dict(cohort_intent_sha256=digest(row['intent']), plan_digest=caller['plan_digest'],
                owners_sha256=caller['owners_sha256'], communication_scope_sha256=digest(scope))
            membership, publication = observations['membership_admission'], observations['group_publication']
            activation = observations['admission_activation_plan']
            plan = activation['plan']
            selected = phases['activation_ready']
            steady = phases['steady_ready']
            if (phases['execution_intent'] != intent or membership['recipe_sha256'] != digest(caller['social'])
                    or membership['result_sha256'] != digest(membership['result'])
                    or publication['result_sha256'] != digest(publication['result'])
                    or publication['membership_sha256'] != membership['result_sha256']
                    or publication['recipe_sha256'] != digest(row['intended_transition']['admission_publications'])
                    or set(publication['result']['snapshots']) != names
                    or set(observations['admission_lifecycles']) != old
                    or activation['admission_sha256'] != digest(admission) or activation['plan_sha256'] != digest(plan)
                    or any(plan[key] != value for key,value in admission['activation'].items())
                    or set(plan['receivers']) != names or set(observations['sender_selections']) != names
                    or set(observations['cohort_activation']['records']) != names
                    or selected['schema'] != 'cluster-receiving-cohort-selection/v1'
                    or selected['operation_id'] != row['operation_id']
                    or selected['sender_selections'] != observations['sender_selections']
                    or selected['readers'] != observations['cohort_activation']['readers']
                    or selected['evidence_sha256'] != observations['cohort_activation']['evidence_sha256']
                    or steady != observations['initial_steady'][entrant]['completed']
                    or steady['schema'] != 'cluster-managed-initial-steady/v1'
                    or steady['cohort_selection_sha256'] != digest(selected)
                    or steady['initial_sha256'] != digest(observations['initial_managed'][entrant]['controlled_loaded'])
                    or 'cohort_reassessment' in observations):
                raise ValueError
            proofs: dict[str, dict] = {}
            inbound: set[tuple[str, str]] = set()
            for name, approved in admission['receivers'].items():
                recipe = plan['receivers'][name]
                if (any(recipe[key] != value for key,value in approved['recipe'].items())
                        or recipe['selection'] != loaded_selection(phases['loaded-'+name])
                        or recipe['lifecycle_operation_id'] != (row['operation_id'] if name == entrant
                            else observations['admission_lifecycles'][name]['lifecycle_operation_id'])
                        or recipe['tooling']['profile'] == 'codex' and name not in observations['native_tooling']):
                    raise ValueError
            for step in ('group', 'direct', 'reply'):
                saved = phases['communication-'+step]
                expected = self._communication_intent(row, scope, step, proofs.get('group'))
                if saved['intent'] != expected or phases['communication-intent-'+step] != expected:
                    raise ValueError
                proof = communication_result(saved['response'], expected, tribe_ref=admission['tribe_ref'],
                    parent=proofs.get('group') if step == 'reply' else None)
                if proof != saved['proof']:
                    raise ValueError
                proofs[step] = proof
                inbound.update((item['being_ref'],item['embodiment_id']) for item in proof['inbound'])
            if not {(item['being_ref'],item['embodiment_id']) for item in admission['receivers'].values()} <= inbound:
                raise ValueError
            # Hash the retained producer evidence too: a completed marker alone
            # must not release the target or select a runtime for a later stage.
            keys = ('membership_admission', 'group_publication', 'admission_lifecycles', 'initial_managed',
                'admission_activation_plan', 'native_tooling', 'cohort_activation', 'sender_revocations',
                'sender_replacements', 'sender_initials', 'sender_selections', 'initial_steady')
            retained = {key:value for key,value in phases.items() if key != 'completed'}
            return dict(schema=COMPLETION_SCHEMA, operation_id=row['operation_id'],
                plan_digest=caller['plan_digest'], manifest_digest=row['intent']['runtime_call']['manifest_digest'],
                evidence_sha256=digest(dict(phases=retained, **{key:observations.get(key) for key in keys})),
                receiving_readiness='qualified-local-projection', communication_acceptance='signed-intake-and-confirmed-echo')
        except (KeyError, TypeError, ValueError, AttributeError, OnboardingError):
            raise OnboardingError('onboarding_group_completion_unobserved') from None

    @staticmethod
    def _communication_intent(row: dict, scope: dict, step: str, parent: dict | None) -> dict:
        send_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'portal-communication:'+row['operation_id']+':'+step))
        item = scope[step]
        parameters = dict(channel_id='tribe', send_id=send_id, text=item['text'])
        if step == 'reply':
            if parent is None:
                raise OnboardingError('receiving_communication_unobserved')
            parameters.update(received_channel_id='tribe', message_id=parent['message_id'])
        else:
            parameters['thread_id'] = str(uuid.uuid5(uuid.NAMESPACE_URL,
                'portal-communication-thread:'+row['operation_id']+':'+step))
            if step == 'direct':
                parameters['destination'] = item['destination']
        return dict(step=step, sender=item['sender'], parameters=parameters)

    def _finish(self, plan, journal, row, admission, cohort, *, deadline_ns: int) -> dict:
        """Join maintained lifecycle, activation and communication operations.

        Only the closed, explicitly scoped full operation can enter here. Old
        preparation-only bindings never gain interruption or messaging effects.
        """
        from .onboarding_managed import ManagedRuntime
        from .onboarding_receiving_update import GuestBootstrapController
        scope = communication_recipe(row['intended_transition']['admission_communication'], row, admission)
        caller = row['intended_transition']['portal_admission']
        def current():
            return journal.get(row['operation_id'])
        def phases():
            return (current()['runtime_observation'] or {}).get('portal_admission', {})
        def remaining():
            seconds = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
            if seconds <= 0:
                raise OnboardingError('receiving_host_deadline_expired')
            return seconds
        def retain(key, value):
            remaining()
            self._retain(journal, row, key, value)
        def authorized():
            remaining()
            with self._job_scope(plan):
                self._binding(plan)
        managed = ManagedRuntime(self.backend)
        if 'admission_activation_plan' not in (current()['runtime_observation'] or {}):
            authorized()
            if ('execution_intent' not in phases()
                    and time.time_ns() // 1_000_000 >= admission['activation']['expires_at_ms']):
                raise OnboardingError('receiving_preservation_authorization_expired')
            # Fresh exact endpoint checks precede the first interruption, even
            # if the earlier preparation was retained by another worker turn.
            if 'execution_intent' not in phases():
                for name, receiver in sorted(admission['receivers'].items()):
                    cohort.owners[name].preflight_native(Path(receiver['recipe']['tooling']['native_endpoint']))
                    remaining()
            retain('execution_intent', dict(cohort_intent_sha256=digest(row['intent']),
                plan_digest=caller['plan_digest'], owners_sha256=caller['owners_sha256'],
                communication_scope_sha256=digest(scope)))
            cohort.revoke_senders()
            for name in sorted(row['intended_transition']['admission_preparations']):
                authorized()
                recipe, _child = cohort._bound_admission_lifecycle(current(), name)
                if 'loaded-'+name in phases():
                    continue
                if 'preserved-'+name not in phases():
                    if recipe['profile'] == 'source':
                        owner = cohort.owners[name]
                        if 'quiesced-'+name not in phases():
                            retain('quiesced-'+name, dict(result_sha256=digest(owner.lifecycle_action(
                                recipe['lifecycle_operation_id'], 'quiesce'))))
                        result = owner.lifecycle_action(recipe['lifecycle_operation_id'], 'preserve')
                    else:
                        controller = GuestBootstrapController(journal, recipe['lifecycle_operation_id'], self.backend, name)
                        if 'quiesced-'+name not in phases():
                            retain('quiesced-'+name, dict(result_sha256=digest(controller.quiesce(timeout_seconds=remaining(), deadline_ns=deadline_ns))))
                        result = controller.preserve(timeout_seconds=remaining(), deadline_ns=deadline_ns)
                    retain('preserved-'+name, dict(result_sha256=digest(result)))
            authorized()
            cohort.admit_membership(deadline_ns=deadline_ns)
            cohort.publish_admission_group(deadline_ns=deadline_ns)
            for name in sorted(row['intended_transition']['admission_preparations']):
                authorized()
                recipe, _child = cohort._bound_admission_lifecycle(current(), name)
                if 'loaded-'+name in phases():
                    continue
                if recipe['profile'] == 'source':
                    owner = cohort.owners[name]
                    if 'derived-'+name not in phases():
                        retain('derived-'+name, dict(result_sha256=digest(owner.lifecycle_action(
                            recipe['lifecycle_operation_id'], 'derive'))))
                    loaded = owner.lifecycle_action(recipe['lifecycle_operation_id'], 'start')
                else:
                    controller = GuestBootstrapController(journal, recipe['lifecycle_operation_id'], self.backend, name)
                    closure = {ref:value for ref,value in caller['social']['authority_closure'].items()
                        if ref != admission['receivers'][name]['being_ref']}
                    if 'derived-'+name not in phases():
                        retain('derived-'+name, dict(result_sha256=digest(controller.retain_admission_group(
                            authority_closure=closure, timeout_seconds=remaining(), deadline_ns=deadline_ns))))
                    loaded = controller.execute(authority_closure=closure, timeout_seconds=remaining(), deadline_ns=deadline_ns)
                retain('loaded-'+name, loaded)
            authorized()
            entrant = plan['name']
            if 'loaded-'+entrant not in phases():
                loaded = managed.execute_initial(plan, cohort, timeout_seconds=remaining())
                # execute_initial has reconciled physical registry adoption too;
                # a native controlled_loaded marker alone cannot skip that work.
                retain('loaded-'+entrant, loaded)
            owner = cohort.owners[entrant]
            tooling = admission['receivers'][entrant]['recipe']['tooling']
            publication = current()['runtime_observation']['group_publication']['result']['snapshots'][entrant]['group']
            loaded = phases()['loaded-'+entrant]
            if 'attachment_ready' not in phases():
                request = dict(schema='cluster-group-chat-attachment/v1',
                    operation_id=str(uuid.uuid5(uuid.NAMESPACE_URL, 'portal-chat-attachment:'+row['operation_id'])),
                    runtime_root=str(owner.root), server=current()['runtime_observation']['initial_managed'][entrant]['intent']['owner']['origin'],
                    runtime_bundle_sha256=loaded_selection(loaded)['runtime_bundle_sha256'], group=publication)
                authorized()
                result = owner.prepare_attachment(request, attachment=Path(tooling['attachment']), codex_home=Path(tooling['codex_home']))
                retain('attachment_ready', result)
            cohort.retain_admission_activation(self._activation_plan(current(), admission, cohort, deadline_ns=deadline_ns))
        authorized()
        if 'host_runtime' in row['intended_transition'] and 'host_selection' not in (current()['runtime_observation'] or {}):
            cohort.apply_host_selection(Path(row['expected_precondition']['host_config']))
        if 'activation_ready' not in phases():
            retain('activation_ready', cohort.activate())
        if 'steady_ready' not in phases():
            retain('steady_ready', managed.complete_initial(plan, cohort, timeout_seconds=remaining()))
        authoring_until = 0
        def before_authoring():
            nonlocal authoring_until
            authorized()
            # Completed activation is an observation-only native path. Retained
            # ACKs cannot authorize new speech from a restarted receiver set.
            if time.monotonic_ns() >= authoring_until:
                begun = time.monotonic_ns()
                selected = cohort.activate()
                if selected != phases()['activation_ready']:
                    raise OnboardingError('receiving_cohort_selection_changed')
                reader_until = min(item['expires_at_ms'] for item in selected['readers'])
                authoring_until = min(deadline_ns,
                    begun + admission['activation']['observation_window_ms'] * 1_000_000,
                    time.monotonic_ns() + (reader_until-time.time_ns()//1_000_000)*1_000_000)
            if time.monotonic_ns() >= authoring_until:
                raise OnboardingError('receiving_cohort_observation_expired')
        if not self._communicate(plan, journal, row, admission, cohort.owners, scope,
                deadline_ns=deadline_ns, before_authoring=before_authoring):
            return dict(operation_id=row['operation_id'], receiving_readiness='qualified-local-projection',
                communication_acceptance='unobserved')
        authorized()
        row = current()
        complete = self._completion(row, admission)
        observations = copy.deepcopy(row['runtime_observation'])
        observations['portal_admission']['completed'] = complete
        journal.advance(row['operation_id'], 'completed', result=complete, runtime_observation=observations,
            expected_runtime_observation=row['runtime_observation'])
        remaining()
        return complete

    def _activation_plan(self, row: dict, admission: dict, cohort, *, deadline_ns: int) -> dict:
        """Derive late pins from actual loads and correlate owner publications."""
        from .onboarding_receiving_update import admission_lifecycle_projection
        observations = row['runtime_observation']
        snapshots = observations['group_publication']['result']['snapshots']
        plans, rosters = {}, set()
        old = {item['name'] for item in row['expected_precondition']['senders']}
        for name, approved in sorted(admission['receivers'].items()):
            loaded = observations['portal_admission']['loaded-'+name]
            selection = loaded_selection(loaded)
            group = snapshots[name]['group']
            if (selection['receiving_code'] != approved['recipe']['prepared']['code_digest']
                    or selection['matrix_sdk'] != approved['recipe']['prepared']['matrix_wheel_sha256']
                    or any(selection[key] != group[field] for key,field in (
                        ('application_sha256','application_sha256'), ('publication_sha256','publication_sha256'),
                        ('visibility_installation_sha256','installation_sha256')))):
                raise OnboardingError('onboarding_group_load_unobserved')
            lifecycle_id = row['operation_id']
            if name in old:
                recipe, child = cohort._bound_admission_lifecycle(row, name)
                lifecycle_id = recipe['lifecycle_operation_id']
                proof = child['admission'] if recipe['profile'] == 'source' else admission_lifecycle_projection(child, profile='guest', name=name)
                if not isinstance(proof, dict):
                    raise OnboardingError('receiving_admission_lifecycle_unobserved')
                derived = proof['derived']
                if not isinstance(derived, dict) or derived['group'] != {key:group[key] for key in (
                        'application_sha256','publication_sha256','installation_sha256')}:
                    raise OnboardingError('onboarding_group_publication_changed')
                for action, key in (('application','application'), ('visibility-publish','visibility'), ('selection','selection')):
                    request = observations['group_publication']['requests'][name][key]
                    if derived['publications'][action] != dict(command_sha256=digest(request['command']), result_sha256=digest(request['result'])):
                        raise OnboardingError('onboarding_group_publication_changed')
            if time.monotonic_ns() >= deadline_ns:
                raise OnboardingError('receiving_host_deadline_expired')
            observed = cohort.owners[name].status()
            if observed['process'] != loaded['process'] or observed['runtime_status']['loaded_runtime'] != loaded['loaded_runtime']:
                raise OnboardingError('onboarding_group_load_unobserved')
            roster = observed['runtime_status']['receiving']['rosters']['tribe']
            if (roster.get('schema') != 'dm.runtime.tribe-roster/v1'
                    or re.fullmatch('[0-9a-f]{64}', roster.get('roster_sha256','')) is None):
                raise OnboardingError('receiving_cohort_roster_unready')
            rosters.add(roster['roster_sha256'])
            plans[name] = {**approved['recipe'], 'selection':selection, 'lifecycle_operation_id':lifecycle_id}
        if len(rosters) != 1 or time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_cohort_roster_unready')
        return {**admission['activation'], 'roster_sha256':rosters.pop(), 'receivers':plans}

    def _communicate(self, plan: dict, journal, row: dict, admission: dict, owners: dict, scope: dict,
                     *, deadline_ns: int, before_authoring) -> bool:
        """One finite check per phase on worker cadence; exact IDs never renew."""
        proofs = {}
        for step in ('group', 'direct', 'reply'):
            phases = (journal.get(row['operation_id'])['runtime_observation'] or {}).get('portal_admission', {})
            if 'communication-'+step in phases:
                proofs[step] = phases['communication-'+step]['proof']
                continue
            intent = self._communication_intent(row, scope, step, proofs.get('group'))
            attempted = 'communication-intent-'+step in phases
            self._retain(journal, row, 'communication-intent-'+step, intent)
            if time.monotonic_ns() >= deadline_ns:
                raise OnboardingError('receiving_host_deadline_expired')
            owner = owners[intent['sender']['owner']]
            tooling = admission['receivers'][intent['sender']['owner']]['recipe']['tooling']
            binding = Path(tooling['attachment'])/tooling.get('binding_filename','binding.json')
            def call(method: str, parameters: dict, **options) -> dict:
                # The frozen intent identifies the native group. A configured
                # multi-link attachment exposes that same group under its
                # approved public alias; the SDK normalizes it before journaling.
                public = {**parameters, 'channel_id':tooling['tribe_channel']}
                if method == 'messaging_reply':
                    public['received_channel_id'] = tooling['tribe_channel']
                return owner.messaging(method, public, binding=binding, **options)
            response = None
            dispatched = False
            if attempted:
                try:
                    response = call('messaging_delivery', dict(channel_id='tribe', send_id=intent['parameters']['send_id']))
                except (OnboardingError, OSError):
                    pass
            if response is None:
                if time.time_ns() // 1_000_000 >= scope['expires_at_ms']:
                    return False
                before_authoring()
                response = call('messaging_reply' if step == 'reply' else 'messaging_send',
                    intent['parameters'], authoring_expires_at_ms=scope['expires_at_ms'])
                dispatched = True
            required = {(item['being_ref'],item['embodiment_id']) for item in admission['receivers'].values()
                if (item['being_ref'],item['embodiment_id']) != (intent['sender']['being_ref'],intent['sender']['embodiment_id'])}
            if step == 'direct':
                target = intent['parameters']['destination']
                required = {item for item in required if item[0] == target['being_ref']
                    and (target['kind'] != 'body' or item[1] == target['embodiment_id'])}
            def qualify(value):
                try:
                    proof = communication_result(value, intent, tribe_ref=admission['tribe_ref'],
                        parent=proofs.get('group') if step == 'reply' else None)
                except OnboardingError:
                    return None
                inbound = {(item['being_ref'],item['embodiment_id']) for item in proof['inbound']}
                return proof if required <= inbound else None
            proof = qualify(response)
            if (proof is None and attempted and not dispatched
                    and time.time_ns() // 1_000_000 < scope['expires_at_ms']):
                # Inspection cannot resume a busy/interrupted native fanout.
                # Replay the SAME durable request, never another message ID.
                before_authoring()
                response = call('messaging_reply' if step == 'reply' else 'messaging_send',
                    intent['parameters'], authoring_expires_at_ms=scope['expires_at_ms'])
                proof = qualify(response)
            if proof is None:
                return False
            if time.monotonic_ns() >= deadline_ns:
                raise OnboardingError('receiving_host_deadline_expired')
            self._retain(journal, row, 'communication-'+step, dict(intent=intent, response=response, proof=proof))
            proofs[step] = proof
        return True

    def advance(self, name: str, *, timeout_seconds: float = 30) -> dict | None:
        """Resume the approved admission, preserving preparation-only bindings.

        A complete v2 operation with explicit technical communication scope can
        join the retained lifecycle/publication/activation/receiving phases.
        Other bindings prepare their existing prerequisites without stopping.
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
                finishing = 'execution_intent' in retained
                expired = time.time_ns() // 1_000_000 >= admission['activation']['expires_at_ms']
                if expired:
                    request = retained.get('controller_intent')
                    if not finishing and (not native_prepared or 'physical_ready' not in retained
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
                if not finishing and not native_prepared and 'target_ready' not in retained:
                    if not self.backend.prepare_group_target(plan, candidate, deadline_ns=deadline):
                        return None
                    # Preparation is durable progress, never receiving acceptance.
                    # Do not spend every worker budget repeating the same SDK/V8
                    # checks before the first native endpoint can be inspected.
                    self._retain(journal, row, 'target_ready', dict(
                        plan_digest=digest(plan), code=str(candidate[0]), code_digest=candidate[1]))
                    remaining()
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
                if finishing:
                    return self._finish(plan, journal, row, admission, cohort, deadline_ns=deadline)
                if not native_prepared:
                    readiness = {}
                    for current in sorted(owners):
                        recipe = admission['receivers'][current]['recipe']['tooling']
                        if recipe['profile'] == 'matrix-only':
                            continue
                        ready_key = 'native_ready-' + current
                        phases = (journal.get(row['operation_id'])['runtime_observation'] or {}).get('portal_admission', {})
                        if ready_key in phases:
                            readiness[current] = phases[ready_key]
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
                        self._retain(journal, row, ready_key, observed)
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
                self._prepare_communication(plan, journal, row, admission, owners[name], deadline_ns=deadline)
                remaining()
                lifecycles = self._prepare_lifecycles(plan, journal, row, admission, cohort, deadline_ns=deadline)
                remaining()
                if 'admission_communication' in row['intended_transition']:
                    return self._finish(plan, journal, row, admission, cohort, deadline_ns=deadline)
                return dict(operation_id=row['operation_id'], native_prepared=True,
                    physical_prepared=True, controller_prepared=True, receiving_readiness='unobserved',
                    **({'lifecycle_prepared': True} if lifecycles else {}))

    def _prepare_communication(self, plan, journal, row, admission, owner, *, deadline_ns: int) -> None:
        """Retain the entrant's schema phase after controller tree publication.

        Reuse the existing owner route and original native plan. No old member
        is interrupted, and no capability publication is retried after DDL.
        """
        caller = row['intended_transition']['portal_admission']
        if caller['schema'] != SOCIAL_CALLER_SCHEMA:
            return
        def retained():
            return (journal.get(row['operation_id'])['runtime_observation'] or {}).get('portal_admission', {})
        with self._job_scope(plan):
            self._binding(plan)
        if 'communication_ready' in retained():
            return
        if time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_host_deadline_expired')
        social = caller['social']
        from .onboarding_group_admission import admission_owner_contexts
        context = admission_owner_contexts(journal.get(row['operation_id']), social)[plan['name']]
        authorities = {ref: value for ref, value in social['authority_closure'].items()
            if ref != admission['receivers'][plan['name']]['being_ref']}
        request = retained().get('communication_intent')
        if request is None:
            preview = owner.group_publication(dict(operation_id=social['operation_id'],
                step='communication-context', action='context-preview', params={}),
                authority_closure=authorities, expected_context_sha256=context)
            native = preview.get('communication_plan')
            if (preview.get('owner_context_sha256') != context
                    or preview.get('predecessor_selection_sha256') is not None
                    or not isinstance(native, dict) or native.get('target_version') not in {3, 4}
                    or re.fullmatch('[0-9a-f]{64}', native.get('plan_sha256', '')) is None):
                raise OnboardingError('onboarding_group_initial_schema_required')
            request = dict(operation_id=social['operation_id'], step='communication-prepare',
                action='communication-prepare', params=dict(expected_plan_sha256=native['plan_sha256'],
                    expires_at_ms=admission['activation']['expires_at_ms']))
            self._retain(journal, row, 'communication_intent', request)
        if time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_host_deadline_expired')
        result = owner.group_publication(request, authority_closure=authorities,
            expected_context_sha256=context)
        migration = result.get('migration', {})
        if (result.get('schema') != 'cluster-group-publication-result/v1'
                or result.get('status') != 'recorded'
                or any(result.get(key) != request[key] for key in ('operation_id', 'step', 'action'))
                or result.get('receiving_readiness') != 'unobserved'
                or migration.get('target_version') not in {3, 4}
                or migration.get('source_plan_sha256', migration.get('plan_sha256'))
                    != request['params']['expected_plan_sha256']):
            raise OnboardingError('onboarding_group_initial_schema_required')
        if time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_host_deadline_expired')
        self._retain(journal, row, 'communication_ready', result)

    def _prepare_lifecycles(self, plan, journal, row, admission, cohort, *, deadline_ns: int) -> bool:
        """Prepare/bind old lifecycles only; never stop without a full finisher."""
        from .onboarding_receiving_update import prepare_guest_admission
        preparations = row['intended_transition'].get('admission_preparations')
        if preparations is None:
            return False
        social = row['intended_transition']['portal_admission']['social']
        before = {item['name']: item for item in row['expected_precondition']['senders']}
        for name in sorted(preparations):
            if time.monotonic_ns() >= deadline_ns:
                raise OnboardingError('receiving_host_deadline_expired')
            with self._job_scope(plan):
                self._binding(plan)
            selected = preparations[name]
            owner = cohort.owners[name]
            identity = admission['receivers'][name]
            request = dict(schema='cluster-'+selected['profile']+'-admission-preparation/v1',
                operation_id=social['operation_id'], cohort_operation_id=row['operation_id'],
                cohort_intent_sha256=digest(row['intent']), tribe_ref=admission['tribe_ref'],
                owner={key: identity[key] for key in ('being_ref', 'embodiment_id')},
                predecessor={key: before[name][key] for key in ('process', 'server')},
                **{key: value for key, value in admission['activation'].items() if key != 'observation_window_ms'},
                manifest_digest=row['intent']['runtime_call']['manifest_digest'],
                authority_closure={ref: value for ref, value in social['authority_closure'].items()
                    if ref != identity['being_ref']}, owner_context_sha256=social['owner_contexts'][name],
                steps=selected['steps'])
            if selected['profile'] == 'source':
                request.update(home=selected['home'], unit=selected['unit'])
            else:
                request['root'] = str(owner.root)
            key = 'lifecycle-prepared-' + name
            current = journal.get(row['operation_id'])
            retained = (current['runtime_observation'] or {}).get('portal_admission', {}).get(key)
            if retained is None:
                if selected['profile'] == 'source':
                    result = owner.prepare_admission_lifecycle(request)
                else:
                    configured = self.settings['owners'][name]
                    result = prepare_guest_admission(self.backend, configured['plan'], journal, request,
                        config=Path(row['expected_precondition']['host_config']),
                        candidate=(Path(configured['candidate']['code']), configured['candidate']['digest']),
                        deadline_ns=deadline_ns)
                if (result.get('schema') != 'cluster-'+selected['profile']+'-admission-prepared/v1'
                        or result.get('request_sha256') != digest(request)
                        or result.get('cohort_operation_id') != row['operation_id']
                        or result.get('cohort_intent_sha256') != digest(row['intent'])
                        or result.get('receiving_readiness') != 'unobserved'):
                    raise OnboardingError('onboarding_group_admission_binding_changed')
                # The established binder independently validates the actual
                # private Source projection or local guest child, not this ACK.
                cohort.bind_admission_lifecycle(name, result['operation_id'])
                self._retain(journal, row, key, dict(request_sha256=digest(request), prepared=result))
            else:
                if retained.get('request_sha256') != digest(request):
                    raise OnboardingError('onboarding_group_admission_binding_changed')
                cohort.bind_admission_lifecycle(name, retained['prepared']['operation_id'])
        return True

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
                caller = row['intended_transition']['portal_admission']
                if caller['schema'] == SOCIAL_CALLER_SCHEMA:
                    social = caller['social']
                    request['group_context'] = dict(operation_id=social['operation_id'], owner_name=plan['name'],
                        authority_closure={ref:value for ref,value in social['authority_closure'].items()
                            if ref != approved['being_ref']}, expected_context_sha256=social['owner_contexts'][plan['name']])
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

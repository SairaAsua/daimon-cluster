"""Owner-local native relationship requests for shared group admission.

Authenticated relationship frames/results and their approved public authority
context are retained here. No transport, membership shortcut, background
attention or running-admission claim is added.
Offline callers must hold the native runtime writer for the entire invocation.
"""
from __future__ import annotations

import copy
import json
import os
import re
import time
import uuid
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path

from . import being_seed
from .onboarding import OnboardingError, digest, private_directory

METHODS = frozenset({'tribe.invite', 'tribe.membership.accept', 'relationship.event.ingest',
                     'relationship.snapshot'})
PUBLICATIONS = {
    'context-preview': set(),
    'application': {'expected_application_sha256', 'specification', 'additions',
                    'admitted_being_refs', 'secret_sources'},
    'visibility-disclosure': {'approved_destination', 'issued_at_ms'},
    'visibility-accept': {'approved_destination', 'disclosures'},
    'visibility-publish': {'disclosure', 'bindings', 'expected_installation_sha256', 'initial_configuration'},
    'selection': {'expected_selection_sha256'},
    'snapshot': {'application_step', 'visibility_step', 'selection_step', 'owner_context_sha256'},
}


def membership_recipe(value: dict, admission: dict, senders: list[dict]) -> dict:
    """Validate the protected social intent with the native signed reducer.

    Public signature consistency is not approval: the caller must obtain this
    recipe from its immutable receiving operation, never from portal input.
    """
    from daimon_matrix.operator_messaging import public_authority_history
    from daimon_matrix.relationship_store import RelationshipView
    from daimon_matrix.relationships import relationship_event_subject, validate_relationship_event_payload
    from daimon_matrix.weave import verify_event

    try:
        fields = {'schema', 'operation_id', 'founder_owner', 'entrant_owner', 'authority_closure',
                  'governance', 'invitation', 'membership_sequence', 'previous_membership_terminal_ref',
                  'acceptance_not_after_ms', 'owner_contexts'}
        receivers = admission['receivers']
        old = {row['name'] for row in senders}
        if (not isinstance(value, dict) or set(value) != fields
                or value['schema'] != 'cluster-membership-admission/v1'
                or str(uuid.UUID(value['operation_id'])) != value['operation_id']
                or value['founder_owner'] not in old or value['entrant_owner'] not in set(receivers) - old
                or not isinstance(value['authority_closure'], dict)
                or set(value['authority_closure']) != {row['being_ref'] for row in receivers.values()}
                or not isinstance(value['governance'], list) or not 1 <= len(value['governance']) <= 256
                or not isinstance(value['owner_contexts'], dict) or set(value['owner_contexts']) != set(receivers)
                or any(not isinstance(pin, str) or re.fullmatch('[0-9a-f]{64}', pin) is None
                       for pin in value['owner_contexts'].values())
                or type(value['membership_sequence']) is not int or value['membership_sequence'] < 0
                or type(value['acceptance_not_after_ms']) is not int
                or not 0 < value['acceptance_not_after_ms'] <= admission['activation']['expires_at_ms']):
            raise ValueError
        authorities = {}
        for ref, row in value['authority_closure'].items():
            if not isinstance(row, dict) or set(row) != {'authority', 'history'}:
                raise ValueError
            authority = public_authority_history(row['authority'], row['history'])
            if authority.active.manifest.being_ref != ref:
                raise ValueError
            authorities[ref] = authority
        founder = receivers[value['founder_owner']]['being_ref']
        entrant = receivers[value['entrant_owner']]['being_ref']
        if entrant != admission['entrant']['being_ref']:
            raise ValueError
        invitation = validate_relationship_event_payload('matrix/tribe-invitation', value['invitation'],
            author_being_ref=founder, causal_parents=[])
        if (invitation != value['invitation'] or invitation['tribe_ref'] != admission['tribe_ref']
                or invitation['founder_being_ref'] != founder or invitation['invitee_being_ref'] != entrant
                or not invitation['issued_at_ms'] < value['acceptance_not_after_ms'] <= invitation['expires_at_ms']):
            raise ValueError
        events = []
        for event in value['governance']:
            checked = verify_event(event, authorities[event['being_ref']])
            payload = validate_relationship_event_payload(checked['kind'], checked['payload'],
                author_being_ref=checked['being_ref'], causal_parents=checked['causal_parents'])
            if (not checked['kind'].startswith('matrix/tribe-') or payload.get('tribe_ref') != admission['tribe_ref']
                    or checked['subject'] != relationship_event_subject(checked['kind'], payload)):
                raise ValueError
            events.append(checked)
        view = RelationshipView(events, at_ms=invitation['issued_at_ms'], card_verifier=None)
        tribe = view.tribes[admission['tribe_ref']]
        if (len(view.complete) != len(events) or len({event['event_id'] for event in events}) != len(events)
                or tribe['state'] != 'active' or tribe['founder_being_ref'] != founder
                or tribe['founder_epoch'] != invitation['founder_epoch']
                or {ref for ref, row in tribe['memberships'].items() if row['state'] == 'active'}
                    != {row['being_ref'] for row in senders}):
            raise ValueError
        previous = tribe['memberships'].get(entrant)
        episodes = [] if previous is None else previous['episodes']
        terminal = None if not episodes else episodes[-1].get('terminal_event')
        expected_terminal = None if terminal is None else dict(event_id=terminal['event_id'], event_hash=terminal['content_hash'])
        if (previous is not None and previous['state'] not in {'left', 'expelled'}
                or value['membership_sequence'] != len(episodes)
                or value['previous_membership_terminal_ref'] != expected_terminal):
            raise ValueError
        digest(value)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_membership_recipe_required') from None
    return copy.deepcopy(value)


def admit_membership(cohort, *, deadline_ns: int) -> dict:
    """Resume the fixed native social phase; never publish or enable a group.

    The physical caller still owns preparing/binding every old lifecycle and
    stopping its Matrix service. This phase requires their observed quiescence,
    uses only the operation's protected recipe and retains commands before RPC.
    """
    from daimon_matrix.relationships import (
        MEMBERSHIP_ACCEPTANCE_SCHEMA, relationship_event_subject, validate_relationship_event_payload,
    )
    from daimon_matrix.weave import verify_event
    from daimon_matrix.operator_messaging import public_authority_history

    def budget():
        if type(deadline_ns) is not int or time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('onboarding_group_relationship_deadline_expired')

    with cohort.journal.mutation_lock(cohort.operation_id), ExitStack() as scope:
        row = cohort._row()
        admission = cohort._admission(row)
        portal = row['intended_transition'].get('portal_admission', {})
        if admission is None or portal.get('schema') != 'cluster-portal-group-admission/v2':
            raise OnboardingError('onboarding_group_membership_recipe_required')
        recipe = membership_recipe(portal.get('social'), admission, row['expected_precondition']['senders'])
        budget()
        previous = (row['runtime_observation'] or {}).get('membership_admission')
        if previous is not None:
            if previous.get('recipe_sha256') != digest(recipe):
                raise OnboardingError('onboarding_group_membership_intent_changed')
            if previous.get('result') is not None:
                result = previous['result']
                if (previous.get('result_sha256') != digest(result)
                        or result.get('schema') != 'cluster-native-membership-admission/v1'
                        or result.get('operation_id') != recipe['operation_id']
                        or result.get('receiving_readiness') != 'unobserved'):
                    raise OnboardingError('onboarding_group_membership_intent_changed')
                # A later lifecycle may already have loaded replacements. This
                # retained social completion cannot re-quiesce or reissue them,
                # and remains explicitly historical rather than fresh readiness.
                return copy.deepcopy(result)
        for owner in cohort.owners.values():
            scope.enter_context(cohort._owner_deadline(owner, deadline_ns))

        def barrier():
            budget()
            proof = cohort.require_revocation_barrier()
            if (proof.get('schema') != 'cluster-receiving-admission-barrier/v1'
                    or set(proof.get('current_senders', {})) != {s['name'] for s in row['expected_precondition']['senders']}
                    or any(item.get('state') != 'stopped' for item in proof['current_senders'].values())):
                raise OnboardingError('onboarding_group_membership_quiescence_required')
            return proof

        # A revoked live sender is insufficient for an offline native writer.
        barrier()
        receivers = admission['receivers']
        authorities = {ref: public_authority_history(item['authority'], item['history'])
                       for ref, item in recipe['authority_closure'].items()}

        def retain(name: str, step: str, make: Callable[[], dict]) -> dict:
            current = cohort._row()
            observations = copy.deepcopy(current['runtime_observation'] or {})
            social = observations.setdefault('membership_admission', dict(recipe_sha256=digest(recipe), requests={}))
            if social.get('recipe_sha256') != digest(recipe):
                raise OnboardingError('onboarding_group_membership_intent_changed')
            entries = social['requests'].setdefault(name, {})
            entry = entries.get(step)
            if entry is None:
                entries[step] = entry = dict(command=command(make()), result=None)
                cohort.journal.advance(cohort.operation_id, current['state'], runtime_observation=observations,
                    expected_runtime_observation=current['runtime_observation'])
            elif entry['command']['operation_id'] != recipe['operation_id'] or entry['command']['step'] != step:
                raise OnboardingError('onboarding_group_membership_intent_changed')
            if entry['result'] is None:
                barrier()
                owner = cohort.owners[name]
                options = dict(authority_closure={ref: item for ref, item in recipe['authority_closure'].items()
                    if ref != receivers[name]['being_ref']}, expected_context_sha256=recipe['owner_contexts'][name])
                if receivers[name]['recipe']['profile'] == 'source':
                    options['offline'] = True
                if entry['command']['method'] in {'tribe.invite', 'tribe.membership.accept'}:
                    options['membership_precondition'] = dict(schema='cluster-membership-authoring-precondition/v1',
                        tribe_ref=admission['tribe_ref'], founder_being_ref=recipe['invitation']['founder_being_ref'],
                        founder_epoch=recipe['invitation']['founder_epoch'], invitee_being_ref=admission['entrant']['being_ref'],
                        membership_sequence=recipe['membership_sequence'],
                        previous_membership_terminal_ref=recipe['previous_membership_terminal_ref'],
                        active_members=sorted({item['being_ref'] for item in row['expected_precondition']['senders']}),
                        not_after_ms=recipe['acceptance_not_after_ms'])
                result = owner.group_relationship(entry['command'], **options)
                budget()
                current = cohort._row()
                observations = copy.deepcopy(current['runtime_observation'] or {})
                saved = observations['membership_admission']['requests'][name][step]
                if saved != entry:
                    raise OnboardingError('onboarding_group_membership_intent_changed')
                saved['result'] = result
                cohort.journal.advance(cohort.operation_id, current['state'], runtime_observation=observations,
                    expected_runtime_observation=current['runtime_observation'])
            else:
                result = entry['result']
            if (result.get('schema') != 'cluster-group-relationship-result/v1'
                    or result.get('status') != 'recorded' or result.get('native_error') is not None):
                raise OnboardingError('onboarding_group_membership_native_rejected')
            return result

        def request(step: str, method: str, params: dict) -> dict:
            return dict(operation_id=recipe['operation_id'], step=step, method=method, params=params)

        founder, entrant = recipe['founder_owner'], recipe['entrant_owner']
        invitation = retain(founder, 'membership-invite',
            lambda: request('membership-invite', 'tribe.invite', dict(payload=recipe['invitation'])))

        def event(result: dict, author: str, kind: str) -> dict:
            try:
                value = verify_event(result['result']['event'], authorities[receivers[author]['being_ref']])
                payload = validate_relationship_event_payload(kind, value['payload'],
                    author_being_ref=value['being_ref'], causal_parents=value['causal_parents'])
                if (value['kind'] != kind or payload['tribe_ref'] != admission['tribe_ref']
                        or value['subject'] != relationship_event_subject(kind, payload)):
                    raise ValueError
                return value
            except (KeyError, TypeError, ValueError):
                raise OnboardingError('onboarding_group_membership_native_event_changed') from None

        invited = event(invitation, founder, 'matrix/tribe-invitation')
        if invited['payload'] != recipe['invitation']:
            raise OnboardingError('onboarding_group_membership_native_event_changed')
        for name in sorted(receivers):
            for index, value in enumerate([*recipe['governance'], invited]):
                step = 'membership-governance-' + str(index)
                retain(name, step, lambda:
                    request(step, 'relationship.event.ingest', dict(event=value)))

        def acceptance():
            now = time.time_ns() // 1_000_000
            if not recipe['invitation']['issued_at_ms'] <= now < recipe['acceptance_not_after_ms']:
                raise OnboardingError('onboarding_group_membership_acceptance_expired')
            payload = dict(schema=MEMBERSHIP_ACCEPTANCE_SCHEMA, tribe_ref=admission['tribe_ref'],
                founder_epoch=recipe['invitation']['founder_epoch'],
                invitation_ref=dict(event_id=invited['event_id'], event_hash=invited['content_hash']),
                invitee_being_ref=admission['entrant']['being_ref'], membership_sequence=recipe['membership_sequence'],
                previous_membership_terminal_ref=recipe['previous_membership_terminal_ref'], accepted_at_ms=now)
            return request('membership-accept', 'tribe.membership.accept', dict(payload=payload))

        accepted = event(retain(entrant, 'membership-accept', acceptance), entrant, 'matrix/tribe-membership-acceptance')
        accepted_command = cohort._row()['runtime_observation']['membership_admission']['requests'][entrant]['membership-accept']['command']
        if accepted['payload'] != accepted_command['params']['payload']:
            raise OnboardingError('onboarding_group_membership_native_event_changed')
        snapshots = {}
        expected = {item['being_ref'] for item in receivers.values()}
        for name in sorted(receivers):
            retain(name, 'membership-acceptance', lambda:
                request('membership-acceptance', 'relationship.event.ingest', dict(event=accepted)))
            result = retain(name, 'membership-result', lambda:
                request('membership-result', 'relationship.snapshot', dict(tribe_ref=admission['tribe_ref'], at_ms=None)))
            snapshot = result['result']
            if (snapshot.get('tribe_ref') != admission['tribe_ref']
                    or {member['principal_id'] for member in snapshot.get('members', []) if member['state'] == 'active'} != expected
                    or not any(member['principal_id'] == admission['entrant']['being_ref']
                        and member['membership_ref'] == accepted['event_id'] for member in snapshot['members'])):
                raise OnboardingError('onboarding_group_membership_unobserved')
            snapshots[name] = snapshot
        barrier()
        result = dict(schema='cluster-native-membership-admission/v1', operation_id=recipe['operation_id'],
            invitation=invited, acceptance=accepted, snapshots=snapshots, receiving_readiness='unobserved')
        current = cohort._row()
        observations = copy.deepcopy(current['runtime_observation'])
        observations['membership_admission'].update(result=result, result_sha256=digest(result))
        cohort.journal.advance(cohort.operation_id, current['state'], runtime_observation=observations,
            expected_runtime_observation=current['runtime_observation'])
        return result


def publication_recipe(value: dict, admission: dict, social: dict, senders: list[dict],
                       preparations: dict) -> dict:
    """Close approved publication inputs before any old service is stopped.

    The recipe is protected receiving intent, not a portal-supplied program.
    Only the actual retained invitation/acceptance are filled in later. Native
    owner APIs still validate and sign each application/visibility/selection.
    """
    from daimon_matrix.messaging_config import application_routes, validate_shape
    from daimon_matrix.native_egress import _SAFE_LEAF
    from daimon_matrix.operator_messaging import public_authority_history
    from daimon_matrix.telegram_mirror import REPRESENTATIONS

    try:
        receivers = admission['receivers']
        old = {row['name'] for row in senders}
        refs = {row['being_ref'] for row in receivers.values()}
        entrant = admission['entrant']['being_ref']
        required = {(ref, body['embodiment_id'], body['body_ref'])
            for ref, item in social['authority_closure'].items()
            for body in public_authority_history(item['authority'], item['history']).active.manifest.value['embodiments']
            if body['status'] == 'active'}
        if (not isinstance(value, dict) or set(value) != {'schema', 'owners', 'signers'}
                or value['schema'] != 'cluster-admission-publications/v1'
                or not isinstance(value['owners'], dict) or set(value['owners']) != set(receivers)
                or not isinstance(value['signers'], dict) or set(value['signers']) != refs
                or any(name not in receivers or receivers[name]['being_ref'] != ref
                       for ref, name in value['signers'].items())
                or not isinstance(preparations, dict) or set(preparations) != old):
            raise ValueError
        destination = None
        for name, row in value['owners'].items():
            if (not isinstance(row, dict) or set(row) != {'application', 'disclosure', 'visibility', 'selection', 'steps'}
                    or not isinstance(row['steps'], dict)
                    or set(row['steps']) != {'application', 'disclosure', 'acceptance', 'visibility', 'selection', 'snapshot'}
                    or any(not isinstance(step, str) or re.fullmatch('[a-z][a-z0-9-]{0,79}', step) is None
                           for step in row['steps'].values())
                    or len(set(row['steps'].values())) != 6
                    or name in old and (any(row['steps'][key] != preparations[name]['steps'][key]
                        for key in ('application', 'visibility', 'selection'))
                        or preparations[name]['steps']['snapshot'] in row['steps'].values())):
                raise ValueError
            for action, key in (('application', 'application'), ('visibility-disclosure', 'disclosure'),
                                ('selection', 'selection')):
                publication_command(dict(operation_id=social['operation_id'], step=row['steps'][key],
                    action=action, params=row[key]))
            app = row['application']
            first = name not in old
            if ((app['expected_application_sha256'] is None) != first
                    or app['admitted_being_refs'] != ([] if first else [entrant])
                    or any(not isinstance(path, str) or not Path(path).is_absolute() or '..' in Path(path).parts
                           for path in app['secret_sources'].values())):
                raise ValueError
            if first:
                spec = app['specification']
                if (spec['tribe']['channel_id'] != 'tribe'
                        or spec['tribe']['policy']['tribe_ref'] != admission['tribe_ref']
                        or spec['tribe']['policy']['membership_ref'] is not None
                        or spec['relationship_events'] != social['governance']
                        or spec['authorities'] != [social['authority_closure'][ref]['authority'] for ref in sorted(refs)]):
                    raise ValueError
                pending = copy.deepcopy(spec)
                pending['tribe']['policy']['membership_ref'] = 'pending-native-acceptance'
                validate_shape(pending, specification=True)
                if ({(row['being_ref'], row['embodiment_id'], row['body_ref']) for row in spec['roster']} != required
                        or set(app['secret_sources']) != {route['secret_file'] for route in application_routes(spec)}):
                    raise ValueError
            elif (re.fullmatch('[0-9a-f]{64}', app['expected_application_sha256']) is None
                    or app['additions']['relationship_events'] != []
                    or app['additions']['authorities'] != [social['authority_closure'][entrant]['authority']]):
                raise ValueError
            if not first:
                # Validate added rows through the same native group shape, using
                # an approved entrant template solely as its public schema context.
                template = copy.deepcopy(value['owners'][social['entrant_owner']]['application']['specification'])
                template['tribe']['policy']['membership_ref'] = 'pending-native-acceptance'
                template['roster'] = app['additions']['roster']
                validate_shape(template, specification=True)
                rows = app['additions']['roster']
                if ({(row['being_ref'], row['embodiment_id'], row['body_ref']) for row in rows}
                        != {row for row in required if row[0] == entrant}
                        or set(app['secret_sources']) != {row['route']['secret_file'] for row in rows}):
                    raise ValueError
            disclosure, visibility = row['disclosure'], row['visibility']
            if (not isinstance(visibility, dict) or set(visibility) != {'expected_installation_sha256', 'initial_configuration'}
                    or type(disclosure['issued_at_ms']) is not int
                    or not 0 <= disclosure['issued_at_ms'] < social['acceptance_not_after_ms']
                    or not isinstance(disclosure['approved_destination'], dict)
                    or set(disclosure['approved_destination']) != {'bot_id', 'chat_id', 'topic_id', 'representation'}):
                raise ValueError
            if destination is None:
                destination = disclosure['approved_destination']
            if (disclosure['approved_destination'] != destination
                    or type(destination['bot_id']) is not int or not 0 < destination['bot_id'] < 2**52
                    or type(destination['chat_id']) is not int or not 0 < abs(destination['chat_id']) < 2**52
                    or destination['topic_id'] is not None and (
                        type(destination['topic_id']) is not int or not 0 < destination['topic_id'] < 2**52)
                    or destination['representation'] not in REPRESENTATIONS):
                raise ValueError
            if first:
                if (visibility['expected_installation_sha256'] is not None
                        or not isinstance(visibility['initial_configuration'], dict)
                        or set(visibility['initial_configuration']) != {'destination', 'secrets', 'telegram_qualification'}
                        or visibility['initial_configuration']['destination'] != destination
                        or row['selection']['expected_selection_sha256'] is not None):
                    raise ValueError
                initial = visibility['initial_configuration']
                secrets, qualification = initial['secrets'], initial['telegram_qualification']
                if (not isinstance(secrets, dict) or set(secrets) != {
                        'telegram_token_file', 'telegram_token_sha256', 'proof_key_file'}
                        or any(not isinstance(secrets[key], str) or _SAFE_LEAF.fullmatch(secrets[key]) is None
                               for key in ('telegram_token_file', 'proof_key_file'))
                        or re.fullmatch('[0-9a-f]{64}', secrets['telegram_token_sha256']) is None
                        or not isinstance(qualification, dict) or set(qualification) != {
                            'schema', 'qualified_at_ms', 'token_sha256', 'get_me_bot_id', 'probe_chat_id',
                            'probe_topic_id', 'probe_message_id', 'probe_text_sha256'}
                        or qualification['schema'] != 'dm.messaging.telegram-qualification/v1'
                        or type(qualification['qualified_at_ms']) is not int
                        or not 0 <= qualification['qualified_at_ms'] < 2**52
                        or qualification['token_sha256'] != secrets['telegram_token_sha256']
                        or any(qualification[field] != destination[key] for field, key in (
                            ('get_me_bot_id', 'bot_id'), ('probe_chat_id', 'chat_id'), ('probe_topic_id', 'topic_id')))
                        or type(qualification['probe_message_id']) is not int or qualification['probe_message_id'] <= 0
                        or re.fullmatch('[0-9a-f]{64}', qualification['probe_text_sha256']) is None):
                    raise ValueError
            elif (visibility['initial_configuration'] is not None
                    or re.fullmatch('[0-9a-f]{64}', visibility['expected_installation_sha256']) is None
                    or re.fullmatch('[0-9a-f]{64}', row['selection']['expected_selection_sha256']) is None):
                raise ValueError
        digest(value)
    except (KeyError, TypeError, ValueError, AttributeError, OnboardingError):
        raise OnboardingError('onboarding_group_publication_recipe_required') from None
    return copy.deepcopy(value)


def publish_admission_group(cohort, *, deadline_ns: int) -> dict:
    """Resume fixed offline publication after actual native social completion.

    No lifecycle, sender enable or readiness is implied. Exact native owner
    operations own recovery and CAS; a completed phase is historical evidence.
    """
    from daimon_matrix.messaging_config import config_digest

    def budget():
        if type(deadline_ns) is not int or time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('onboarding_group_relationship_deadline_expired')

    with cohort.journal.mutation_lock(cohort.operation_id), ExitStack() as scope:
        row = cohort._row()
        admission = cohort._admission(row)
        portal = row['intended_transition'].get('portal_admission', {})
        if admission is None or portal.get('schema') != 'cluster-portal-group-admission/v2':
            raise OnboardingError('onboarding_group_membership_recipe_required')
        social = membership_recipe(portal.get('social'), admission, row['expected_precondition']['senders'])
        recipe = publication_recipe(row['intended_transition'].get('admission_publications'), admission,
            social, row['expected_precondition']['senders'], row['intended_transition'].get('admission_preparations'))
        budget()
        membership = (row['runtime_observation'] or {}).get('membership_admission', {})
        joined = membership.get('result')
        if (membership.get('recipe_sha256') != digest(social) or not isinstance(joined, dict)
                or membership.get('result_sha256') != digest(joined)
                or joined.get('schema') != 'cluster-native-membership-admission/v1'
                or joined.get('operation_id') != social['operation_id']
                or joined.get('receiving_readiness') != 'unobserved'):
            raise OnboardingError('onboarding_group_membership_unobserved')
        identity = dict(recipe_sha256=digest(recipe), membership_sha256=digest(joined))
        previous = (row['runtime_observation'] or {}).get('group_publication')
        if previous is not None:
            if any(previous.get(key) != pin for key, pin in identity.items()):
                raise OnboardingError('onboarding_group_publication_intent_conflict')
            if previous.get('result') is not None:
                if previous.get('result_sha256') != digest(previous['result']):
                    raise OnboardingError('onboarding_group_publication_changed')
                return copy.deepcopy(previous['result'])
        for owner in cohort.owners.values():
            scope.enter_context(cohort._owner_deadline(owner, deadline_ns))

        def barrier():
            budget()
            proof = cohort.require_revocation_barrier()
            if (proof.get('schema') != 'cluster-receiving-admission-barrier/v1'
                    or set(proof.get('current_senders', {})) != {s['name'] for s in row['expected_precondition']['senders']}
                    or any(item.get('state') != 'stopped' for item in proof['current_senders'].values())):
                raise OnboardingError('onboarding_group_membership_quiescence_required')

        barrier()

        applications: dict[str, str] = {}
        installations: dict[str, str] = {}

        def submit(name: str, key: str, action: str, params: dict) -> dict:
            value = publication_command(dict(operation_id=social['operation_id'],
                step=recipe['owners'][name]['steps'][key], action=action, params=params,
                **({} if action == 'application' else {'application_precondition': dict(
                    application_step=recipe['owners'][name]['steps']['application'],
                    application_sha256=applications[name])}),
                **({} if action != 'selection' else {'visibility_precondition': dict(
                    visibility_step=recipe['owners'][name]['steps']['visibility'],
                    installation_sha256=installations[name])})))
            current = cohort._row()
            observations = copy.deepcopy(current['runtime_observation'] or {})
            phase = observations.setdefault('group_publication', {**identity, 'requests': {}})
            entries = phase['requests'].setdefault(name, {})
            entry = entries.get(key)
            if entry is None:
                entries[key] = entry = dict(command=value, result=None)
                cohort.journal.advance(cohort.operation_id, current['state'], runtime_observation=observations,
                    expected_runtime_observation=current['runtime_observation'])
            elif entry['command'] != value:
                raise OnboardingError('onboarding_group_publication_intent_conflict')
            # Incomplete phases must validate retained native publications too.
            # An authentic later renewal must win before dependent visibility or
            # selector effects, not merely fail the final snapshot afterward.
            barrier()
            owner = cohort.owners[name]
            result = owner.group_publication(value, expected_context_sha256=social['owner_contexts'][name],
                authority_closure={ref: item for ref, item in social['authority_closure'].items()
                    if ref != admission['receivers'][name]['being_ref']})
            budget()
            if entry['result'] is None:
                current = cohort._row()
                observations = copy.deepcopy(current['runtime_observation'] or {})
                saved = observations['group_publication']['requests'][name][key]
                if saved != entry:
                    raise OnboardingError('onboarding_group_publication_intent_conflict')
                saved['result'] = result
                cohort.journal.advance(cohort.operation_id, current['state'], runtime_observation=observations,
                    expected_runtime_observation=current['runtime_observation'])
            elif entry['result'] != result:
                raise OnboardingError('onboarding_group_publication_changed')
            if (result.get('schema') != 'cluster-group-publication-result/v1'
                    or any(result.get(field) != value[field] for field in ('operation_id', 'step', 'action'))
                    or result.get('status') != 'recorded' or result.get('receiving_readiness') != 'unobserved'):
                raise OnboardingError('onboarding_group_publication_changed')
            return result

        disclosures = {}
        for name, owner in sorted(recipe['owners'].items()):
            app = copy.deepcopy(owner['application'])
            events = app['specification']['relationship_events'] if app['specification'] is not None else app['additions']['relationship_events']
            events.extend([joined['invitation'], joined['acceptance']])
            if app['specification'] is not None:
                app['specification']['tribe']['policy']['membership_ref'] = joined['acceptance']['event_id']
            application = submit(name, 'application', 'application', app)
            applications[name] = application['application_sha256']
            result = submit(name, 'disclosure', 'visibility-disclosure', owner['disclosure'])
            disclosure = result.get('disclosure')
            if (not isinstance(disclosure, dict) or result.get('disclosure_sha256') != config_digest(disclosure)
                    or disclosure.get('destination') != owner['disclosure']['approved_destination']
                    or disclosure.get('issued_at_ms') != owner['disclosure']['issued_at_ms']
                    or set(disclosure.get('participants', [])) != set(recipe['signers'])):
                raise OnboardingError('onboarding_group_publication_changed')
            disclosures[name] = disclosure
        accepted = {}
        ordered = [disclosures[name] for name in sorted(disclosures)]
        for ref, name in sorted(recipe['signers'].items()):
            result = submit(name, 'acceptance', 'visibility-accept', dict(disclosures=ordered,
                approved_destination=recipe['owners'][name]['disclosure']['approved_destination']))
            bindings = result.get('bindings')
            if (not isinstance(bindings, list) or len(bindings) != len(ordered)
                    or any(not isinstance(binding, dict) or set(binding) != {'disclosure_sha256', 'binding'}
                        or binding['disclosure_sha256'] != config_digest(disclosure)
                        or binding['binding'].get('body', {}).get('being_ref') != ref
                        for binding, disclosure in zip(bindings, ordered, strict=True))):
                raise OnboardingError('onboarding_group_publication_changed')
            accepted[ref] = bindings
        snapshots = {}
        for index, (name, owner) in enumerate(sorted(recipe['owners'].items())):
            visibility = submit(name, 'visibility', 'visibility-publish', dict(disclosure=disclosures[name],
                bindings=[accepted[ref][index]['binding'] for ref in sorted(accepted)], **owner['visibility']))
            installations[name] = visibility['installation_sha256']
            submit(name, 'selection', 'selection', owner['selection'])
            snapshot = submit(name, 'snapshot', 'snapshot', dict(
                **{key+'_step': owner['steps'][key] for key in ('application', 'visibility', 'selection')},
                owner_context_sha256=social['owner_contexts'][name]))
            if (snapshot.get('owner_context_sha256') != social['owner_contexts'][name]
                    or snapshot.get('group', {}).get('selected', {}).get('tribe_ref') != admission['tribe_ref']):
                raise OnboardingError('onboarding_group_publication_changed')
            snapshots[name] = snapshot
        barrier()
        result = dict(schema='cluster-admission-group-publications/v1', operation_id=social['operation_id'],
            **identity, snapshots=snapshots, receiving_readiness='unobserved')
        current = cohort._row()
        observations = copy.deepcopy(current['runtime_observation'])
        observations['group_publication'].update(result=result, result_sha256=digest(result))
        cohort.journal.advance(cohort.operation_id, current['state'], runtime_observation=observations,
            expected_runtime_observation=current['runtime_observation'])
        return result


def command(value: dict) -> dict:
    try:
        if (not isinstance(value, dict) or set(value) != {'operation_id', 'step', 'method', 'params'}
                or str(uuid.UUID(value['operation_id'])) != value['operation_id']
                or not isinstance(value['step'], str)
                or re.fullmatch(r'[a-z][a-z0-9-]{0,79}', value['step']) is None
                or value['method'] not in METHODS or not isinstance(value['params'], dict)):
            raise ValueError
        digest(value)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_relationship_command_required') from None
    return copy.deepcopy(value)


def validate_membership_precondition(value: dict, selected: dict) -> dict:
    """Closed authoring constraints, checked again by the actual native owner."""
    fields = {'schema', 'tribe_ref', 'founder_being_ref', 'founder_epoch', 'invitee_being_ref',
              'membership_sequence', 'previous_membership_terminal_ref', 'active_members', 'not_after_ms'}
    try:
        if (not isinstance(value, dict) or set(value) != fields
                or value['schema'] != 'cluster-membership-authoring-precondition/v1'
                or selected['method'] not in {'tribe.invite', 'tribe.membership.accept'}
                or any(not isinstance(value[key], str) or not value[key]
                       for key in ('tribe_ref', 'founder_being_ref', 'invitee_being_ref'))
                or any(type(value[key]) is not int or value[key] < 0
                       for key in ('founder_epoch', 'membership_sequence'))
                or type(value['not_after_ms']) is not int or not 0 < value['not_after_ms'] < 2**53
                or not isinstance(value['active_members'], list)
                or any(not isinstance(ref, str) or not ref for ref in value['active_members'])
                or value['active_members'] != sorted(set(value['active_members']))):
            raise ValueError
        payload = selected['params']['payload']
        if any(payload[key] != value[key] for key in ('tribe_ref', 'founder_epoch', 'invitee_being_ref')):
            raise ValueError
        if selected['method'] == 'tribe.invite':
            if payload['founder_being_ref'] != value['founder_being_ref']:
                raise ValueError
        elif any(payload[key] != value[key] for key in ('membership_sequence', 'previous_membership_terminal_ref')):
            raise ValueError
        digest(value)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_membership_precondition_required') from None
    return copy.deepcopy(value)


def check_membership_precondition(hosted, value: dict, *, now_ms: int) -> None:
    """Compare actual native state, not a stale recipe's supplied event subset."""
    with hosted.service.relationships.store.authorization_view(at_ms=now_ms,
            card_verifier=hosted.service.relationships.card_verifier, busy_timeout_ms=0) as view:
        tribe = view.tribes.get(value['tribe_ref'])
    if (tribe is None or tribe['state'] != 'active'
            or tribe['founder_being_ref'] != value['founder_being_ref']
            or tribe['founder_epoch'] != value['founder_epoch']
            or any(row['state'] == 'forked' for row in tribe['memberships'].values())
            or sorted(ref for ref, row in tribe['memberships'].items() if row['state'] == 'active') != value['active_members']):
        raise OnboardingError('onboarding_group_membership_precondition_changed')
    previous = tribe['memberships'].get(value['invitee_being_ref'])
    episodes = [] if previous is None else previous['episodes']
    terminal = None if not episodes else episodes[-1].get('terminal_event')
    expected_terminal = None if terminal is None else dict(event_id=terminal['event_id'], event_hash=terminal['content_hash'])
    if (previous is not None and previous['state'] not in {'left', 'expelled'}
            or len(episodes) != value['membership_sequence']
            or expected_terminal != value['previous_membership_terminal_ref']):
        raise OnboardingError('onboarding_group_membership_precondition_changed')


def request_packet(value: dict) -> dict:
    fields = {'command', 'offline', 'authority_closure'}
    optional = {'expected_context_sha256', 'membership_precondition'}
    if (not isinstance(value, dict) or not fields <= set(value) <= fields | optional
            or type(value['offline']) is not bool or not isinstance(value['authority_closure'], dict)
            or 'expected_context_sha256' in value and (not value['offline']
                or not isinstance(value['expected_context_sha256'], str)
                or re.fullmatch('[0-9a-f]{64}', value['expected_context_sha256']) is None)):
        raise OnboardingError('onboarding_group_relationship_command_required')
    publication = isinstance(value['command'], dict) and 'action' in value['command']
    if publication and not value['offline']:
        raise OnboardingError('onboarding_group_relationship_writer_required')
    precondition = {}
    if 'membership_precondition' in value:
        if publication or not value['offline']:
            raise OnboardingError('onboarding_group_relationship_writer_required')
        precondition = dict(membership_precondition=validate_membership_precondition(value['membership_precondition'], command(value['command'])))
    return dict(command=(publication_command if publication else command)(value['command']), offline=value['offline'],
                authority_closure=copy.deepcopy(value['authority_closure']),
                **({'expected_context_sha256': value['expected_context_sha256']}
                   if 'expected_context_sha256' in value else {}), **precondition)


def publication_command(value: dict) -> dict:
    try:
        if (not isinstance(value, dict) or set(value) - {'application_precondition', 'visibility_precondition'} != {'operation_id', 'step', 'action', 'params'}
                or str(uuid.UUID(value['operation_id'])) != value['operation_id']
                or not isinstance(value['step'], str)
                or re.fullmatch(r'[a-z][a-z0-9-]{0,79}', value['step']) is None
                or not isinstance(value['action'], str) or value['action'] not in PUBLICATIONS
                or not isinstance(value['params'], dict)
                or set(value['params']) != PUBLICATIONS[value['action']] and not (
                    value['action'] == 'snapshot'
                    and PUBLICATIONS['snapshot'] <= set(value['params'])
                    and set(value['params']) - PUBLICATIONS['snapshot'] <= {'expected_stores', 'expected_preservation'})):
            raise ValueError
        params = value['params']
        if 'application_precondition' in value:
            guard = value['application_precondition']
            if (value['action'] in {'application', 'context-preview'}
                    or not isinstance(guard, dict) or set(guard) != {'application_step', 'application_sha256'}
                    or not isinstance(guard['application_step'], str)
                    or re.fullmatch('[a-z][a-z0-9-]{0,79}', guard['application_step']) is None
                    or not isinstance(guard['application_sha256'], str)
                    or re.fullmatch('[0-9a-f]{64}', guard['application_sha256']) is None):
                raise ValueError
        if 'visibility_precondition' in value:
            guard = value['visibility_precondition']
            if (value['action'] != 'selection' or not isinstance(guard, dict)
                    or set(guard) != {'visibility_step', 'installation_sha256'}
                    or not isinstance(guard['visibility_step'], str)
                    or re.fullmatch('[a-z][a-z0-9-]{0,79}', guard['visibility_step']) is None
                    or not isinstance(guard['installation_sha256'], str)
                    or re.fullmatch('[0-9a-f]{64}', guard['installation_sha256']) is None):
                raise ValueError
        if value['action'] == 'application':
            from daimon_matrix.messaging_config import APPLICATION_SCHEMA_V3
            first = params['expected_application_sha256'] is None
            if (not isinstance(params['secret_sources'], dict)
                    or not isinstance(params['admitted_being_refs'], list)
                    or first and (not isinstance(params['specification'], dict) or params['additions'] is not None
                        or params['admitted_being_refs'] != []
                        or params['specification'].get('schema') != APPLICATION_SCHEMA_V3)
                    or not first and (params['specification'] is not None or not isinstance(params['additions'], dict)
                        or set(params['additions']) != {'authorities', 'relationship_events', 'roster'}
                        or any(not isinstance(rows, list) for rows in params['additions'].values()))):
                raise ValueError
        if value['action'] == 'visibility-accept' and (not isinstance(params['disclosures'], list)
                or not 1 <= len(params['disclosures']) <= 256):
            raise ValueError
        if value['action'] == 'snapshot' and (any(not isinstance(step, str)
                or re.fullmatch(r'[a-z][a-z0-9-]{0,79}', step) is None
                for key, step in params.items() if key not in {
                    'owner_context_sha256', 'expected_stores', 'expected_preservation'})
                or not isinstance(params['owner_context_sha256'], str)
                or re.fullmatch('[0-9a-f]{64}', params['owner_context_sha256']) is None):
            raise ValueError
        if 'expected_stores' in params and (not isinstance(params['expected_stores'], dict)
                or 'ledger' not in params['expected_stores']):
            raise ValueError
        if 'expected_preservation' in params and (not isinstance(params['expected_preservation'], dict)
                or 'expected_stores' not in params):
            raise ValueError
        digest(value)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_publication_command_required') from None
    return copy.deepcopy(value)


def check_snapshot_context(journal: Path, value: dict) -> None:
    """A snapshot never creates/reconstructs its approved owner context."""
    if value['action'] == 'snapshot':
        context = being_seed._read(journal / value['operation_id'] / 'owner/context.json',
                                  limit=being_seed.MAX_SELECTION)
        if digest(context) != value['params']['owner_context_sha256']:
            raise OnboardingError('onboarding_group_owner_context_conflict')
        if 'expected_stores' in value['params']:
            from .onboarding_receiving_update import admission_store_bindings, preserved_admission_stores
            identity = context['identity']
            root = Path(identity['runtime_root'])
            bundle = being_seed._read(root / 'runtime.json', limit=being_seed.MAX_SELECTION)
            if digest(bundle) != identity['runtime_bundle_sha256']:
                raise OnboardingError('onboarding_group_owner_context_conflict')
            if 'expected_preservation' in value['params']:
                preserved_admission_stores(root, bundle, value['params']['expected_preservation'],
                                          value['params']['expected_stores'])
            else:
                admission_store_bindings(root, bundle, value['params']['expected_stores'])


def public_authorities(bundle: dict, closure: dict) -> dict:
    """Validate the public closure already approved by this owner CLI's caller.

    Self-consistent signatures alone are not approval. The protected operation
    and existing Source/Target owner routes supply that separate authorization.
    """
    from daimon_matrix import operator_messaging
    reader = getattr(operator_messaging, 'public_authority_history', None)
    if not callable(reader):
        raise OnboardingError('onboarding_group_history_sdk_required')
    if not isinstance(closure, dict) or len(closure) > 256:
        raise OnboardingError('approved_onboarding_group_history_required')
    result = {}
    for ref, row in closure.items():
        if (ref == bundle['manifest']['being_ref'] or not isinstance(row, dict)
                or set(row) != {'authority', 'history'}):
            raise OnboardingError('approved_onboarding_group_history_required')
        authority = reader(row['authority'], row['history'])
        if authority.active.manifest.being_ref != ref:
            raise OnboardingError('approved_onboarding_group_history_required')
        result[ref] = authority
    return result


def merge_authorities(current: dict, supplied: dict) -> dict:
    result = dict(current)
    for ref, authority in supplied.items():
        previous = result.get(ref)
        if previous is not None and (getattr(previous, 'active', previous) != authority.active
                or hasattr(previous, 'historical') and previous != authority):
            raise OnboardingError('approved_onboarding_group_history_conflict')
        result[ref] = authority
    return result


def _owner_context(runtime_root: Path, group_root: Path, operation_id: str, closure: dict) -> tuple[dict, dict]:
    """Construct the same public pins for preparation and writer retention."""
    from . import onboarding_peer
    try:
        if str(uuid.UUID(operation_id)) != operation_id:
            raise ValueError
    except (TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_owner_context_conflict') from None
    bundle = being_seed._read(runtime_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    identity = dict(runtime_root=str(runtime_root), group_root=str(group_root),
        runtime_bundle_sha256=digest(bundle),
        ledger=_ledger_identity(runtime_root, bundle))
    approved = dict(schema='cluster-group-owner-context/v1',
        operation_id=operation_id, identity=identity,
        authority_closure=copy.deepcopy(closure))
    authorities = public_authorities(bundle, closure)
    # A self-consistent replacement chain cannot erase native known history.
    onboarding_peer._group_authorities_with_history(bundle, authorities,
        {ref: authority.active for ref, authority in authorities.items()})
    return approved, authorities


def _first_owner_context(runtime_root: Path, group_root: Path, approved: dict, authorities: dict) -> dict:
    from . import onboarding_peer
    bundle = being_seed._read(runtime_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    if digest(bundle) != approved['identity']['runtime_bundle_sha256']:
        raise OnboardingError('onboarding_group_owner_context_conflict')
    current = onboarding_peer.approved_group_authorities(runtime_root, group_root, bundle)
    if not set(current) <= set(authorities):
        raise OnboardingError('onboarding_group_owner_context_incomplete')
    merge_authorities(current, authorities)
    selection = group_root / 'selection.json'
    predecessor = digest(being_seed._read(selection, limit=being_seed.MAX_SELECTION)) if selection.exists() else None
    return {**approved, 'predecessor_selection_sha256': predecessor}


def preview_owner_context(runtime_root: Path, group_root: Path, operation_id: str, closure: dict,
                          *, deadline_ns: int | None = None) -> dict:
    """Read public context pins before interruption, without custody or writes.

    This is a prospective digest, not writer ownership or receiving acceptance.
    The later writer compares these exact pins before retaining any context.
    """
    def budget():
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('onboarding_group_relationship_deadline_expired')
    budget()
    approved, authorities = _owner_context(runtime_root, group_root, operation_id, closure)
    context = _first_owner_context(runtime_root, group_root, approved, authorities)
    # Read-only observation must not certify a mixture across a concurrent
    # bundle/ledger/selector change. The writer remains the final CAS boundary.
    fresh, _ = _owner_context(runtime_root, group_root, operation_id, closure)
    if fresh != approved or _first_owner_context(runtime_root, group_root, fresh, authorities) != context:
        raise OnboardingError('onboarding_group_owner_context_conflict')
    budget()
    return dict(schema='cluster-group-owner-context-preview/v1', operation_id=operation_id,
        owner_context_sha256=digest(context), runtime_bundle_sha256=approved['identity']['runtime_bundle_sha256'],
        predecessor_selection_sha256=context['predecessor_selection_sha256'], receiving_readiness='unobserved')


def owner_authorities(runtime_root: Path, group_root: Path, journal: Path,
                      operation_id: str, closure: dict, *, expected_context_sha256: str | None = None) -> dict:
    """Freeze the complete owner-approved closure before partial publication.

    The caller holds the native writer. First use validates the actual serving
    selector and preserves all its Roots. An exact retained operation can then
    load a closed maintenance context even while that selector lags publication.
    Normal serving and observation keep their strict application pins.
    """
    if expected_context_sha256 is not None and (not isinstance(expected_context_sha256, str)
            or re.fullmatch('[0-9a-f]{64}', expected_context_sha256) is None):
        raise OnboardingError('onboarding_group_owner_context_conflict')
    approved, authorities = _owner_context(runtime_root, group_root, operation_id, closure)
    private_directory(journal, create=True)
    with being_seed._locked(journal):
        operation = private_directory(journal / operation_id, create=True)
        context = private_directory(operation / 'owner', create=True)
        path = context / 'context.json'
        if path.exists():
            retained = being_seed._read(path, limit=being_seed.MAX_SELECTION)
            predecessor = retained.get('predecessor_selection_sha256')
            if (retained != {**approved, 'predecessor_selection_sha256': predecessor}
                    or predecessor is not None
                    and (not isinstance(predecessor, str) or re.fullmatch('[0-9a-f]{64}', predecessor) is None)):
                raise OnboardingError('onboarding_group_owner_context_conflict')
        else:
            retained = _first_owner_context(runtime_root, group_root, approved, authorities)
        if expected_context_sha256 is not None and digest(retained) != expected_context_sha256:
            raise OnboardingError('onboarding_group_owner_context_conflict')
        if not path.exists():
            being_seed._write(path, retained, limit=being_seed.MAX_SELECTION)
        # Retry the durability boundary even after a lost write/fsync reply.
        # No native load or relationship dispatch precedes this boundary.
        for parent in (context, operation, journal, journal.parent):
            _sync(parent)
    return authorities


def load_owner_runtime(runtime_root: Path, reader, *, authorities: dict,
                       qualified_startup: dict | None = None):
    """Load only a closed owner context, never a serving selector or egress."""
    from daimon_matrix import native_egress, runtime
    def clock():
        return time.time_ns() // 1_000_000
    return runtime.load_runtime(runtime_root, 'runtime.json', reader, clock=clock,
        relationship_authorities=authorities,
        egress=native_egress.closed_visibility(clock=clock, catalog_mode='migrate'),
        **({} if qualified_startup is None else {'qualified_startup': qualified_startup}))


def _sync(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def check_retained_ledger(runtime_root: Path, journal: Path, value: dict) -> dict:
    """Check the original ledger before a loader could initialize missing state."""
    selected = command(value)
    bundle = being_seed._read(runtime_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    identity = _ledger_identity(runtime_root, bundle)
    path = journal / selected['operation_id'] / (selected['step'] + '.json')
    if path.exists() and being_seed._read(path, limit=being_seed.MAX_SELECTION).get('identity', {}).get('ledger') != identity:
        raise OnboardingError('onboarding_group_relationship_ledger_changed')
    return identity


def _ledger_identity(runtime_root: Path, bundle: dict) -> dict:
    from daimon_matrix.service import LoadedStoreBinding
    name = bundle['ledger']
    if not isinstance(name, str) or Path(name).name != name or name in {'', '.', '..'}:
        raise OnboardingError('onboarding_group_relationship_ledger_changed')
    return dict(filename=name, file_identity=list(LoadedStoreBinding.file_identity(runtime_root / name)))


def _publish_application(hosted, directory: Path, params: dict) -> dict:
    from daimon_matrix import operator_messaging
    from daimon_matrix.messaging_config import (
        config_digest, load_application, read_document, read_publication, read_verified_publication, verify_binding,
    )
    expected = params['expected_application_sha256']
    if expected is None:
        published = directory.exists()
        if not published:
            operator_messaging.prepare(hosted, directory, params['specification'],
                secret_sources=params['secret_sources'])
        snapshot = read_verified_publication(hosted, directory)
        publication = json.loads(snapshot.publication)
        if (snapshot.metadata != directory or publication['body']['generation'] != '.'
                or publication['body']['predecessor_sha256'] is not None):
            raise OnboardingError('onboarding_group_publication_changed')
        application = json.loads(snapshot.application)
        specification = {key: value for key, value in application.items() if key != 'client'}
        if specification != params['specification']:
            raise OnboardingError('onboarding_group_publication_changed')
        # prepare can publish before its reply/load-validation is lost. Reuse
        # that exact client and finish native validation, never prepare over it.
        if published:
            load_application(hosted, directory)
        _sync(directory.parent)
    else:
        previous, metadata = read_publication(hosted, directory)
        if config_digest(previous) != expected:
            # The SDK retains its authenticated predecessor with the selected
            # successor. Derive the same additions from it on an exact retry.
            previous = read_document(metadata / 'predecessor.json')
            verify_binding(hosted, previous, read_document(metadata / 'predecessor-binding.json'))
        if config_digest(previous) != expected:
            raise OnboardingError('onboarding_group_publication_changed')
        specification = copy.deepcopy(previous)
        for key, rows in params['additions'].items():
            specification[key].extend(rows)
        operator_messaging.admit_group_application(hosted, directory, specification,
            expected_application_sha256=expected, admitted_being_refs=params['admitted_being_refs'],
            secret_sources=params['secret_sources'])
        application, _ = read_publication(hosted, directory)
    return dict(application_sha256=config_digest(application),
                publication_sha256=config_digest(read_document(directory / 'publication.json')))


def _publication_snapshot(hosted, group_root: Path, operation: Path, value: dict,
                          context: dict, snapshot: Callable[[], dict] | None) -> dict:
    """Correlate a fresh signed group view with this owner's actual effects.

    The owner supplies the profile-specific authenticated group reader while
    retaining its native writer. Step references identify existing records;
    they never supply hashes, paths or a substitute candidate group.
    """
    if snapshot is None:
        raise OnboardingError('onboarding_group_snapshot_reader_required')
    if digest(context) != value['params']['owner_context_sha256']:
        raise OnboardingError('onboarding_group_owner_context_conflict')
    receipts: dict[str, dict] = {}
    for action, key in (('application', 'application_step'), ('visibility-publish', 'visibility_step'),
                        ('selection', 'selection_step')):
        step = value['params'][key]
        retained = being_seed._read(operation / 'publications' / (step + '.json'),
                                   limit=being_seed.MAX_SELECTION)
        command = retained.get('command')
        result = retained.get('result')
        if (retained.get('schema') != 'cluster-group-publication-operation/v1'
                or retained.get('owner_context_sha256') != digest(context)
                or not isinstance(command, dict) or command.get('operation_id') != value['operation_id']
                or command.get('step') != step or command.get('action') != action
                or not isinstance(result, dict) or result.get('schema') != 'cluster-group-publication-result/v1'
                or result.get('operation_id') != value['operation_id'] or result.get('step') != step
                or result.get('action') != action or result.get('status') != 'recorded'
                or result.get('receiving_readiness') != 'unobserved'):
            raise OnboardingError('onboarding_group_snapshot_publication_required')
        publication_command(command)
        receipts[action] = dict(command_sha256=digest(command), result=result)
    from daimon_matrix import operator_messaging
    from daimon_matrix.messaging_config import config_digest
    application_value, _members = operator_messaging._group_visibility_context(hosted, group_root / 'application')
    authorities = operator_messaging._application_authorities(application_value)
    controller = operator_messaging._owner_visibility_controller(authorities=authorities,
        application_sha256=config_digest(application_value),
        installation_path=group_root / 'visibility/installation.json',
        authority=operator_messaging._runtime_authority(hosted), origin=hosted.service.origin,
        runtime_id=hosted.service.runtime_id, runtime_label=hosted.service.runtime_label,
        signer_public_key=hosted.service.signer.public_key, clock=hosted.service.clock,
        catalog_mode='validate')
    group = snapshot()
    selected = being_seed._read(group_root / 'selection.json', limit=being_seed.MAX_SELECTION)
    application = receipts['application']['result']
    visibility = receipts['visibility-publish']['result']
    selection = receipts['selection']['result']
    if (any(group.get(key) != application.get(key) for key in ('application_sha256', 'publication_sha256'))
            or group.get('installation_sha256') != visibility.get('installation_sha256')
            or group.get('installation_sha256') != controller.installation_digest
            or group.get('application_sha256') != config_digest(application_value)
            # The receiving selector retains Cluster's document codec. Native
            # application/visibility receipts use Matrix's canonical codec.
            or digest(application_value) != selection.get('application_sha256')
            or digest(selected) != selection.get('selection_sha256')):
        raise OnboardingError('onboarding_group_snapshot_publication_changed')
    return dict(group=group, selection_sha256=digest(selected), publications=receipts,
                owner_context_sha256=digest(context),
                stores={role: json.loads(binding.observation)
                        for role, binding in hosted.service.loaded_stores.items()})


def _publication_effect(hosted, group_root: Path, value: dict, closure: dict, *,
                        operation: Path, context: dict,
                        snapshot: Callable[[], dict] | None) -> dict:
    from daimon_matrix import operator_messaging
    from daimon_matrix.messaging_config import config_digest
    params = value['params']
    directory = group_root / 'application'
    action = value['action']
    if action == 'snapshot':
        return _publication_snapshot(hosted, group_root, operation, value, context, snapshot)
    if action == 'application':
        return _publish_application(hosted, directory, params)
    if action == 'visibility-disclosure':
        disclosure = operator_messaging.group_visibility_disclosure(hosted, directory, **params)
        return dict(disclosure=disclosure, disclosure_sha256=config_digest(disclosure))
    if action == 'visibility-accept':
        return dict(bindings=[dict(disclosure_sha256=config_digest(disclosure),
            binding=operator_messaging.accept_group_visibility(hosted, directory, disclosure,
                approved_destination=params['approved_destination'])) for disclosure in params['disclosures']])
    if action == 'visibility-publish':
        installation = private_directory(group_root / 'visibility', create=True) / 'installation.json'
        result = operator_messaging.publish_group_visibility(hosted, directory, installation, **params)
        return dict(installation_sha256=result['installation_sha256'])
    from .onboarding_peer import publish_group_selection
    result = publish_group_selection(hosted, group_root, operation_id=value['operation_id'],
        expected_selection_sha256=params['expected_selection_sha256'],
        authority_history={ref: row['history'] for ref, row in closure.items()})
    return {key: result[key] for key in ('selection_sha256', 'application_sha256')}


def publication_request(hosted, group_root: Path, journal: Path, value: dict, *,
                        deadline_ns: int | None = None,
                        snapshot: Callable[[], dict] | None = None) -> dict:
    """Resume one exact owner publication through supported Matrix operations.

    The caller holds the runtime writer and has retained owner_authorities.
    SDK publication preimages and CAS remain authoritative; cached results do
    not bypass current publication checks or prove receiving readiness.
    """
    selected = publication_command(value)
    if selected['action'] == 'context-preview':
        raise OnboardingError('onboarding_group_context_preview_is_read_only')
    def check_deadline():
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('onboarding_group_relationship_deadline_expired')
    check_deadline()
    private_directory(group_root, create=True)
    with being_seed._locked(journal):
        operation = private_directory(journal / selected['operation_id'])
        context = being_seed._read(operation / 'owner/context.json', limit=being_seed.MAX_SELECTION)
        bundle = being_seed._read(hosted.state_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
        expected = dict(runtime_root=str(hosted.state_root), group_root=str(group_root),
            runtime_bundle_sha256=digest(bundle), ledger=_ledger_identity(hosted.state_root, bundle))
        if (context['identity'] != expected or hosted.service.origin != bundle['local_origin']
                or hosted.service.runtime_identity != {key: bundle[key] for key in ('runtime_id', 'runtime_label')}):
            raise OnboardingError('onboarding_group_owner_context_conflict')
        for binding in hosted.service.loaded_stores.values():
            binding.verify()
        directory = private_directory(operation / 'publications', create=True)
        path = directory / (selected['step'] + '.json')
        intent = dict(schema='cluster-group-publication-operation/v1', command=selected,
                      owner_context_sha256=digest(context))
        if path.exists():
            retained = being_seed._read(path, limit=being_seed.MAX_SELECTION)
            if retained != {**intent, 'result': retained.get('result')}:
                raise OnboardingError('onboarding_group_publication_intent_conflict')
        else:
            if (selected['action'] == 'application' and selected['params']['expected_application_sha256'] is None
                    and (group_root / 'application').exists()):
                raise OnboardingError('onboarding_group_publication_changed')
            retained = {**intent, 'result': None}
            being_seed._write(path, retained, limit=being_seed.MAX_SELECTION)
        for parent in (directory, operation, journal, journal.parent):
            _sync(parent)
        check_deadline()
        if 'application_precondition' in selected:
            from daimon_matrix.messaging_config import config_digest, read_publication
            guard = selected['application_precondition']
            application = being_seed._read(directory / (guard['application_step'] + '.json'),
                                           limit=being_seed.MAX_SELECTION)
            application_result = application.get('result')
            if (application.get('owner_context_sha256') != digest(context)
                    or application.get('command', {}).get('operation_id') != selected['operation_id']
                    or application['command'].get('action') != 'application'
                    or application['command'].get('step') != guard['application_step']
                    or not isinstance(application_result, dict) or application_result.get('status') != 'recorded'
                    or application_result.get('schema') != 'cluster-group-publication-result/v1'
                    or any(application_result.get(key) != application['command'][key]
                           for key in ('operation_id', 'step', 'action'))
                    or application_result.get('application_sha256') != guard['application_sha256']
                    or config_digest(read_publication(hosted, group_root / 'application')[0]) != guard['application_sha256']):
                raise OnboardingError('onboarding_group_publication_application_changed')
            # The caller still holds the native writer: a later valid renewal
            # cannot interleave this check and the dependent native effect.
            check_deadline()
        if 'visibility_precondition' in selected:
            from daimon_matrix.messaging_config import config_digest, read_document
            guard = selected['visibility_precondition']
            visibility = being_seed._read(directory / (guard['visibility_step'] + '.json'),
                                         limit=being_seed.MAX_SELECTION)
            visibility_result = visibility.get('result')
            if (visibility.get('owner_context_sha256') != digest(context)
                    or visibility.get('command', {}).get('operation_id') != selected['operation_id']
                    or visibility['command'].get('action') != 'visibility-publish'
                    or visibility['command'].get('step') != guard['visibility_step']
                    or not isinstance(visibility_result, dict) or visibility_result.get('status') != 'recorded'
                    or visibility_result.get('schema') != 'cluster-group-publication-result/v1'
                    or any(visibility_result.get(key) != visibility['command'][key]
                           for key in ('operation_id', 'step', 'action'))
                    or visibility_result.get('installation_sha256') != guard['installation_sha256']
                    or config_digest(read_document(group_root / 'visibility/installation.json')['document'])
                       != guard['installation_sha256']):
                raise OnboardingError('onboarding_group_publication_visibility_changed')
            check_deadline()
        observed = _publication_effect(hosted, group_root, selected, context['authority_closure'],
            operation=operation, context=context, snapshot=snapshot)
        if (selected['action'] == 'snapshot' and retained['result'] is not None
                and 'stores' not in retained['result'] and 'expected_stores' not in selected['params']):
            # Preserve an older completed observation's exact result shape.
            # It remains fresh-validated but cannot become admission store proof.
            observed.pop('stores', None)
        result = dict(schema='cluster-group-publication-result/v1', operation_id=selected['operation_id'],
            step=selected['step'], action=selected['action'], status='recorded',
            receiving_readiness='unobserved', **observed)
        if retained['result'] is not None and retained['result'] != result:
            raise OnboardingError('onboarding_group_publication_changed')
        if retained['result'] is None:
            being_seed._write(path, {**retained, 'result': result}, limit=being_seed.MAX_SELECTION)
        check_deadline()
        return result


def relationship_request(runtime_root: Path, journal: Path, value: dict, *,
                         offline=None, deadline_ns: int | None = None,
                         membership_precondition: dict | None = None) -> dict:
    """Record or retry one native request; never return local capability material.

    A relationship snapshot is the native reducer's observation at its retained
    verified_at_ms. Exact retry returns that observation, not fresh membership
    or receiving readiness. A later phase needs its own approved step.
    """
    from daimon_matrix.client import ClientConfig, LocalClient
    from daimon_matrix.local_api import MAX_CLOCK_SKEW_MS, authenticate_request, verify_response
    from daimon_matrix.messaging_config import protected_read
    from daimon_matrix.operator_capabilities import operator_capability_profile

    selected = command(value)
    guard = None
    if membership_precondition is not None:
        if offline is None:
            raise OnboardingError('onboarding_group_relationship_writer_required')
        guard = validate_membership_precondition(membership_precondition, selected)
    private_directory(runtime_root)
    bundle = being_seed._read(runtime_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    role = 'observe' if selected['method'] == 'relationship.snapshot' else 'relationships'
    profile = operator_capability_profile(role)
    directory = runtime_root / profile['client_directory']
    config = ClientConfig.load(directory / profile['client_config_filename'],
        bytearray(protected_read(directory / profile['client_key_filename'])))
    identity = dict(runtime_id=bundle['runtime_id'], runtime_label=bundle['runtime_label'],
                    server=bundle['local_origin'], capability_id=config.capability.capability_id,
                    ledger=check_retained_ledger(runtime_root, journal, selected))
    if guard is not None:
        identity['membership_precondition_sha256'] = digest(guard)
    if (config.runtime_id != identity['runtime_id'] or config.runtime_label != identity['runtime_label']
            or config.expected_server != identity['server']
            or config.capability.client_id != 'client:operator:' + config.runtime_label + ':' + role
            or selected['method'] not in config.capability.methods):
        raise OnboardingError('onboarding_group_relationship_client_conflict')
    clock = (lambda: time.time_ns() // 1_000_000) if offline is None else offline.service.clock
    if offline is not None and (offline.state_root != runtime_root
            or offline.service.runtime_identity != {key: identity[key] for key in ('runtime_id', 'runtime_label')}
            or offline.service.origin != identity['server']):
        raise OnboardingError('onboarding_group_relationship_client_conflict')
    client = LocalClient(runtime_root / bundle['socket'], config, clock=clock,
                         timeout_seconds=40, deadline_ns=deadline_ns)

    def check_deadline():
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('onboarding_group_relationship_deadline_expired')

    def authenticate(frame: dict) -> str:
        normalized, request_hash = authenticate_request(frame, config.capability,
            now_ms=frame['issued_at_ms'])
        if normalized['method'] != selected['method'] or normalized['params'] != selected['params']:
            raise OnboardingError('onboarding_group_relationship_request_conflict')
        return request_hash

    def verify_loaded_stores():
        binding = offline.service.loaded_stores.get('ledger')
        if (binding is None or binding.path != offline.service.ledger.path
                or list(binding.identity) != identity['ledger']['file_identity']):
            raise OnboardingError('onboarding_group_relationship_ledger_changed')
        for item in offline.service.loaded_stores.values():
            item.verify()

    def authoring_precondition(request: dict, request_hash: str):
        if guard is None:
            return
        verify_loaded_stores()
        rows = [row for row in offline.service.ledger.rpc_requests()
                if row['client_id'] == request['client_id'] and row['request_id'] == request['request_id']]
        verify_loaded_stores()
        if rows:
            if rows[0]['request_hash'] != request_hash or rows[0]['method'] != request['method']:
                raise OnboardingError('onboarding_group_relationship_request_conflict')
            if rows[0]['state'] != 'completed':
                # Pending can contain an atomically appended event. It is not
                # absence or permission to author/refresh after an unknown effect.
                raise OnboardingError('onboarding_group_membership_native_uncertain')
            return
        now = clock()
        if now >= guard['not_after_ms']:
            raise OnboardingError('onboarding_group_membership_acceptance_expired')
        check_membership_precondition(offline, guard, now_ms=now)
        if clock() >= guard['not_after_ms']:
            raise OnboardingError('onboarding_group_membership_acceptance_expired')

    check_deadline()
    private_directory(journal, create=True)
    with being_seed._locked(journal):
        operation = private_directory(journal / selected['operation_id'], create=True)
        path = operation / (selected['step'] + '.json')
        if path.exists():
            retained = being_seed._read(path, limit=being_seed.MAX_SELECTION)
            if (set(retained) != {'schema', 'command', 'identity', 'request', 'retired_requests', 'response'}
                    or retained['schema'] != 'cluster-group-relationship-operation/v1'
                    or retained['command'] != selected or retained['identity'] != identity
                    or not isinstance(retained['retired_requests'], list)):
                raise OnboardingError('onboarding_group_relationship_request_conflict')
        else:
            retained = dict(schema='cluster-group-relationship-operation/v1', command=selected,
                identity=identity, request=client.prepare(selected['method'], selected['params']),
                retired_requests=[], response=None)
            being_seed._write(path, retained, limit=being_seed.MAX_SELECTION)
        request_hash = authenticate(retained['request'])
        for earlier in retained['retired_requests']:
            authenticate(earlier)
            if earlier['request_id'] != retained['request']['request_id']:
                raise OnboardingError('onboarding_group_relationship_request_conflict')
        for parent in (operation, journal, journal.parent):
            _sync(parent)
        request = retained['request']
        if retained['response'] is None:
            check_deadline()
            authoring_precondition(request, request_hash)
            if offline is not None and clock() - request['issued_at_ms'] > MAX_CLOCK_SKEW_MS:
                # Current capability validity is still required. Actual exclusive
                # writer ownership makes native RPC absence a stable fact.
                authenticate_request(request, config.capability, now_ms=clock(), allow_stale=True)
                verify_loaded_stores()
                rows = [row for row in offline.service.ledger.rpc_requests()
                    if row['client_id'] == request['client_id'] and row['request_id'] == request['request_id']]
                verify_loaded_stores()
                if rows and (rows[0]['request_hash'] != request_hash or rows[0]['method'] != request['method']):
                    raise OnboardingError('onboarding_group_relationship_request_conflict')
                if not rows:
                    retained['retired_requests'].append(request)
                    request = client.prepare(selected['method'], selected['params'], request_id=request['request_id'])
                    retained['request'] = request
                    being_seed._write(path, retained, limit=being_seed.MAX_SELECTION)
                    request_hash = authenticate(request)
            check_deadline()
            authoring_precondition(request, request_hash)
            check_deadline()
            response = client.send(request) if offline is None else offline.service.handle(request)
        else:
            response = retained['response']
        verified = verify_response(response, config.capability,
            expected_request_id=request['request_id'], expected_request_hash=request_hash,
            expected_server=config.expected_server,
            expected_runtime=dict(runtime_id=config.runtime_id, runtime_label=config.runtime_label))
        if retained['response'] is None:
            retained['response'] = verified
            # A failed local result write remains recoverable through native RPC.
            being_seed._write(path, retained, limit=being_seed.MAX_SELECTION)
        check_deadline()
        return dict(schema='cluster-group-relationship-result/v1',
            status='recorded' if verified['ok'] else 'rejected',
            request_id=request['request_id'], request_sha256=request_hash,
            response_sha256=digest(verified), result=verified['result'], native_error=verified['error'])

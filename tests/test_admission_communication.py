"""Protected speech scope and native evidence classification, without effects.

These are contract fixtures, not native delivery or full portal qualification.
Native signing, transport and visibility are qualified by the SDK integration.
"""
import copy
import uuid

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_group_coordinator import communication_recipe, communication_result


def reference(label):
    return 'dm:being:v1:' + label * 43


@pytest.fixture
def recipe():
    receivers = {name:dict(being_ref=reference(letter), embodiment_id='embodiment:'+name)
        for name,letter in (('founder','A'), ('entrant','B'))}
    row = dict(intended_transition=dict(portal_admission=dict(social=dict(founder_owner='founder', entrant_owner='entrant'))))
    admission = dict(receivers=receivers, activation=dict(expires_at_ms=2000))
    def sender(name):
        return dict(owner=name, **receivers[name])
    value = dict(schema='cluster-admission-communication/v1', expires_at_ms=1500,
        group=dict(sender=sender('founder'), text='Group check'),
        direct=dict(sender=sender('entrant'), text='Directed check', destination=dict(kind='being', being_ref=reference('A'))),
        reply=dict(sender=sender('entrant'), text='Connected reply', parent='group'))
    return value, row, admission


@pytest.mark.parametrize('fault', [None, 'actor', 'destination', 'body', 'expiry', 'parent', 'extra'])
def test_technical_scope_is_bound_to_the_approved_bodies_and_fixed_horizon(recipe, fault):
    value, row, admission = recipe
    if fault == 'actor':
        value['group']['sender']['owner'] = 'entrant'
    elif fault == 'destination':
        value['direct']['destination']['being_ref'] = reference('B')
    elif fault == 'body':
        value['direct']['destination'].update(kind='body', embodiment_id='embodiment:unknown')
    elif fault == 'expiry':
        value['expires_at_ms'] = 2001
    elif fault == 'parent':
        value['reply']['parent'] = 'direct'
    elif fault == 'extra':
        value['allow_models'] = True
    if fault:
        with pytest.raises(OnboardingError, match='communication_scope_required'):
            communication_recipe(value, row, admission)
    else:
        result = communication_recipe(value, row, admission)
        assert result == value
        result['group']['text'] = 'changed copy'
        assert value['group']['text'] == 'Group check'
        value['direct']['destination'].update(kind='body', embodiment_id='embodiment:founder')
        assert communication_recipe(value, row, admission) == value


def delivery(step='group', *, parent=None):
    author = dict(being_ref=reference('A'), embodiment_id='embodiment:founder')
    recipient = dict(being_ref=reference('B'), embodiment_id='embodiment:entrant')
    parameters = dict(channel_id='tribe', send_id=str(uuid.uuid4()), thread_id=str(uuid.uuid4()))
    context = None
    if step == 'direct':
        parameters['destination'] = dict(kind='body', **recipient)
    elif step == 'reply':
        parameters.pop('thread_id')
        parameters.update(message_id=parent['message_id'], received_channel_id='tribe')
        context = dict(message_id=parent['message_id'], message_hash=parent['message_hash'],
            sender_being_ref=parent['author']['being_ref'], sender_embodiment_id=parent['author']['embodiment_id'])
    result = dict(schema='dm.tribe.direct-delivery/v1' if step == 'direct' else 'dm.tribe.delivery/v1',
        send_id=parameters['send_id'], message_id=str(uuid.uuid4()), message_hash='a'*64,
        thread_id=parent['thread_id'] if parent else parameters['thread_id'], tribe_ref='tribe:fixture', author=author,
        response_context=context, visibility=dict(echo_state='confirmed', part_count=3, confirmed_parts=3),
        audience=[dict(membership_ref='membership:author', **author), dict(membership_ref='membership:recipient', **recipient)],
        semantic=dict(legs=[]), transport=dict(expired=True))
    if step == 'direct':
        result['audience'] = result['audience'][1:]
        result['destination'] = dict(**parameters['destination'], authority_manifest_hash='b'*64)
    for item in result['audience']:
        result['semantic']['legs'].append(dict(recipient_id=item['membership_ref'], receipt_origin_embodiment_id=item['embodiment_id'],
            message_id=result['message_id'], thread_id=result['thread_id'], state='delivered',
            terminal_receipt_event_id=str(uuid.uuid4()), terminal_receipt_hash='c'*64))
    response = dict(schema='dm.local.response/v1', ok=True, error=None, result=result)
    intent = dict(step=step, parameters=parameters, sender=author)
    return response, intent


def qualify(response, intent, parent=None):
    return communication_result(response, intent, tribe_ref='tribe:fixture', parent=parent)


def test_late_signed_intake_is_distinct_from_the_authors_retained_copy():
    response, intent = delivery()
    result = qualify(response, intent)
    assert [(item['being_ref'], item['embodiment_id']) for item in result['inbound']] == [(reference('B'), 'embodiment:entrant')]
    response['result']['semantic']['legs'].pop()
    assert qualify(response, intent)['inbound'] == [], 'author retention never proves any receiving body'


@pytest.mark.parametrize('fault', ['unconfirmed', 'partial', 'empty', 'receipt', 'audience', 'author', 'message'])
def test_incomplete_or_unrelated_proof_is_not_admission_acceptance(fault):
    response, intent = delivery()
    result = response['result']
    if fault == 'unconfirmed':
        result['visibility']['echo_state'] = 'pending'
    elif fault == 'partial':
        result['visibility']['confirmed_parts'] = 2
    elif fault == 'empty':
        result['visibility'].update(part_count=0, confirmed_parts=0)
    elif fault == 'receipt':
        result['semantic']['legs'][-1]['terminal_receipt_hash'] = None
    elif fault == 'audience':
        result['audience'].append(copy.deepcopy(result['audience'][0]))
    elif fault == 'author':
        result['author'] = dict(being_ref=reference('C'), embodiment_id='embodiment:unknown')
    elif fault == 'message':
        result['semantic']['legs'][-1]['message_id'] = str(uuid.uuid4())
    with pytest.raises(OnboardingError, match='communication_unobserved'):
        qualify(response, intent)


def test_reply_is_correlated_to_the_exact_signed_parent_and_native_request():
    response, intent = delivery()
    parent = qualify(response, intent)
    response, intent = delivery('reply', parent=parent)
    result = qualify(response, intent, parent)
    assert result['response_context']['message_hash'] == parent['message_hash']
    response['result']['response_context']['message_hash'] = 'f'*64
    with pytest.raises(OnboardingError, match='communication_unobserved'):
        qualify(response, intent, parent)
    response, intent = delivery('reply', parent=parent)
    intent['parameters']['message_id'] = str(uuid.uuid4())
    with pytest.raises(OnboardingError, match='communication_unobserved'):
        qualify(response, intent, parent)
    with pytest.raises(OnboardingError, match='communication_unobserved'):
        qualify(response, intent)


def test_direct_preserves_the_exact_target_with_no_group_fanout():
    response, intent = delivery('direct')
    assert qualify(response, intent)['inbound'][0]['embodiment_id'] == 'embodiment:entrant'
    response['result']['audience'][0]['embodiment_id'] = 'embodiment:other'
    with pytest.raises(OnboardingError, match='communication_unobserved'):
        qualify(response, intent)

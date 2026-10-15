"""Group receiving selection must never reconstruct the legacy pair mesh."""
import copy
from types import SimpleNamespace

from clusterctl.onboarding_acceptance import matrix_delivery_result
from clusterctl.onboarding_peer_host import PeerHost


def test_signed_group_selection_precedes_pair_identity_and_proxy_onboarding():
    host = object.__new__(PeerHost)
    root = '/home/agent/.local/state/daimon-onboarding/eko/matrix'
    group = dict(tribe_ref='dm:tribe:v1:approved', application=root+'/tribe/application',
        visibility=root+'/tribe/visibility/installation.json',
        socket=root+'/package/runtime/tribe.sock', channel_id='tribe')
    host.backend = SimpleNamespace(_matrix_command=lambda *_: {'phase':'v8','group':group})
    def obsolete(*_args, **_kwargs):
        raise AssertionError('group participation must not bootstrap a pair')
    host._identity = host._proxies = obsolete
    assert host.application({'name':'eko'}) == (group['application'],group['visibility'])


def test_group_intake_evidence_does_not_require_offline_siblings_to_finish():
    identifier='1ea0eed3-1055-49c0-a7df-4e096e37b9c3'
    response={'ok':True,'error':None,'result':{'schema':'dm.tribe.delivery/v1',
        'send_id':identifier,'audience':[
            {'being_ref':'source','membership_ref':'member-source','embodiment_id':'body-live'},
            {'being_ref':'source','membership_ref':'member-source','embodiment_id':'body-offline'}],
        'semantic':{'terminal':False,'legs':[
            {'recipient_id':'member-source','receipt_origin_embodiment_id':'body-live','state':'delivered'},
            {'recipient_id':'member-source','receipt_origin_embodiment_id':'body-offline','state':'accepted'}]}}}
    evidence=matrix_delivery_result(response,identifier,'source')
    assert evidence['verified'] is True and evidence['agent_read'] is False
    assert matrix_delivery_result(response,identifier,'other')=={'verified':False}
    unknown=copy.deepcopy(response)
    unknown['result']['semantic']['legs'][0]['state']='accepted'
    unknown['result']['transport']=[{'state':'recipient-intake'}]
    assert matrix_delivery_result(unknown,identifier,'source')=={'verified':False}
    malformed=copy.deepcopy(response)
    del malformed['result']['audience'][0]['membership_ref']
    assert matrix_delivery_result(malformed,identifier,'source')=={'verified':False}


def test_group_worker_cannot_fall_back_to_a_new_founder_member_tribe(tmp_path):
    import pytest
    from clusterctl.onboarding import OnboardingError
    host=object.__new__(PeerHost)
    host.application=lambda _:None
    host._source=lambda *_:{'running':True,'group':{'tribe_ref':'already-selected'}}
    host._identity=lambda _: (_ for _ in ()).throw(AssertionError('must not enroll pair'))
    with pytest.raises(OnboardingError,match='onboarding_group_enrollment_required'):
        host._execute({'name':'new-member'})


def test_legacy_pair_is_not_group_onboarding_completion():
    import pytest
    from clusterctl.onboarding import OnboardingError
    host=object.__new__(PeerHost)
    host.application=lambda _:('/matrix/peer/application','/matrix/peer/visibility/installation.json')
    with pytest.raises(OnboardingError,match='onboarding_group_enrollment_required'):
        host._execute({'name':'eko'})


def test_legacy_pair_receipt_cannot_make_worker_group_selection_complete(tmp_path):
    from clusterctl import being_seed
    from clusterctl.onboarding import digest

    host = object.__new__(PeerHost)
    plan = {'name': 'eko', 'owner': 'fixture-human'}
    host.state = tmp_path
    host.settings = {'source_being_ref': 'fixture-source'}
    host.backend = SimpleNamespace(_matrix_command=lambda *_: {
        'phase': 'v8', 'receipt': {'peer_being_ref': 'fixture-source'},
    })
    host._identity = lambda *_: None
    host._proxies = lambda *_: True
    host._source = lambda *_: {'running': True, 'applications': [digest(plan)]}
    directory = tmp_path / digest(plan)
    directory.mkdir(mode=0o700)
    being_seed._write(directory / 'complete.json', {
        'schema': 'cluster-onboarding-peer-complete/v1',
        'plan_digest': digest(plan),
        'source_being_ref': 'fixture-source',
    })
    before = (directory / 'complete.json').read_bytes()
    assert host.application(plan) is None
    assert (directory / 'complete.json').read_bytes() == before

"""Genuine signed fixture metadata, with no listener or transport effects."""
import copy

import pytest

from daimon_matrix.messaging_config import config_digest
from tests.integration.portal_admission_baseline import addressed, publish
from tests import test_onboarding_group_authorities as group_fixtures

@pytest.fixture
def group_source(tmp_path):
    location = tmp_path/'mémoire'
    location.mkdir(mode=0o700)
    return group_fixtures.group_source.__wrapped__(location)


def setup(group_source):
    from daimon_matrix.messaging_config import read_publication
    source = group_source[0]
    hosted = source._load(signed=False)
    directory = source.outputs/'tribe/application'
    previous, _ = read_publication(hosted, directory)
    local = hosted.service.origin['body_ref']
    endpoints = {local: previous['intake']['endpoint'].replace('127.0.0.1', '10.99.227.1')}
    return hosted, directory, previous, endpoints


def test_signed_baseline_lost_publication_reply_retains_client_and_all_stores(group_source, tmp_path, monkeypatch):
    from daimon_matrix import operator_messaging as native
    from daimon_matrix.messaging_config import load_application, read_document, read_publication
    hosted, directory, before, endpoints = setup(group_source)
    paths = [directory/name for name in [*before['stores'].values(), before['client']['secret_file']]]
    original = {p: (p.stat().st_ino, p.read_bytes()) for p in paths}
    publication = read_document(directory/'publication.json')
    sync = native._sync
    failed = []
    def interrupted(path):
        sync(path)
        if path == directory and read_document(directory/'publication.json') != publication and not failed:
            failed.append(True)
            raise OSError('lost fixture publication acknowledgement')
    options = dict(endpoints=endpoints, operation=directory.parent/'qualification'/'fixture-operation',
        expected_application_sha256=config_digest(before))
    with monkeypatch.context() as fault:
        fault.setattr(native, '_sync', interrupted)
        with pytest.raises(OSError, match='lost fixture publication'):
            publish(hosted, directory, **options)
    result = publish(hosted, directory, **options)
    assert publish(hosted, directory, **options) == result
    after, _ = read_publication(hosted, directory)
    assert after == addressed(before, endpoints, local_body=hosted.service.origin['body_ref'])
    assert after['client'] == before['client']
    assert all((p.stat().st_ino, p.read_bytes()) == value for p, value in original.items())
    load_application(hosted, directory)
    assert result['receiving_readiness'] == 'unobserved'


def test_later_native_publication_is_never_replaced_by_fixture_retry(group_source, tmp_path):
    from daimon_matrix.operator_messaging import renew
    from daimon_matrix.messaging_config import read_publication
    hosted, directory, before, endpoints = setup(group_source)
    options = dict(endpoints=endpoints, operation=directory.parent/'qualification'/'fixture-operation',
        expected_application_sha256=config_digest(before))
    first = publish(hosted, directory, **options)
    renew(hosted, directory, expected_application_sha256=first['application_sha256'])
    winner, _ = read_publication(hosted, directory)
    with pytest.raises(ValueError, match='later or conflicting'):
        publish(hosted, directory, **options)
    assert read_publication(hosted, directory)[0] == winner


def test_fixture_route_map_cannot_change_roster_ports_or_escape_bridge(group_source):
    hosted, _directory, before, endpoints = setup(group_source)
    local = hosted.service.origin['body_ref']
    for target in ('http://144.217.95.152:48675/dm-messaging/v1/message',
            'http://10.99.227.1:22/dm-messaging/v1/message',
            'http://user@10.99.227.1:48675/dm-messaging/v1/message'):
        with pytest.raises(ValueError):
            addressed(before, {local:target}, local_body=local)
    wrong = copy.deepcopy(endpoints)
    wrong['foreign'] = wrong.pop(local)
    with pytest.raises(ValueError, match='original baseline roster'):
        addressed(before, wrong, local_body=local)

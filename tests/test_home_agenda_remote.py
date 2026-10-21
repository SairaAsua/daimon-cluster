"""Actual private HTTP application hop, current pairing and retained mutations."""
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
import json
import os
import threading
import urllib.error
import urllib.request

import pytest

from clusterctl.homes.agenda import Agenda, AgendaError, Vikunja
from clusterctl.homes.agenda_remote import ReceivingContext, RemoteAgenda, service_handler
from tests.test_home_agenda import app, Engine  # noqa: F401
from tests.test_home_agenda_calendar import Google


@contextmanager
def remote(app, tmp_path):
    token = tmp_path / 'transport-token'
    token.write_text('fixture-private-transport-key-000000000')
    token.chmod(0o600)
    context = ReceivingContext()
    core = Agenda(context, tmp_path / 'remote-state', 'http://127.0.0.1:1', provider=Engine())
    core.calendar.provider = Google()
    server = ThreadingHTTPServer(('127.0.0.1', 0), service_handler(core, context, token,
        {k: v['public_url'] for k, v in app.homes.items()}))
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    origin = 'http://127.0.0.1:' + str(server.server_port)
    config = tmp_path / 'remote.json'
    config.write_text(json.dumps({'origin': origin, 'token_file': str(token)}))
    proxy = RemoteAgenda(app, config)
    try:
        yield proxy, core, config, origin
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)


def test_remote_real_http_separate_agendas_and_exact_mutation_retry(app, tmp_path):
    with remote(app, tmp_path) as (proxy, core, _, _):
        one, two = (app.authority.actor('human-' + n) for n in ('one', 'two'))
        assert not proxy.dispatch('one', one, 'state', {})['initialized']
        proxy.dispatch('one', one, 'init', {'operation_id': 'remote-init-one'})
        proxy.dispatch('two', two, 'init', {'operation_id': 'remote-init-two'})
        payload = {'operation_id': 'remote-project-one', 'title': 'Our plan'}
        first = proxy.dispatch('one', one, 'project-create', payload)
        assert proxy.dispatch('one', one, 'project-create', payload) == first
        assert [p['title'] for p in proxy.dispatch('one', one, 'state', {})['projects']] == ['Personal', 'Our plan']
        assert [p['title'] for p in proxy.dispatch('two', two, 'state', {})['projects']] == ['Personal']
        with pytest.raises(AgendaError, match='agenda_access_denied'):
            proxy.dispatch('one', two, 'state', {})


def test_remote_native_owner_and_current_pairing_revision(app, tmp_path):
    with remote(app, tmp_path) as (proxy, _, _, _):
        owner = app.authority.actor('being-one')
        human = app.authority.actor('human-one')
        proxy.dispatch('one', owner, 'init', {'operation_id': 'native-remote-init'}, native=True)
        assert proxy.dispatch('one', human, 'state', {})['initialized']
        app.authority.pairs['one'] = 'human-two'
        with pytest.raises(AgendaError, match='agenda_access_denied'):
            proxy.dispatch('one', human, 'state', {})
        from dataclasses import replace
        app.authority.people[owner.ref] = replace(owner, revision='v2')
        with pytest.raises(AgendaError, match='agenda_access_denied'):
            proxy.dispatch('one', owner, 'state', {}, native=True)


def test_remote_calendar_binds_parent_without_forwarding_browser_cookie(app, tmp_path):
    with remote(app, tmp_path) as (proxy, core, _, _):
        human = app.authority.actor('human-one')
        proxy.dispatch('one', human, 'init', {'operation_id': 'calendar-remote-init'})
        result = proxy.calendar.begin('one', human, 'private-browser-cookie', 'https://one.example')
        assert result['authorization_url'].startswith('https://accounts.google.com/')
        from contextlib import closing
        with closing(core.connect()) as db:
            row = db.execute('SELECT parent FROM agenda_google_flows').fetchone()
            assert row['parent'] != 'private-browser-cookie'
        state = core.calendar.provider.flow[0]
        with pytest.raises(AgendaError, match='agenda_google_flow_unavailable'):
            proxy.calendar.finish('one', human, 'different-cookie', state, 'fixture-code')
        proxy.calendar.finish('one', human, 'private-browser-cookie', state, 'fixture-code')
        assert proxy.dispatch('one', human, 'state', {})['calendar']['connected']
        app.authority.pairs['one'] = 'human-two'
        assert not proxy.dispatch('one', app.authority.actor('human-two'), 'state', {})['calendar']['connected']


def test_remote_transport_rejects_untrusted_clients_and_nonlocal_plain_http(app, tmp_path):
    with remote(app, tmp_path) as (_, _, config, origin):
        request = urllib.request.Request(origin + '/agenda-operation', data=b'{}', method='POST')
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        assert error.value.code == 403
        value = json.loads(config.read_text())
        value['origin'] = 'http://192.0.2.1:9999'
        config.write_text(json.dumps(value))
        with pytest.raises(ValueError, match='agenda_remote_requires_https_or_loopback'):
            RemoteAgenda(app, config)


def test_remote_unavailable_does_not_repeat_provider_work(app, tmp_path):
    with remote(app, tmp_path) as (proxy, core, config, origin):
        human = app.authority.actor('human-one')
        proxy.dispatch('one', human, 'init', {'operation_id': 'uncertain-remote-init'})
        project = proxy.dispatch('one', human, 'project-create', {
            'operation_id': 'uncertain-remote-project', 'title': 'One'})
        core.provider.drop_ack = True
        payload = {'operation_id': 'uncertain-remote-task', 'project_id': project['project']['id'], 'title': 'Retain me'}
        with pytest.raises(AgendaError, match='agenda_provider_unavailable'):
            proxy.dispatch('one', human, 'task-create', payload)
        with pytest.raises(AgendaError, match='agenda_operation_uncertain'):
            proxy.dispatch('one', human, 'task-create', payload)
        assert len(proxy.dispatch('one', human, 'state', {})['tasks']) == 1


@pytest.mark.skipif(not os.environ.get('DAIMON_AGENDA_VIKUNJA'), reason='Official disposable engine not selected')
def test_remote_official_engine_human_and_native_share_saved_records(app, tmp_path):
    with remote(app, tmp_path) as (proxy, core, _, _):
        core.provider = Vikunja(os.environ['DAIMON_AGENDA_VIKUNJA'])
        human = app.authority.actor('human-one')
        owner = app.authority.actor('being-one')
        proxy.dispatch('one', human, 'init', {'operation_id': 'real-remote-initialize'})
        project = proxy.dispatch('one', human, 'project-create', {
            'operation_id': 'real-remote-project', 'title': 'Remote deployment check'})['project']
        task = proxy.dispatch('one', owner, 'task-create', {
            'operation_id': 'real-remote-task', 'project_id': project['id'],
            'title': 'Read the same record'}, native=True)['task']
        result = proxy.dispatch('one', human, 'task-update', {'operation_id': 'real-remote-complete',
            'task_id': task['id'], 'revision': task['revision'], 'done': True})
        assert result['task']['done']
        saved = proxy.dispatch('one', owner, 'state', {}, native=True)['tasks']
        assert next(t for t in saved if t['id'] == task['id'])['done']

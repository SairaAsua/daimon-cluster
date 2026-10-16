"""Only the synthetic external API is doubled; retain actual bounded HTTP I/O."""
import json
import os
import threading
import types
from unittest.mock import patch

import pytest

from clusterctl import onboarding_release
from clusterctl.onboarding_code_successor import build
from tests.integration import portal_admission_echo as echo
from tests.test_onboarding_code_successor import fixture


@pytest.mark.parametrize('value', [
    'https://127.0.0.1:1234', 'http://localhost:1234', 'http://127.0.0.1:80',
    'http://127.0.0.1:1234/path', 'http://127.0.0.1:1234?x=1',
    'http://user@127.0.0.1:1234', 'http://127.0.0.1:1234#x'])
def test_mapper_requires_fixed_loopback_api(value):
    with pytest.raises(ValueError):
        echo.mapper(value)


def load_mapper(base):
    module = types.ModuleType('q227_telegram_fixture')
    exec(compile(echo.mapper(base), '<captured-fixture-mapper>', 'exec'), module.__dict__)
    return module


def test_no_rejected_url_can_start_an_executor_or_fall_back_publicly():
    from daimon_matrix import telegram_mirror as mirror
    original = mirror._plain_http_exchange
    try:
        load_mapper('http://127.0.0.1:49137').install()
        for url in (
            'https://api.telegram.org/botOTHER/getMe',
            f'https://api.telegram.org/bot{echo.TOKEN}/getUpdates',
            f'https://api.telegram.org/bot{echo.TOKEN}/sendMessage?x=1',
            f'https://api.telegram.org.evil/bot{echo.TOKEN}/getMe',
            'http://127.0.0.1:49137/getMe',
        ):
            with patch.object(mirror.subprocess, 'Popen') as spawn:
                with pytest.raises(mirror.EchoTransportFailure) as refused:
                    mirror._plain_http_exchange(url, b'{}')
                assert refused.value.reason == 'synthetic-url-refused'
                spawn.assert_not_called()
        first = mirror._plain_http_exchange
        load_mapper('http://127.0.0.1:49137').install()
        assert mirror._plain_http_exchange is first
        with pytest.raises(ValueError, match='already_changed'):
            load_mapper('http://127.0.0.1:49138').install()
    finally:
        mirror._plain_http_exchange = original


def test_real_isolated_executor_reaches_durable_api_with_unique_posts_and_replies(tmp_path):
    from daimon_matrix import telegram_mirror as mirror
    state = echo.State(tmp_path/'api.sqlite3')
    listener = echo.server(state, 0)
    worker = threading.Thread(target=listener.serve_forever)
    worker.start()
    original = mirror._plain_http_exchange
    try:
        load_mapper(f'http://127.0.0.1:{listener.server_port}').install()
        status, raw = mirror._plain_http_exchange(
            f'https://api.telegram.org/bot{echo.TOKEN}/getMe', b'{}')
        assert status == 200 and json.loads(raw)['result']['id'] == echo.BOT
        transport = mirror.PlainTelegramTransport(token=echo.TOKEN, bot_id=echo.BOT,
            chat_id=echo.CHAT, topic_id=None)
        request = mirror.plain_request('Synthetic header\nfull message ✓',
            chat_id=echo.CHAT, topic_id=None, readable=True)
        first = json.loads(transport.send(request))['result']
        second = json.loads(transport.send(request))['result']
        # Do not hide a client duplicate behind unrealistic API idempotency.
        assert first['message_id'] != second['message_id']
        reply = mirror.plain_request('Connected synthetic reply', chat_id=echo.CHAT,
            topic_id=None, readable=True, reply_message_id=first['message_id'])
        response = json.loads(transport.send(reply))['result']
        assert response['reply_to_message'] == first
        rows = echo.State(state.path).requests()
        assert [r['method'] for r in rows] == ['getMe', 'sendMessage', 'sendMessage', 'sendMessage']
        assert rows[-1]['request'] == reply
        assert rows[-1]['response']['result'] == response
    finally:
        mirror._plain_http_exchange = original
        listener.shutdown()
        listener.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


def test_api_refuses_other_destinations_and_unknown_parents_without_recording_success(tmp_path):
    from daimon_matrix.telegram_mirror import plain_request
    state = echo.State(tmp_path/'api.sqlite3')
    request = plain_request('synthetic', chat_id=echo.CHAT, topic_id=None, readable=True)
    for invalid in ({**request, 'chat_id': 123}, {**request, 'text': ''},
            {**request, 'parse_mode': 'HTML'}, {**request, 'message_thread_id': 999}):
        with pytest.raises(ValueError):
            state.exchange('sendMessage', invalid)
    reply = {**request, 'reply_parameters': {'message_id': 999, 'allow_sending_without_reply': True}}
    with pytest.raises(ValueError):
        state.exchange('sendMessage', reply)
    with pytest.raises(ValueError):
        state.exchange('getUpdates', {})
    assert state.requests() == []


def test_composition_preserves_original_sdk_context_helpers_and_later_writer(tmp_path):
    base, base_digest, source, _profile = fixture(tmp_path)
    # Minimal source for this constructor test; no installed-runtime claim.
    original = ('def qualified_startup(venv, imports, code):\n' + echo.GUARD
        + echo.ANCHOR + ' process_id=1)\n').encode()
    (source/'onboarding_sdk.py').write_bytes(original)
    selected = tmp_path/'selected'
    old = build(base, base_digest, source, ('onboarding_sdk.py',), selected)
    output = tmp_path/'instrumented'
    value = echo.compose(selected, old['runtime_digest'], base, base_digest,
        output, api='http://127.0.0.1:49137', uid=os.geteuid())
    assert value['fixture_only'] is True and value['public_telegram_qualified'] is False
    assert (selected/echo.STARTUP).read_bytes() == original
    assert (output/'sdk/pinned.whl').read_bytes() == (selected/'sdk/pinned.whl').read_bytes()
    assert (output/'inheritance.md').read_bytes() == (selected/'inheritance.md').read_bytes()
    release = onboarding_release.verify(output, value['runtime_digest'], uid=os.geteuid())
    assert echo.MODULE in {r['path'] for r in release['files']}
    changed = (output/echo.STARTUP).read_text()
    assert changed.count('    origins()\n') == 2
    assert changed.count('    if not startup_context(') == 2
    assert echo.compose(selected, old['runtime_digest'], base, base_digest,
        output, api=value['api'], uid=os.geteuid()) == value
    with pytest.raises(ValueError, match='preserve'):
        echo.compose(selected, old['runtime_digest'], base, base_digest,
            output, api='http://127.0.0.1:49138', uid=os.geteuid())
    assert (output/echo.MODULE).read_bytes() == echo.mapper(value['api'])


def test_hook_refuses_unrecognized_or_already_instrumented_startup():
    for raw in (b'def qualified_startup(): pass',
            (echo.GUARD+echo.ANCHOR+' x=1)').encode()):
        if raw.startswith(b'def'):
            with pytest.raises(ValueError):
                echo.instrument(raw)
        else:
            # A supported function must parse; do not accept a text-only marker.
            with pytest.raises((ValueError, SyntaxError, IndentationError)):
                echo.instrument(raw)

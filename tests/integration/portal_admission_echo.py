"""Synthetic external Telegram API and explicitly instrumented admission code.

This file never changes production modules, SDK wheels, identity or custody.
The captured startup hook is part of a DIFFERENT, fixture-only code digest.
Native lifecycle/communication evidence from it is not public Telegram evidence.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import threading
import time
from urllib.parse import urlsplit

from clusterctl import onboarding_release, onboarding_code_successor
from clusterctl.onboarding import digest, private_directory

TOKEN = '137:DISPOSABLE-MIXED-FIXTURE'
BOT = 137
CHAT = -100137
MODULE = 'clusterctl/q227_telegram_fixture.py'
STARTUP = 'clusterctl/onboarding_sdk.py'
ANCHOR = "    return dict(schema='cluster-onboarding-loaded-startup/v1',"
GUARD = "    origins()\n    if not startup_context(venv, imports, code):\n        raise OnboardingError('qualified_runtime_context_required')\n"


def endpoint(value: str) -> str:
    selected = urlsplit(value)
    if (selected.scheme != 'http' or selected.hostname != '127.0.0.1'
            or selected.port is None or not 1024 <= selected.port <= 65535
            or selected.netloc != '127.0.0.1:' + str(selected.port)
            or selected.path or selected.query or selected.fragment):
        raise ValueError('only a fixed loopback synthetic API is supported')
    return value


def mapper(value: str) -> bytes:
    """Capture the only exchange substitution, with no public network fallback."""
    value = endpoint(value)
    return ('''"""FIXTURE ONLY: synthetic Telegram external service, not public delivery."""
from daimon_matrix import telegram_mirror as mirror
BASE = ''' + repr(value) + '''
URLS = {"https://api.telegram.org/bot''' + TOKEN + '''/" + method: BASE + "/" + method
        for method in ("getMe", "sendMessage")}


def install():
    original = mirror._plain_http_exchange
    if getattr(original, "_q227_endpoint", None) == BASE:
        return
    if (original.__module__ != "daimon_matrix.telegram_mirror"
            or original.__name__ != "_plain_http_exchange"):
        raise ValueError("synthetic_exchange_already_changed")

    def exchange(url, payload):
        if type(url) is not str or url not in URLS:
            raise mirror.EchoTransportFailure("synthetic-url-refused")
        return original(URLS[url], payload)

    exchange._q227_endpoint = BASE
    mirror._plain_http_exchange = exchange
''').encode()


def instrument(raw: bytes) -> bytes:
    """Keep both native integrity checks before AND after the fixture hook."""
    source = raw.decode('utf-8')
    if source.count(GUARD + ANCHOR) != 1 or 'q227_telegram_fixture' in source:
        raise ValueError('the exact supported qualified-startup boundary is required')
    hook = (GUARD + '    from .q227_telegram_fixture import install\n    install()\n'
            + GUARD + ANCHOR)
    result = source.replace(GUARD + ANCHOR, hook, 1).encode()
    compile(result, STARTUP, 'exec')
    return result


def compose(selected: Path, selected_digest: str, base: Path, base_digest: str,
            output: Path, *, api: str, uid: int) -> dict:
    """Reseal a public-code copy; preserve all original context/helper/SDK bytes."""
    original = onboarding_release.verify(selected, selected_digest, uid=uid)
    onboarding_release.verify(base, base_digest, uid=os.geteuid())
    originals = {row['path']: row['sha256'] for row in original['files']}
    if STARTUP not in originals or MODULE in originals:
        raise ValueError('an uninstrumented native code selection is required')
    changed = instrument(onboarding_release.regular(selected / STARTUP, uid=uid))
    replacement = mapper(api)
    expected = {**originals, STARTUP: hashlib.sha256(changed).hexdigest(),
        MODULE: hashlib.sha256(replacement).hexdigest()}
    private_directory(output.parent)
    if output.exists() or output.is_symlink():
        release = json.loads(onboarding_release.regular(output / 'release.json', uid=os.geteuid()))
        fingerprint = digest(release)
        current = onboarding_code_successor.verify(output, fingerprint, base,
            base_digest, uid=os.geteuid())
        if {row['path']: row['sha256'] for row in current['files']} != expected:
            raise ValueError('preserve a different fixture composition')
    else:
        with tempfile.TemporaryDirectory(prefix='.q227-echo-', dir=output.parent) as temporary:
            stage = Path(temporary) / 'code'
            stage.mkdir(mode=0o755)
            for row in original['files']:
                source = selected / row['path']
                raw = onboarding_release.regular(source, uid=uid)
                if hashlib.sha256(raw).hexdigest() != row['sha256']:
                    raise ValueError('source code changed during capture')
                path = stage / row['path']
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                path.write_bytes(changed if row['path'] == STARTUP else raw)
                path.chmod(0o755 if source.stat().st_mode & 0o100 else 0o644)
            (stage / MODULE).write_bytes(replacement)
            (stage / MODULE).chmod(0o644)
            # mkdir(parents=True) applies its mode only to the leaf. Keep every
            # captured directory immutable to other users, independent of umask.
            for directory in stage.rglob('*'):
                if directory.is_dir():
                    directory.chmod(0o755)
            fingerprint = onboarding_release.seal(stage, original['profile'])
            current = onboarding_code_successor.verify(stage, fingerprint, base,
                base_digest, uid=os.geteuid())
            if {row['path']: row['sha256'] for row in current['files']} != expected:
                raise ValueError('unexpected fixture code delta')
            from clusterctl.matrix_host import _publish_directory_noreplace
            fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                # Publish a complete sealed directory; never replace a later writer.
                os.rename(stage, Path(temporary) / 'ready')
                _publish_directory_noreplace(fd,
                    Path(temporary).name + '/ready', output.name,
                    exists_code='fixture_composition_already_exists')
                os.fsync(fd)
            finally:
                os.close(fd)
    return dict(schema='cluster-synthetic-telegram-composition/v1', fixture_only=True,
        source_code_digest=selected_digest, runtime_digest=fingerprint,
        base_release_digest=base_digest, api=endpoint(api),
        changed_files=[STARTUP], added_files=[MODULE],
        sdk_manifest_sha256=originals.get('sdk/sdk.json'),
        public_telegram_qualified=False, model_turns_started=0)


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key')
        value[key] = item
    return value


class State:
    """One durable external-service journal; retries deliberately are NOT deduped."""
    def __init__(self, path: Path):
        private_directory(path.parent)
        if not path.exists() and not path.is_symlink():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError('a private synthetic API journal is required')
        self.path, self.lock = path, threading.Lock()
        with closing(sqlite3.connect(path)) as db, db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and tables != {'q227_api', 'sqlite_sequence'}:
                raise ValueError('preserve a different database')
            db.execute('CREATE TABLE IF NOT EXISTS q227_api '
                '(sequence INTEGER PRIMARY KEY AUTOINCREMENT, method TEXT NOT NULL, '
                'request TEXT NOT NULL, response TEXT NOT NULL)')

    def exchange(self, method: str, request: dict) -> dict:
        with self.lock, closing(sqlite3.connect(self.path)) as db, db:
            if db.execute('SELECT COUNT(*) FROM q227_api').fetchone()[0] >= 4096:
                raise ValueError('the finite synthetic API budget is exhausted')
            if method == 'getMe' and request == {}:
                result = dict(id=BOT, is_bot=True, first_name='Synthetic DM137')
            elif method == 'sendMessage':
                if (set(request) - {'chat_id', 'text', 'link_preview_options', 'entities', 'reply_parameters'}
                        or type(request.get('chat_id')) is not int or request['chat_id'] != CHAT
                        or type(request.get('text')) is not str or not request['text']
                        or len(request['text'].encode('utf-16-le')) // 2 > 4096
                        or request.get('link_preview_options') != {'is_disabled': True}):
                    raise ValueError('request outside the fixed synthetic bot destination')
                result = dict(date=int(time.time()), chat=dict(id=CHAT, type='supergroup'),
                    **{'from': dict(id=BOT, is_bot=True, first_name='Synthetic DM137')},
                    text=request['text'])
                if 'entities' in request:
                    if type(request['entities']) is not list:
                        raise ValueError('invalid entities')
                    result['entities'] = request['entities']
                if 'reply_parameters' in request:
                    parent = request['reply_parameters']
                    if (type(parent) is not dict or set(parent) != {'message_id', 'allow_sending_without_reply'}
                            or type(parent['message_id']) is not int or parent['allow_sending_without_reply'] is not True):
                        raise ValueError('invalid synthetic reply')
                    prior = db.execute('SELECT response FROM q227_api WHERE sequence=? AND method=?',
                        (parent['message_id'], 'sendMessage')).fetchone()
                    if prior is None:
                        raise ValueError('unknown synthetic reply parent')
                    result['reply_to_message'] = json.loads(prior[0])['result']
            else:
                raise ValueError('unknown synthetic API method')
            row = db.execute('INSERT INTO q227_api(method,request,response) VALUES(?,?,?)',
                (method, json.dumps(request, ensure_ascii=False), '{}'))
            if method == 'sendMessage':
                result['message_id'] = row.lastrowid
            response = dict(ok=True, result=result)
            db.execute('UPDATE q227_api SET response=? WHERE sequence=?',
                (json.dumps(response, ensure_ascii=False), row.lastrowid))
            return response

    def requests(self) -> list[dict]:
        with self.lock, closing(sqlite3.connect(self.path)) as db, db:
            return [dict(sequence=r[0], method=r[1], request=json.loads(r[2]), response=json.loads(r[3]))
                for r in db.execute('SELECT sequence,method,request,response FROM q227_api ORDER BY sequence')]


def server(state: State, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.connection.settimeout(2)
            try:
                length = int(self.headers.get('Content-Length', '-1'))
                if not 0 < length <= 65536 or self.path not in {'/getMe', '/sendMessage'}:
                    raise ValueError
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError
                request = json.loads(raw, object_pairs_hook=unique)
                if type(request) is not dict:
                    raise ValueError
                response = state.exchange(self.path[1:], request)
                status = 200
            except (ValueError, OSError):
                response, status = dict(ok=False), 400
            raw = json.dumps(response, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            pass
    return ThreadingHTTPServer(('127.0.0.1', port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--seconds', type=int, required=True)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535 or not 1 <= args.seconds <= 3600:
        parser.error('a fixed unprivileged port and finite lifetime are required')
    with server(State(args.state), args.port) as listener:
        listener.timeout = 0.2
        until = time.monotonic() + args.seconds
        print(json.dumps(dict(ready=True, synthetic_external_api=True, public_telegram_qualified=False)), flush=True)
        while time.monotonic() < until:
            listener.handle_request()


if __name__ == '__main__':
    main()

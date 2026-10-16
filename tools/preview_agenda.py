"""Disposable loopback-only agenda rehearsal, never a live identity adapter.

Serves the actual app and Vikunja with an explicitly synthetic fixture session.
No receiving binding, real home state, Google client or public listener is read.
"""
import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from clusterctl.homes.policy import Actor
from clusterctl.homes.service import Application, handler
from clusterctl.homes.sessions import Sessions
from tools.qualify_agenda import disposable_engine


class FixtureAuthority:
    """Explicit test doubles, not signed or receiving Matrix coordinates."""
    def __init__(self):
        self.people = {
            'preview-being': Actor('preview-being', 'being', 'fixture-v1', 'Daimon de prueba'),
            'preview-human': Actor('preview-human', 'human', 'fixture-v1', 'Persona de prueba'),
        }

    def actor(self, ref): return self.people.get(ref)
    def actors(self): return self.people
    def paired_human(self, home): return 'preview-human' if home == 'preview' else None
    def tribe_member(self, *_): return False
    def tribes(self): return {}


@contextmanager
def preview(backend, directory):
    directory = Path(directory)
    server = ThreadingHTTPServer(('127.0.0.1', 0), BaseHTTPRequestHandler)
    thread = None
    try:
        origin = 'https://127.0.0.1:' + str(server.server_port)
        config = {'homes': {'preview': {'name': 'Agenda de prueba',
            'owner_being_ref': 'preview-being', 'owner_revision': 'fixture-v1',
            'public_url': origin, 'vpn_url': 'https://private.example.invalid', 'ring': []}},
            'content_public_url': 'https://content.example.invalid',
            'content_vpn_url': 'https://private-content.example.invalid'}
        app = Application(config, FixtureAuthority(), Sessions(directory/'sessions'),
                          backends={'preview': None}, agenda_state=directory/'adapter',
                          agenda_backend=backend)
        token = app.sessions.issue(home='preview', origin=origin,
                                  subject=app.authority.actor('preview-human'))

        class PreviewHandler(handler(app)):
            def log_message(self, *_): pass

            def respond(self, status, body, kind='application/json', **kwargs):
                if status == 200 and kind.startswith('text/html'):
                    banner = ('<aside class="rehearsal" role="note">Prueba local · '
                              'datos de ejemplo · Google sin conectar. '
                              'La sesión es de prueba; no representa una identidad Matrix real.</aside>')
                    body = body.replace(b'<body>', ('<body>'+banner).encode())
                    # Telegram behavior is qualified separately in an actual client.
                    body = body.replace(b'<script src="https://telegram.org/js/telegram-web-app.js"></script>', b'')
                    kwargs['cookies'] = (*kwargs.get('cookies', ()),
                        '__Host-home='+token+'; Secure; HttpOnly; SameSite=Strict; Path=/')
                if status == 200 and self.path == '/agenda/agenda.css':
                    body += b'\n.rehearsal{padding:14px 20px;background:#fff3c4;color:#302a18;font:600 16px/1.5 system-ui;border-bottom:2px solid #a07121}'
                super().respond(status, body, kind, **kwargs)

        server.RequestHandlerClass = PreviewHandler
        cert, key = directory/'preview-cert.pem', directory/'preview-key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        key.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield app, origin
    finally:
        if thread:
            server.shutdown()
            thread.join(timeout=3)
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--check-dom', action='store_true', help='Run the real UI through JSDOM; not visual/WebView QA')
    parser.add_argument('--jsdom', type=Path, default=ROOT/'.work/dom-tools/node_modules/jsdom')
    parser.add_argument('--snapshot', type=Path, help='Optional read-only HTML snapshot from the DOM journey')
    args = parser.parse_args()
    def interrupted(*_):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    try:
        with disposable_engine(args.binary) as (backend, directory):
            with preview(backend, directory) as (_, origin):
                if args.check_dom:
                    return subprocess.run(['node', str(ROOT/'tests/js/agenda-journey.cjs')], cwd=ROOT, timeout=120,
                        env={**os.environ, 'AGENDA_PREVIEW_ORIGIN': origin,
                             'AGENDA_JSDOM': str(args.jsdom.resolve()),
                             'AGENDA_SNAPSHOT': str(args.snapshot.resolve()) if args.snapshot else '',
                             'TZ': 'America/Costa_Rica'}).returncode
                print('Disposable rehearsal: '+origin+'/agenda/', flush=True)
                print('Open on this computer. The one-day local certificate is self-signed. '
                      'Use example data; Google is disabled. Ctrl+C removes all rehearsal state.', flush=True)
                threading.Event().wait()
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    raise SystemExit(main())

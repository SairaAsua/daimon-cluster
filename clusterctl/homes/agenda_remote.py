"""Private Agenda application hop; Matrix identity stays at the homes gateway.

Run the application and its provider state on the receiving operator's host.
Only a selected loopback/private tunnel carries the gateway's verified scope.
No browser cookie, owner credential or Matrix custody is sent to this service.
"""
import argparse
from contextvars import ContextVar
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import http.client
import ipaddress
import json
from pathlib import Path
import stat
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

from .agenda import Agenda, AgendaError
from .policy import Actor, Policy

LIMIT = 2 * 1024 * 1024


def private_token(filename):
    path = Path(filename)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError('private_agenda_transport_token_required')
    value = path.read_text().strip()
    if len(value) < 32 or len(value) > 256 or not value.isascii() or any(c.isspace() for c in value):
        raise ValueError('invalid_agenda_transport_token')
    return value


class RemoteCalendar:
    def __init__(self, remote):
        self.remote = remote

    def begin(self, home, subject, parent, origin):
        return self.remote.call(home, subject, 'calendar-start', {'parent': parent, 'origin': origin})

    def finish(self, home, subject, parent, state, code):
        return self.remote.call(home, subject, 'calendar-finish', {'parent': parent, 'state': state, 'code': code})


class RemoteAgenda:
    scope = Agenda.scope

    def __init__(self, app, config_file):
        self.app = app
        config = json.loads(Path(config_file).read_text())
        if set(config) != {'origin', 'token_file'}:
            raise ValueError('invalid_agenda_remote_config')
        target = urlsplit(config['origin'])
        try:
            loopback = ipaddress.ip_address(target.hostname).is_loopback
        except ValueError:
            loopback = False
        if (target.scheme not in ('http', 'https') or not target.hostname or target.username or
                target.password or target.path not in ('', '/') or target.query or target.fragment or
                (target.scheme == 'http' and not loopback)):
            raise ValueError('agenda_remote_requires_https_or_loopback')
        self.target, self.token_file = target, config['token_file']
        private_token(self.token_file)
        self.calendar = RemoteCalendar(self)

    def dispatch(self, home, subject, action, payload, *, native=False):
        return self.call(home, subject, 'dispatch', {'action': action, 'payload': payload}, native=native)

    def call(self, home, subject, operation, payload, *, native=False):
        # The ordinary gateway resolves the current actor and pairing on EVERY
        # operation; a hostname or client-supplied actor never authorizes this hop.
        self.scope(home, subject, native=native)
        receiving = self.app.homes[home]
        owner = self.app.authority.actor(receiving['owner_being_ref'])
        pair_ref = self.app.authority.paired_human(home)
        pair = self.app.authority.actor(pair_ref) if pair_ref else None
        actors = {a.ref: asdict(a) for a in (owner, subject, pair) if a}
        # Bind OAuth to a digest of the parent session, not the actual cookie.
        if 'parent' in payload:
            import hashlib
            payload = {**payload, 'parent': hashlib.sha256(payload['parent'].encode()).hexdigest()}
        body = json.dumps({'home': home, 'receiving': {
            'name': receiving['name'], 'public_url': receiving['public_url'],
            'owner_being_ref': owner.ref, 'owner_revision': owner.revision},
            'actors': actors, 'paired_human': pair_ref, 'subject': subject.ref,
            'native': native, 'operation': operation, 'payload': payload,
            'expires': int(time.time()) + 30}).encode()
        if len(body) > LIMIT:
            raise AgendaError('agenda_invalid_request')
        connection_type = http.client.HTTPSConnection if self.target.scheme == 'https' else http.client.HTTPConnection
        connection = connection_type(self.target.hostname, self.target.port, timeout=25)
        try:
            connection.request('POST', '/agenda-operation', body, {
                'Authorization': 'Bearer ' + private_token(self.token_file),
                'Content-Type': 'application/json'})
            response = connection.getresponse()
            raw = response.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError('oversized_response')
            result = json.loads(raw)
            if response.status != 200:
                code = result.get('error') if isinstance(result, dict) else None
                if isinstance(code, str) and code.startswith('agenda_') and len(code) < 100:
                    raise AgendaError(code, response.status)
                raise ValueError('invalid_error')
            return result
        except AgendaError:
            raise
        except (OSError, ValueError, http.client.HTTPException):
            # Never retry a possibly completed operation or expose provider data.
            raise AgendaError('agenda_remote_unavailable', 503) from None
        finally:
            connection.close()


class ReceivingContext:
    """Per-request view of the gateway-verified scope, never signed authority."""
    def __init__(self):
        self.current = ContextVar('agenda_gateway_scope')
        self.authority = SimpleNamespace(actor=self.actor, paired_human=self.paired_human)
        self.policy = Policy(actor=self.actor, paired_human=self.paired_human, tribe_member=lambda *_: False)

    @property
    def homes(self):
        value = self.current.get()
        return {value['home']: value['receiving']}

    def actor(self, ref):
        value = self.current.get()['actors'].get(ref)
        return Actor(**value) if value else None

    def paired_human(self, home):
        value = self.current.get()
        return value['paired_human'] if value['home'] == home else None


def service_handler(agenda, context, token_file, allowed_homes):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Scope, OAuth replies and provider state are not request logs.

        def do_POST(self):
            reset = None
            try:
                if self.path != '/agenda-operation' or not hmac.compare_digest(
                        self.headers.get('Authorization', ''), 'Bearer ' + private_token(token_file)):
                    raise AgendaError('agenda_transport_denied', 403)
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= LIMIT:
                    raise AgendaError('agenda_invalid_request')
                value = json.loads(self.rfile.read(length))
                if (set(value) != {'home', 'receiving', 'actors', 'paired_human', 'subject',
                                  'native', 'operation', 'payload', 'expires'} or
                        type(value['expires']) is not int or not time.time() < value['expires'] <= time.time() + 35 or
                        type(value['native']) is not bool or not isinstance(value['actors'], dict) or
                        len(value['actors']) > 3 or
                        allowed_homes.get(value['home']) != value['receiving']['public_url']):
                    raise AgendaError('agenda_transport_scope_denied', 403)
                for ref, actor in value['actors'].items():
                    if Actor(**actor).ref != ref:
                        raise AgendaError('agenda_transport_scope_denied', 403)
                reset = context.current.set(value)
                home, subject, payload = value['home'], context.actor(value['subject']), value['payload']
                agenda.scope(home, subject, native=value['native'])
                if value['operation'] == 'dispatch':
                    result = agenda.dispatch(home, subject, payload['action'], payload['payload'], native=value['native'])
                elif value['operation'] == 'calendar-start' and not value['native']:
                    if payload['origin'] != allowed_homes[home]:
                        raise AgendaError('agenda_exact_origin_required', 403)
                    result = agenda.calendar.begin(home, subject, payload['parent'], payload['origin'])
                elif value['operation'] == 'calendar-finish' and not value['native']:
                    agenda.calendar.finish(home, subject, payload['parent'], payload['state'], payload['code'])
                    result = {'connected': True}
                else:
                    raise AgendaError('agenda_unknown_operation')
                status = 200
            except AgendaError as error:
                status, result = error.status, {'error': str(error)}
            except (ValueError, TypeError, KeyError, AttributeError, OSError):
                status, result = 400, {'error': 'agenda_invalid_request'}
            finally:
                if reset is not None:
                    context.current.reset(reset)
            body = json.dumps(result).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    private_token(config['token_file'])
    context = ReceivingContext()
    agenda = Agenda(context, config['state'], config['backend'], google_client=config.get('google_client'))
    server = ThreadingHTTPServer(('127.0.0.1', config['port']),
        service_handler(agenda, context, config['token_file'], config['homes']))
    server.daemon_threads = True
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()

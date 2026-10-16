"""Optional private agendas backed by Vikunja, using current home authority.

Vikunja owns projects, tasks, dates and observations. This adapter stores only
backend credentials and a command journal. It cannot create Matrix identities,
authenticate a browser or accept a caller-selected being. No provider token is
returned to a browser. Each verified being has a separate backend account.
"""
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
import hashlib
import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlencode, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ASSETS = Path(__file__).parent / 'agenda_assets'
MAX_PROVIDER_BYTES = 4 * 1024 * 1024
ZERO = '0001-01-01T00:00:00Z'


class AgendaError(ValueError):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.status = status


class _Plain(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, value):
        self.parts.append(value)

    def handle_endtag(self, tag):
        if tag in ('p', 'div', 'li'):
            self.parts.append('\n')

    def handle_starttag(self, tag, attrs):
        if tag == 'br':
            self.parts.append('\n')


def plain(value):
    parser = _Plain()
    parser.feed(value or '')
    return ''.join(parser.parts).strip()


def text(value, *, limit=10000, required=False):
    if not isinstance(value, str) or len(value) > limit or '\x00' in value:
        raise AgendaError('agenda_invalid_text')
    value = value.strip()
    if required and not value:
        raise AgendaError('agenda_title_required')
    return value


def identifier(value):
    if type(value) is not int or not 1 <= value < 2**53:
        raise AgendaError('agenda_invalid_identifier')
    return value


class Vikunja:
    """Pinned v2.7's maintained v1 API; redirects never receive credentials."""
    def __init__(self, origin):
        u = urlsplit(origin)
        if (u.scheme != 'http' or u.hostname != '127.0.0.1' or not u.port or
                u.path not in ('', '/') or u.query or u.fragment or u.username or u.password):
            raise ValueError('agenda_backend_requires_exact_loopback_origin')
        self.origin = origin.rstrip('/')
        self.tokens = {}

    def request(self, method, path, payload=None, *, token=None):
        if not path.startswith('/') or path.startswith('//'):
            raise AgendaError('agenda_invalid_provider_path')

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_):
                return None

        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request(self.origin + '/api/v1' + path,
            data=json.dumps(payload).encode() if payload is not None else None,
            method=method, headers=headers)
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=10) as response:
                data = response.read(MAX_PROVIDER_BYTES + 1)
                if len(data) > MAX_PROVIDER_BYTES:
                    raise AgendaError('agenda_provider_response_too_large', 502)
                return json.loads(data)
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            raise AgendaError('agenda_provider_denied' if code in (401, 403, 404)
                              else 'agenda_provider_unavailable', 502) from None
        except (OSError, json.JSONDecodeError):
            raise AgendaError('agenda_provider_unavailable', 503) from None

    def login(self, account):
        key = hashlib.sha256((account['username'] + '\0' + account['password']).encode()).hexdigest()
        cached = self.tokens.get(key)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        result = self.request('POST', '/login',
            {'username': account['username'], 'password': account['password']})
        token = result.get('token')
        if not isinstance(token, str) or len(token) > 8192:
            raise AgendaError('agenda_provider_invalid_login', 502)
        # Server-only, short-lived, per provider account. Matrix authorization
        # is still rechecked on every operation; no browser receives this token.
        self.tokens[key] = (time.monotonic() + 60, token)
        return token

    def pages(self, path, token):
        """Preserve pagination instead of presenting a truncated project as all."""
        rows = []
        for page in range(1, 101):
            value = self.request('GET', path + ('&' if '?' in path else '?') +
                                 urlencode({'page': page, 'per_page': 100}), token=token)
            if not isinstance(value, list):
                raise AgendaError('agenda_provider_invalid_list', 502)
            rows.extend(value)
            if len(value) < 100:
                return rows
        raise AgendaError('agenda_too_many_records', 413)


class Agenda:
    def __init__(self, app, directory, backend, *, provider=None, google_client=None):
        self.app = app
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError('private_agenda_state_required')
        self.path = directory / 'agenda-adapter.sqlite'
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    info.st_mode & 0o077 or info.st_nlink != 1):
                raise ValueError('private_agenda_state_required')
        finally:
            os.close(fd)
        self.provider = provider or Vikunja(backend)
        self.lock = threading.RLock()
        self.operation_locks = {}
        with closing(self.connect()) as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS agenda_accounts(
                being TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL, registered INTEGER NOT NULL DEFAULT 0,
                calendar_email TEXT NOT NULL DEFAULT '',
                calendar_setup INTEGER NOT NULL DEFAULT 0);
              CREATE TABLE IF NOT EXISTS agenda_commands(
                being TEXT NOT NULL, operation TEXT NOT NULL, actor TEXT NOT NULL,
                digest TEXT NOT NULL, state TEXT NOT NULL, result TEXT,
                PRIMARY KEY(being,operation));
            ''')
        from .agenda_calendar import Calendar, GoogleCalendar
        self.calendar = Calendar(self, GoogleCalendar(google_client) if google_client else None)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        return db

    def operation_lock(self, being):
        with self.lock:
            return self.operation_locks.setdefault(being, threading.RLock())

    def scope(self, home, subject, *, native=False):
        receiving = self.app.homes.get(home)
        current = self.app.policy.current(subject.ref, subject.revision) if subject else None
        owner = self.app.authority.actor(receiving['owner_being_ref']) if receiving else None
        if (not current or not owner or not owner.enabled or owner.kind != 'being' or
                receiving.get('owner_revision') != owner.revision):
            raise AgendaError('agenda_access_denied', 403)
        if native:
            allowed = current.kind == 'being' and current.ref == owner.ref
        else:
            allowed = current.kind == 'human' and self.app.authority.paired_human(home) == current.ref
        if not allowed:
            raise AgendaError('agenda_access_denied', 403)
        return owner.ref

    def account(self, being):
        with closing(self.connect()) as db:
            row = db.execute('SELECT * FROM agenda_accounts WHERE being=?', (being,)).fetchone()
        return dict(row) if row else None

    def initialize(self, being):
        account = self.account(being)
        created = account is None
        if not account:
            # These are hidden provider credentials, never Matrix coordinates.
            with closing(self.connect()) as db:
                db.execute('INSERT INTO agenda_accounts(being,username,password) VALUES(?,?,?)',
                           (being, 'agenda_' + secrets.token_hex(12), secrets.token_urlsafe(40)))
            account = self.account(being)
        if not account['registered']:
            # Resume retained provider credentials after an uncertain registration.
            token = None
            if not created:
                try:
                    token = self.provider.login(account)
                except AgendaError as error:
                    if str(error) != 'agenda_provider_denied':
                        raise
            if token is None:
                self.provider.request('POST', '/register', {
                    'username': account['username'], 'password': account['password'],
                    'email': account['username'] + '@agenda.invalid', 'language': 'es-ES'})
                token = self.provider.login(account)
            with closing(self.connect()) as db:
                db.execute('UPDATE agenda_accounts SET registered=1 WHERE being=?', (being,))
        else:
            token = self.provider.login(account)
        return account, token

    def project(self, token, project_id):
        value = self.provider.request('GET', '/projects/' + str(identifier(project_id)), token=token)
        user = self.provider.request('GET', '/user', token=token)
        if value.get('owner', {}).get('id') != user.get('id'):
            raise AgendaError('agenda_project_access_denied', 403)
        return value

    def task(self, token, task_id):
        value = self.provider.request('GET', '/tasks/' + str(identifier(task_id)), token=token)
        self.project(token, value.get('project_id'))
        return value

    @staticmethod
    def project_view(row):
        return {key: row.get(key) for key in ('id', 'title', 'is_archived')}

    @staticmethod
    def task_view(row):
        result = {key: row.get(key) for key in ('id', 'title', 'project_id', 'done', 'priority',
                  'due_date', 'start_date', 'end_date', 'created', 'updated')}
        result['description'] = plain(row.get('description'))
        # Comment creation may update the engine timestamp without changing
        # editable task fields. Compare actual task content to avoid rejecting
        # completion immediately after an observation in the same view.
        editable = {k: v for k, v in result.items() if k not in ('created','updated')}
        result['revision'] = hashlib.sha256(json.dumps(editable, sort_keys=True).encode()).hexdigest()
        return result

    def snapshot(self, home, being, account, token):
        user = self.provider.request('GET', '/user', token=token)
        projects = [p for p in self.provider.pages('/projects', token)
                    if p.get('owner', {}).get('id') == user.get('id')]
        allowed = {p['id'] for p in projects}
        tasks = [self.task_view(t) for t in self.provider.pages('/tasks', token)
                 if t.get('project_id') in allowed]
        return {'initialized': True, 'projects': [self.project_view(p) for p in projects],
                'tasks': tasks, 'calendar': self.calendar.status(home, being)}

    @staticmethod
    def task_input(value):
        if not isinstance(value, dict) or set(value) - {
                'title', 'description', 'project_id', 'date', 'time', 'timezone', 'duration', 'priority'}:
            raise AgendaError('agenda_invalid_task')
        result = {'title': text(value.get('title'), limit=240, required=True),
                  'description': '<p>' + html.escape(text(value.get('description', ''))).replace('\n', '<br>') + '</p>',
                  'project_id': identifier(value.get('project_id'))}
        priority = value.get('priority', 0)
        if type(priority) is not int or not 0 <= priority <= 5:
            raise AgendaError('agenda_invalid_priority')
        result['priority'] = priority
        day, hour = value.get('date'), value.get('time')
        result.update(due_date=ZERO, start_date=ZERO, end_date=ZERO)
        if day:
            try:
                if not isinstance(day, str) or len(day) != 10 or date.fromisoformat(day).isoformat() != day:
                    raise ValueError()
            except (ValueError, TypeError):
                raise AgendaError('agenda_invalid_date') from None
            result['due_date'] = day + 'T00:00:00Z'
        if hour:
            if not day or not isinstance(hour, str) or not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d', hour):
                raise AgendaError('agenda_invalid_time')
            try:
                zone = ZoneInfo(value.get('timezone', ''))
                local = datetime.fromisoformat(day + 'T' + hour).replace(tzinfo=zone)
                start = local.astimezone(timezone.utc)
                if start.astimezone(zone).replace(tzinfo=None) != local.replace(tzinfo=None):
                    raise ValueError()
            except (ValueError, TypeError, ZoneInfoNotFoundError):
                raise AgendaError('agenda_invalid_timezone_or_time') from None
            duration = value.get('duration', 30)
            if type(duration) is not int or not 1 <= duration <= 1440:
                raise AgendaError('agenda_invalid_duration')
            result['start_date'] = start.isoformat().replace('+00:00', 'Z')
            result['end_date'] = (start + timedelta(minutes=duration)).isoformat().replace('+00:00', 'Z')
        return result

    def dispatch(self, home, subject, action, payload, *, native=False):
        being = self.scope(home, subject, native=native)
        if not isinstance(payload, dict):
            raise AgendaError('agenda_invalid_request')
        # Existing owner transport may be called from several bodies concurrently.
        with self.operation_lock(being):
            self.scope(home, subject, native=native)
            if action == 'state':
                if payload:
                    raise AgendaError('agenda_unexpected_fields')
                account = self.account(being)
                if not account or not account['registered']:
                    return {'initialized': False, 'projects': [], 'tasks': [], 'calendar': {'connected': False, 'email': ''}}
                return self.snapshot(home, being, account, self.provider.login(account))
            if action == 'observations':
                if set(payload) != {'task_id'}:
                    raise AgendaError('agenda_unexpected_fields')
                account = self.account(being)
                if not account or not account['registered']:
                    raise AgendaError('agenda_not_initialized', 409)
                token = self.provider.login(account)
                task = self.task(token, payload['task_id'])
                rows = self.provider.pages('/tasks/' + str(task['id']) + '/comments', token)
                return {'observations': [{'id': r['id'], 'text': plain(r['comment']),
                                         'created': r['created']} for r in rows]}
            operation = payload.get('operation_id')
            if not isinstance(operation, str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,128}', operation):
                raise AgendaError('agenda_operation_id_required')
            digest = hashlib.sha256(json.dumps([action, payload], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            with closing(self.connect()) as db:
                row = db.execute('SELECT * FROM agenda_commands WHERE being=? AND operation=?', (being, operation)).fetchone()
                if row:
                    if row['digest'] != digest:
                        raise AgendaError('agenda_operation_conflict', 409)
                    if row['state'] == 'complete':
                        return json.loads(row['result'])
                    raise AgendaError('agenda_operation_uncertain', 409)
                # Reserve before the external write. Lost acknowledgments never
                # replay an upstream mutation; reread state to reconcile instead.
                db.execute('INSERT INTO agenda_commands VALUES(?,?,?,?,?,NULL)',
                           (being, operation, subject.ref, digest, 'reserved'))
            result = self.mutate(home, being, subject, action,
                                 {k: v for k, v in payload.items() if k != 'operation_id'})
            with closing(self.connect()) as db:
                db.execute('UPDATE agenda_commands SET state=?, result=? WHERE being=? AND operation=?',
                           ('complete', json.dumps(result), being, operation))
            return result

    def mutate(self, home, being, subject, action, value):
        if action == 'init':
            if value:
                raise AgendaError('agenda_unexpected_fields')
            account, token = self.initialize(being)
            projects = self.provider.pages('/projects', token)
            if not projects:
                self.provider.request('PUT', '/projects', {'title': 'Personal'}, token=token)
            return self.snapshot(home, being, account, token)
        account = self.account(being)
        if not account or not account['registered']:
            raise AgendaError('agenda_not_initialized', 409)
        token = self.provider.login(account)
        if action == 'project-create':
            if set(value) != {'title'}:
                raise AgendaError('agenda_unexpected_fields')
            result = self.provider.request('PUT', '/projects',
                {'title': text(value['title'], limit=240, required=True)}, token=token)
            return {'project': self.project_view(result)}
        if action == 'task-create':
            task = self.task_input(value)
            self.project(token, task['project_id'])
            result = self.provider.request('PUT', '/projects/' + str(task['project_id']) + '/tasks', task, token=token)
            saved = self.task_view(result)
            try:
                calendar = self.calendar.sync(home, being, saved)
            except AgendaError:
                calendar = {'status': 'pending'}
            return {'task': saved, 'calendar': calendar}
        if action == 'task-update':
            if set(value) != {'task_id', 'revision', 'done'} or type(value['done']) is not bool:
                raise AgendaError('agenda_invalid_task_update')
            task = self.task(token, value['task_id'])
            if self.task_view(task)['revision'] != value['revision']:
                raise AgendaError('agenda_task_changed', 409)
            # Preserve all engine fields while changing the requested completion.
            result = self.provider.request('POST', '/tasks/' + str(task['id']),
                                            {**task, 'done': value['done']}, token=token)
            return {'task': self.task_view(result)}
        if action == 'task-edit':
            task_id, revision = value.get('task_id'), value.get('revision')
            changes = self.task_input({k: v for k, v in value.items() if k not in ('task_id','revision')})
            task = self.task(token, task_id)
            if self.task_view(task)['revision'] != revision:
                raise AgendaError('agenda_task_changed', 409)
            self.project(token, changes['project_id'])
            result = self.provider.request('POST', '/tasks/' + str(task['id']), {**task, **changes}, token=token)
            saved = self.task_view(result)
            try:
                calendar = self.calendar.sync(home, being, saved)
            except AgendaError:
                calendar = {'status': 'pending'}
            return {'task': saved, 'calendar': calendar}
        if action == 'observation-add':
            if set(value) != {'task_id', 'text'}:
                raise AgendaError('agenda_unexpected_fields')
            task = self.task(token, value['task_id'])
            observation = text(value['text'], required=True)
            authored = html.escape(subject.name) + ' · ' + ('daimon' if subject.kind == 'being' else 'humana')
            self.provider.request('PUT', '/tasks/' + str(task['id']) + '/comments',
                {'comment': '<p>' + authored + '</p><p>' + html.escape(observation).replace('\n', '<br>') + '</p>'}, token=token)
            return {'saved': True}
        if action == 'calendar-account':
            if (set(value) != {'email'} or not isinstance(value['email'], str) or
                    (value['email'] and not re.fullmatch(r'[^\s@]{1,120}@[^\s@]{1,120}\.[^\s@]{2,20}', value['email']))):
                raise AgendaError('agenda_invalid_calendar_account')
            if self.calendar.connection(home, being):
                raise AgendaError('agenda_disconnect_calendar_first', 409)
            with closing(self.connect()) as db:
                db.execute('UPDATE agenda_accounts SET calendar_email=?,calendar_setup=0 WHERE being=?', (value['email'], being))
            return {'calendar': self.calendar.status(home, being)}
        if action == 'calendar-skip':
            if value:
                raise AgendaError('agenda_unexpected_fields')
            with closing(self.connect()) as db:
                db.execute('UPDATE agenda_accounts SET calendar_setup=1 WHERE being=?', (being,))
            return {'calendar': self.calendar.status(home, being)}
        if action == 'calendar-disconnect':
            if value:
                raise AgendaError('agenda_unexpected_fields')
            return {'calendar': self.calendar.disconnect(home, being)}
        if action == 'calendar-sync':
            if set(value) != {'task_id'}:
                raise AgendaError('agenda_unexpected_fields')
            task = self.task_view(self.task(token, value['task_id']))
            return {'calendar': self.calendar.sync(home, being, task)}
        raise AgendaError('agenda_unknown_action')


def routes(handler, app, method, data=None):
    path = urlsplit(handler.path).path
    if not path.startswith('/agenda/'):
        return False
    if not app.agenda:
        handler.respond(404, {'error': 'agenda_unavailable'})
        return True
    try:
        home, origin, subject, vpn, _, parent = handler.context()
        if vpn or handler.headers.get('Authorization'):
            raise AgendaError('agenda_requires_public_browser', 403)
        if method == 'GET' and path in ('/agenda/', '/agenda/miniapp.html'):
            from .service import auth_controls
            auth, script = auth_controls(None, False, bool(app.passkeys), handler.path, bool(app.sso)) if not subject else ('', '')
            content = (ASSETS / 'index.html').read_text().replace('<!--AUTH-->', auth + script)
            content = content.replace('__HOME_NAME__', html.escape(app.homes[home]['name']))
            handler.respond(200, content.encode(), 'text/html; charset=utf-8', telegram_sdk=True)
            return True
        files = {'/agenda/agenda.js': ('agenda.js', 'text/javascript; charset=utf-8'),
                 '/agenda/agenda.css': ('agenda.css', 'text/css; charset=utf-8')}
        if method == 'GET' and path in files:
            file, kind = files[path]
            handler.respond(200, (ASSETS / file).read_bytes(), kind)
            return True
        if method == 'POST' and path == '/agenda/google/start':
            if handler.headers.get('Origin') != origin or json.loads(data) != {}:
                raise AgendaError('agenda_exact_origin_required', 403)
            handler.respond(200, app.agenda.calendar.begin(home, subject, parent, origin))
            return True
        if method == 'GET' and path == '/agenda/google/callback':
            query = parse_qs(urlsplit(handler.path).query, keep_blank_values=True, strict_parsing=True)
            if (any(len(v) != 1 for v in query.values()) or set(query) -
                    {'state','code','scope','authuser','prompt','error','error_description','iss'}):
                raise AgendaError('agenda_google_flow_unavailable', 403)
            if 'error' in query:
                handler.respond(303, b'', headers=(('Location','/agenda/?calendar=denied'),))
                return True
            try:
                app.agenda.calendar.finish(home, subject, parent, query.get('state',[''])[0], query.get('code',[''])[0])
            except AgendaError:
                handler.respond(303, b'', headers=(('Location','/agenda/?calendar=failed'),))
                return True
            handler.respond(303, b'', headers=(('Location','/agenda/?calendar=connected'),))
            return True
        if path == '/agenda/api/state' and method == 'GET':
            result = app.agenda.dispatch(home, subject, 'state', {})
        elif path == '/agenda/api/observations' and method == 'GET':
            query = parse_qs(urlsplit(handler.path).query, strict_parsing=True)
            if set(query) != {'task_id'} or len(query['task_id']) != 1 or not query['task_id'][0].isdecimal():
                raise AgendaError('agenda_invalid_identifier')
            result = app.agenda.dispatch(home, subject, 'observations', {'task_id': int(query['task_id'][0])})
        elif path == '/agenda/api/command' and method == 'POST':
            if handler.headers.get('Origin') != origin:
                raise AgendaError('agenda_exact_origin_required', 403)
            payload = json.loads(data)
            if not isinstance(payload, dict) or set(payload) != {'action', 'payload'}:
                raise AgendaError('agenda_invalid_request')
            result = app.agenda.dispatch(home, subject, payload['action'], payload['payload'])
        else:
            raise AgendaError('agenda_unknown_route', 404)
        handler.respond(200, result)
    except AgendaError as error:
        handler.respond(error.status, {'error': str(error)})
    except (ValueError, TypeError, KeyError):
        handler.respond(400, {'error': 'agenda_invalid_request'})
    return True

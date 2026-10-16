"""Optional Google Calendar consent and deterministic event updates.

This is provider access, separate from shared-home Google sign-in. Current
Matrix pairing authorizes the application scope; Google's verified subject
identifies the provider account. No email creates or selects a Matrix identity.
"""
import base64
from contextlib import closing
from datetime import date, timedelta
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode

from .agenda import AgendaError, ZERO

SCOPE = 'https://www.googleapis.com/auth/calendar.events.owned'


class GoogleCalendar:
    def __init__(self, filename):
        from .login import Google
        config = Google(filename)
        self.client_id, self.client_secret = config.client_id, config.client_secret

    def authorization(self, state, nonce, verifier, callback, email):
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        parameters = {
            'client_id': self.client_id, 'redirect_uri': callback, 'response_type': 'code',
            'scope': 'openid email ' + SCOPE, 'access_type': 'offline', 'prompt': 'consent',
            'state': state, 'nonce': nonce, 'code_challenge': challenge,
            'code_challenge_method': 'S256'}
        if email:
            parameters['login_hint'] = email
        return 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(parameters)

    @staticmethod
    def http(method, url, *, form=None, body=None, bearer=None, allow_missing=False):
        import requests
        try:
            with requests.Session() as client:
                client.trust_env = False
                headers = {'Authorization': 'Bearer ' + bearer} if bearer else {}
                with client.request(method, url, data=form, json=body, headers=headers,
                                    timeout=10, allow_redirects=False, stream=True) as response:
                    if allow_missing and response.status_code == 404:
                        return None
                    if not 200 <= response.status_code < 300:
                        raise AgendaError('agenda_google_request_failed', 502)
                    data = bytearray()
                    for chunk in response.iter_content(8192):
                        data.extend(chunk)
                        if len(data) > 262144:
                            raise AgendaError('agenda_google_request_failed', 502)
                    return json.loads(data) if data else {}
        except (requests.RequestException, ValueError):
            raise AgendaError('agenda_google_request_failed', 502) from None

    def exchange(self, code, verifier, nonce, callback):
        import requests
        from google.oauth2.id_token import verify_oauth2_token
        from google.auth.transport.requests import Request
        value = self.http('POST', 'https://oauth2.googleapis.com/token', form={
            'client_id': self.client_id, 'client_secret': self.client_secret, 'code': code,
            'code_verifier': verifier, 'redirect_uri': callback, 'grant_type': 'authorization_code'})
        try:
            with requests.Session() as client:
                client.trust_env = False
                transport = Request(client)
                claims = verify_oauth2_token(value['id_token'],
                    lambda *args, **kwargs: transport(*args, timeout=10, **kwargs), self.client_id)
        except Exception:
            # Provider verifier errors never escape with tokens or claims.
            raise AgendaError('agenda_google_identity_unverified', 403) from None
        if (claims.get('nonce') != nonce or not claims.get('sub') or
                claims.get('email_verified') is not True or not isinstance(claims.get('email'), str) or
                SCOPE not in value.get('scope', '').split()):
            raise AgendaError('agenda_google_consent_incomplete', 403)
        if not all(isinstance(value.get(k), str) and value[k] for k in ('access_token', 'refresh_token')):
            raise AgendaError('agenda_google_offline_consent_required', 403)
        return claims, value

    def refresh(self, refresh_token):
        return self.http('POST', 'https://oauth2.googleapis.com/token', form={
            'client_id': self.client_id, 'client_secret': self.client_secret,
            'refresh_token': refresh_token, 'grant_type': 'refresh_token'})

    def event(self, token, event_id, body):
        root = 'https://www.googleapis.com/calendar/v3/calendars/primary/events'
        existing = self.http('GET', root + '/' + event_id, bearer=token, allow_missing=True)
        if existing:
            return self.http('PATCH', root + '/' + event_id + '?sendUpdates=none', bearer=token, body=body)
        return self.http('POST', root + '?sendUpdates=none', bearer=token, body={'id': event_id, **body})

    def remove(self, token, event_id):
        self.http('DELETE', 'https://www.googleapis.com/calendar/v3/calendars/primary/events/' + event_id,
                  bearer=token, allow_missing=True)


class Calendar:
    def __init__(self, agenda, provider=None):
        self.agenda, self.provider = agenda, provider
        with closing(agenda.connect()) as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS agenda_google_flows(
                state TEXT PRIMARY KEY, being TEXT NOT NULL, home TEXT NOT NULL,
                actor TEXT NOT NULL, revision TEXT NOT NULL, parent TEXT NOT NULL,
                nonce TEXT NOT NULL, verifier TEXT NOT NULL, callback TEXT NOT NULL,
                email TEXT NOT NULL, expires INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS agenda_google_connections(
                being TEXT PRIMARY KEY, actor TEXT NOT NULL, revision TEXT NOT NULL,
                subject TEXT NOT NULL, email TEXT NOT NULL, refresh_token TEXT NOT NULL,
                access_token TEXT NOT NULL, expires INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS agenda_google_events(
                being TEXT NOT NULL, task INTEGER NOT NULL, event TEXT NOT NULL,
                url TEXT NOT NULL, PRIMARY KEY(being,task));
            ''')

    def connection(self, home, being):
        with closing(self.agenda.connect()) as db:
            row = db.execute('SELECT * FROM agenda_google_connections WHERE being=?', (being,)).fetchone()
        if not row or self.agenda.app.authority.paired_human(home) != row['actor']:
            return None
        actor = self.agenda.app.policy.current(row['actor'], row['revision'])
        return dict(row) if actor and actor.kind == 'human' else None

    def status(self, home, being):
        connection = self.connection(home, being)
        account = self.agenda.account(being)
        return {'available': bool(self.provider), 'connected': bool(connection and self.provider),
                'setup_complete': bool(account and account['calendar_setup']),
                'email': connection['email'] if connection else (account['calendar_email'] if account else '')}

    def begin(self, home, subject, parent, origin):
        being = self.agenda.scope(home, subject)
        account = self.agenda.account(being)
        if not self.provider:
            raise AgendaError('agenda_google_not_configured', 503)
        if not account or not account['registered']:
            raise AgendaError('agenda_not_initialized', 409)
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        callback = origin + '/agenda/google/callback'
        with closing(self.agenda.connect()) as db:
            db.execute('DELETE FROM agenda_google_flows WHERE expires<?', (int(time.time()),))
            if db.execute('SELECT count(*) FROM agenda_google_flows WHERE being=?', (being,)).fetchone()[0] >= 10:
                raise AgendaError('agenda_google_connection_busy', 429)
            db.execute('INSERT INTO agenda_google_flows VALUES(?,?,?,?,?,?,?,?,?,?,?)', (
                hashlib.sha256(state.encode()).hexdigest(), being, home, subject.ref, subject.revision,
                hashlib.sha256(parent.encode()).hexdigest(), nonce, verifier, callback,
                account['calendar_email'], int(time.time()) + 600))
        return {'authorization_url': self.provider.authorization(state, nonce, verifier, callback, account['calendar_email'])}

    def finish(self, home, subject, parent, state, code):
        being = self.agenda.scope(home, subject)
        with self.agenda.operation_lock(being), closing(self.agenda.connect()) as db:
            self.agenda.scope(home, subject)
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM agenda_google_flows WHERE state=?',
                (hashlib.sha256(state.encode()).hexdigest(),)).fetchone()
            if (not row or row['expires'] <= time.time() or row['home'] != home or row['being'] != being or
                    (row['actor'], row['revision']) != (subject.ref, subject.revision) or
                    row['parent'] != hashlib.sha256(parent.encode()).hexdigest()):
                db.rollback()
                raise AgendaError('agenda_google_flow_unavailable', 403)
            # One-use even when exchange fails; reconnect is an explicit action.
            db.execute('DELETE FROM agenda_google_flows WHERE state=?', (row['state'],))
            db.commit()
            claims, tokens = self.provider.exchange(code, row['verifier'], row['nonce'], row['callback'])
            if row['email'] and claims['email'].casefold() != row['email'].casefold():
                raise AgendaError('agenda_google_wrong_account', 403)
            expiry = int(tokens.get('expires_in', 3600))
            if not 60 <= expiry <= 86400:
                raise AgendaError('agenda_google_consent_incomplete', 403)
            db.execute('INSERT OR REPLACE INTO agenda_google_connections VALUES(?,?,?,?,?,?,?,?)', (
                being, subject.ref, subject.revision, claims['sub'], claims['email'],
                tokens['refresh_token'], tokens['access_token'], int(time.time()) + expiry))
            db.execute('UPDATE agenda_accounts SET calendar_setup=1,calendar_email=? WHERE being=?', (claims['email'], being))

    def disconnect(self, home, being):
        # Stop use immediately. Revoking consent at Google is a separate control.
        with closing(self.agenda.connect()) as db:
            db.execute('DELETE FROM agenda_google_connections WHERE being=?', (being,))
        return self.status(home, being)

    def sync(self, home, being, task):
        row = self.connection(home, being)
        if not row or not self.provider:
            return {'status': 'not_connected'}
        day = task.get('due_date')
        with closing(self.agenda.connect()) as db:
            previous = db.execute('SELECT event FROM agenda_google_events WHERE being=? AND task=?',
                                  (being, task['id'])).fetchone()
        if not day or day.startswith('0001-'):
            if not previous:
                return {'status': 'no_date'}
        if row['expires'] <= time.time() + 60:
            value = self.provider.refresh(row['refresh_token'])
            token, expiry = value.get('access_token'), value.get('expires_in', 3600)
            if not isinstance(token, str) or type(expiry) is not int or not 60 <= expiry <= 86400:
                raise AgendaError('agenda_google_refresh_failed', 502)
            row['access_token'] = token
            with closing(self.agenda.connect()) as db:
                db.execute('UPDATE agenda_google_connections SET access_token=?,expires=? WHERE being=?',
                           (token, int(time.time()) + expiry, being))
        if not day or day.startswith('0001-'):
            self.provider.remove(row['access_token'], previous['event'])
            with closing(self.agenda.connect()) as db:
                db.execute('DELETE FROM agenda_google_events WHERE being=? AND task=?', (being, task['id']))
            return {'status': 'removed'}
        body = {'summary': task['title'], 'description': task.get('description', ''), 'visibility': 'private'}
        if task.get('start_date') and not task['start_date'].startswith('0001-'):
            body.update(start={'dateTime': task['start_date']}, end={'dateTime': task['end_date']})
        else:
            day = date.fromisoformat(day[:10])
            body.update(start={'date': day.isoformat()}, end={'date': (day + timedelta(days=1)).isoformat()})
        event_id = hashlib.sha256(('dm.agenda/v1\0' + being + '\0' + str(task['id'])).encode()).hexdigest()
        result = self.provider.event(row['access_token'], event_id, body)
        if result.get('id') != event_id:
            raise AgendaError('agenda_google_event_unconfirmed', 502)
        url = result.get('htmlLink', '')
        if not isinstance(url, str) or not url.startswith('https://www.google.com/calendar/event?'):
            url = 'https://calendar.google.com/calendar/u/0/r'
        with closing(self.agenda.connect()) as db:
            db.execute('INSERT OR REPLACE INTO agenda_google_events VALUES(?,?,?,?)', (being, task['id'], event_id, url))
        return {'status': 'synced', 'url': url}

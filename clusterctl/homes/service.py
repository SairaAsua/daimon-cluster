"""Shared read gateway and separate owner-local publication adapter.

Only the trusted front proxy selects the home/network fence. The owner adapter
is never routed publicly. Artifact metadata becomes authoritative when committed
to the shared Registry, and every delivery checks its serving manifest digest.
"""

from __future__ import annotations

import argparse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import html
import json
import mimetypes
import os
from pathlib import Path
import re
import threading
import urllib.error
import urllib.request
from urllib.parse import parse_qs, quote, unquote, urlsplit, urlencode

from .authority import NativeAuthority
from .policy import Policy, validate_audience
from .registry import Registry
from .sessions import Sessions
from .styles import StyleConsumer

MAX_MANIFEST = 8 * 1024 * 1024


def validate_config(config, *, credential_uid=None):
    required = {
        "schema",
        "state",
        "binding_source",
        "relationship_store",
        "authority_source",
        "homes",
        "viewer_port",
        "owner_port",
        "content_public_url",
        "content_vpn_url",
    }
    if (
        not isinstance(config, dict)
        or set(config) != required
        or config["schema"] != "dm.resource-access.host/v1"
        or not isinstance(config["homes"], dict)
        or not 0 <= len(config["homes"]) <= 256
    ):
        raise ValueError("invalid_resource_access_configuration")

    def origin(url):
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("home_requires_exact_https_origin")
        return parsed.netloc

    origins = {origin(config[key]) for key in ("content_public_url", "content_vpn_url")}
    if len(origins) != 2:
        raise ValueError("isolated_content_origins_required")
    for field in ("state", "binding_source", "relationship_store", "authority_source"):
        if not isinstance(config[field], str) or not Path(config[field]).is_absolute():
            raise ValueError("invalid_home_receiving_path")
    ports = [config[k] for k in ("viewer_port", "owner_port")]
    if (
        any(type(p) is not int or not 1024 <= p <= 65535 for p in ports)
        or len(set(ports)) != 2
    ):
        raise ValueError("separate_home_listener_ports_required")
    for reference, home in config["homes"].items():
        if (
            not isinstance(reference, str)
            or not re.fullmatch("[A-Za-z0-9:_-]{1,128}", reference)
            or not isinstance(home, dict)
            or set(home)
            != {
                "name",
                "owner_being_ref",
                "owner_revision",
                "public_url",
                "vpn_url",
                "backend",
                "owner_token_file",
                "gateway_token_file",
                "ring",
            }
            or not isinstance(home["name"], str)
            or not 1 <= len(home["name"]) <= 128
            or not isinstance(home["owner_being_ref"], str)
            or not home["owner_being_ref"]
            or not isinstance(home["owner_revision"], str)
            or not re.fullmatch("[a-f0-9]{64}", home["owner_revision"])
        ):
            raise ValueError("invalid_home_receiving_binding")
        for field in ("public_url", "vpn_url"):
            hostname = origin(home[field])
            if hostname in origins:
                raise ValueError("unique_home_content_origins_required")
            origins.add(hostname)
        for field in ("owner_token_file", "gateway_token_file"):
            if not isinstance(home[field], str) or not Path(home[field]).is_absolute():
                raise ValueError("invalid_home_receiving_path")
            if credential_uid is None:
                private_text(home[field])
            else:
                private_credential(home[field], uid=credential_uid)
        if not isinstance(home["ring"], list) or len(home["ring"]) > 256:
            raise ValueError("invalid_home_ring")
        for peer in home["ring"]:
            if (
                not isinstance(peer, dict)
                or set(peer) != {"name", "url"}
                or not isinstance(peer["name"], str)
            ):
                raise ValueError("invalid_home_ring")
            origin(peer["url"])
        Backend(home)
    return config


def private_credential(path, *, uid):
    """Check an operator-selected gateway owner's file without reading its key."""
    import stat
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 1024):
            raise ValueError("private_home_credential_required")
    finally:
        os.close(descriptor)


def private_text(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor) as stream:
        import stat

        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or info.st_size > 1024
        ):
            raise ValueError("private_home_credential_required")
        return stream.read().strip()


class Backend:
    def __init__(self, home):
        self.home = home
        url = urlsplit(home["backend"])
        if (
            url.scheme != "http"
            or url.hostname != "127.0.0.1"
            or url.path not in ("", "/")
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError("home_backend_must_be_loopback")

    def open(self, path, *, method="GET", byte_range=None, timeout=15):
        headers = {
            "Authorization": "Bearer " + private_text(self.home["gateway_token_file"])
        }
        if byte_range:
            headers["Range"] = byte_range

        # No redirects: an untrusted backend response must not disclose its key.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_):
                return None

        request = urllib.request.Request(
            self.home["backend"].rstrip("/") + path, method=method, headers=headers
        )
        return urllib.request.build_opener(NoRedirect).open(request, timeout=timeout)

    def state(self, *, timeout=15):
        with self.open("/_home/state", timeout=timeout) as response:
            data = response.read(MAX_MANIFEST + 1)
            if len(data) > MAX_MANIFEST:
                raise ValueError("home_manifest_too_large")
            return json.loads(data)


class Application:
    def __init__(self, config, authority, sessions, *, backends=None, passkey_rp_id=None, client_example=False, style_provider=None, auth_origin=None, google_client=None, homemaker_source=None, homemaker_state=None, homemaker_home=None, homemaker_returns=(), miniapp_routes=None, miniapp_receivers=None, agenda_state=None, agenda_backend=None, agenda_google_client=None):
        self.styles = StyleConsumer(style_provider, authority, config["homes"]) if style_provider else None
        from .launcher import validate_launch_routes
        self.miniapp_routes=validate_launch_routes(miniapp_routes)
        from .applications import receiver_routes
        self.miniapp_receivers=receiver_routes(miniapp_receivers, config["homes"])
        self.sso = None
        self.designs = None
        self.agenda = None
        self.client_example = client_example
        self.config, self.homes, self.authority, self.sessions = (
            config,
            config["homes"],
            authority,
            sessions,
        )
        self.registry = Registry(sessions)
        self.policy = Policy(
            actor=authority.actor,
            paired_human=authority.paired_human,
            tribe_member=authority.tribe_member,
        )
        self.backends = backends or {
            ref: Backend(home) for ref, home in self.homes.items()
        }
        for reference, home in self.homes.items():
            self.registry.bind_home(reference, home["owner_being_ref"])
            if "owner_token_file" in home:
                self.sessions.register_owner(
                    home=reference,
                    actor=home["owner_being_ref"],
                    revision=home["owner_revision"],
                    token=private_text(home["owner_token_file"]),
                )
        self.locks = {ref: threading.RLock() for ref in self.homes}
        self.passkeys = None
        if passkey_rp_id:
            from .passkeys import Passkeys
            self.passkeys = Passkeys(self, passkey_rp_id)
        if auth_origin:
            from .login import Login, Google
            self.sso = Login(self, auth_origin, Google(google_client) if google_client else None)
        elif google_client:
            raise ValueError('google_requires_shared_login')
        if homemaker_home is not None and (
                homemaker_home not in self.homes or not (homemaker_source and homemaker_state)):
            raise ValueError('invalid_canonical_homemaker_home')
        self.homemaker_home = homemaker_home
        self.homemaker_returns = tuple(dict.fromkeys(
            ([h['public_url'] + '/' for h in self.homes.values()] if homemaker_home else []) + list(homemaker_returns)))
        for destination in self.homemaker_returns:
            parsed = urlsplit(destination)
            if (parsed.scheme != 'https' or parsed.username or parsed.password or
                    parsed.netloc not in {urlsplit(h['public_url']).netloc for h in self.homes.values()} or
                    any(ord(c) < 33 or c == '\\' for c in destination)):
                raise ValueError('invalid_homemaker_return')
        if homemaker_source or homemaker_state:
            if not (homemaker_source and homemaker_state) or style_provider:
                raise ValueError('one_canonical_homemaker_required')
            from .homemaker import Homemaker
            self.designs = Homemaker(self, homemaker_source, homemaker_state)
            self.styles = StyleConsumer(self.designs, authority, self.homes)
        if agenda_state or agenda_backend:
            if not (agenda_state and agenda_backend):
                raise ValueError('agenda_state_and_backend_required')
            from .agenda import Agenda
            self.agenda = Agenda(self, agenda_state, agenda_backend, google_client=agenda_google_client)
        elif agenda_google_client:
            raise ValueError('agenda_google_requires_agenda')

    def identity(self, token, home, origin):
        row = self.sessions.resolve(token, home=home, origin=origin)
        return self.policy.current(row["actor"], row["revision"]) if row else None

    def publication(self, home, *, timeout=None):
        observed = (self.backends[home].state() if timeout is None
                    else self.backends[home].state(timeout=timeout))
        committed = self.registry.current(home, observed_state=observed)
        return (
            committed["state"]
            if committed and committed["owner"] == self.homes[home]["owner_being_ref"]
            else {"schema": 1, "entries": []}
        )

    def entries(self, home, subject, vpn=False, *, timeout=None):
        return [
            e
            for e in self.publication(home, timeout=timeout)["entries"]
            if self.policy.allows(e, home=home, subject=subject, dedicated_vpn=vpn)
        ]

    def selected(self, home, reference, version, subject, vpn=False):
        for current in self.entries(home, subject, vpn):
            if current["artifact_ref"] != reference:
                continue
            if version == "current":
                return current
            selected = self.registry.version(
                home=home, resource=reference, version=version
            )
            if selected and self.policy.allows(
                selected, home=home, subject=subject, dedicated_vpn=vpn
            ):
                return selected
        return None

    def owner(self, home, token, operation, payload):
        if home not in self.homes or not token:
            raise ValueError("home_owner_denied")
        receiving = self.homes[home]
        if not hmac.compare_digest(token, private_text(receiving["owner_token_file"])):
            raise ValueError("home_owner_denied")
        owner = self.authority.actor(receiving["owner_being_ref"])
        if (
            not owner
            or owner.kind != "being"
            or not owner.enabled
            or receiving.get("owner_revision") != owner.revision
            or not self.sessions.owner(token, home=home, subject=owner)
        ):
            raise ValueError("home_owner_binding_unavailable")
        if operation.startswith('agenda-'):
            if not self.agenda:
                raise ValueError('agenda_unavailable')
            return self.agenda.dispatch(home, owner, operation.removeprefix('agenda-'), payload, native=True)
        if operation in ('style-baseline', 'style-default', 'style-selection', 'style-select', 'style-recipe'):
            if not self.designs:
                raise ValueError('homemaker_unavailable')
            if operation == 'style-baseline':
                if set(payload) != {'variant'}:
                    raise ValueError('invalid_design_request')
                self.designs.variant(payload['variant'])
                return self.designs.authority.editor_default(owner.ref,
                    owner={'kind':'being','ref':owner.ref},identifier=payload['variant'])
            if operation in ('style-selection','style-select'):
                return self.designs.selection_native(home,owner,payload,write=operation=='style-select')
            if operation == 'style-recipe':
                return self.designs.recipe_native(owner,payload)
            return self.designs.save_native(home, owner, payload)
        if operation == "validate-audience":
            validate_audience(
                payload,
                known_actor=self.authority.actor,
                known_tribe=lambda ref: ref in self.authority.tribes(),
            )
            return {"status": "valid"}
        if operation == "sync":
            if payload:
                raise ValueError("home_sync_takes_no_manifest_from_client")
            with self.locks[home]:
                revision = self.registry.revision(home)
                state = self.backends[home].state()
                return self.registry.register(
                    home=home,
                    owner=owner.ref,
                    state=state,
                    expected_revision=revision,
                    known_actor=self.authority.actor,
                    known_tribe=lambda ref: ref in self.authority.tribes(),
                )
        if operation == "targets":
            if payload:
                raise ValueError("invalid_home_owner_request")
            return {
                "actors": [
                    {"ref": a.ref, "kind": a.kind, "name": a.name}
                    for a in self.authority.actors().values()
                ],
                "tribes": list(self.authority.tribes()),
                "homes": [
                    {"ref": ref, "name": h["name"], "public_url": h["public_url"]}
                    for ref, h in self.homes.items()
                ],
            }
        if operation == "reader-session":
            if set(payload) != {"origin"}:
                raise ValueError("invalid_home_reader_request")
            targets = [
                ref
                for ref, h in self.homes.items()
                if payload["origin"] in (h["public_url"], h["vpn_url"])
            ]
            if len(targets) != 1:
                raise ValueError("unknown_home_reader_target")
            return {
                "credential": self.sessions.issue(
                    home=targets[0], origin=payload["origin"], subject=owner
                )
            }
        if operation == "approve-browser":
            if set(payload) != {"home", "code"} or (payload["home"] not in self.homes and
                    not (self.sso and payload['home']==self.sso.context)):
                raise ValueError("invalid_home_browser_approval")
            pair = self.authority.actor(self.authority.paired_human(home))
            if not pair or pair.kind != "human":
                raise ValueError("home_pairing_unavailable")
            # The credential of a pair can prove only its own human identity,
            # even when that browser is visiting a different owner's home.
            self.sessions.approve(
                home=payload["home"], code=payload["code"], subject=pair
            )
            return {"status": "approved"}
        if operation == "tribe-readers":
            if set(payload) != {
                "tribe",
                "expected_revision",
                "readers",
                "revoked",
                "expires_at_ms",
            }:
                raise ValueError("invalid_home_reader_roster")
            tribe = self.authority.tribes().get(payload["tribe"])
            if not tribe or tribe["founder_principal_id"] != owner.ref:
                raise ValueError("home_roster_founder_required")

            def known_human(ref):
                actor = self.authority.actor(ref)
                return actor and actor.enabled and actor.kind == "human"

            return self.registry.roster(
                tribe=payload["tribe"],
                founder=owner.ref,
                expected_revision=payload["expected_revision"],
                known_human=known_human,
                document={
                    k: payload[k] for k in ("readers", "revoked", "expires_at_ms")
                },
            )
        raise ValueError("unknown_home_owner_operation")


def audience_view(entry, home):
    """Already-authorized visitor projection: no recipients, local paths or history."""
    reference = entry["artifact_ref"]
    url = (
        entry["url"]
        if entry["kind"] == "link"
        else "/works/" + reference + "/current/" + quote(entry["entrypoint"])
    )
    return {
        **{
            k: entry[k]
            for k in (
                "id",
                "title",
                "summary",
                "kind",
                "revision",
                "version_ref",
                "updated_at",
                "visibility",
            )
            if k in entry
        },
        "resource_ref": "dm:resource:v1:" + reference,
        "url": url,
        "preview_url": "/view/" + reference if entry["kind"] == "artifact" else None,
    }


def return_target(value):
    """Presentation-only same-origin return; never an arbitrary redirect URL."""
    if (not isinstance(value, str) or len(value) > 2048 or not value.startswith('/')
        or value.startswith('//') or unquote(value).startswith('//')
        or '\\' in unquote(value) or any(ord(c) < 32 for c in unquote(value))
        or urlsplit(value).netloc or urlsplit(value).scheme):
        raise ValueError('invalid_home_return')
    return value


def auth_controls(subject, vpn, passkeys, return_path='/', shared_login=False):
    if subject:
        controls = '<form method="post" action="/access/logout"><button>Sign out</button></form>'
        if passkeys and subject.kind == 'human' and not vpn:
            controls = '<a href="/access/keys">Access keys</a>' + controls
        return controls, ''
    code_url = '/access?' + urlencode({'return': return_target(return_path)})
    if shared_login and not vpn:
        return ('<button id="passkey-action" type="button" data-mode="sso">Sign in</button>',
                '<script src="/access-client.js" defer></script><script src="/passkeys.js" defer></script>')
    if passkeys and not vpn:
        return ('<button id="passkey-action" type="button" data-mode="login" '
                'data-reload="true">Sign in</button><a data-code-login href="' +
                html.escape(code_url, quote=True) + '">Use a code</a>',
                '<script src="/access-client.js" defer></script><script src="/passkeys.js" defer></script>')
    return '<a href="' + html.escape(code_url, quote=True) + '">Sign in</a>', ''


def render(home, works, subject, vpn, *, signed_out=False, passkeys=False, key_revoked=False, return_path='/', shared_login=False):
    esc = html.escape
    cards = "".join(
        "<article><small>"
        + esc(e.get("visibility", ""))
        + "</small><h2>"
        + esc(e["title"])
        + "</h2><p>"
        + esc(e["summary"])
        + '</p><a href="'
        + esc(e["preview_url"] or e["url"], quote=True)
        + '">Explore ↗</a></article>'
        for e in reversed(works)
    )
    rings = "".join(
        '<a href="' + esc(r["url"], quote=True) + '">' + esc(r["name"]) + "</a>"
        for r in home.get("ring", [])
    )
    scope = (
        ("Signed in as " + subject.name)
        if subject
        else ("Dedicated VPN" if vpn else "Public view")
    )
    auth, script = auth_controls(subject, vpn, passkeys, return_path, shared_login)
    notice = (
        '<p role="status">You’re signed out. Only work available without your '
        'personal access is shown.</p>'
        if signed_out and not subject
        else ''
    )
    if key_revoked:
        notice = '<p role="status">Access key revoked. Sessions opened with it are closed.</p>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(home["name"])} · Home</title><link rel="stylesheet" href="/home.css"><script src="/home-style.js" defer></script>{script}</head><body><main><nav><span>DAIMON MATRIX</span>{auth}</nav>{notice}<p id="passkey-status" role="status" aria-live="polite"></p><header><svg viewBox="0 0 88 48" aria-hidden="true"><ellipse cx="44" cy="24" rx="41" ry="17"/><ellipse cx="44" cy="24" rx="22" ry="22"/><circle cx="44" cy="24" r="4"/></svg><small>{esc(scope)}</small><h1>{esc(home["name"])}</h1><p>A shared starting place for ideas, experiments and things we make.</p><a href="{esc(home["vpn_url"], quote=True)}">Dedicated VPN space ↗</a></header><section class="works">{cards or "<p>Room for what comes next. Selected work will appear here as it is shared.</p>"}</section><nav class="ring" aria-label="Tribe web-ring">{rings}</nav><footer>Only work selected for your current access is shown. This page does not indicate current daimon activity.</footer></main></body></html>'''.encode()


def preview(app, home, reference, version, subject, vpn, *, origin, parent_token, display_mode="details"):
    if display_mode not in ("details", "work"):
        raise ValueError("invalid_display_mode")
    selected = app.selected(home, reference, version, subject, vpn)
    if not selected or selected["kind"] != "artifact":
        raise ValueError("preview_denied")
    current = next(
        e for e in app.entries(home, subject, vpn) if e["artifact_ref"] == reference
    )
    esc = html.escape
    content_origin = app.config[
        "content_vpn_url" if vpn else "content_public_url"
    ].rstrip("/")
    child = app.sessions.content_read(
        home=home,
        origin=origin,
        content_origin=content_origin,
        resource=reference,
        version=selected["version_ref"],
        subject=subject,
        parent_token=parent_token,
    )
    prefix = content_origin + "/r/" + child + "/"
    source = prefix + quote(selected["entrypoint"])
    mime = mimetypes.guess_type(selected["entrypoint"])[0] or "application/octet-stream"
    if mime.startswith("image/") and mime != "image/svg+xml":
        display = (
            '<img class="media" src="'
            + esc(source, quote=True)
            + '" alt="'
            + esc(selected["title"], quote=True)
            + '">'
        )
    elif mime.startswith("audio/") or mime.startswith("video/"):
        tag = mime.split("/")[0]
        display = (
            "<"
            + tag
            + ' class="media" controls preload="metadata" src="'
            + esc(source, quote=True)
            + '"></'
            + tag
            + ">"
        )
    else:
        display = (
            '<iframe class="preview" sandbox="allow-scripts" src="'
            + esc(source, quote=True)
            + '" title="'
            + esc(selected["title"], quote=True)
            + '"></iframe>'
        )
    if display_mode == "work":
        if display.startswith('<iframe '):
            display = display.replace(' src="', ' data-src="', 1)
            media_files = [name for name in selected["files"] if re.fullmatch(r"media/[a-f0-9]{64}\.[a-z0-9]{1,8}", name)]
            download_root = "/works/" + reference + "/" + selected["version_ref"] + "/"
            display = display.replace('<iframe ', '<iframe data-download-root="' + esc(download_root, quote=True) + '" data-download-files="' + esc(json.dumps(media_files), quote=True) + '" ', 1)
        return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(selected["title"])} · {esc(app.homes[home]["name"])}</title><link rel="stylesheet" href="/home.css"><script src="/home-style.js" defer></script><script src="/work-view.js" defer></script></head><body class="work-view">{display}</body></html>'''.encode()
    versions = ['<li><a href="/view/' + reference + '">Current version</a></li>']
    for previous in reversed(current.get("versions", [])):
        if app.policy.allows(previous, home=home, subject=subject, dedicated_vpn=vpn):
            versions.append(
                '<li><a href="/view/'
                + reference
                + "?version="
                + previous["version_ref"]
                + '">'
                + esc(previous.get("updated_at", "Earlier version"))
                + "</a></li>"
            )
    files = "".join(
        '<li><a download href="'
        + prefix
        + quote(filename)
        + '">'
        + esc(filename)
        + "</a></li>"
        for filename in selected["files"]
    )
    auth, script = auth_controls(subject, vpn, bool(app.passkeys), '/view/' + reference, bool(app.sso))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(selected["title"])} · {esc(app.homes[home]["name"])}</title><link rel="stylesheet" href="/home.css"><script src="/home-style.js" defer></script>{script}</head><body><main><nav><a href="/">← Home</a>{auth}</nav><p id="passkey-status" role="status" aria-live="polite"></p><header><small>{esc(selected["visibility"])} · {"Current version" if version == "current" else "Earlier version"}</small><h1>{esc(selected["title"])}</h1><p>{esc(selected["summary"])}</p><a href="{esc(source, quote=True)}">Open selected work ↗</a></header>{display}<details><summary>Selected files</summary><ul>{files}</ul></details><details><summary>Versions available to you</summary><ul>{"".join(versions)}</ul></details></main></body></html>'''.encode()


def key_page(app, subject=None, *, registered=False):
    mode = 'register' if subject else 'login'
    if subject:
        rows = ''.join('<li>' + html.escape(k['label']) +
            ' <button type="button" data-revoke="' + html.escape(k['id'], quote=True) +
            '">Revoke</button></li>' for k in app.passkeys.list(subject))
        heading = 'Use your phone to sign in'
        copy = 'Add a passkey after a recent sign-in. Your phone can use a fingerprint, face or device PIN. The same key identifies you across our homes; each work keeps its permissions.'
        button = 'Activate access with my phone'
        extra = '<h2>Your access keys</h2><ul>' + (rows or '<li>No keys yet.</li>') + '</ul><p>Revoking a key also ends sessions opened with it in every home. Synced copies of that key are revoked together.</p>'
    else:
        heading, copy, button = 'Welcome back', 'Use a saved passkey to sign in with your phone.', 'Sign in with a passkey'
        extra = ''
    notice = 'Access key saved. You can now sign out and sign in with a passkey.' if registered and subject else ''
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/home.css"><script src="/access-client.js" defer></script><script src="/passkeys.js" defer></script><title>Access keys · Daimon Matrix</title></head><body><main><a href="/">← Home</a><h1>{heading}</h1><p>{copy}</p><button type="button" id="passkey-action" data-mode="{mode}">{button}</button><p id="passkey-status" role="status" aria-live="polite">{notice}</p>{extra}<p><a href="/access">Use an approved code instead</a></p><p>Keep this recovery route if you lose your phone. Biometrics stay on your device.</p></main></body></html>'''.encode()


def handler(app, *, owner=False):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(30)

        def log_message(self, *_):
            pass

        def end_headers(self):
            self._headers_sent = True
            super().end_headers()

        def respond(self, status, body, kind="application/json", cookies=(), headers=(), form_action="'self'", style_inline=False, telegram_sdk=False, cache_control="no-store"):
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            if status == 200 and cache_control != 'no-store':
                import hashlib
                etag = '"'+hashlib.sha256(body).hexdigest()+'"'
                headers = (*headers, ('ETag',etag))
                if self.headers.get('If-None-Match') == etag:
                    status, body = 304, b''
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache_control)
            self.send_header("X-Content-Type-Options", "nosniff")
            # The single exact-origin login return must preserve its Origin
            # on a cross-host form POST. Only the public origin is disclosed;
            # its request query and response secret never become a Referer.
            self.send_header("Referrer-Policy", "strict-origin" if form_action != "'self'" else "same-origin")
            self.send_header("Permissions-Policy",
                             "publickey-credentials-create=(self), publickey-credentials-get=(self)")
            frames = " ".join(
                app.config.get(k, "") for k in ("content_public_url", "content_vpn_url")
            )
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'"
                + (" https://telegram.org/js/telegram-web-app.js" if telegram_sdk else "")
                + "; frame-src "
                + frames
                + "; img-src 'self' "
                + frames
                + "; media-src "
                + frames
                + ("; style-src 'self' 'unsafe-inline'" if style_inline else "")
                + "; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action " + form_action,
            )
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def context(self, *, login_callback=False, public_style=False):
            home = self.headers.get("X-Daimon-Home", "")
            network = self.headers.get("X-Daimon-Vpn", "")
            if not home:
                field = "vpn_url" if network == "1" else "public_url"
                matches = [
                    ref
                    for ref, row in app.homes.items()
                    if urlsplit(row[field]).netloc == self.headers.get("Host", "")
                ]
                home = matches[0] if len(matches) == 1 else ""
            if home not in app.homes:
                raise ValueError("unknown_home")
            origin = app.homes[home][
                "vpn_url" if network == "1" else "public_url"
            ].rstrip("/")
            supplied = self.headers.get("Origin")
            expected = app.sso.origin if login_callback and app.sso else origin
            if supplied is not None and supplied != expected and not public_style:
                raise ValueError("cross_origin_home_request")
            host = self.headers.get("Host", "")
            if host != urlsplit(origin).netloc:
                raise ValueError("home_origin_mismatch")
            if public_style:
                if network == '1':
                    raise ValueError('public_style_requires_public_home')
                # A public stylesheet never consumes ambient credentials or
                # exposes viewer preferences, even from a same-site browser.
                return home, origin, None, False, {}, ''
            cookies = SimpleCookie()
            cookies.load(self.headers.get("Cookie", ""))
            token = cookies.get("__Host-home")
            # Bearer credentials use the same read-only, exact-origin sessions.
            authorization = self.headers.get("Authorization", "")
            token = (
                authorization[7:]
                if authorization.startswith("Bearer ")
                else (token.value if token else "")
            )
            subject = app.identity(token, home, origin)
            return home, origin, subject, network == "1", cookies, token

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            if owner:
                self.respond(404, {})
                return
            try:
                if app.sso:
                    from .login import routes
                    if routes(self, app, 'GET'): return
                if app.designs:
                    from .homemaker import routes
                    if routes(self, app, 'GET'): return
                if urlsplit(self.path).path.startswith('/agenda/'):
                    from .agenda import routes
                    if routes(self, app, 'GET'): return
                content_origins = {
                    urlsplit(app.config[k]).netloc: app.config[k].rstrip("/")
                    for k in ("content_public_url", "content_vpn_url")
                    if app.config.get(k)
                }
                if self.headers.get("Host", "") in content_origins:
                    return self.content(content_origins[self.headers["Host"]])
                if urlsplit(self.path).path == '/style.css':
                    from .styles import appearance_css
                    home, origin, _, _, _, _ = self.context(public_style=True)
                    query = parse_qs(urlsplit(self.path).query, strict_parsing=True)
                    if (set(query) - {'surface','refresh'} or len(query.get('surface',['home'])) != 1 or
                            len(query.get('refresh',['0'])) != 1 or
                            not re.fullmatch(r'[0-9]{1,16}',query.get('refresh',['0'])[0])):
                        raise ValueError('invalid_public_style_query')
                    surface = query.get('surface',['home'])[0]
                    if surface not in ('home','apps','sessions','nexus'):
                        raise ValueError('style_surface_denied')
                    value = app.styles.resolved(home, surface) if app.styles else {}
                    css = appearance_css(value,fonts_origin=origin)
                    reset = (isinstance(value,dict) and value.get('contract') == 'homemaker.resolved/v1'
                             and value.get('mode') == 'default' and value.get('appearance',False) is None)
                    if not css and not reset:
                        self.respond(503, b'Appearance temporarily unavailable', 'text/plain; charset=utf-8')
                        return
                    self.respond(200, css.encode(), 'text/css; charset=utf-8')
                    return
                home, origin, subject, vpn, cookies, parent_token = self.context()
                path = urlsplit(self.path).path
                if path.startswith("/apps/"):
                    from .launcher import routes
                    if routes(self, app, path, home, subject, vpn): return
                    self.respond(404, {})
                elif path == "/":
                    self.respond(
                        200,
                        render(
                            app.homes[home],
                            [
                                audience_view(e, home)
                                for e in app.entries(home, subject, vpn)
                            ],
                            subject,
                            vpn,
                            signed_out=parse_qs(urlsplit(self.path).query).get(
                                "signed-out"
                            ) == ["1"],
                            passkeys=bool(app.passkeys),
                            key_revoked=parse_qs(urlsplit(self.path).query).get('key-revoked') == ['1'],
                            return_path=self.path,
                            shared_login=bool(app.sso),
                        ),
                        "text/html; charset=utf-8",
                    )
                elif path in ("/home-style.js", "/artifact-style.js", "/home-miniapp-login.js"):
                    body = (Path(__file__).parent / "assets" / path[1:]).read_bytes()
                    import hashlib
                    immutable = parse_qs(urlsplit(self.path).query) == {'v':[hashlib.sha256(body).hexdigest()[:16]]}
                    self.respond(200, body, "text/javascript; charset=utf-8",
                                 cache_control='public, max-age=31536000, immutable' if immutable else 'public, max-age=0, must-revalidate')
                elif path == "/style.json":
                    if not app.styles:
                        self.respond(200, {"contract":"homemaker.resolved/v1","mode":"default","style_ref":"default","style_revision":None,"appearance":None})
                        return
                    query = parse_qs(urlsplit(self.path).query, strict_parsing=True)
                    surface = query.get("surface", ["home"])
                    viewer = query.get('viewer', ['author'])
                    if set(query) - {"surface", "viewer"} or len(surface) != 1 or len(viewer) != 1 or viewer[0] not in ('author', 'personal'):
                        raise ValueError("invalid_style_surface")
                    surface = surface[0]
                    if viewer[0] == 'personal' and (not subject or subject.kind != 'human'):
                        raise ValueError('style_viewer_denied')
                    if surface not in ("home", "apps", "sessions", "nexus") and not (surface == 'homemaker' and app.designs) and not app.selected(home, surface, "current", subject, vpn):
                        raise ValueError("style_surface_denied")
                    self.respond(200, app.styles.resolved(home, surface, subject, personal=viewer[0] == 'personal'))
                elif path == "/access/status":
                    self.respond(200, {
                        "contract": "dm.home-browser/v1",
                        "home": {"name": app.homes[home]["name"]},
                        "signed_in": bool(subject),
                        "visitor": {"name": subject.name, "kind": subject.kind} if subject else None,
                        "dedicated_vpn": vpn,
                        "passkeys": bool(app.passkeys) and not vpn,
                        **({'shared_login':True} if app.sso and not vpn else {}),
                    })
                elif path == "/access/identity":
                    # Trusted same-origin applications reuse this session. The
                    # receiving application still authorizes its own operations.
                    if vpn or self.headers.get("Authorization") or not subject or subject.kind != 'human':
                        self.respond(401, {"detail": "human_browser_required"})
                        return
                    session = app.sessions.resolve(parent_token, home=home, origin=origin)
                    if not session:
                        self.respond(401, {"detail": "human_browser_required"})
                        return
                    self.respond(200, {
                        "contract": "dm.home-session/v1",
                        "origin": origin,
                        "expires": session['expires'],
                        "actor": {"ref": subject.ref, "revision": subject.revision,
                                  "kind": subject.kind, "name": subject.name},
                    })
                elif path == "/access-client.js":
                    self.respond(200, (Path(__file__).parent / "assets" / "access-client.js").read_bytes(),
                                 "text/javascript; charset=utf-8")
                elif app.client_example and path in (
                    "/examples/home-client/", "/home-client-example.js", "/home-client-example.css"
                ):
                    asset, kind = {
                        "/examples/home-client/": ("index.html", "text/html; charset=utf-8"),
                        "/home-client-example.js": ("client.js", "text/javascript; charset=utf-8"),
                        "/home-client-example.css": ("style.css", "text/css; charset=utf-8"),
                    }[path]
                    self.respond(200, (Path(__file__).parent / "examples" / "library" / asset).read_bytes(), kind)
                elif path == "/catalog.json":
                    self.respond(
                        200,
                        {
                            "home_ref": home,
                            "access_contract": "dm.resource-access/v1",
                            "entries": [
                                audience_view(e, home)
                                for e in app.entries(home, subject, vpn)
                            ],
                        },
                    )
                elif path.startswith("/view/"):
                    reference = path.removeprefix("/view/")
                    if not re.fullmatch("[a-f0-9]{32}", reference):
                        raise ValueError("invalid_resource_reference")
                    query = parse_qs(urlsplit(self.path).query, strict_parsing=True)
                    if (
                        set(query) - {"version", "display"}
                        or len(query.get("version", ["current"])) != 1
                        or len(query.get("display", ["details"])) != 1
                    ):
                        raise ValueError("invalid_version_query")
                    version = query.get("version", ["current"])[0]
                    display_mode = query.get("display", ["details"])[0]
                    self.respond(
                        200,
                        preview(
                            app,
                            home,
                            reference,
                            version,
                            subject,
                            vpn,
                            origin=origin,
                            parent_token=parent_token,
                            display_mode=display_mode,
                        ),
                        "text/html; charset=utf-8",
                    )
                elif path == "/work-view.js":
                    self.respond(
                        200,
                        (Path(__file__).parent / "assets" / "work-view.js").read_bytes(),
                        "text/javascript; charset=utf-8",
                    )
                elif path == "/passkeys.js" and app.passkeys:
                    self.respond(200, (Path(__file__).parent / 'assets' / 'passkeys.js').read_bytes(),
                                 'text/javascript; charset=utf-8')
                elif path == "/access/passkey" and app.passkeys and not vpn:
                    app.passkeys.trusted(home, origin)
                    self.respond(200, key_page(app), 'text/html; charset=utf-8')
                elif path == "/access/keys" and app.passkeys and not vpn:
                    app.passkeys.trusted(home, origin)
                    if not subject or subject.kind != 'human' or self.headers.get('Authorization'):
                        raise ValueError('human_browser_required')
                    self.respond(200, key_page(app, subject,
                        registered=parse_qs(urlsplit(self.path).query).get('registered') == ['1']),
                        'text/html; charset=utf-8')
                elif path == "/home.css":
                    self.respond(
                        200,
                        (Path(__file__).parent / "assets" / "home.css").read_bytes(),
                        "text/css",
                    )
                elif path.startswith("/fonts/"):
                    filename = path.removeprefix("/fonts/")
                    if filename not in ("space-grotesk-latin.woff2",):
                        raise ValueError("unknown_asset")
                    self.respond(
                        200,
                        (
                            Path(__file__).resolve().parents[2]
                            / "clusterd"
                            / "assets"
                            / "fonts"
                            / filename
                        ).read_bytes(),
                        "font/woff2",
                    )
                elif path == '/access/sso/start' and app.sso and not vpn:
                    destinations = parse_qs(urlsplit(self.path).query).get('return', ['/'])
                    if len(destinations)!=1: raise ValueError('invalid_home_return')
                    request,proof=app.sso.begin(home,origin,destinations[0])
                    self.respond(303,b'',cookies=(f'__Host-home-sso={proof}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=300',),
                        headers=(('Location',app.sso.origin+'/signin?'+urlencode({'request':request})),))
                elif path == "/access":
                    destinations = parse_qs(urlsplit(self.path).query).get('return', ['/'])
                    if len(destinations) != 1:
                        raise ValueError('invalid_home_return')
                    destination = return_target(destinations[0])
                    request, proof = app.sessions.request(home=home, origin=origin)
                    code = request["code"]
                    home_name = html.escape(app.homes[home]["name"])
                    body = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/home.css"><title>Sign in · {home_name}</title><main><a href="/">← Home</a><h1>Open your shared space</h1><p>Send this code to your own daimon in your existing conversation:</p><p><strong>{code}</strong></p><p>Ask them to approve your browser for {home_name}. The code expires in 15 minutes. Approval proves who you are; each resource keeps its selected audience.</p><form method="post" action="/access/claim"><input name="code" type="hidden" value="{code}"><button>Continue after approval</button></form></main></html>'''.encode()
                    if app.passkeys and not vpn:
                        body = body.replace(b'<h1>', b'<p><a href="/access/passkey">Sign in with a passkey</a></p><h1>', 1)
                    body = body.replace(b'</form>', ('<input type="hidden" name="return" value="' +
                        html.escape(destination, quote=True) + '"></form>').encode(), 1)
                    self.respond(
                        200,
                        body,
                        "text/html; charset=utf-8",
                        cookies=(
                            f"__Host-home-proof={proof}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=900",
                        ),
                    )
                elif path.startswith("/works/") or path.startswith("/artifacts/"):
                    parts = [unquote(p) for p in path.split("/")]
                    if path.startswith("/artifacts/"):
                        if len(parts) < 4:
                            raise ValueError("invalid_artifact_path")
                        selected = next(
                            (
                                e
                                for e in app.entries(home, subject, vpn)
                                if e["id"] == parts[2] and e["kind"] == "artifact"
                            ),
                            None,
                        )
                        reference, version, files = (
                            (selected["artifact_ref"] if selected else ""),
                            "current",
                            parts[3:],
                        )
                    else:
                        if len(parts) < 5:
                            raise ValueError("invalid_artifact_path")
                        reference, version, files = parts[2], parts[3], parts[4:]
                        selected = app.selected(home, reference, version, subject, vpn)
                    if (
                        not selected
                        or selected["kind"] != "artifact"
                        or "/".join(files) not in selected["files"]
                        or any(
                            p in ("", ".", "..") or "/" in p or "\\" in p or "\0" in p
                            for p in files
                        )
                    ):
                        raise ValueError("artifact_denied")
                    # Never follow a mutable current pointer after authorization.
                    backend_path = (
                        "/_home/artifact/"
                        + reference
                        + "/"
                        + selected["version_ref"]
                        + "/"
                        + "/".join(quote(p, safe="") for p in files)
                    )
                    with app.backends[home].open(
                        backend_path,
                        method=self.command,
                        byte_range=self.headers.get("Range"),
                    ) as response:
                        if (
                            response.headers.get("X-Home-Version")
                            != selected["version_ref"]
                        ):
                            raise ValueError("home_delivery_version_mismatch")
                        self.send_response(response.status)
                        for name in (
                            "Content-Type",
                            "Content-Length",
                            "Content-Range",
                            "Accept-Ranges",
                        ):
                            if response.headers.get(name):
                                self.send_header(name, response.headers[name])
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("X-Content-Type-Options", "nosniff")
                        self.send_header("Permissions-Policy", "publickey-credentials-create=(), publickey-credentials-get=()")
                        self.send_header("Referrer-Policy", "no-referrer")
                        content_type = response.headers.get("Content-Type", "").split(
                            ";"
                        )[0]
                        if content_type in ("text/html", "image/svg+xml"):
                            # Active content executes only on the cookie-free
                            # isolated viewer, never on the authenticated home.
                            self.send_header("Content-Disposition", "attachment")
                            self.send_header(
                                "Content-Security-Policy", "default-src 'none'; sandbox"
                            )
                        else:
                            self.send_header(
                                "Content-Security-Policy", "default-src 'none'; sandbox"
                            )
                        self.end_headers()
                        if self.command != "HEAD":
                            while block := response.read(256 * 1024):
                                self.wfile.write(block)
                else:
                    self.respond(404, {})
            except (ValueError, KeyError, OSError, urllib.error.URLError):
                if not getattr(self, "_headers_sent", False):
                    self.respond(404, {})
                else:
                    self.close_connection = True

        def content(self, origin):
            """One artifact child context, without home cookies or login APIs."""
            supplied = self.headers.get("Origin")
            if supplied not in (None, "null", origin):
                raise ValueError("content_origin_denied")
            parts = urlsplit(self.path).path.split("/")
            if len(parts) < 4 or parts[1] != "r":
                raise ValueError("invalid_content_route")
            ticket = parts[2]
            row = app.sessions.resolve_content(ticket, content_origin=origin)
            if not row:
                raise ValueError("content_read_denied")
            subject = (
                app.policy.current(row["actor"], row["revision"])
                if row["actor"]
                else None
            )
            if row["actor"] and not subject:
                raise ValueError("content_actor_changed")
            vpn = self.headers.get("X-Daimon-Vpn") == "1"
            selected = app.selected(
                row["home"], row["resource"], row["version"], subject, vpn
            )
            files = [unquote(p) for p in parts[3:]]
            if (
                not selected
                or selected["kind"] != "artifact"
                or "/".join(files) not in selected["files"]
                or any(
                    p in ("", ".", "..") or "/" in p or "\\" in p or "\0" in p
                    for p in files
                )
            ):
                raise ValueError("content_file_denied")
            path = (
                "/_home/artifact/"
                + row["resource"]
                + "/"
                + selected["version_ref"]
                + "/"
                + "/".join(quote(p, safe="") for p in files)
            )
            with app.backends[row["home"]].open(
                path, method=self.command, byte_range=self.headers.get("Range")
            ) as response:
                if response.headers.get("X-Home-Version") != selected["version_ref"]:
                    raise ValueError("content_delivery_version_mismatch")
                self.send_response(response.status)
                for name in (
                    "Content-Type",
                    "Content-Length",
                    "Content-Range",
                    "Accept-Ranges",
                ):
                    if response.headers.get(name):
                        self.send_header(name, response.headers[name])
                prefix = origin + "/r/" + ticket + "/"
                # Opaque-origin modules, fonts and own JSON use only this
                # artifact-scoped context. Null never authenticates a home.
                self.send_header(
                    "Access-Control-Allow-Origin",
                    "null" if supplied == "null" else origin,
                )
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Permissions-Policy", "publickey-credentials-create=(), publickey-credentials-get=()")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header(
                    "Content-Security-Policy",
                    "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline' "
                    + prefix
                    + "; style-src 'unsafe-inline' "
                    + prefix
                    + "; font-src "
                    + prefix
                    + "; img-src data: blob: "
                    + prefix
                    + "; media-src data: blob: "
                    + prefix
                    + "; connect-src "
                    + prefix
                    + "; frame-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors "
                    + app.homes[row["home"]]["public_url"]
                    + " "
                    + app.homes[row["home"]]["vpn_url"],
                )
                self.end_headers()
                if self.command != "HEAD":
                    while block := response.read(256 * 1024):
                        self.wfile.write(block)

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 65536:
                    raise ValueError("invalid_request_size")
                data = self.rfile.read(length)
                if len(data) != length:
                    raise ValueError("incomplete_home_request")
                if owner:
                    parts = urlsplit(self.path).path.split("/")
                    if len(parts) != 4 or parts[1] != "owner":
                        raise ValueError("unknown_owner_route")
                    token = self.headers.get("Authorization", "")
                    if not token.startswith("Bearer "):
                        raise ValueError("home_owner_denied")
                    payload = json.loads(data)
                    if not isinstance(payload, dict):
                        raise ValueError("invalid_owner_payload")
                    try:
                        result=app.owner(unquote(parts[2]), token[7:], parts[3], payload)
                    except ValueError as error:
                        if parts[3].startswith('agenda-'):
                            from .agenda import AgendaError
                            if isinstance(error, AgendaError):
                                self.respond(error.status, {'error':str(error)});return
                        if parts[3].startswith('style-') and str(error) in (
                                'design_revision_conflict','design_selection_conflict','design_operation_conflict'):
                            self.respond(409,{'error':str(error)});return
                        raise
                    self.respond(200,result)
                    return
                if app.sso:
                    from .login import routes
                    if routes(self, app, 'POST', data): return
                if app.designs:
                    from .homemaker import routes
                    if routes(self, app, 'POST', data): return
                if urlsplit(self.path).path.startswith('/agenda/'):
                    from .agenda import routes
                    if routes(self, app, 'POST', data): return
                callback = urlsplit(self.path).path == '/access/sso/finish' and bool(app.sso)
                home, origin, subject, vpn, cookies, token = self.context(login_callback=callback)
                if callback:
                    if vpn or self.headers.get('Origin') != app.sso.origin or self.headers.get('Authorization'):
                        raise ValueError('login_callback_origin_mismatch')
                    payload=parse_qs(data.decode(),keep_blank_values=True,strict_parsing=True)
                    if set(payload)!={'request','response'} or any(len(v)!=1 for v in payload.values()):
                        raise ValueError('invalid_login_callback')
                    proof=cookies['__Host-home-sso'].value if cookies.get('__Host-home-sso') else ''
                    session,destination=app.sso.redeem(home,origin,payload['request'][0],payload['response'][0],proof)
                    self.respond(303,b'',cookies=(
                        f'__Host-home={session}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800',
                        '__Host-home-sso=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'),
                        headers=(('Location',destination),))
                    return
                if self.headers.get("Origin") != origin:
                    raise ValueError("home_post_requires_exact_origin")
                path = urlsplit(self.path).path
                if path.startswith('/access/passkeys/') and app.passkeys:
                    if self.headers.get('Authorization') or vpn:
                        raise ValueError('passkeys_require_browser_cookie')
                    operation = path.removeprefix('/access/passkeys/')
                    payload = json.loads(data)
                    if not isinstance(payload, dict) or len(data) > 32768:
                        raise ValueError('invalid_passkey_payload')
                    browser_proof = cookies['__Host-home-proof'].value if cookies.get('__Host-home-proof') else ''
                    if operation in ('register-options', 'login-options'):
                        if payload:
                            raise ValueError('unexpected_passkey_fields')
                        result, proof = app.passkeys.begin(home=home, origin=origin,
                            mode=operation.split('-')[0], token=token, browser_proof=browser_proof)
                        self.respond(200, result, cookies=(f'__Host-home-passkey={proof}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=300',))
                    elif operation in ('register-finish', 'login-finish'):
                        if set(payload) != {'nonce', 'credential'}:
                            raise ValueError('unexpected_passkey_fields')
                        proof = cookies['__Host-home-passkey'].value if cookies.get('__Host-home-passkey') else ''
                        result, session = app.passkeys.finish(home=home, origin=origin,
                            mode=operation.split('-')[0], nonce=payload['nonce'], proof=proof,
                            credential=payload['credential'], token=token, browser_proof=browser_proof)
                        headers = ['__Host-home-passkey=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0']
                        if session:
                            headers.append(f'__Host-home={session}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800')
                        self.respond(200, result, cookies=tuple(headers))
                    elif operation == 'revoke':
                        if set(payload) != {'id'}:
                            raise ValueError('unexpected_passkey_fields')
                        app.passkeys.revoke(home=home, origin=origin, token=token,
                            browser_proof=browser_proof, identifier=payload['id'])
                        expired = () if app.identity(token, home, origin) else (
                            '__Host-home=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0',)
                        self.respond(200, {'status':'revoked'}, cookies=expired)
                    else:
                        raise ValueError('unknown_passkey_operation')
                elif path == "/access/logout":
                    app.sessions.revoke(home=home, token=token)
                    browser = "text/html" in self.headers.get("Accept", "")
                    self.respond(
                        303 if browser else 200,
                        b"" if browser else {"status": "signed-out"},
                        cookies=(
                            "__Host-home=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
                        ),
                        headers=(("Location", "/?signed-out=1"),) if browser else (),
                    )
                elif path == "/access/claim":

                    payload = parse_qs(data.decode(), strict_parsing=True)
                    if (
                        set(payload) not in ({"code"}, {"code", "return"})
                        or len(payload["code"]) != 1
                        or not cookies.get("__Host-home-proof")
                    ):
                        raise ValueError("invalid_browser_claim")
                    destinations = payload.get('return', ['/'])
                    if len(destinations) != 1:
                        raise ValueError('invalid_home_return')
                    destination = return_target(destinations[0])
                    status, credential = app.sessions.claim(
                        home=home,
                        origin=origin,
                        code=payload["code"][0],
                        proof=cookies["__Host-home-proof"].value,
                        current_actor=app.policy.current,
                    )
                    if credential:
                        if 'text/html' in self.headers.get('Accept', ''):
                            self.respond(303, b'', headers=(('Location', destination),), cookies=(
                                f'__Host-home={credential}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800',))
                            return
                        self.respond(
                            200,
                            b'<!doctype html><html><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/home.css"><main><h1>Signed in</h1><a href="/">Open home</a></main></html>',
                            "text/html",
                            cookies=(
                                f"__Host-home={credential}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800",
                            ),
                        )
                    else:
                        self.respond(200, status)
                else:
                    self.respond(404, {})
            except (ValueError, KeyError, OSError, urllib.error.URLError):
                self.respond(403, {"status": "denied"})

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--passkey-rp-id", help="Enable shared passkeys for exact configured public home origins")
    parser.add_argument("--client-example", action="store_true", help="Serve the optional independently authored library client")
    parser.add_argument('--auth-origin', help='Exact trusted shared login origin under the passkey RP')
    parser.add_argument('--google-client', help='Private optional Google OIDC client JSON file')
    parser.add_argument('--homemaker-source', help='Qualified immutable Homemaker source and public build')
    parser.add_argument('--homemaker-state', help='Private canonical Homemaker design state')
    parser.add_argument('--homemaker-home', help='Registered home serving the owner-operated multi-pair application')
    parser.add_argument('--homemaker-return', action='append', default=[], help='Additional exact registered consumer return URL')
    parser.add_argument('--miniapp-routes', help='Operator-selected public same-origin destination map JSON')
    parser.add_argument('--miniapp-receivers', help='Verified same-origin per-pair application routes JSON')
    parser.add_argument('--agenda-state', help='Private optional Vikunja adapter state directory')
    parser.add_argument('--agenda-backend', help='Exact loopback origin of a pinned, private Vikunja instance')
    parser.add_argument('--agenda-google-client', help='Private optional Google Calendar OAuth client; separate Calendar consent')
    args = parser.parse_args()
    from daimon_matrix.messaging_config import protected_read

    config = validate_config(json.loads(protected_read(Path(args.config))))
    sessions = Sessions(Path(config["state"]))
    registry = Registry(sessions)
    authority = NativeAuthority(
        Path(config["binding_source"]),
        Path(config["relationship_store"]),
        config["homes"],
        authority_source=Path(config["authority_source"]),
        human_rosters=registry.rosters,
    )
    app = Application(config, authority, sessions, passkey_rp_id=args.passkey_rp_id, client_example=args.client_example,
                      auth_origin=args.auth_origin, google_client=args.google_client,
                      homemaker_source=args.homemaker_source, homemaker_state=args.homemaker_state,
                      homemaker_home=args.homemaker_home, homemaker_returns=args.homemaker_return,
                      miniapp_routes=json.loads(protected_read(Path(args.miniapp_routes))) if args.miniapp_routes else None,
                      miniapp_receivers=json.loads(protected_read(Path(args.miniapp_receivers))) if args.miniapp_receivers else None,
                      agenda_state=args.agenda_state, agenda_backend=args.agenda_backend,
                      agenda_google_client=args.agenda_google_client)
    servers = [
        ThreadingHTTPServer(("127.0.0.1", config[key]), handler(app, owner=owner))
        for key, owner in (("viewer_port", False), ("owner_port", True))
    ]
    for server in servers:
        server.daemon_threads = True
    threading.Thread(target=servers[1].serve_forever, daemon=True).start()
    try:
        servers[0].serve_forever()
    finally:
        for server in servers:
            server.server_close()


if __name__ == "__main__":
    main()

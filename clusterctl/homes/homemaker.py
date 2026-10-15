"""Receiving adapter for the single source-owned Homemaker component.

Verified identity and current pairing permissions come from the home gateway.
Recipes, design history and selections stay in Homemaker's canonical authority.
The source directory is operator-selected immutable code, never a request field.
"""
import importlib.util
import importlib
import hashlib
import json
import sys
from pathlib import Path


class Homemaker:
    def __init__(self, app, source, state):
        self.app = app
        self.source = Path(source).resolve(strict=True)
        self.public = self.source / 'dist'
        if not (self.public / 'index.html').is_file():
            raise ValueError('homemaker_public_build_required')
        module_path = self.source / 'backend/authority.py'
        spec = importlib.util.spec_from_file_location('home_homemaker_authority', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.authority = module.DesignAuthority(state, authorize=self.authorize)
        templates = json.loads((self.source / 'public/content/templates.json').read_text())
        self.templates = {entry['id']: entry['name'] for entry in templates}
        self.owner_application = None
        if app.homemaker_home:
            declaration = json.loads((self.source / 'release.json').read_text())
            origin = app.homes[app.homemaker_home]['public_url']
            if (declaration.get('contract') != 'homemaker.owner-release/v1' or
                    declaration.get('origin') != origin or
                    declaration.get('component') != 'backend.application.OwnerApplication' or
                    declaration.get('entries') != {'web':'/homemaker/', 'compact':'/homemaker/miniapp.html'}):
                raise ValueError('invalid_homemaker_owner_release')
            # Operator-selected immutable code only. A distinct namespace keeps
            # relative imports local to this release, including in fixture runs.
            name = '_home_creator_' + hashlib.sha256(str(self.source).encode()).hexdigest()[:24]
            if name not in sys.modules:
                spec = importlib.util.spec_from_file_location(name, self.source / 'backend/__init__.py',
                    submodule_search_locations=[str(self.source / 'backend')])
                package = importlib.util.module_from_spec(spec)
                sys.modules[name] = package
                try:
                    spec.loader.exec_module(package)
                except BaseException:
                    sys.modules.pop(name, None)
                    raise
            owner_module = importlib.import_module(name + '.application')
            self.context_type = owner_module.ApplicationContext
            self.owner_application = owner_module.OwnerApplication(self.source,
                authority=self.authority, resolve_context=self.verified_context, origin=origin,
                allowed_returns=app.homemaker_returns)

    def verified_context(self, principal, *, target, mode):
        home = self.app.homemaker_home
        owner, audience, label = self.scope(home, principal, mode)
        if target is not None:
            if (target not in self.app.homes or
                    self.app.authority.paired_human(target) != principal.ref or
                    (mode == 'pair' and self.app.homes[target]['owner_being_ref'] != owner['ref'])):
                raise ValueError('design_operation_denied')
        return self.context_type(principal.ref, owner, audience, label)

    def application_context(self, subject, mode, *, target=None, return_to=None):
        context = self.owner_application.context(subject, target=target, mode=mode, return_to=return_to)
        selected = target
        if selected is None:
            if mode == 'personal':
                matches = [ref for ref in self.app.homes
                           if self.app.authority.paired_human(ref) == subject.ref]
                selected = matches[0] if len(matches) == 1 else self.app.homemaker_home
            else:
                selected = self.pair_home(self.app.homemaker_home, subject)
        if return_to is not None:
            from urllib.parse import urlsplit
            if urlsplit(return_to).netloc != urlsplit(self.app.homes[selected]['public_url']).netloc:
                raise ValueError('application_return_denied')
        return context, selected

    def application_selection(self, subject, mode, *, target=None, surface='default', payload=None):
        context, selected = self.application_context(subject, mode, target=target)
        surface = self.surface(selected, surface)
        if payload is None:
            return self.authority.read_selection(context.actor, scope=context.owner, surface=surface)
        if not isinstance(payload, dict) or set(payload) != {'selection','expected_revision','operation_id'}:
            raise ValueError('invalid_design_selection')
        return self.authority.select(context.actor, scope=context.owner, surface=surface, **payload)

    def authorize(self, subject, action, scope):
        current = self.app.authority.actor(subject) if subject else None
        if not current or not current.enabled:
            return False
        if scope['kind'] == 'human':
            owns = current.kind == 'human' and current.ref == scope['ref']
        else:
            owns = (current.kind == 'being' and current.ref == scope['ref']) or (
                current.kind == 'human' and any(
                    home['owner_being_ref'] == scope['ref'] and
                    self.app.authority.paired_human(ref) == current.ref
                    for ref, home in self.app.homes.items()))
        if action in ('design.read', 'design.preference.read'):
            return owns
        return owns and action in (
            'design.update', 'design.select', 'design.share')

    def pair_home(self, home, subject):
        """Resolve a central editor's member from current pairing, never its host."""
        if getattr(self.app, 'homemaker_home', None) != home:
            return home
        matches = [ref for ref in self.app.homes
                   if self.app.authority.paired_human(ref) == subject.ref]
        owners = {self.app.homes[ref]['owner_being_ref'] for ref in matches}
        if len(owners) != 1:
            raise ValueError('design_pair_context_unavailable')
        return home if home in matches else matches[0]

    def scope(self, home, subject, context):
        if (not subject or subject.kind != 'human' or
                not self.app.policy.current(subject.ref, subject.revision)):
            raise ValueError('design_operation_denied')
        if context == 'personal':
            return {'kind': 'human', 'ref': subject.ref}, 'private', 'Mi estilo personal'
        if context == 'pair':
            selected = self.pair_home(home, subject)
            if self.app.authority.paired_human(selected) == subject.ref:
                return {'kind': 'being', 'ref': self.app.homes[selected]['owner_being_ref']}, 'public', 'Nuestra dupla'
        raise ValueError('design_operation_denied')

    def variant(self, variant):
        if not isinstance(variant, str) or not variant.startswith('template-'):
            raise ValueError('invalid_design_variant')
        template = variant.removeprefix('template-')
        if template not in self.templates:
            raise ValueError('invalid_design_variant')
        return template, self.templates[template]

    def baseline(self, home, subject, context, variant):
        if getattr(self, 'owner_application', None):
            return self.owner_application.baseline(subject, target=None, mode=context, variant=variant)
        owner, _, _ = self.scope(home, subject, context)
        self.variant(variant)
        return self.authority.editor_default(subject.ref, owner=owner, identifier=variant)

    def save(self, home, subject, context, payload):
        if getattr(self, 'owner_application', None):
            return self.owner_application.save(subject, target=None, mode=context,
                origin=self.app.homes[self.app.homemaker_home]['public_url'], payload=payload)
        owner, audience, _ = self.scope(home, subject, context)
        return self._save(subject, owner, audience, payload)

    def save_native(self, home, subject, payload):
        """Called only after the gateway verifies its publishing owner credential.

        Being reader cookies cannot use this operation. Its namespace is fixed
        to that owner; it cannot edit a human or another being's preference.
        """
        if subject.kind != 'being' or subject.ref != self.app.homes[home]['owner_being_ref']:
            raise ValueError('design_operation_denied')
        if not isinstance(payload, dict) or payload.get('audience') not in ('public', 'private'):
            raise ValueError('explicit_design_audience_required')
        return self._save(subject, {'kind':'being','ref':subject.ref}, payload['audience'],
                          {key:value for key,value in payload.items() if key != 'audience'})

    def surface(self, home, value):
        if value in ('default', 'home', 'homemaker', 'apps'):
            return value
        if not isinstance(value, str) or not any(
                entry['artifact_ref'] == value for entry in self.app.publication(home)['entries']):
            raise ValueError('unregistered_design_surface')
        return value

    def selection_native(self, home, subject, payload, *, write=False):
        keys={'surface','selection','expected_revision','operation_id'} if write else {'surface'}
        if not isinstance(payload,dict) or set(payload)!=keys:
            raise ValueError('invalid_design_selection')
        scope={'kind':'being','ref':subject.ref}
        surface=self.surface(home,payload['surface'])
        if not write:
            return self.authority.read_selection(subject.ref,scope=scope,surface=surface)
        return self.authority.select(subject.ref,scope=scope,surface=surface,
            selection=payload['selection'],expected_revision=payload['expected_revision'],operation_id=payload['operation_id'])

    def recipe_native(self, subject, payload):
        if not isinstance(payload,dict) or not {'design_ref'}<=set(payload)<={'design_ref','design_revision'}:
            raise ValueError('invalid_design_recipe_request')
        recipe=self.authority.read_recipe(subject.ref,payload['design_ref'],payload.get('design_revision'))
        if recipe is None:
            raise ValueError('design_recipe_unavailable')
        return recipe

    def _save(self, subject, owner, audience, payload):
        if (not isinstance(payload, dict) or set(payload) != {
                'variant', 'recipe', 'expected_design_revision', 'expected_selection_revision', 'operation_id'}):
            raise ValueError('invalid_design_save')
        template, name = self.variant(payload['variant'])
        if (not isinstance(payload['recipe'], dict) or not isinstance(payload['recipe'].get('config'), dict)
                or payload['recipe']['config'].get('templateId') != template):
            raise ValueError('design_variant_recipe_mismatch')
        return self.authority.save_default(subject.ref, owner=owner,
            identifier=payload['variant'], name=name, recipe=payload['recipe'], audience=audience,
            expected_design_revision=payload['expected_design_revision'],
            expected_selection_revision=payload['expected_selection_revision'],
            operation_id=payload['operation_id'])

    def resolve(self, subject, **context):
        value = self.authority.resolve(subject, **context)
        return {**value, 'font_assets': bool(value.get('appearance'))}

    def asset(self, name):
        """Serve only the built public source; no backend/state/repository paths."""
        if (not isinstance(name, str) or not name or '\\' in name or
                any(part in ('', '.', '..') or part.startswith('.') for part in name.split('/'))):
            raise ValueError('invalid_homemaker_asset')
        path = self.public.joinpath(name)
        if path.is_symlink() or not path.resolve().is_relative_to(self.public.resolve()) or not path.is_file():
            raise ValueError('homemaker_asset_unavailable')
        return path


BOOTSTRAP = '''import {mountBuilder} from './app.js';
const scope=new URL(location.href).searchParams.get('scope') || 'pair';
const endpoint='/homemaker/api/default?scope='+encodeURIComponent(scope);
async function request(url, options={}) {
  const response=await fetch(url,{credentials:'same-origin',redirect:'error',...options});
  const value=await response.json();
  if(!response.ok) throw Object.assign(Error(value.error || 'design_operation_denied'),{code:value.error});
  return value;
}
const context=await request('/homemaker/api/context?scope='+encodeURIComponent(scope));
const data=await request('./content/bundle.json');
const app=mountBuilder(data,document,{sharedDefault:{
  origin:location.origin,audience:context.audience,label:context.label,
  variant:recipe=>'template-'+recipe.config.templateId,
  load:({variant,signal})=>request(endpoint+'&variant='+encodeURIComponent(variant),{signal}),
  save:({signal,...payload})=>request(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload),signal}),
}});
document.addEventListener('homemaker:default-saved',()=>window.dispatchEvent(new CustomEvent('home-style:refresh')));
window.addEventListener('pagehide',event=>{if(!event.persisted)app.destroy();});
'''

OWNER_BOOTSTRAP = '''import {mountOwnerEntry} from './lib/owner-entry.js';
mountOwnerEntry().catch(() => {
  const message = document.createElement('p');
  message.setAttribute('role', 'alert');
  message.textContent = 'No pudimos recuperar tu taller. No guardamos ni cambiamos tu estilo.';
  const retry = document.createElement('button');
  retry.className = 'button'; retry.textContent = 'Volver a intentar';
  retry.addEventListener('click', () => location.reload(), {once:true});
  const main = document.querySelector('main') || document.body;
  main.prepend(retry); main.prepend(message);
});
'''



def editor_page(provider, entry='index.html', *, context='pair'):
    # Disable the source's standalone initializer and inject its existing
    # builder with this receiving transport. Its escaped shadow previews remain
    # tab-local; shadow DOM is style isolation, not a security boundary. Published
    # artifacts retain the separate gateway's opaque-origin sandbox.
    body = provider.asset(entry).read_bytes()
    body = body.replace(b'<html ', (b'<html data-style-surface="homemaker" ' +
        (b'data-style-viewer="personal" ' if context == 'personal' else b'')), 1)
    return body.replace(b'data-builder-app', b'data-trusted-builder').replace(
        b'</body>', b'<script src="/access-client.js"></script><script src="/home-style.js"></script><script type="module" src="/homemaker/bootstrap.js"></script></body>')


def routes(handler, app, method, data=b''):
    import html
    import mimetypes
    from urllib.parse import parse_qs, unquote, urlsplit, urlencode
    from .service import auth_controls
    provider = app.designs
    path = urlsplit(handler.path).path
    if not provider:
        return False
    if method == 'GET' and path.startswith('/design-assets/'):
        host = handler.headers.get('Host', '')
        if host not in {urlsplit(h['public_url']).netloc for h in app.homes.values()}:
            raise ValueError('unregistered_font_origin')
        name = unquote(path.removeprefix('/design-assets/'))
        if name != 'styles/fonts.css' and not (name.startswith('fonts/') and '/' not in name[6:]):
            raise ValueError('invalid_design_asset')
        asset = provider.asset('assets/' + name)
        handler.respond(200, asset.read_bytes(), mimetypes.guess_type(asset.name)[0] or 'application/octet-stream',
                        headers=(('Access-Control-Allow-Origin', '*'),));return True
    if not path.startswith('/homemaker/'):
        return False
    home, origin, subject, vpn, _, _ = handler.context()
    if vpn or handler.headers.get('Authorization'):
        raise ValueError('homemaker_requires_public_browser')
    query = parse_qs(urlsplit(handler.path).query, keep_blank_values=True, strict_parsing=True)
    if any(len(v) != 1 for v in query.values()) or set(query) - {
            'scope', 'variant', 'target', 'return_to', 'surface', 'design_ref', 'design_revision'}:
        raise ValueError('invalid_homemaker_query')
    context = query.get('scope', ['pair'])[0]
    canonical = getattr(app, 'homemaker_home', None)
    if canonical and home != canonical:
        if method == 'GET' and path in ('/homemaker/', '/homemaker/miniapp.html'):
            target_query = {'scope':context, 'target':home,
                            'return_to':query.get('return_to', [app.homes[home]['public_url'] + '/'])[0]}
            handler.respond(307, b'', headers=(('Location', app.homes[canonical]['public_url'] +
                                              path + '?' + urlencode(target_query)),))
        else:
            handler.respond(410, {'error':'use_canonical_homemaker'})
        return True
    if method == 'GET' and path in ('/homemaker/', '/homemaker/miniapp.html') and not subject:
        miniapp = path.endswith('miniapp.html')
        presentation = ('<script src="https://telegram.org/js/telegram-web-app.js"></script>'
                        '<script src="/home-miniapp-login.js" defer></script>') if miniapp else ''
        auth, script = auth_controls(None, False, bool(app.passkeys), handler.path, bool(app.sso))
        body = ('<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                '<link rel="stylesheet" href="/home.css"><title>Tu taller · Homemaker</title>'+presentation+script+
                '<main><h1>Tu taller de estilos</h1><p>Entrá con tu identidad habitual para elegir el estilo de tus espacios.</p>'+
                auth+'<p id="passkey-status" role="status" aria-live="polite"></p></main></html>')
        handler.respond(200, body.encode(), 'text/html; charset=utf-8', telegram_sdk=miniapp);return True
    owner_app = getattr(provider, 'owner_application', None)
    target = query.get('target', [None])[0]
    return_to = query.get('return_to', [None])[0]
    verified = None
    if owner_app and (path.startswith('/homemaker/api/') or path in ('/homemaker/', '/homemaker/miniapp.html')):
        verified, selected_home = provider.application_context(subject, context, target=target, return_to=return_to)
    if path == '/homemaker/api/context' and method == 'GET':
        if verified:
            value = {'audience':verified.audience, 'label':verified.label,
                     'target':selected_home, 'return_to':return_to or app.homes[selected_home]['public_url'] + '/'}
        else:
            _, audience, label = provider.scope(home, subject, context)
            value = {'audience':audience, 'label':label}
        handler.respond(200, value);return True
    if owner_app and path in ('/homemaker/api/selection', '/homemaker/api/recipe'):
        if method == 'POST' and handler.headers.get('Origin') != origin:
            raise ValueError('design_operation_denied')
        if path.endswith('/recipe') and method == 'GET':
            revision = query.get('design_revision', [None])[0]
            if revision is not None:
                if not revision.isdecimal() or len(revision) > 12:
                    raise ValueError('invalid_design_recipe_request')
                revision = int(revision)
            value = owner_app.recipe(subject, target=target, mode=context,
                design_ref=query.get('design_ref', [None])[0], revision=revision)
        elif path.endswith('/selection') and method in ('GET', 'POST'):
            try:
                value = provider.application_selection(subject, context, target=target,
                    surface=query.get('surface', ['default'])[0],
                    payload=json.loads(data) if method == 'POST' else None)
            except ValueError as error:
                if str(error) in ('design_selection_conflict', 'design_operation_conflict'):
                    handler.respond(409, {'error':str(error)});return True
                raise
        else:
            raise ValueError('unknown_homemaker_operation')
        handler.respond(200, value);return True
    if path == '/homemaker/api/default':
        if method == 'GET':
            handler.respond(200, provider.baseline(home, subject, context, query.get('variant', [None])[0]));return True
        if method == 'POST':
            if handler.headers.get('Origin') != origin:
                raise ValueError('design_operation_denied')
            try:
                value = provider.save(home, subject, context, json.loads(data))
            except ValueError as error:
                # Stable machine codes let the existing editor preserve the
                # draft on conflict and retain its operation on uncertain I/O.
                code = str(error)
                if code not in {'design_operation_denied', 'design_revision_conflict',
                                'design_selection_conflict', 'design_operation_conflict'}:
                    code = 'invalid_design_save'
                handler.respond(409 if code.endswith('conflict') else 403, {'error': code});return True
            handler.respond(200, value);return True
    if method == 'GET':
        provider.scope(home, subject, context if path in ('/homemaker/', '/homemaker/miniapp.html') else 'personal')
        if path in ('/homemaker/', '/homemaker/miniapp.html'):
            entry = 'miniapp.html' if path.endswith('miniapp.html') else 'index.html'
            handler.respond(200, editor_page(provider, entry, context=context), 'text/html; charset=utf-8',
                            style_inline=True, telegram_sdk=entry == 'miniapp.html');return True
        if path == '/homemaker/bootstrap.js':
            handler.respond(200, (OWNER_BOOTSTRAP if owner_app else BOOTSTRAP).encode(), 'text/javascript; charset=utf-8');return True
        asset = provider.asset(unquote(path.removeprefix('/homemaker/')))
        handler.respond(200, asset.read_bytes(), mimetypes.guess_type(asset.name)[0] or 'application/octet-stream');return True
    raise ValueError('unknown_homemaker_operation')

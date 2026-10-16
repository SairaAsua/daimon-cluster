"""A read-only Mini App client of existing publication and style authorities.

Public app links published through any selected home's ordinary owner
workflow become shared navigation. Only this home may contribute private links
through its current authorized reader. No launch is a permission grant.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import hashlib
import html
from pathlib import Path
import re
import threading
from urllib.parse import parse_qsl, urlsplit

ASSETS = Path(__file__).parent / 'launcher'
CAPACITY = threading.BoundedSemaphore(4)


def validate_launch_routes(value):
    """Operator-selected same-origin paths; selectors are never access grants."""
    if value is None:
        return {'schema':'dm.miniapp-routes/v1','origins':{}}
    if (not isinstance(value,dict) or set(value)!={'schema','origins'} or
            value['schema']!='dm.miniapp-routes/v1' or not isinstance(value['origins'],dict) or
            len(value['origins'])>16):
        raise ValueError('invalid_miniapp_routes')
    for origin, routes in value['origins'].items():
        u=urlsplit(origin)
        if (u.scheme!='https' or not u.netloc or u.path or u.query or u.fragment or
                u.username or u.password or any(c.isspace() or c in '\\"\'<> ' for c in origin) or
                not isinstance(routes,list) or not 1<=len(routes)<=16):
            raise ValueError('invalid_miniapp_route_origin')
        prefixes=[]
        for route in routes:
            if (not isinstance(route,dict) or set(route)!={'prefix','path'} or
                    not isinstance(route['prefix'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',route['prefix']) or
                    not isinstance(route['path'],str) or not re.fullmatch(r'/[a-zA-Z0-9_-]+/',route['path']) or
                    route['path']=='/apps/' or any(route['prefix'].startswith(p) or p.startswith(route['prefix']) for p in prefixes)):
                raise ValueError('invalid_miniapp_route')
            prefixes.append(route['prefix'])
    return value


def app_url(value):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 for c in value):
        return False
    try:
        u = urlsplit(value)
        query = parse_qsl(u.query, keep_blank_values=True, strict_parsing=False)
        if (u.scheme != 'https' or u.netloc != 't.me' or u.fragment
                or len({k for k, _ in query}) != len(query)
                or any(k not in ('startapp', 'mode') for k, _ in query)):
            return False
        parts = u.path.strip('/').split('/')
        if not 1 <= len(parts) <= 2 or not re.fullmatch(r'[A-Za-z0-9_]{5,32}', parts[0]):
            return False
        if len(parts) == 2 and not re.fullmatch(r'[A-Za-z0-9_]{3,30}', parts[1]):
            return False
        return (len(parts) == 2 or 'startapp' in dict(query)) and all(
            (v in ('compact', 'fullscreen') if k == 'mode'
             else bool(re.fullmatch(r'[A-Za-z0-9_-]{0,512}', v)))
            for k, v in query)
    except ValueError:
        return False


def owner_app_url(app):
    """Only the configured, qualified owner application is a web launch target."""
    home = app.homemaker_home
    if home and app.designs and app.designs.owner_application:
        return app.homes[home]['public_url'] + '/homemaker/miniapp.html'
    return None


def catalog(app, home, subject, vpn, *, local_only=False):
    # Aggregate only registered members of this home's already-selected public
    # ring. Do not invent membership from labels or forward its private session.
    origins = {peer['url'].rstrip('/') for peer in app.homes[home]['ring']}
    homes = [home] + [ref for ref, row in app.homes.items()
                     if ref != home and row['public_url'].rstrip('/') in origins]
    # Bound fan-out; larger rings retain an explicit partial result.
    selected = homes[:1] if local_only else homes[:16]

    def read(ref):
        try:
            entries = app.entries(ref, subject if ref == home else None,
                                  vpn if ref == home else False, timeout=2)
            return ref, entries, True
        except (ValueError, OSError, TimeoutError, json.JSONDecodeError):
            return ref, [], False

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(read, selected))
    apps, seen, unavailable = [], set(), 0 if local_only else len(homes) - len(selected)
    owner_url = owner_app_url(app)
    for ref, entries, available in results:
        unavailable += not available
        for entry in entries:
            url = entry.get('url')
            owner_app = owner_url is not None and url == owner_url
            if entry.get('kind') != 'link' or not (owner_app or app_url(url)):
                continue
            # Private links are never collapsed into a public author's entry.
            key = (entry['url'], ref)
            if key in seen:
                continue
            seen.add(key)
            apps.append({'id': ref + ':' + entry['artifact_ref'],
                         'title': entry['title'], 'summary': entry.get('summary', ''),
                         'url': entry['url'], 'author': app.homes[ref]['name'],
                         'launch': 'web' if owner_app else 'telegram',
                         'source': app.homes[ref]['public_url'] + '/view/' + entry['artifact_ref'],
                         'version_ref': entry['version_ref']})
            if len(apps) == 256:
                break
        if len(apps) == 256:
            unavailable += 1
            break
    return {'schema': 'dm.miniapp-navigation/v1', 'apps': apps,
            'partial': bool(unavailable), 'unavailable_sources': unavailable}


def page(app, home, subject, vpn):
    from .styles import appearance_css
    source = (ASSETS / 'index.html').read_text()
    routes=json.dumps(getattr(app,'miniapp_routes',validate_launch_routes(None))).replace('&','\\u0026').replace('<','\\u003c').replace('>','\\u003e')
    source=source.replace('</body>','<script id="miniapp-routes" type="application/json">'+routes+'</script></body>')
    value = app.styles.resolved(home, 'apps', subject) if app.styles else {}
    css = appearance_css(value)
    fonts = '<link id="homemaker-font-assets" rel="stylesheet" href="/design-assets/styles/fonts.css">' if css and value.get('font_assets') is True else ''
    source = source.replace('</head>', fonts+'<style>'+css+'</style></head>')
    # Show the current local publications in the first response. Foreign homes
    # are reconciled separately, so one slow peer cannot hold the first screen.
    initial = catalog(app, home, subject, vpn, local_only=True)
    cards = []
    esc = html.escape
    for e in initial['apps']:
        cards.append('<li class="app"><a class="app-link" href="'+esc(e['url'],quote=True)+'">'
                     '<span class="app-icon" aria-hidden="true">↗</span>'
                     '<span class="app-title">'+esc(e['title'])+'</span>'
                     '<span class="app-summary">'+esc(e['summary'])+'</span>'
                     '<span class="app-author">'+esc(e['author'])+' ↗</span></a></li>')
    source = source.replace('<ul id="apps" class="apps" aria-label="Aplicaciones"></ul>',
                            '<ul id="apps" class="apps" aria-label="Aplicaciones">'+''.join(cards)+'</ul>')
    source = source.replace('<span id="count" aria-live="polite"></span>',
                            '<span id="count" aria-live="polite">'+str(len(cards))+'</span>')
    initial_json = json.dumps(initial).replace('&','\\u0026').replace('<','\\u003c').replace('>','\\u003e')
    source = source.replace('</body>', '<script id="initial-apps" type="application/json">'+initial_json+'</script></body>')
    for url, path in (('/apps/launcher.css',ASSETS/'launcher.css'),
                      ('/apps/launcher.js',ASSETS/'launcher.js'),
                      ('/apps/launch.js',ASSETS/'launch.js'),
                      ('/home-style.js',ASSETS.parent/'assets/home-style.js')):
        source = source.replace('"'+url+'"', '"'+url+'?v='+hashlib.sha256(path.read_bytes()).hexdigest()[:16]+'"')
    return source.encode()


def routes(handler, app, path, home, subject, vpn):
    if path == '/apps/':
        if not CAPACITY.acquire(blocking=False):
            handler.respond(503, b'Please retry shortly', 'text/plain', headers=(('Retry-After','1'),))
            return True
        try:
            body = page(app, home, subject, vpn)
        finally:
            CAPACITY.release()
        handler.respond(200,body,'text/html; charset=utf-8',telegram_sdk=True,style_inline=True)
        return True
    if path == '/apps/catalog.json':
        if not CAPACITY.acquire(blocking=False):
            handler.respond(503, {'error': 'catalog_busy'}, headers=(('Retry-After', '3'),))
            return True
        try:
            handler.respond(200, catalog(app, home, subject, vpn))
        finally:
            CAPACITY.release()
        return True
    files = {'/apps/': ('index.html', 'text/html; charset=utf-8'),
             '/apps/launcher.js': ('launcher.js', 'text/javascript; charset=utf-8'),
             '/apps/launch.js': ('launch.js','text/javascript; charset=utf-8'),
             '/apps/launcher.css': ('launcher.css', 'text/css; charset=utf-8')}
    if path not in files:
        return False
    name, kind = files[path]
    from urllib.parse import parse_qs
    body = (ASSETS / name).read_bytes()
    version = hashlib.sha256(body).hexdigest()[:16]
    immutable = parse_qs(urlsplit(handler.path).query) == {'v':[version]}
    handler.respond(200, body, kind,
                    cache_control='public, max-age=31536000, immutable' if immutable else 'public, max-age=0, must-revalidate')
    return True

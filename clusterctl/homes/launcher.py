"""A read-only Mini App client of existing publication and style authorities.

Public Telegram app links published through any selected home's ordinary owner
workflow become shared navigation. Only this home may contribute private links
through its current authorized reader. No launch is a permission grant.
"""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import threading
from urllib.parse import parse_qsl, urlsplit

ASSETS = Path(__file__).parent / 'launcher'
CAPACITY = threading.BoundedSemaphore(4)


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


def catalog(app, home, subject, vpn):
    # Aggregate only registered members of this home's already-selected public
    # ring. Do not invent membership from labels or forward its private session.
    origins = {peer['url'].rstrip('/') for peer in app.homes[home]['ring']}
    homes = [home] + [ref for ref, row in app.homes.items()
                     if ref != home and row['public_url'].rstrip('/') in origins]
    # Bound fan-out; larger rings retain an explicit partial result.
    selected = homes[:16]

    def read(ref):
        try:
            entries = app.entries(ref, subject if ref == home else None,
                                  vpn if ref == home else False, timeout=2)
            return ref, entries, True
        except (ValueError, OSError, TimeoutError, json.JSONDecodeError):
            return ref, [], False

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(read, selected))
    apps, seen, unavailable = [], set(), len(homes) - len(selected)
    for ref, entries, available in results:
        unavailable += not available
        for entry in entries:
            if entry.get('kind') != 'link' or not app_url(entry.get('url')):
                continue
            # Private links are never collapsed into a public author's entry.
            key = (entry['url'], ref)
            if key in seen:
                continue
            seen.add(key)
            apps.append({'id': ref + ':' + entry['artifact_ref'],
                         'title': entry['title'], 'summary': entry.get('summary', ''),
                         'url': entry['url'], 'author': app.homes[ref]['name'],
                         'source': app.homes[ref]['public_url'] + '/view/' + entry['artifact_ref'],
                         'version_ref': entry['version_ref']})
            if len(apps) == 256:
                break
        if len(apps) == 256:
            unavailable += 1
            break
    return {'schema': 'dm.miniapp-navigation/v1', 'apps': apps,
            'partial': bool(unavailable), 'unavailable_sources': unavailable}


def routes(handler, app, path, home, subject, vpn):
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
             '/apps/launcher.css': ('launcher.css', 'text/css; charset=utf-8')}
    if path not in files:
        return False
    name, kind = files[path]
    handler.respond(200, (ASSETS / name).read_bytes(), kind,
                    telegram_sdk=path == '/apps/', style_inline=path == '/apps/')
    return True

"""Published application intent is navigation, never an identity/access grant."""
import re
from urllib.parse import urlsplit


def web_url(url):
    if not isinstance(url, str) or not 1 <= len(url) <= 2048 or any(ord(c) < 33 or c == '\\' for c in url):
        return False
    try:
        parsed = urlsplit(url)
        parsed.port  # Reject malformed/out-of-range ports before publication.
        return bool(parsed.scheme == 'https' and parsed.hostname and not parsed.username
                    and not parsed.password and not parsed.fragment)
    except ValueError:
        return False


def application(entry):
    value = entry.get('application')
    if value is None:
        return None
    if not isinstance(value, dict) or value.get('schema') != 'dm.application/v1':
        raise ValueError('invalid_application_publication')
    mode = value.get('mode')
    required = {'schema', 'mode'} | ({'capability'} if mode == 'paired' else {'dependency'} if mode == 'author' else set())
    if set(value) != required or mode not in ('shared', 'paired', 'author') or entry.get('kind') != 'link' or not web_url(entry.get('url')):
        raise ValueError('invalid_application_publication')
    if mode != 'author' and urlsplit(entry['url']).hostname.lower() == 't.me':
        raise ValueError('shared_application_cannot_require_author_bot')
    if mode == 'paired' and (not isinstance(value['capability'], str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', value['capability'])):
        raise ValueError('invalid_application_capability')
    if mode == 'author' and (not isinstance(value['dependency'], str) or not 1 <= len(value['dependency'].strip()) <= 512):
        raise ValueError('author_application_dependency_required')
    return value


def receiver_routes(value, homes):
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > 64:
        raise ValueError('invalid_application_receivers')
    for home, routes in value.items():
        if home not in homes or not isinstance(routes, dict) or len(routes) > 32:
            raise ValueError('invalid_application_receivers')
        origin = homes[home]['public_url'].rstrip('/')
        for capability, url in routes.items():
            if (not isinstance(capability, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', capability)
                    or not web_url(url) or not url.startswith(origin + '/')
                    or not re.fullmatch(r'/[A-Za-z0-9_-]+/', urlsplit(url).path) or urlsplit(url).query):
                raise ValueError('invalid_application_receiver')
    return value


def paired_receiver(app, home, subject):
    # A verified common login may select a pair even on another author's home.
    # Anonymous visits never infer a pair from the author being visited.
    if subject is not None:
        matches = [ref for ref in app.homes if app.authority.paired_human(ref) == subject.ref]
        return matches[0] if len(matches) == 1 else None
    return None

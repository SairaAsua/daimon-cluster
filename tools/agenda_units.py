"""Stage bounded Agenda units using existing private receiving configuration.

This renders files for operator review. It never installs/restarts services,
copies credentials, changes the gateway or creates an application identity.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import pwd
import re
import stat
from urllib.parse import urlsplit

import yaml


def path_value(value):
    path = Path(value)
    if not path.is_absolute() or any(c.isspace() or c in '%"\\' for c in str(path)):
        raise ValueError('absolute paths without systemd expansion required')
    return path


def private_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError('owner-private regular configuration required')


def units(release, python, config, engine_config, user, group, slice_name=None, private_bind=None):
    release, python, config, engine_config = map(path_value, (release, python, config, engine_config))
    for name in (user, group):
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', name):
            raise ValueError('invalid service user/group')
    if slice_name and not re.fullmatch(r'[A-Za-z0-9_.-]+\.slice', slice_name):
        raise ValueError('invalid slice')
    if not (release/'clusterctl/homes/agenda_remote.py').is_file() or not (release/'engine/vikunja').is_file() or not python.is_file():
        raise ValueError('selected release, engine and Python must exist')
    private_file(config)
    private_file(engine_config)
    app = json.loads(config.read_text())
    engine = yaml.safe_load(engine_config.read_text())
    state, engine_state = path_value(app['state']), path_value(engine['service']['rootpath'])
    if state.parent != engine_state.parent or state.parent == Path('/'):
        raise ValueError('application and engine need separate directories in one private state root')
    if state == engine_state:
        raise ValueError('application and engine state must be separate')
    uid = pwd.getpwnam(user).pw_uid
    for path in (state.parent, state, engine_state):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
            raise ValueError('owner-private application and engine state directories required')
    port = app['port']
    backend = urlsplit(app['backend'])
    if (type(port) is not int or not 1024 <= port <= 65535 or backend.scheme != 'http' or
            backend.hostname != '127.0.0.1' or not backend.port or backend.port == port or
            backend.path or backend.query or backend.fragment or backend.username or backend.password or
            engine['service']['interface'] != f'127.0.0.1:{backend.port}'):
        raise ValueError('distinct exact loopback application/engine ports required')
    private_file(path_value(app['token_file']))
    if app.get('google_client'):
        private_file(path_value(app['google_client']))
    common = f'User={user}\nGroup={group}\nWorkingDirectory={release}\n'
    safety = (f'Environment=PYTHONDONTWRITEBYTECODE=1 GOMAXPROCS=2\n'
              f'Restart=on-failure\nRestartSec=3\nUMask=0077\nNoNewPrivileges=true\n'
              f'PrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\n'
              f'ReadWritePaths={state.parent}\n')
    selected_slice = f'Slice={slice_name}\n' if slice_name else ''
    result = {}
    for kind, description, command, memory, dependency in (
        ('engine', 'engine', f'{release}/engine/vikunja --config {engine_config}', '384M', ''),
        ('application', 'application', f'{python} -B -m clusterctl.homes.agenda_remote --config {config}', '256M',
         'Wants=daimon-agenda-engine.service\nAfter=daimon-agenda-engine.service\n'),
    ):
        result[f'daimon-agenda-{kind}.service'] = (
            f'[Unit]\nDescription=Daimon Agenda {description}\n{dependency}'
            f'StartLimitIntervalSec=120\nStartLimitBurst=4\n[Service]\n{selected_slice}{common}'
            f'ExecStart={command}\n{safety}MemoryMax={memory}\nTasksMax=96\n'
            'StandardOutput=null\nStandardError=null\n[Install]\nWantedBy=multi-user.target\n')
    if private_bind:
        address = ipaddress.IPv4Address(private_bind)
        if (not address.is_private or address.is_loopback or address.is_unspecified or
                address.is_multicast or address.is_reserved):
            raise ValueError('private VPN address required; no wildcard/public listener')
        result['daimon-agenda-private.socket'] = (
            '[Unit]\nDescription=Daimon Agenda private transport listener\n'
            'After=network-online.target\nWants=network-online.target\n'
            f'[Socket]\nListenStream={address}:{port}\nNoDelay=true\n'
            '[Install]\nWantedBy=sockets.target\n')
        result['daimon-agenda-private.service'] = (
            '[Unit]\nDescription=Daimon Agenda private transport proxy\n'
            'Requires=daimon-agenda-application.service\nAfter=daimon-agenda-application.service\n'
            f'[Service]\n{selected_slice}DynamicUser=true\n'
            f'ExecStart=/usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:{port}\n'
            'NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n'
            'MemoryMax=32M\nTasksMax=16\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('release', 'python', 'config', 'engine-config', 'output'):
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--user', required=True)
    parser.add_argument('--group', required=True)
    parser.add_argument('--slice', dest='slice_name')
    parser.add_argument('--private-bind', help='Optional exact VPN IPv4 address; transport token remains required')
    args = parser.parse_args()
    rendered = units(args.release, args.python, args.config, args.engine_config,
                     args.user, args.group, args.slice_name, args.private_bind)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, content in rendered.items():
        path = args.output/name
        if path.is_symlink() or (path.exists() and path.read_text() != content):
            raise ValueError('existing staged unit differs; choose a new output directory')
    for name, content in rendered.items():
        (args.output/name).write_text(content)
    print(json.dumps({'units': {name: hashlib.sha256(value.encode()).hexdigest()
                               for name, value in rendered.items()}, 'installed': False}))


if __name__ == '__main__':
    main()

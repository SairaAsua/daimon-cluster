"""Construct reachable signed metadata for the existing synthetic baseline.

Test input preparation only, not a production route-update API. The caller owns
the offline runtime writer. Preserve every client, key, store and old generation.
"""
from __future__ import annotations

import copy
import fcntl
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from clusterctl import being_seed
from clusterctl.onboarding import digest, private_directory


def addressed(previous: dict, endpoints: dict, *, local_body: str) -> dict:
    """Change only the two old fixture bodies' approved bridge endpoints."""
    from daimon_matrix.messaging_config import validate_shape
    refs = [row['body_ref'] for row in previous['roster']]
    if len(set(refs)) != len(refs) or set(endpoints) != set(refs) or refs.count(local_body) != 1:
        raise ValueError('preserve the exact original baseline roster')
    candidate = copy.deepcopy(previous)
    for row in candidate['roster']:
        before, after = urlsplit(row['route']['endpoint']), urlsplit(endpoints[row['body_ref']])
        if (before.scheme != after.scheme or after.scheme != 'http'
                or before.port != after.port or before.path != after.path
                or before.query or after.query or before.fragment or after.fragment
                or after.username is not None or after.password is not None
                or before.hostname != '127.0.0.1'
                or after.hostname not in {'10.99.227.1', '10.99.227.2'}):
            raise ValueError('only the approved synthetic baseline addresses may change')
        row['route']['endpoint'] = endpoints[row['body_ref']]
    local = urlsplit(endpoints[local_body])
    candidate['intake']['endpoint'] = endpoints[local_body]
    candidate['listen'] = dict(host=local.hostname, port=local.port)
    validate_shape(candidate)
    return candidate


def publish(hosted, directory: Path, *, endpoints: dict, operation: Path,
            expected_application_sha256: str) -> dict:
    """Retain one exact fixture intent before a native signed publication CAS."""
    from daimon_matrix import operator_messaging as native
    from daimon_matrix.canonical import canonical_bytes
    from daimon_matrix.messaging_config import config_digest, create_binding, read_document, read_publication, verify_binding
    if operation.parent.parent != directory.parent:
        raise ValueError('keep fixture recovery beside the original group')
    command = dict(endpoints=endpoints, expected_application_sha256=expected_application_sha256,
        directory=str(directory), runtime_id=hosted.service.runtime_id)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = operation/'intent.json'
        current, metadata = read_publication(hosted, directory)
        publication = read_document(directory/'publication.json')
        if path.exists():
            retained = being_seed._read(path, limit=being_seed.MAX_SELECTION)
            if retained['command'] != command:
                raise ValueError('preserve the original fixture metadata intent')
        else:
            if config_digest(current) != expected_application_sha256:
                raise ValueError('preserve the original fixture publication')
            successor = addressed(current, endpoints, local_body=hosted.service.origin['body_ref'])
            client = read_document(metadata/'client.json')
            if client != dict(schema='dm.local.client-config/v3', capability=current['client']['descriptor'],
                    expected_server=dict(hosted.service.origin), runtime_id=hosted.service.runtime_id,
                    runtime_label=hosted.service.runtime_label):
                raise ValueError('preserve the original native client')
            generation = 'generation-'+digest(command)[:32]
            retained = dict(command=command, before=publication, predecessor=current,
                predecessor_binding=read_document(metadata/'binding.json'),
                client=client, application=successor,
                binding=create_binding(hosted, successor),
                publication=json.loads(native._publication(hosted, successor, generation, config_digest(current))))
            private_directory(operation.parent, create=True)
            private_directory(operation, create=True)
            being_seed._write(path, retained, limit=being_seed.MAX_SELECTION)
        verify_binding(hosted, retained['predecessor'], retained['predecessor_binding'])
        verify_binding(hosted, retained['application'], retained['binding'])
        verify_binding(hosted, retained['before']['body'], retained['before']['binding'])
        verify_binding(hosted, retained['publication']['body'], retained['publication']['binding'])
        if (config_digest(retained['predecessor']) != expected_application_sha256
                or retained['application'] != addressed(retained['predecessor'], endpoints,
                    local_body=hosted.service.origin['body_ref'])
                or publication not in (retained['before'], retained['publication'])):
            raise ValueError('preserve a later or conflicting fixture publication')
        generation = retained['publication']['body']['generation']
        destination = private_directory(directory/generation, create=True)
        for name, value in dict(application=retained['application'], binding=retained['binding'],
                client=retained['client'], predecessor=retained['predecessor'],
                **{'predecessor-binding': retained['predecessor_binding']}).items():
            name += '.json'
            raw = canonical_bytes(value)
            if (destination/name).exists():
                if (destination/name).read_bytes() != raw:
                    raise ValueError('preserve the intended fixture generation')
            else:
                native._write(destination, name, raw)
        native._sync(destination)
        # Complete a previous lost intent fsync acknowledgement before selection.
        native._sync(operation)
        native._sync(operation.parent)
        native._sync(directory.parent)
        if read_document(directory/'publication.json') not in (retained['before'], retained['publication']):
            raise ValueError('preserve a later fixture publication')
        if publication != retained['publication']:
            temporary = '.fixture-network-publication.json'
            raw = canonical_bytes(retained['publication'])
            if (directory/temporary).exists():
                if (directory/temporary).read_bytes() != raw:
                    raise ValueError('preserve the intended fixture publication')
            else:
                native._write(directory, temporary, raw)
            native._sync(directory)
            os.replace(directory/temporary, directory/'publication.json')
        native._sync(directory)
        actual, _ = read_publication(hosted, directory)
        if actual != retained['application']:
            raise ValueError('fixture publication was not observed')
        return dict(application_sha256=config_digest(actual), predecessor_sha256=expected_application_sha256,
            generation=generation, receiving_readiness='unobserved', production_effects=0)
    finally:
        os.close(descriptor)


def select_original_profile(hosted, group: Path, *, original: dict, prepared: dict,
                            operation: Path) -> dict:
    """Keep this baseline readable by its original v1 Cluster loader.

    The new admission publisher chooses v2 only after the old senders stop.
    Initial fixture addressing is not that admission. Preserve the prepared v2
    packet as history rather than silently upgrading the old baseline loader.
    """
    from daimon_matrix import operator_messaging as native
    from daimon_matrix.messaging_config import create_binding, read_publication, verify_binding
    from clusterctl.onboarding_peer import _approved_group, _validate_group_packet
    if original['document']['schema'] != 'cluster-onboarding-group-selection/v1':
        raise ValueError('only the original synthetic v1 baseline is supported')
    if operation.parent.parent != group:
        raise ValueError('keep fixture recovery beside the original group')
    with being_seed._locked(group):
        for packet in (original, prepared):
            verify_binding(hosted, packet['document'], packet['binding'])
        application, _ = read_publication(hosted, group/'application')
        document = {**original['document'], 'application_sha256': digest(application)}
        candidate = dict(document=document, binding=create_binding(hosted, document))
        _validate_group_packet(group,candidate,lambda value,binding:verify_binding(hosted,value,binding))
        intent = dict(original=original, prepared=prepared, candidate=candidate)
        path = operation/'original-profile-selection.json'
        if path.exists():
            if being_seed._read(path, limit=being_seed.MAX_SELECTION) != intent:
                raise ValueError('preserve the original fixture selection intent')
        else:
            being_seed._write(path, intent, limit=being_seed.MAX_SELECTION)
        for parent in (operation, operation.parent, group):
            native._sync(parent)
        selected = group/'selection.json'
        current = being_seed._read(selected, limit=being_seed.MAX_SELECTION)
        if current not in (original, prepared, candidate):
            raise ValueError('preserve a later fixture selector')
        if current != candidate:
            being_seed._write(selected, candidate, limit=being_seed.MAX_SELECTION)
        else:
            native._sync(group)
        actual = _approved_group(group, lambda value, binding: verify_binding(hosted, value, binding))
        if actual != document:
            raise ValueError('original fixture profile was not observed')
        return dict(selection_sha256=digest(candidate), receiving_readiness='unobserved')

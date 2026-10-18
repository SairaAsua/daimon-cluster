"""Close a human-accepted onboarding and retire only duplicate input payloads.

Operator-only, dry-run by default. The worker must be drained by its existing
scoped preservation control before apply. No body, harness or authority changes.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import stat
import time
from pathlib import Path

from clusterctl import being_seed, onboarding_input
from clusterctl.onboarding import ACCEPTANCE, STAGES, JobStore, OnboardingError, digest
from clusterctl.onboarding_progress import Progress


def checksum(path: Path) -> str:
    being_seed._path(path)
    result = hashlib.sha256()
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077:
            raise OnboardingError('private_closeout_file_required')
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
        after = os.fstat(stream.fileno())
    if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise OnboardingError('closeout_input_changed')
    return result.hexdigest()


def tree_state(path: Path) -> str:
    return digest(onboarding_input.VerificationCache.snapshot(path))


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def unused_payload(path: Path) -> None:
    rows = onboarding_input.VerificationCache.snapshot(path)
    identities = {(row[1], row[2]) for row in rows}
    if any(row[1] != path.stat().st_dev for row in rows):
        raise OnboardingError('mounted_onboarding_payload_preserved')
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            references = [proc / 'cwd', proc / 'exe', *list((proc / 'fd').iterdir())]
            for line in (proc / 'maps').read_text().splitlines():
                fields = line.split(None, 5)
                if len(fields) == 6 and fields[5].startswith('/'):
                    references.append(proc / 'root' / fields[5].removesuffix(' (deleted)').lstrip('/'))
            for reference in references:
                try:
                    info = reference.stat()
                except FileNotFoundError:
                    continue
                if (info.st_dev, info.st_ino) in identities:
                    raise OnboardingError('active_onboarding_payload_preserved')
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            raise OnboardingError('onboarding_activity_observation_required') from None


def prepare(config, name: str, archive: Path, human_reference: str) -> dict:
    if not human_reference or len(human_reference) > 512:
        raise OnboardingError('explicit_human_acceptance_required')
    store = JobStore(config.jobs)
    job = store._load(name)
    if any(job['steps'][stage]['state'] != 'complete' for stage in STAGES[:-1]):
        raise OnboardingError('onboarding_earlier_stage_incomplete')
    if job['stage'] != 'acceptance':
        raise OnboardingError('onboarding_acceptance_stage_required')
    plan = job['plan']
    source = config.inputs / name
    manifest = onboarding_input.verify(source, plan['seed_digest'])
    view = config.views / digest(plan) / 'input'
    view_manifest = onboarding_input.verify(view, plan['seed_digest'], uid=view.stat().st_uid)
    if manifest != view_manifest or checksum(archive) != manifest['archive_sha256']:
        raise OnboardingError('retained_original_archive_required')
    if archive.stat().st_dev == source.stat().st_dev:
        raise OnboardingError('original_archive_on_data_volume_required')
    roots = [source / 'received', view / 'received']
    if any(archive.is_relative_to(path) for path in roots):
        raise OnboardingError('retained_original_archive_required')
    result = dict(schema='cluster-onboarding-closeout/v1', name=name,
        owner=plan['owner'], plan_digest=digest(plan), human_reference=human_reference,
        evidence_source='explicit-human-acceptance', before=job,
        archive=dict(path=str(archive), sha256=manifest['archive_sha256']),
        manifests=[dict(path=str(root / 'manifest.json'), sha256=checksum(root / 'manifest.json'))
                   for root in (source, view)],
        payloads=[dict(path=str(path), uid=path.stat().st_uid,
            device=path.stat().st_dev, inode=path.stat().st_ino, state=tree_state(path))
            for path in roots])
    result['operation_digest'] = digest(result)
    return result


def validate_binding(config, value: dict) -> None:
    raw = {key: item for key, item in value.items() if key != 'operation_digest'}
    if value.get('schema') != 'cluster-onboarding-closeout/v1' or digest(raw) != value['operation_digest']:
        raise OnboardingError('closeout_plan_changed')
    plan = value['before']['plan']
    if (value['name'] != plan['name'] or value['owner'] != plan['owner']
            or value['plan_digest'] != digest(plan)
            or value['evidence_source'] != 'explicit-human-acceptance'
            or not value['human_reference']):
        raise OnboardingError('closeout_binding_changed')
    roots = [config.inputs / plan['name'], config.views / digest(plan) / 'input']
    if ([row['path'] for row in value['payloads']] != [str(root / 'received') for root in roots]
            or [row['path'] for row in value['manifests']] != [str(root / 'manifest.json') for root in roots]):
        raise OnboardingError('closeout_binding_changed')


def same_job(left: dict, right: dict) -> bool:
    # An unchanged failed observation refreshes updated_ms every worker tick.
    # It cannot authorize different steps, facts, plans or acceptance effects.
    return ({key: value for key, value in left.items() if key != 'updated_ms'}
            == {key: value for key, value in right.items() if key != 'updated_ms'})


def apply(config, value: dict, receipt: Path, *, worker_inactive: bool) -> dict:
    validate_binding(config, value)
    if not worker_inactive:
        raise OnboardingError('onboarding_worker_drain_required')
    # Resume only this exact operation; an existing receipt is never overwritten
    # by a new request. Original archive and metadata remain separately retained.
    previous = being_seed._read(receipt) if receipt.exists() else None
    if previous is not None and previous['operation_digest'] != value['operation_digest']:
        raise OnboardingError('existing_closeout_preserved')
    if checksum(Path(value['archive']['path'])) != value['archive']['sha256']:
        raise OnboardingError('retained_original_archive_required')
    for row in value['manifests']:
        if checksum(Path(row['path'])) != row['sha256']:
            raise OnboardingError('closeout_manifest_changed')
    store = JobStore(config.jobs)
    with being_seed._locked(store.directory(value['name'])):
        job = store._load(value['name'])
        if previous is None:
            if not same_job(job, value['before']):
                raise OnboardingError('closeout_job_changed')
            for row in value['payloads']:
                if tree_state(Path(row['path'])) != row['state']:
                    raise OnboardingError('closeout_input_changed')
                unused_payload(Path(row['path']))
            previous = dict(operation_digest=value['operation_digest'], phase='prepared',
                            human_acceptance=value, observed_before=job, removed=[])
            being_seed._write(receipt, previous)
        if not same_job(job, value['before']):
            expected = previous.get('after')
            if job != expected:
                raise OnboardingError('closeout_job_changed')
        else:
            completed = copy.deepcopy(job)
            facts = dict(verified=True, **dict.fromkeys(ACCEPTANCE, True))
            if job['plan']['browser']:
                facts['browser_verified'] = True
            now = int(time.time() * 1000)
            completed['steps']['acceptance'].update(state='complete', facts=facts, completed_ms=now)
            completed.update(state='complete', stage=None, reason=None)
            # Publish the intended accepted state before its atomic commit.
            # Facts are human-attested here, not invented automatic test results;
            # the original hosted-checks and job preimage remain in the receipt.
            completed['updated_ms'] = now
            previous.update(after=completed, phase='accepting')
            being_seed._write(receipt, previous)
            being_seed._write(store.directory(value['name']) / 'job.json', completed)
            store._load(value['name'])
        Progress(config.progress, worker_uid=os.geteuid()).publish(store.project(store._load(value['name'])))
        previous['phase'] = 'accepted'
        being_seed._write(receipt, previous)
        for row in value['payloads']:
            path = Path(row['path'])
            held = path.with_name(path.name + '.closeout-' + value['operation_digest'][:16])
            if row['path'] in previous['removed']:
                if path.exists() or held.exists():
                    raise OnboardingError('retired_onboarding_payload_reappeared')
                continue
            if path.exists():
                if held.exists() or tree_state(path) != row['state']:
                    raise OnboardingError('closeout_input_changed')
                unused_payload(path)
                path.rename(held)
                sync_directory(path.parent)
            if held.exists():
                info = held.lstat()
                if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (row['device'], row['inode']):
                    raise OnboardingError('closeout_payload_changed')
                shutil.rmtree(held)
                sync_directory(path.parent)
            previous['removed'].append(row['path'])
            being_seed._write(receipt, previous)
        previous['phase'] = 'retired'
        being_seed._write(receipt, previous)
    return dict(state='complete', retirement='retired', operation_digest=value['operation_digest'])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--name')
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--human-reference')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args(argv)
    from clusterctl.onboarding_host import HostConfig
    config = HostConfig.load(args.config)
    if args.apply:
        import subprocess
        result = subprocess.run(['systemctl', 'is-active', 'daimon-onboarding-worker.service'],
            capture_output=True, text=True, check=False)
        if args.receipt is None:
            parser.error('--receipt is required for apply')
        result_value = apply(config, being_seed._read(args.plan), args.receipt,
            worker_inactive=result.returncode == 3 and result.stdout.strip() == 'inactive')
    else:
        if not args.name or args.archive is None or not args.human_reference:
            parser.error('preparation requires name, archive and human reference')
        result_value = prepare(config, args.name, args.archive, args.human_reference)
        if args.plan.exists() and being_seed._read(args.plan) != result_value:
            raise OnboardingError('existing_closeout_preserved')
        being_seed._write(args.plan, result_value)
    print(json.dumps({key: item for key, item in result_value.items()
                      if key in ('operation_digest', 'state', 'retirement')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

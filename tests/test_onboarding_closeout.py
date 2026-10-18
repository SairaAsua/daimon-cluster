"""Real input retirement keeps the accepted receiver and original export intact."""
import copy
import json
import os
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl import being_seed, onboarding, onboarding_input
from tests.test_onboarding import FixtureBackend, plan
from tools import close_completed_onboarding as closeout


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    if not Path('/dev/shm').is_dir() or Path('/dev/shm').stat().st_dev == tmp_path.stat().st_dev:
        pytest.skip('a separate small archive filesystem is required')
    config = SimpleNamespace(inputs=tmp_path / 'inputs', views=tmp_path / 'views',
                             jobs=tmp_path / 'jobs', progress=tmp_path / 'progress')
    config.progress.mkdir(mode=0o700)
    source = config.inputs / 'eko'
    received = source / 'received'
    received.mkdir(parents=True, mode=0o700)
    source.chmod(0o700)
    (received / 'source.archive').write_bytes(b'complete-original-history')
    (received / 'source.archive').chmod(0o600)
    (received / 'original-memory').write_bytes(b'memory to be installed')
    (received / 'original-memory').chmod(0o600)
    manifest = dict(schema=onboarding_input.SCHEMA,
                    archive_sha256=closeout.checksum(received / 'source.archive'),
                    files=onboarding_input.inventory(received, uid=os.geteuid()))
    being_seed._write(source / 'manifest.json', manifest)
    request = plan(browser=False)
    request['seed_digest'] = onboarding.digest(manifest)
    store = onboarding.JobStore(config.jobs)
    backend = FixtureBackend()
    store.submit(request, backend)
    for _ in range(7):
        store.tick('eko', backend)
    backend.wait = 'acceptance'
    store.tick('eko', backend)
    view = config.views / onboarding.digest(request) / 'input'
    shutil.copytree(source, view)
    being_seed._write(view / 'plan.json', request)
    monkeypatch.setattr(closeout, 'unused_payload', lambda path: None)
    with tempfile.TemporaryDirectory(dir='/dev/shm', prefix='closeout-') as directory:
        archive = Path(directory) / 'source.archive'
        shutil.copyfile(received / 'source.archive', archive)
        archive.chmod(0o600)
        value = closeout.prepare(config, 'eko', archive, 'human:existing-operational-acceptance')
        yield config, store, backend, value, tmp_path / 'receipt.json', view, archive


def test_closeout_preserves_original_and_runtime_metadata_and_is_idempotent(prepared):
    config, store, backend, value, receipt, view, archive = prepared
    original_calls = list(backend.calls)
    closeout.apply(config, value, receipt, worker_inactive=True)
    assert store.status('eko', owner='sai')['state'] == 'complete'
    assert not (config.inputs / 'eko/received').exists()
    assert not (view / 'received').exists()
    assert json.loads((view / 'plan.json').read_text()) == value['before']['plan']
    assert archive.read_bytes() == b'complete-original-history'
    assert (view / 'manifest.json').exists()
    closeout.apply(config, value, receipt, worker_inactive=True)
    store.tick('eko', backend)
    assert backend.calls == original_calls
    retained = json.loads(receipt.read_text())
    assert retained['human_acceptance']['evidence_source'] == 'explicit-human-acceptance'
    assert retained['human_acceptance']['before']['steps']['acceptance']['state'] == 'pending'


@pytest.mark.parametrize('conflict', ['active-worker', 'archive', 'input', 'job', 'manifest'])
def test_changed_dependencies_refuse_before_acceptance_or_deletion(prepared, conflict):
    config, store, _, value, receipt, view, archive = prepared
    if conflict == 'archive':
        archive.write_bytes(b'not the original')
    elif conflict == 'input':
        (view / 'received/new').write_bytes(b'new work')
    elif conflict == 'job':
        job = store._load('eko')
        job['reason'] = 'backend_unavailable'
        being_seed._write(store.directory('eko') / 'job.json', job)
    elif conflict == 'manifest':
        (view / 'manifest.json').write_bytes(b'changed')
    with pytest.raises(onboarding.OnboardingError):
        closeout.apply(config, value, receipt, worker_inactive=conflict != 'active-worker')
    assert store._load('eko')['state'] != 'complete'
    assert (view / 'received').is_dir()
    assert (config.inputs / 'eko/received').is_dir()


def test_interrupted_retirement_resumes_same_accepted_job(prepared, monkeypatch):
    config, store, _, value, receipt, view, archive = prepared
    actual = closeout.shutil.rmtree
    def interrupted(path):
        raise InterruptedError('fictional lost retirement result')
    monkeypatch.setattr(closeout.shutil, 'rmtree', interrupted)
    with pytest.raises(InterruptedError):
        closeout.apply(config, value, receipt, worker_inactive=True)
    accepted = copy.deepcopy(store._load('eko'))
    monkeypatch.setattr(closeout.shutil, 'rmtree', actual)
    closeout.apply(config, value, receipt, worker_inactive=True)
    assert store._load('eko') == accepted
    assert not (view / 'received').exists() and archive.is_file()


def test_scope_cannot_be_retargeted_to_other_state(prepared):
    config, _, _, value, receipt, _, _ = prepared
    value['payloads'][0]['path'] = str(config.jobs)
    value['operation_digest'] = onboarding.digest({k: v for k, v in value.items() if k != 'operation_digest'})
    with pytest.raises(onboarding.OnboardingError, match='closeout_binding_changed'):
        closeout.apply(config, value, receipt, worker_inactive=True)


def test_unchanged_worker_observation_does_not_invalidate_acceptance(prepared):
    config, store, _, value, receipt, _, _ = prepared
    job = store._load('eko')
    job['updated_ms'] += 1
    being_seed._write(store.directory('eko') / 'job.json', job)
    closeout.apply(config, value, receipt, worker_inactive=True)
    assert json.loads(receipt.read_text())['observed_before'] == job

"""Retained host selection fences jobs and refreshes warm worker backends."""
import os
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

import pytest

from clusterctl import being_seed, onboarding_receiving_update as updates
from clusterctl.onboarding import JobStore, OnboardingError, digest
from clusterctl.onboarding_code_successor import build, plan_update
from clusterctl.onboarding_host import CurrentHostConfig, HostConfig
from clusterctl.operation_journal import JournalConflict, OperationJournal
from tests.test_onboarding import FixtureBackend, advance, plan
from tests.test_onboarding_code_successor import fixture as code_fixture


def fixture(tmp_path):
    base, checksum, source, _ = code_fixture(tmp_path)
    output = tmp_path / 'successor'
    selected = build(base, checksum, source, ('onboarding_target.py',), output)
    original = dict(schema='cluster-onboarding-host/v1', code=str(base),
        release_digest=checksum, native_image='3'*64, browser_image='4'*64,
        pool='daimon-cluster', profile='daimon-agent', concurrency=1)
    for key in ('jobs', 'grants', 'inputs', 'views', 'progress'):
        directory = tmp_path / key
        directory.mkdir(mode=0o700)
        original[key] = str(directory)
    path = tmp_path / 'host.json'
    being_seed._write(path, original)
    HostConfig.load(path)
    runtime = dict(runtime_code=str(output), runtime_digest=selected['runtime_digest'])
    journal = OperationJournal(tmp_path / 'journal')
    row = plan_update(journal, manifest_digest='a'*64, target='receiving:fixture',
        expected_precondition=dict(host_config=str(path), host_configuration=original,
                                   host_config_sha256=digest(original)),
        intended_transition=dict(host_runtime=runtime), audit_identity={'actor': 'fixture'})
    return path, original, runtime, journal, row['operation_id']


def test_actual_selection_refreshes_warm_worker_and_retains_exact_journal(tmp_path):
    path, original, runtime, journal, identifier = fixture(tmp_path)
    warm = CurrentHostConfig(path)
    previous = warm.current()
    result = updates.apply_host_selection(journal, identifier, path)
    assert result['selected'] and result['receiving_readiness'] == 'unobserved'
    assert being_seed._read(path) == {**original, **runtime}
    selected = warm.current()
    assert selected.runtime_code is not None and previous.runtime_code is None
    assert selected.jobs == previous.jobs and selected.code == previous.code
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(config is selected for config in pool.map(lambda _: warm.current(), range(8)))
    assert updates.apply_host_selection(journal, identifier, path) == result
    row = journal.get(identifier)
    assert row['state'] == 'runtime-dispatching'
    assert row['runtime_observation'] == {'host_selection': result}
    assert len(journal.list_all()) == 1
    assert path.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob('.receiving-selection-*'))


def test_atomic_replace_before_ack_is_reconciled_without_replacement(tmp_path, monkeypatch):
    path, original, runtime, journal, identifier = fixture(tmp_path)
    replace = os.replace
    calls = []
    def lost_ack(source, target):
        replace(source, target)
        if target == path:
            calls.append(target)
            raise OSError('fixture lost ACK after actual replacement')
    monkeypatch.setattr(updates.os, 'replace', lost_ack)
    with pytest.raises(OSError):
        updates.apply_host_selection(journal, identifier, path)
    assert being_seed._read(path) == {**original, **runtime}
    assert journal.get(identifier)['state'] == 'runtime-dispatching'
    assert journal.get(identifier)['runtime_observation'] is None
    assert updates.apply_host_selection(journal, identifier, path)['selected']
    assert calls == [path]


@pytest.mark.parametrize('scope', ['parent', 'job'])
def test_selection_cannot_cross_an_owned_submit_or_tick(tmp_path, scope):
    path, original, _, journal, identifier = fixture(tmp_path)
    store = JobStore(HostConfig.load(path).jobs)
    backend = FixtureBackend()
    store.submit(plan(), backend)
    directory = store.root if scope == 'parent' else store.directory('eko')
    with being_seed._locked(directory):
        with pytest.raises(being_seed.SeedError, match='seed_operation_in_progress'):
            updates.apply_host_selection(journal, identifier, path)
        assert being_seed._read(path) == original
        assert journal.get(identifier)['state'] == 'planned'
    assert updates.apply_host_selection(journal, identifier, path)['selected']


def test_stale_update_preserves_a_newly_registered_receivers_selection(tmp_path):
    path, original, runtime, journal, identifier = fixture(tmp_path)
    concurrent = {**original, 'runtime_by_name': {'future-member': runtime}}
    being_seed._write(path, concurrent)
    HostConfig.load(path)
    with pytest.raises(JournalConflict, match='advanced beyond'):
        updates.apply_host_selection(journal, identifier, path)
    assert being_seed._read(path) == concurrent
    assert journal.get(identifier)['state'] == 'planned'


def test_invalid_candidate_is_refused_before_selector_or_journal_effect(tmp_path):
    path, original, runtime, journal, identifier = fixture(tmp_path)
    # Mutating a sealed artifact does not make its candidate a qualified one.
    from pathlib import Path
    (Path(runtime['runtime_code']) / 'clusterctl/onboarding_target.py').write_bytes(b'corrupted')
    with pytest.raises(OnboardingError):
        updates.apply_host_selection(journal, identifier, path)
    assert being_seed._read(path) == original
    assert journal.get(identifier)['state'] == 'planned'
    assert not list(tmp_path.glob('.receiving-selection-*'))


@pytest.mark.parametrize('state', ['degraded', 'compensated', 'completed'])
def test_advanced_or_abandoned_operation_cannot_reapply_absent_effect(tmp_path, state):
    path, original, _, journal, identifier = fixture(tmp_path)
    journal.advance(identifier, state)
    with pytest.raises((OnboardingError, JournalConflict)):
        updates.apply_host_selection(journal, identifier, path)
    assert being_seed._read(path) == original
    assert journal.get(identifier)['state'] == state


def test_concurrent_journal_evidence_is_preserved_then_retry_merges(tmp_path, monkeypatch):
    path, _, _, journal, identifier = fixture(tmp_path)
    advance_row = journal.advance
    once = True
    def concurrent(operation_id, state, **kwargs):
        nonlocal once
        if once and 'expected_runtime_observation' in kwargs:
            once = False
            advance_row(operation_id, state, runtime_observation={'sdk': {'prepared': True}})
        return advance_row(operation_id, state, **kwargs)
    monkeypatch.setattr(journal, 'advance', concurrent)
    with pytest.raises(JournalConflict, match='observation changed'):
        updates.apply_host_selection(journal, identifier, path)
    assert journal.get(identifier)['runtime_observation'] == {'sdk': {'prepared': True}}
    before = path.stat()
    result = updates.apply_host_selection(journal, identifier, path)
    assert path.stat().st_ino == before.st_ino
    assert journal.get(identifier)['runtime_observation'] == {
        'sdk': {'prepared': True}, 'host_selection': result}


def test_warm_worker_refuses_private_root_or_nonruntime_configuration_changes(tmp_path):
    path, original, runtime, _, _ = fixture(tmp_path)
    warm = CurrentHostConfig(path)
    being_seed._write(path, {**original, **runtime, 'concurrency': 2})
    with pytest.raises(OnboardingError, match='configuration_restart_required'):
        warm.current()
    being_seed._write(path, original)
    assert warm.current().concurrency == 1


def test_factory_is_resolved_inside_job_lock_and_complete_job_never_calls_it(tmp_path):
    store = JobStore(tmp_path / 'jobs')
    backend = FixtureBackend()
    store.submit(plan(), backend)
    calls = []
    def current():
        with pytest.raises(being_seed.SeedError, match='seed_operation_in_progress'):
            with being_seed._locked(store.directory('eko')):
                pytest.fail('backend resolved before owning the job')
        calls.append('fresh')
        return backend
    assert store.tick('eko', current)['completed_steps'] == ['environment']
    assert calls == ['fresh']
    advance(store, backend)
    assert store.tick('eko', lambda: pytest.fail('completed job resolved a backend'))['active']


def test_submit_reauthorizes_current_backend_inside_parent_lock(tmp_path):
    store = JobStore(tmp_path / 'jobs')
    first, latest = FixtureBackend(), FixtureBackend()
    latest.granted = False
    choices = iter((first, latest))
    with pytest.raises(OnboardingError, match='host_authorization_required'):
        store.submit(plan(), lambda: next(choices))
    assert not store.directory('eko').exists()


@pytest.mark.parametrize('during_init', [False, True])
def test_configuration_changed_while_loading_is_not_cached(tmp_path, monkeypatch, during_init):
    path, original, runtime, _, _ = fixture(tmp_path)
    warm = None if during_init else CurrentHostConfig(path)
    if not during_init:
        being_seed._write(path, {**original, **runtime})
    load = HostConfig.load
    def changed(target, **kwargs):
        result = load(target, **kwargs)
        being_seed._write(target, {**original, 'concurrency': 2})
        return result
    monkeypatch.setattr(HostConfig, 'load', changed)
    with pytest.raises(OnboardingError, match='configuration_changed'):
        CurrentHostConfig(path) if during_init else warm.current()


@pytest.mark.parametrize('state', ['degraded', 'compensated', 'completed'])
def test_abandonment_or_advance_cannot_cross_owned_config_validation(tmp_path, monkeypatch, state):
    path, _, _, journal, identifier = fixture(tmp_path)
    competitor = OperationJournal(path.parent / 'journal')
    load = HostConfig.load
    calls = []
    def competing(target, **kwargs):
        with pytest.raises(JournalConflict, match='mutation is in progress'):
            competitor.advance(identifier, state)
        calls.append(state)
        return load(target, **kwargs)
    monkeypatch.setattr(HostConfig, 'load', competing)
    assert updates.apply_host_selection(journal, identifier, path)['selected']
    assert calls == [state] and journal.get(identifier)['state'] == 'runtime-dispatching'
    competitor.advance(identifier, state)
    assert journal.get(identifier)['state'] == state


@pytest.mark.parametrize('during_init', [False, True])
def test_loader_binds_its_own_protected_read_despite_aba_change(tmp_path, monkeypatch, during_init):
    path, original, runtime, _, _ = fixture(tmp_path)
    warm = None if during_init else CurrentHostConfig(path)
    value = original if during_init else {**original, **runtime}
    being_seed._write(path, value)
    read = being_seed._read
    calls = 0
    def aba(target, **kwargs):
        nonlocal calls
        result = read(target, **kwargs)
        if target == path:
            calls += 1
            if calls == 2:
                return {**result, 'concurrency': 2}
        return result
    monkeypatch.setattr(being_seed, '_read', aba)
    with pytest.raises(OnboardingError, match='configuration_changed'):
        CurrentHostConfig(path) if during_init else warm.current()


def test_home_provider_resolves_current_backend_inside_the_same_job_lock(tmp_path, monkeypatch):
    from clusterctl.onboarding_homes import IncusProvider
    store = JobStore(tmp_path / 'jobs')
    backend = FixtureBackend()
    store.submit(plan(), backend)
    selected = []
    def current():
        with pytest.raises(being_seed.SeedError, match='seed_operation_in_progress'):
            with being_seed._locked(store.directory('eko')):
                pytest.fail('home backend resolved without job ownership')
        selected.append(backend)
        return backend
    def observed(provider, placement):
        assert provider.backend is backend
        return {'verified': True}
    monkeypatch.setattr(IncusProvider, '_reconcile', observed)
    provider = IncusProvider(store, current)
    with being_seed._locked(store.directory('eko')):
        with pytest.raises(being_seed.SeedError, match='seed_operation_in_progress'):
            provider.reconcile({'name': 'eko'})
        assert selected == []
    assert provider.reconcile({'name': 'eko'}) == {'verified': True}
    assert selected == [backend]


def _forked_advance(journal, identifier, result):
    try:
        journal.advance(identifier, 'compensated')
        result.put('bypassed')
    except JournalConflict:
        result.put('owned')


def test_fork_inheriting_journal_cannot_bypass_parent_mutation_ownership(tmp_path):
    _, _, _, journal, identifier = fixture(tmp_path)
    context = multiprocessing.get_context('fork')
    result = context.Queue()
    with journal.mutation_lock(identifier):
        child = context.Process(target=_forked_advance, args=(journal, identifier, result))
        child.start()
        try:
            assert result.get(timeout=5) == 'owned'
            child.join(5)
            assert not child.is_alive() and child.exitcode == 0
        finally:
            if child.is_alive():
                child.terminate()
                child.join(5)
            result.close()
    journal.advance(identifier, 'compensated')
    assert journal.get(identifier)['state'] == 'compensated'

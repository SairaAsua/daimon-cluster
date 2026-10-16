"""Actual qualified reader process and immutable offline generation preparation."""
import copy
import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

from clusterctl import onboarding_release, onboarding_sdk
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_receiving_update import preflight, prepare_sdk
from tests.test_onboarding_sdk import fixture as sdk_fixture

CONTRACT = Path(__file__).parent / 'fixtures/receiving_reader'
REVISION = 'b' * 40
BEING = 'dm:being:v1:synthetic'
BODY = 'embodiment:synthetic'


def manifest_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def fixture(tmp_path, *, reader=True):
    code, _, home = sdk_fixture(tmp_path)
    marker = tmp_path / 'unexpected-startup'
    hook = 'from pathlib import Path; Path(' + repr(str(marker)) + ').write_text("executed")\n'
    wheel = next((code / 'sdk/wheels').glob('*.whl'))
    # Keep the qualified contract bytes attributed to their actual source. The
    # deliberately hostile package/startup members must never execute in preflight.
    provenance = json.loads((CONTRACT / 'PROVENANCE.json').read_text())
    with zipfile.ZipFile(wheel, 'a') as archive:
        if reader:
            for row in provenance['files']:
                raw = (CONTRACT / row['path']).read_bytes()
                assert hashlib.sha256(raw).hexdigest() == row['sha256']
                archive.writestr('daimon_matrix/' + row['path'], raw)
        archive.writestr('hostile.pth', hook)
        archive.writestr('sitecustomize.py', hook)
        archive.writestr('daimon_matrix/startup.py', hook)
    # Existing __init__ is harmless in the install fixture; reader isolation also
    # has a separate malicious-__init__ regression below.
    sdk = json.loads((code / 'sdk/sdk.json').read_bytes())
    sdk['matrix_commit'] = REVISION
    sdk['wheels'] = [onboarding_sdk.wheel(wheel, uid=os.geteuid())]
    (code / 'sdk/sdk.json').write_text(json.dumps(sdk))
    (code / 'sdk/requirements.txt').write_bytes(onboarding_sdk.requirement_lines(sdk['wheels']))
    profile = json.loads((code / 'release.json').read_bytes())['profile']
    (code / 'release.json').unlink()
    code_digest = onboarding_release.seal(code, profile)
    authority = dict(being_ref=BEING, control_head='dm:control:v1:synthetic', manifest_hash='1' * 64)
    # The candidate's actual descriptor is probed by the production helper. This
    # minimum requirement allows stronger support without claiming live load.
    contract = dict(profile='membership-group/v1',
        interpreter=dict(implementation=sys.implementation.name, version=list(sys.version_info[:3])),
        wire_read=['dm.tribe.conversation/v1'], wire_write=['dm.tribe.conversation/v1'],
        store_versions={'communication': [4]}, capabilities=['per-receiver-artifacts/v1'],
        pending_inspection=['dm.tribe.delivery/v1'], pending_transmission='original-binding-unexpired')
    manifest = dict(schema='dm.receiving-release/v1',
        artifacts={'matrix_sdk': sdk['wheels'][0]['sha256']},
        provenance=dict(matrix_revision=REVISION, qualification_sha256='2' * 64), contract=contract,
        authorities=dict(current=[authority], candidate=[copy.deepcopy(authority)]),
        required_receivers=[dict(being_ref=BEING, embodiment_id=BODY,
            expected_selection_sha256='3' * 64, artifacts=dict(receiving_code=code_digest))])
    path = tmp_path / 'receiving-manifest.json'
    path.write_text(json.dumps(manifest))
    path.chmod(0o644)
    return code, code_digest, home, path, manifest, marker


def call(code, code_digest, path, manifest, *, prepare=False, home=None, **changes):
    args = dict(being_ref=BEING, embodiment_id=BODY, code_uid=os.geteuid(), manifest_uid=os.geteuid())
    args.update(changes)
    if prepare:
        return prepare_sdk(home, code, code_digest, path, manifest_digest(manifest), **args)
    return preflight(code, code_digest, path, manifest_digest(manifest), **args)


def test_preflight_uses_exact_qualified_reader_without_claiming_loaded_readiness(tmp_path):
    code, checksum, home, path, manifest, marker = fixture(tmp_path)
    result = call(code, checksum, path, manifest)
    assert result['assessment']['compatible'] is True
    assert result['receiving_readiness'] == result['assessment']['receiving_readiness'] == 'unobserved'
    assert result['artifacts']['receiving_code'] == checksum
    assert result['matrix_revision'] == REVISION
    assert not marker.exists() and list(home.iterdir()) == []
    assert 'installation' not in result and 'prepared' not in result


def test_prepare_retries_actual_offline_sdk_without_changing_native_state(tmp_path, monkeypatch):
    code, checksum, home, path, manifest, marker = fixture(tmp_path)
    for name in ('.codex/auth.json', '.codex/native-session.json', 'matrix/state.sqlite3'):
        p = home / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b'Existing private receiving state; preserve exactly.')
    before = {p: p.read_bytes() for p in home.rglob('*') if p.is_file()}
    first = call(code, checksum, path, manifest, prepare=True, home=home)
    second = call(code, checksum, path, manifest, prepare=True, home=home)
    with monkeypatch.context() as observation:
        observation.setattr(onboarding_sdk, 'install', lambda *a, **k: pytest.fail('installed-only installed an SDK'))
        assert call(code, checksum, path, manifest, prepare=True, home=home, installed_only=True) == first
    assert first == second and first['prepared'] is True
    assert first['installation']['matrix_commit'] == REVISION
    assert first['installation']['sdk_digest'] == first['sdk_digest']
    assert first['receiving_readiness'] == 'unobserved'
    assert all(p.read_bytes() == raw for p, raw in before.items())
    assert len(list(home.rglob('installation.json'))) == 1 and not marker.exists()


def test_new_revision_requires_exact_wheel_selection_not_a_commit_label(tmp_path):
    code, _, _, _, manifest, _ = fixture(tmp_path)
    with pytest.raises(OnboardingError, match='invalid_onboarding_sdk'):
        onboarding_sdk.verify(code, uid=os.geteuid(), matrix_commit=REVISION)
    for checksum in ('invalid', '0' * 64):
        with pytest.raises(OnboardingError):
            onboarding_sdk.verify(code, uid=os.geteuid(), matrix_commit=REVISION, matrix_wheel_sha256=checksum)
    assert onboarding_sdk.verify(code, uid=os.geteuid(), matrix_commit=REVISION,
        matrix_wheel_sha256=manifest['artifacts']['matrix_sdk'])['matrix_commit'] == REVISION


def test_completed_generation_with_other_interpreter_is_not_reported_prepared(tmp_path, monkeypatch):
    code, checksum, home, path, manifest, _ = fixture(tmp_path)
    call(code, checksum, path, manifest, prepare=True, home=home)
    receipt = next(home.rglob('installation.json'))
    original_receipt = receipt.read_bytes()
    original_module = next(home.glob('.local/share/daimon-matrix/sdk/*/venv/lib/python*/site-packages/daimon_matrix/canonical.py'))
    original_bytes = original_module.read_bytes()
    actual_interpreter = onboarding_sdk.interpreter
    probes = []
    def different_generation_interpreter(venv, **kwargs):
        probes.append(venv)
        observed = copy.deepcopy(actual_interpreter(venv, **kwargs))
        observed['version'][2] += 1
        return observed
    monkeypatch.setattr(onboarding_sdk, 'interpreter', different_generation_interpreter)
    with pytest.raises(OnboardingError, match='incompatible_receiving_interpreter'):
        call(code, checksum, path, manifest, prepare=True, home=home)
    assert probes == [receipt.parent / 'venv']
    assert receipt.read_bytes() == original_receipt and original_module.read_bytes() == original_bytes


@pytest.mark.parametrize('change', ['receiver', 'code', 'wheel', 'revision', 'contract'])
def test_incompatible_or_wrong_frozen_receiver_cannot_prepare_a_generation(tmp_path, change):
    code, checksum, home, path, manifest, marker = fixture(tmp_path)
    if change == 'receiver':
        manifest['required_receivers'][0]['embodiment_id'] = 'embodiment:other'
    elif change == 'code':
        manifest['required_receivers'][0]['artifacts']['receiving_code'] = '4' * 64
    elif change == 'wheel':
        manifest['artifacts']['matrix_sdk'] = '4' * 64
    elif change == 'revision':
        manifest['provenance']['matrix_revision'] = 'c' * 40
    else:
        manifest['contract']['capabilities'] = ['unsupported/v1']
    path.write_text(json.dumps(manifest))
    with pytest.raises(OnboardingError):
        call(code, checksum, path, manifest, prepare=True, home=home)
    assert list(home.iterdir()) == [] and not marker.exists()


def test_tampered_manifest_is_refused_before_candidate_execution(tmp_path, monkeypatch):
    code, checksum, home, path, manifest, _ = fixture(tmp_path)
    changed = copy.deepcopy(manifest)
    changed['artifacts']['matrix_sdk'] = '4' * 64
    path.write_text(json.dumps(changed))
    monkeypatch.setattr('clusterctl.onboarding_receiving_update._reader',
        lambda *a, **k: pytest.fail('unapproved candidate executed'))
    with pytest.raises(OnboardingError, match='receiving_manifest_digest_mismatch'):
        call(code, checksum, path, manifest, prepare=True, home=home)
    assert list(home.iterdir()) == []


@pytest.mark.parametrize('missing', [False, True])
def test_reader_never_imports_candidate_package_init_or_site_startup(tmp_path, missing):
    code, _, home, path, manifest, marker = fixture(tmp_path, reader=not missing)
    wheel = next((code / 'sdk/wheels').glob('*.whl'))
    with zipfile.ZipFile(wheel) as old:
        files = {n: old.read(n) for n in old.namelist()}
    files['daimon_matrix/__init__.py'] = ('from pathlib import Path; Path(' + repr(str(marker))
        + ').write_text("executed"); raise RuntimeError("startup executed")').encode()
    with zipfile.ZipFile(wheel, 'w') as archive:
        for name, raw in files.items():
            archive.writestr(name, raw)
    sdk = json.loads((code / 'sdk/sdk.json').read_bytes())
    sdk['wheels'] = [onboarding_sdk.wheel(wheel, uid=os.geteuid())]
    (code / 'sdk/sdk.json').write_text(json.dumps(sdk))
    (code / 'sdk/requirements.txt').write_bytes(onboarding_sdk.requirement_lines(sdk['wheels']))
    profile = json.loads((code / 'release.json').read_bytes())['profile']
    (code / 'release.json').unlink()
    checksum = onboarding_release.seal(code, profile)
    manifest['artifacts']['matrix_sdk'] = sdk['wheels'][0]['sha256']
    manifest['required_receivers'][0]['artifacts']['receiving_code'] = checksum
    path.write_text(json.dumps(manifest))
    if missing:
        with pytest.raises(OnboardingError, match='qualified_receiving_reader_required'):
            call(code, checksum, path, manifest)
    else:
        assert call(code, checksum, path, manifest)['assessment']['compatible'] is True
    assert not marker.exists() and list(home.iterdir()) == []


def test_omitted_independent_components_stay_omitted(tmp_path):
    code, checksum, _, path, manifest, _ = fixture(tmp_path)
    manifest['required_receivers'][0].pop('artifacts')
    path.write_text(json.dumps(manifest))
    result = call(code, checksum, path, manifest)
    assert result['artifacts'] == manifest['artifacts']
    assert 'telecodex' not in result['artifacts'] and 'owner_client' not in result['artifacts']


def test_non_sdk_component_is_explicitly_unverified(tmp_path):
    code, checksum, _, path, manifest, _ = fixture(tmp_path)
    manifest['required_receivers'][0]['artifacts']['telecodex'] = '9' * 64
    path.write_text(json.dumps(manifest))
    result = call(code, checksum, path, manifest)
    assert result['unverified_artifacts'] == ['telecodex']
    assert set(result['checked_artifacts']) == {'matrix_sdk', 'receiving_code'}
    assert result['receiving_readiness'] == 'unobserved'

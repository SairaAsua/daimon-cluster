"""Actual offline pip installation, crash replay and immutable completed code."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from clusterctl import onboarding_release, onboarding_sdk
from clusterctl.onboarding import OnboardingError, digest
from tests.test_onboarding_guest import artifact
from tools.build_onboarding_sdk import seal


def fixture(tmp_path, *, requirements=(), wheel_tag='py3-none-any'):
    code = tmp_path / "code"
    artifact(code)
    (code / "release.json").unlink()
    root = code / "sdk"
    wheels = root / "wheels"
    wheels.mkdir(parents=True)
    package = "daimon_matrix-0.1.0rc1.dist-info"
    with zipfile.ZipFile(wheels / "daimon_matrix-0.1.0rc1-py3-none-any.whl", "w") as archive:
        archive.writestr("daimon_matrix/__init__.py", "# Synthetic dependency-installation fixture only.\n")
        archive.writestr(package + "/METADATA", "Metadata-Version: 2.1\nName: daimon-matrix\nVersion: 0.1.0rc1\n"
                         + ''.join('Requires-Dist: ' + row + '\n' for row in requirements))
        archive.writestr(package + "/WHEEL", "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: " + wheel_tag + '\n')
        archive.writestr(package + "/RECORD", "")
    seal(root)
    selected = dict(schema=onboarding_release.PROFILE, model="gpt-6.1-sol", reasoning="xhigh",
                    approval="never", sandbox="danger-full-access", skills=["listening"], primary_store=None)
    fingerprint = onboarding_release.seal(code, selected)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    return code, fingerprint, home


def test_actual_offline_install_retry_and_changed_completed_code_are_observed(tmp_path):
    code, fingerprint, home = fixture(tmp_path)
    venv = onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    receipt = json.loads((venv.parent / "installation.json").read_bytes())
    assert receipt["matrix_commit"] == onboarding_sdk.MATRIX_COMMIT and receipt["wheel_count"] == 1
    assert onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid()) == venv
    target = next(venv.glob("lib/python*/site-packages/daimon_matrix/__init__.py"))
    target.write_bytes(b"# Own changed installation must not be overwritten.\n")
    preserved = target.read_bytes()
    with pytest.raises(OnboardingError, match="installed_onboarding_sdk_changed"):
        onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert target.read_bytes() == preserved
    assert not (home / ".codex").exists() and not list(home.rglob("custody.json"))


def test_missing_install_acknowledgement_replays_only_offline_dependencies(tmp_path, monkeypatch):
    code, fingerprint, home = fixture(tmp_path)
    original = onboarding_sdk._run
    failed = []
    def interrupted(argv):
        result = original(argv)
        if "--require-hashes" in argv and not failed:
            failed.append(True)
            raise RuntimeError("process disappeared after pip finished")
        return result
    monkeypatch.setattr(onboarding_sdk, "_run", interrupted)
    with pytest.raises(RuntimeError):
        onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert not list(home.rglob("installation.json"))
    before = next(home.glob(".local/share/daimon-matrix/sdk/*/venv/lib/python*/site-packages/daimon_matrix/__init__.py"))
    checksum = hashlib.sha256(before.read_bytes()).hexdigest()
    marker = tmp_path / 'unexpected-startup'
    hook = 'import pathlib; pathlib.Path(' + repr(str(marker)) + ').write_text("executed")\n'
    (before.parent.parent / 'unexpected.pth').write_text(hook)
    (before.parent.parent / 'sitecustomize.py').write_text(hook)
    venv = onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert hashlib.sha256(before.read_bytes()).hexdigest() == checksum
    assert (venv.parent / "installation.json").exists()
    assert not marker.exists()


def test_completed_sdk_probe_never_executes_site_hooks_or_installed_pip(tmp_path):
    code, fingerprint, home = fixture(tmp_path)
    venv = onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    site = next(venv.glob('lib/python*/site-packages'))
    marker = tmp_path / 'unexpected-startup'
    hook = 'import pathlib; pathlib.Path(' + repr(str(marker)) + ').write_text("executed")\n'
    files = [site / 'unexpected.pth', site / 'sitecustomize.py', site / 'pip/__init__.py']
    for path in files:
        path.write_text(hook + 'raise RuntimeError("unverified installed code executed")\n')
    before = {path: path.read_bytes() for path in files}
    receipt = (venv.parent / 'installation.json').read_bytes()
    assert onboarding_sdk.observe(home, code, code_uid=os.geteuid()) == venv
    assert onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid()) == venv
    assert not marker.exists()
    assert all(path.read_bytes() == raw for path, raw in before.items())
    assert (venv.parent / 'installation.json').read_bytes() == receipt


def test_hook_free_dependency_check_still_rejects_missing_dependencies(tmp_path):
    code, fingerprint, home = fixture(tmp_path, requirements=('missing-synthetic-package>=1',))
    with pytest.raises(OnboardingError, match='native_onboarding_sdk_refused'):
        onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert not list(home.rglob('installation.json'))


def test_hook_free_dependency_check_honors_environment_markers(tmp_path):
    code, fingerprint, home = fixture(tmp_path,
        requirements=('missing-synthetic-package>=1; python_version < "0"',))
    venv = onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert onboarding_sdk.observe(home, code, code_uid=os.geteuid()) == venv


def test_hook_free_check_still_rejects_unsupported_installed_wheel_tags(tmp_path):
    code, fingerprint, home = fixture(tmp_path, wheel_tag='cp99-cp99-unavailable_platform')
    with pytest.raises(OnboardingError, match='native_onboarding_sdk_refused'):
        onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert not list(home.rglob('installation.json'))


def test_changed_wheel_or_requirement_refused_before_home_creation(tmp_path):
    code, fingerprint, home = fixture(tmp_path)
    (code / "sdk/requirements.txt").write_bytes(b"daimon-matrix\n")
    with pytest.raises(OnboardingError, match="receiving_release_digest_mismatch"):
        onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    assert not list(home.iterdir())
    value = json.loads((code / "sdk/sdk.json").read_bytes())
    assert len(digest(value)) == 64
    with pytest.raises(OnboardingError, match="onboarding_sdk_digest_mismatch"):
        onboarding_sdk.verify(code, uid=os.geteuid())


def test_wheel_paths_cannot_escape_site_packages(tmp_path):
    path = tmp_path / "bad-1-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../escape", "bad")
    path.chmod(0o644)
    with pytest.raises(OnboardingError, match="invalid_onboarding_sdk_wheel"):
        onboarding_sdk.wheel(path, uid=os.geteuid())


def test_actual_serving_startup_qualifies_own_closed_tree_and_rejects_contamination(tmp_path):
    code, _, home = fixture(tmp_path)
    (code / 'release.json').unlink()
    package = code / 'clusterctl'
    package.mkdir()
    source = Path(onboarding_sdk.__file__).parent
    for name in ('__init__.py', 'being_seed.py', 'onboarding.py', 'onboarding_input.py',
                 'onboarding_release.py', 'onboarding_sdk.py'):
        shutil.copyfile(source / name, package / name)
    # Tiny synthetic SDK: this tests startup association, not real receiving.
    wheel = next((code / 'sdk/wheels').iterdir())
    with zipfile.ZipFile(wheel, 'a') as archive:
        archive.writestr('daimon_matrix/runtime.py', '''# Synthetic runtime.
import sys
if sys.argv[3] == 'import-drift':
    sys.path.append('/unqualified-import-drift')
''')
        archive.writestr('daimon_matrix/native_egress.py', '# Synthetic egress.\n')
        # Model only the third-party proxy contract. The actual cryptography
        # wheel and complete Source are qualified separately at receiving time.
        archive.writestr('cryptography/__init__.py', '# Synthetic provenance fixture.\n')
        archive.writestr('cryptography/utils.py', '''from types import ModuleType
class _ModuleWithDeprecations(ModuleType):
    def __init__(self, original):
        super().__init__(original.__name__)
        self.__dict__['_module'] = original
    def __getattr__(self, name):
        return getattr(self._module, name)
''')
        archive.writestr('cryptography/wrapper_fixture.py', '''import sys
from cryptography.utils import _ModuleWithDeprecations
sys.modules[__name__] = _ModuleWithDeprecations(sys.modules[__name__])
''')
        codecs = Path(__file__).parent / 'fixtures/receiving_reader'
        for name in ('canonical.py', 'release_compatibility.py'):
            archive.writestr('daimon_matrix/' + name, (codecs / name).read_bytes())
    seal(code / 'sdk')
    (package / 'startup_probe.py').write_text('''import json,os,sys
from pathlib import Path
from clusterctl import onboarding_sdk
from clusterctl.onboarding import OnboardingError
code, fingerprint, mode = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
if mode == 'path-tail':
    sys.path.append('/unqualified-extra-imports')
elif mode in ('installed-module', 'installed-dependency', 'stdlib-escape'):
    from importlib.util import module_from_spec, spec_from_file_location
    path = Path(sys.argv[4])
    if mode == 'stdlib-escape':
        import sysconfig
        standard = sysconfig.get_path('stdlib')
        path = Path(standard) / os.path.relpath(path, standard)
    name = 'daimon_matrix' if mode == 'installed-module' else 'unqualified_dependency'
    spec = spec_from_file_location(name, path, submodule_search_locations=[str(path.parent)])
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules[name] = module
elif mode == 'package-path':
    import daimon_matrix
    daimon_matrix.__path__.append('/unqualified-package-search')
elif mode == 'cluster-path':
    import clusterctl
    clusterctl.__spec__.submodule_search_locations.append('/unqualified-cluster-search')
elif mode == 'native-alias-no-owner':
    import types
    sys.modules['_openssl.lib'] = types.ModuleType('_openssl.lib')
elif mode == 'native-alias-stdlib':
    sys.modules['_openssl.lib'] = json
elif mode in ('native-owner-stdlib', 'native-owner-builtin'):
    import types
    from importlib.machinery import ExtensionFileLoader, ModuleSpec
    name = 'cryptography.hazmat.bindings._rust'
    filename = json.__file__ if mode == 'native-owner-stdlib' else 'built-in'
    native = types.ModuleType(name)
    native.__spec__ = ModuleSpec(name, ExtensionFileLoader(name, filename), origin=filename)
    if mode == 'native-owner-stdlib':
        native.__file__ = filename
    native._openssl = types.ModuleType('_openssl')
    native._openssl.lib = types.ModuleType('_openssl.lib')
    sys.modules[name] = native
    sys.modules['_openssl'] = native._openssl
    sys.modules['_openssl.lib'] = native._openssl.lib
elif mode in ('valid-wrapper', 'wrapper-path', 'wrapper-nonmodule', 'wrapper-spec-name', 'wrapper-outside-tree'):
    import cryptography.wrapper_fixture as wrapped
    original = wrapped._module
    if mode == 'wrapper-path':
        wrapped.__dict__['__path__'] = ['/unqualified-wrapper-search']
    elif mode == 'wrapper-nonmodule':
        from types import SimpleNamespace
        wrapped.__dict__['_module'] = SimpleNamespace(__name__=original.__name__, __file__=original.__file__, __spec__=original.__spec__)
    elif mode == 'wrapper-spec-name':
        original.__spec__.name = 'cryptography.unrelated'
    elif mode == 'wrapper-outside-tree':
        from importlib.util import spec_from_file_location
        original.__file__ = json.__file__
        original.__spec__ = spec_from_file_location(original.__name__, json.__file__)
try:
    observation = onboarding_sdk.qualified_startup(Path(sys.prefix), code,
        code_digest=fingerprint, code_uid=os.geteuid())
    print(json.dumps(dict(ok=True, observation=observation, pid=os.getpid())))
except OnboardingError as error:
    print(json.dumps(dict(ok=False, error=str(error))))
''')
    selected = dict(schema=onboarding_release.PROFILE, model='gpt-6.1-sol', reasoning='xhigh',
                    approval='never', sandbox='danger-full-access', skills=['listening'], primary_store=None)
    for path in package.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    package.chmod(0o755)
    fingerprint = onboarding_release.seal(code, selected)
    venv = onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    imports = onboarding_sdk.runtime_imports(venv, code, code_uid=os.geteuid())
    site = next(venv.glob('lib/python*/site-packages'))
    installed_module = site / 'daimon_matrix/__init__.py'
    ordinary_dependency = home / 'ordinary-dependency.py'
    ordinary_dependency.write_text('# Disposable dependency outside any site/dist-packages.\n')
    marker = home / 'unexpected-startup'
    (site / 'unexpected.pth').write_text('import pathlib; pathlib.Path(' + repr(str(marker))
                                       + ').write_text("executed")\n')
    snapshots = []
    for mode in ('valid', 'valid', 'path-tail', 'installed-module', 'installed-dependency',
                 'package-path', 'cluster-path', 'import-drift', 'stdlib-escape',
                 'native-alias-no-owner', 'native-alias-stdlib', 'native-owner-stdlib', 'native-owner-builtin',
                 'valid-wrapper', 'wrapper-path', 'wrapper-nonmodule', 'wrapper-spec-name', 'wrapper-outside-tree'):
        command = onboarding_sdk.runtime_command(venv, imports, code,
            'clusterctl.startup_probe', [str(code), fingerprint, mode,
                str(ordinary_dependency if mode == 'stdlib-escape' else installed_module)])
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=True,
                                env={'PATH': os.defpath, 'LANG': 'C.UTF-8',
                                     'LD_LIBRARY_PATH': str(Path(sys.base_prefix) / 'lib')})
        observed = json.loads(result.stdout)
        assert observed['ok'] is (mode in {'valid', 'valid-wrapper'}), (mode, result.stdout)
        if observed['ok']:
            snapshot = observed['observation']
            assert snapshot['process_id'] == observed['pid'] != os.getpid()
            assert snapshot['code_digest'] == fingerprint
            assert snapshot['sdk_digest'] == digest(json.loads((code / 'sdk/sdk.json').read_bytes()))
            snapshots.append(snapshot)
        else:
            assert observed['error'] in {'qualified_runtime_context_required',
                                         'qualified_runtime_module_required'}
    assert snapshots[0]['startup_instance_id'] != snapshots[1]['startup_instance_id']
    assert not marker.exists() and not list(home.rglob('custody.json'))


def test_prepared_import_readers_do_not_interrupt_each_other_or_admit_a_writer(tmp_path, monkeypatch):
    """A startup and its status CLI verify the same immutable SDK concurrently."""
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from clusterctl import being_seed
    code, fingerprint, home = fixture(tmp_path)
    venv = onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    imports = onboarding_sdk.runtime_imports(venv, code, code_uid=os.geteuid())
    before = {p.relative_to(venv.parent): p.read_bytes()
              for p in imports.rglob('*') if p.is_file()}
    before[Path('runtime-imports.json')] = (venv.parent/'runtime-imports.json').read_bytes()
    entered, release = threading.Event(), threading.Event()
    original = onboarding_sdk._pip
    def pause_first_reader(*args):
        if threading.current_thread().name.startswith('sdk-reader'):
            entered.set()
            assert release.wait(10), 'second reader never completed'
        return original(*args)
    monkeypatch.setattr(onboarding_sdk, '_pip', pause_first_reader)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix='sdk-reader') as pool:
        first = pool.submit(onboarding_sdk.runtime_imports, venv, code, code_uid=os.geteuid())
        try:
            assert entered.wait(10), 'first reader never reached dependency verification'
            # Actual installation/build ownership must still exclude readers.
            with pytest.raises(being_seed.SeedError, match='seed_operation_in_progress'):
                with being_seed._locked(venv.parent):
                    pytest.fail('a writer crossed active immutable verification')
            assert onboarding_sdk.runtime_imports(venv, code, code_uid=os.geteuid()) == imports
        finally:
            release.set()
        assert first.result(timeout=10) == imports
    assert all((venv.parent/path).read_bytes() == data for path, data in before.items())
    with being_seed._locked(venv.parent):
        with pytest.raises(being_seed.SeedError, match='seed_operation_in_progress'):
            onboarding_sdk.runtime_imports(venv, code, code_uid=os.geteuid())


def test_changed_preparation_cannot_build_or_issue_a_receipt_under_read_ownership(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from clusterctl import being_seed
    code, fingerprint, home = fixture(tmp_path)
    venv = onboarding_sdk.install(home, code, fingerprint, code_uid=os.geteuid())
    imports = onboarding_sdk.runtime_imports(venv, code, code_uid=os.geteuid())
    receipt = venv.parent/'runtime-imports.json'
    original = being_seed._locked
    @contextmanager
    def changed(directory, *, shared=False):
        with original(directory, shared=shared):
            if directory == venv.parent and shared:
                receipt.rename(venv.parent/'retained-import-receipt.json')
            yield
    monkeypatch.setattr(being_seed, '_locked', changed)
    with pytest.raises(OnboardingError, match='qualified_runtime_imports_required'):
        onboarding_sdk.runtime_imports(venv, code, code_uid=os.geteuid())
    assert not receipt.exists()
    assert imports.is_dir()
    assert not list(venv.parent.glob('runtime-imports-*'))

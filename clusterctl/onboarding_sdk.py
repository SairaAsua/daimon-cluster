"""Install a qualified Matrix wheelhouse offline into a body's private venv.

No seed code, account credentials, identity keys or model calls are involved.
The wheelhouse is covered by the receiving release's content digest.
"""
from __future__ import annotations

import hashlib
import ctypes
import errno
import io
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
import zipfile
from contextlib import ExitStack, contextmanager
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from . import being_seed, onboarding_release
from .onboarding import OnboardingError, digest, private_directory

SCHEMA = "cluster-onboarding-sdk/v1"
MATRIX_COMMIT = "9b2b8ec2c455d3bf316bc00dc9e1bac44e9d5094"
PREVIOUS_MATRIX_COMMIT = "196ec7219f954cf4e514a1f61ae72eb3451d851e"


def wheel(path: Path, *, uid: int) -> dict:
    raw = onboarding_release.regular(path, uid=uid)
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or len(names) > 10000:
            raise OnboardingError("invalid_onboarding_sdk_wheel")
        for name in names:
            parts = PurePosixPath(name).parts
            if (not parts or name.startswith("/") or ".." in parts or "\\" in name
                    or any(part.endswith(".data") for part in parts)):
                raise OnboardingError("invalid_onboarding_sdk_wheel")
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise OnboardingError("invalid_onboarding_sdk_wheel")
        message = BytesParser().parsebytes(archive.read(metadata[0]))
        name, version = message.get("Name", ""), message.get("Version", "")
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", version)
            or not re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", path.name)):
        raise OnboardingError("invalid_onboarding_sdk_wheel")
    return dict(filename=path.name, distribution=re.sub(r"[-_.]+", "-", name).lower(),
                version=version, sha256=hashlib.sha256(raw).hexdigest())


def requirement_lines(rows: list[dict]) -> bytes:
    return "".join(f"{row['distribution']}=={row['version']} --hash=sha256:{row['sha256']}\n"
                   for row in rows).encode()


def verify(code: Path, *, uid: int, matrix_commit: str = MATRIX_COMMIT,
           matrix_wheel_sha256: str | None = None) -> dict:
    # New revisions require an exact wheel selection from the protected owning
    # operation. A commit label alone cannot relax the retained pin guard.
    qualified = (isinstance(matrix_wheel_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", matrix_wheel_sha256) is not None
        and isinstance(matrix_commit, str)
        and re.fullmatch(r"[0-9a-f]{40}", matrix_commit) is not None)
    if matrix_wheel_sha256 is not None and not qualified:
        raise OnboardingError("invalid_onboarding_sdk")
    root = code / "sdk"
    value = json.loads(onboarding_release.regular(root / "sdk.json", uid=uid))
    if (not isinstance(value, dict) or set(value) != {"schema", "matrix_commit", "wheels"}
            or not qualified and matrix_commit not in {MATRIX_COMMIT, PREVIOUS_MATRIX_COMMIT}
            or value["schema"] != SCHEMA or value["matrix_commit"] != matrix_commit
            or not isinstance(value["wheels"], list) or not 1 <= len(value["wheels"]) <= 100):
        raise OnboardingError("invalid_onboarding_sdk")
    found = [wheel(path, uid=uid) for path in sorted((root / "wheels").iterdir())]
    if (value["wheels"] != found or len({row["distribution"] for row in found}) != len(found)
            or sum(row["distribution"] == "daimon-matrix" for row in found) != 1
            or onboarding_release.regular(root / "requirements.txt", uid=uid) != requirement_lines(found)):
        raise OnboardingError("onboarding_sdk_digest_mismatch")
    if qualified and next(row for row in found if row['distribution'] == 'daimon-matrix')[
            'sha256'] != matrix_wheel_sha256:
        raise OnboardingError("onboarding_sdk_digest_mismatch")
    return value


def _run(argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, capture_output=True, timeout=180, check=False, umask=0o077,
                                env={"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
                                     "PIP_CONFIG_FILE": os.devnull, "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                                     "LD_LIBRARY_PATH": str(Path(sys.base_prefix) / "lib")})
        if result.returncode:
            raise OnboardingError("native_onboarding_sdk_refused")
        return result.stdout.decode()
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        raise OnboardingError("native_onboarding_sdk_refused") from None


def _pip(venv: Path, mode: str, *arguments: str) -> None:
    """Use the trusted interpreter's ensurepip wheel, never installed site code.

    -I alone executes site hooks. -S also skips venv prefix adjustment on
    Python 3.13, so restore that prefix explicitly while leaving import paths
    limited to stdlib and the interpreter's bootstrap wheel. Dependency checking
    reads installed metadata through an explicit path; it never imports it.
    """
    launcher = '''import ensurepip, runpy, sys
sys.prefix = sys.exec_prefix = sys.argv.pop(1)
mode = sys.argv.pop(1)
with ensurepip._get_pip_whl_path_ctx() as wheel:
    sys.path.append(str(wheel))
    if mode == 'check':
        from pip._internal.metadata import get_environment
        from pip._internal.operations.check import PackageDetails, check_package_set, check_unsupported
        from pip._internal.utils.compatibility_tags import get_supported
        distributions = list(get_environment([sys.argv[1]]).iter_installed_distributions(
                local_only=False, skip=()))
        packages = {}
        for dist in distributions:
            name = dist.canonical_name
            packages[name] = PackageDetails(dist.version, list(dist.iter_dependencies()))
        missing, conflicting = check_package_set(packages)
        unsupported = list(check_unsupported(distributions, get_supported()))
        raise SystemExit(bool(missing or conflicting or unsupported))
    if mode == 'bootstrap':
        sys.argv[1:] = ['install', '--prefix', sys.prefix, '--no-index',
                        '--no-deps', '--upgrade', str(wheel)]
    elif mode != 'install':
        raise SystemExit(1)
    runpy.run_module('pip', run_name='__main__', alter_sys=True)
'''
    _run([str(venv / "bin/python"), "-I", "-S", "-c", launcher,
          str(venv), mode, *arguments])


def interpreter(venv: Path, *, with_executable: bool = False) -> dict:
    """Observe the returned generation's actual interpreter without site hooks."""
    probe = ("import json,sys,hashlib;from pathlib import Path; "
             "value=dict(implementation=sys.implementation.name, version=list(sys.version_info[:3])); "
             + ("value['executable_sha256']=hashlib.sha256(Path('/proc/self/exe').read_bytes()).hexdigest(); "
                if with_executable else '') + "print(json.dumps(value))")
    value = json.loads(_run([str(venv / 'bin/python'), '-I', '-S', '-c', probe]))
    fields = {'implementation', 'version'} | ({'executable_sha256'} if with_executable else set())
    if (not isinstance(value, dict) or set(value) != fields
            or not isinstance(value['implementation'], str)
            or not isinstance(value['version'], list) or len(value['version']) != 3
            or any(type(part) is not int for part in value['version'])):
        raise OnboardingError('qualified_receiving_interpreter_required')
    if with_executable and (not isinstance(value['executable_sha256'], str)
            or re.fullmatch('[0-9a-f]{64}', value['executable_sha256']) is None):
        raise OnboardingError('qualified_receiving_interpreter_required')
    return value


def runtime_imports(venv: Path, code: Path, *, code_uid: int = 0,
                    matrix_commit: str = MATRIX_COMMIT,
                    matrix_wheel_sha256: str | None = None) -> Path:
    return _runtime_imports(venv, code, code_uid=code_uid, matrix_commit=matrix_commit,
                            matrix_wheel_sha256=matrix_wheel_sha256)[0]


@contextmanager
def _import_sync(parent: Path):
    """Select durability before staging and retain its original error cursor.

    Linux >=5.8 syncfs reports filesystem writeback errors since this directory
    FD was opened. Open it before even creating the temporary tree, not after
    writes whose errors another filesystem user might already have observed.
    Unsupported/older kernels retain fsync on each original writer FD.
    """
    kernel = re.match(r'^(\d+)\.(\d+)', os.uname().release)
    if os.uname().sysname != 'Linux' or kernel is None or tuple(map(int, kernel.groups())) < (5, 8):
        yield None
        return
    syncfs = getattr(ctypes.CDLL(None, use_errno=True), 'syncfs', None)
    if syncfs is None:
        yield None
        return
    syncfs.argtypes = [ctypes.c_int]
    syncfs.restype = ctypes.c_int
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # Probe support before mutation. A later flush error is always fatal;
        # it cannot be laundered through a reopened-file fallback.
        if syncfs(descriptor) != 0:
            code = ctypes.get_errno()
            if code not in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL}:
                raise OSError(code, 'SDK filesystem flush failed')
            yield None
        else:
            yield (descriptor, syncfs)
    finally:
        os.close(descriptor)


def _sync_import_tree(root: Path, monitor: tuple) -> None:
    """Flush one staged filesystem through its pre-write error cursor.

    This also flushes unrelated pending writes on the same filesystem;
    preparation budgets include that cost. No mount/runtime settings change.
    """
    descriptor, syncfs = monitor
    observed = os.fstat(descriptor)
    parent = root.parent.lstat()
    if ((observed.st_dev, observed.st_ino) != (parent.st_dev, parent.st_ino)
            or any(path.lstat().st_dev != observed.st_dev for path in (root, *root.rglob('*')))):
        raise OnboardingError('qualified_runtime_imports_required')
    if syncfs(descriptor) != 0:
        raise OSError(ctypes.get_errno(), 'SDK filesystem flush failed')


def _runtime_imports(venv: Path, code: Path, *, code_uid: int = 0,
                     matrix_commit: str = MATRIX_COMMIT,
                     matrix_wheel_sha256: str | None = None) -> tuple[Path, dict, dict[str, str]]:
    """Derive one closed import tree without altering the installed generation.

    Startup executes only the trusted interpreter, approved code and these exact
    wheel bytes. Installed extras, startup hooks and unverified bytecode never
    become import paths. This is artifact closure, not a process sandbox.
    """
    sdk = verify(code, uid=code_uid, matrix_commit=matrix_commit,
                 matrix_wheel_sha256=matrix_wheel_sha256)
    root = private_directory(venv.parent)
    expected_install = dict(schema='cluster-onboarding-sdk-installation/v1', sdk_digest=digest(sdk),
                            matrix_commit=sdk['matrix_commit'], wheel_count=len(sdk['wheels']))
    if venv.name != 'venv' or being_seed._read(root / 'installation.json') != expected_install:
        raise OnboardingError('installed_onboarding_sdk_changed')
    target = root / 'runtime-imports'
    receipt = root / 'runtime-imports.json'
    # Prepared imports are immutable: serving startup and owner observation
    # must not interrupt each other's full verification. Construction and SDK
    # installation retain exclusive ownership of this same lock.
    prepared = target.exists() and receipt.exists()
    with being_seed._locked(root, shared=prepared), ExitStack() as sync_ownership:
        if prepared and (not target.exists() or not receipt.exists()):
            # Do not build or mint a receipt while holding read ownership if
            # preparation changed before acquiring it.
            raise OnboardingError('qualified_runtime_imports_required')
        temporary = root / ('runtime-imports-' + uuid.uuid4().hex)
        building = not target.exists() and not target.is_symlink()
        monitor = sync_ownership.enter_context(_import_sync(root)) if building else None
        if building:
            temporary.mkdir(mode=0o700)
        files: dict[str, str] = {}
        total = 0
        try:
            for row in sdk['wheels']:
                raw = onboarding_release.regular(code / 'sdk/wheels' / row['filename'], uid=code_uid)
                if hashlib.sha256(raw).hexdigest() != row['sha256']:
                    raise OnboardingError('onboarding_sdk_digest_mismatch')
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    for member in archive.infolist():
                        if member.is_dir():
                            continue
                        name = PurePosixPath(member.filename).as_posix()
                        if name != member.filename or member.file_size > 32 * 1024**2:
                            raise OnboardingError('qualified_runtime_imports_required')
                        contents = archive.read(member)
                        checksum = hashlib.sha256(contents).hexdigest()
                        if name in files:
                            if files[name] != checksum:
                                raise OnboardingError('qualified_runtime_imports_required')
                            continue
                        files[name] = checksum
                        total += len(contents)
                        if total > 256 * 1024**2 or len(files) > 20000:
                            raise OnboardingError('qualified_runtime_imports_required')
                        if building:
                            destination = temporary / name
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            with destination.open('xb') as output:
                                output.write(contents)
                                os.fchmod(output.fileno(), 0o600)
                                if monitor is None:
                                    output.flush()
                                    os.fsync(output.fileno())
            expected = dict(schema='cluster-onboarding-runtime-imports/v1', sdk_digest=digest(sdk),
                            files_sha256=digest(files))
            if building:
                for directory in temporary.rglob('*'):
                    if directory.is_dir():
                        directory.chmod(0o700)
                if monitor is not None:
                    _sync_import_tree(temporary, monitor)
                else:
                    directories_to_sync = [temporary, *[p for p in temporary.rglob('*') if p.is_dir()]]
                    for directory in sorted(directories_to_sync, key=lambda p: len(p.parts), reverse=True):
                        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                        try:
                            os.fsync(descriptor)
                        finally:
                            os.close(descriptor)
                os.replace(temporary, target)
                descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            directories = {''}
            for name in files:
                directories.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != '.')
            actual_files, actual_directories = set(), {''}
            private_directory(target)
            for path in target.rglob('*'):
                being_seed._path(path)
                name = path.relative_to(target).as_posix()
                if path.is_dir():
                    private_directory(path)
                    actual_directories.add(name)
                else:
                    if name not in files or hashlib.sha256(onboarding_release.regular(path,
                            uid=os.geteuid())).hexdigest() != files[name]:
                        raise OnboardingError('qualified_runtime_imports_required')
                    actual_files.add(name)
            if actual_files != set(files) or actual_directories != directories:
                raise OnboardingError('qualified_runtime_imports_required')
            # Extra installed distributions must not satisfy dependencies that
            # are missing from this exact, deliberately closed runtime tree.
            _pip(venv, 'check', str(target))
            if receipt.exists():
                if being_seed._read(receipt) != expected:
                    raise OnboardingError('qualified_runtime_imports_required')
            else:
                being_seed._write(receipt, expected)
            return target, sdk, files
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)


def startup_context(venv: Path, imports: Path, code: Path) -> bool:
    """Check the complete actual interpreter context, including its path tail.

    The fresh trusted interpreter supplies its standard-library path list;
    installed sites and arbitrary extra paths cannot become allowed roots.
    This is a startup check, not a wheel verifier or a positive receiving claim.
    """
    baseline = json.loads(_run([str(venv / 'bin/python'), '-I', '-S', '-c',
                               'import json,sys; print(json.dumps(sys.path))']))
    return (Path(sys.prefix) == venv and bool(sys.flags.isolated)
            and bool(sys.flags.no_site) and bool(sys.flags.dont_write_bytecode)
            and sys.dont_write_bytecode
            and sys.pycache_prefix == str(imports / '.disabled-bytecode')
            and sys.path == [str(code), str(imports), *baseline])


def qualified_startup(venv: Path, code: Path, *, code_digest: str, code_uid: int = 0,
                      matrix_commit: str = MATRIX_COMMIT,
                      matrix_wheel_sha256: str | None = None) -> dict:
    """Mint boot evidence in the actual serving process, once before custody.

    Reuse the maintained artifact verifier. Neither a parent receipt nor a
    selected manifest alone qualifies the process. No mutable global marker,
    status-time wheel verification or model-visible qualification override.
    """
    import importlib
    from types import ModuleType
    release = onboarding_release.verify(code, code_digest, uid=code_uid)
    imports, sdk, files = _runtime_imports(venv, code, code_uid=code_uid,
        matrix_commit=matrix_commit, matrix_wheel_sha256=matrix_wheel_sha256)
    if not startup_context(venv, imports, code):
        raise OnboardingError('qualified_runtime_context_required')
    actual_interpreter = dict(implementation=sys.implementation.name,
        version=list(sys.version_info[:3]),
        executable_sha256=hashlib.sha256(Path('/proc/self/exe').read_bytes()).hexdigest())
    if interpreter(venv, with_executable=True) != actual_interpreter:
        raise OnboardingError('qualified_receiving_interpreter_required')
    code_files = {row['path']: row['sha256'] for row in release['files']}
    import_directories = {str(imports)}
    for name in files:
        import_directories.update(str(imports / parent) for parent in PurePosixPath(name).parents
                                  if str(parent) != '.')
    standard = json.loads(_run([str(venv / 'bin/python'), '-I', '-S', '-c',
                               'import json,sys; print(json.dumps(sys.path))']))

    def origins() -> None:
        # Check preloaded packages before importing the selected Matrix. A
        # correct sys.path must never launder an installed/preloaded module.
        # Cryptography's native extension publishes two CFFI objects without
        # file/spec metadata. Accept only its actual exports; the extension
        # itself still undergoes the full inventory/origin checks below.
        native = sys.modules.get('cryptography.hazmat.bindings._rust')
        native_spec = getattr(native, '__spec__', None)
        exports = {}
        if (native_spec is not None
                and isinstance(native_spec.loader, importlib.machinery.ExtensionFileLoader)
                and native_spec.name == 'cryptography.hazmat.bindings._rust'):
            openssl = getattr(native, '_openssl', None)
            exports = {'_openssl': openssl, '_openssl.lib': getattr(openssl, 'lib', None)}
        wrappers = getattr(sys.modules.get('cryptography.utils'), '_ModuleWithDeprecations', None)
        for name, module in list(sys.modules.items()):
            if name in {'_openssl', '_openssl.lib'}:
                if module is None or module is not exports.get(name):
                    raise OnboardingError('qualified_runtime_module_required')
                continue
            wrapped = wrappers is not None and type(module) is wrappers
            if wrapped:
                original = getattr(module, '_module', None)
                if (not name.startswith('cryptography.') or not isinstance(original, ModuleType)
                        or getattr(module, '__name__', None) != name
                        or getattr(original, '__name__', None) != name
                        or getattr(getattr(original, '__spec__', None), 'name', None) != name
                        or getattr(module, '__file__', None) != getattr(original, '__file__', None)
                        or getattr(module, '__path__', ()) != getattr(original, '__path__', ())):
                    raise OnboardingError('qualified_runtime_module_required')
                module = original
            managed = (name == 'clusterctl' or name.startswith('clusterctl.')
                    or name == 'daimon_matrix' or name.startswith('daimon_matrix.')
                    or name in {'cryptography.hazmat.bindings._rust', 'cryptography.utils'} or wrapped
                    or name == '__main__' and getattr(getattr(module, '__spec__', None),
                                                   'name', '').startswith('clusterctl.'))
            spec = getattr(module, '__spec__', None)
            filename = getattr(module, '__file__', None)
            if not managed:
                if spec is not None and spec.origin in {'built-in', 'frozen'}:
                    continue
                if name == '__main__' and filename is None and spec is None:
                    continue  # The trusted -c launcher has no source file.
                if isinstance(filename, str):
                    path = Path(filename)
                    physical = path.resolve()
                    if (path.is_absolute() and '..' not in path.parts
                            and not {'site-packages', 'dist-packages'} & set(physical.parts)
                            and any(physical.is_relative_to(Path(base).resolve()) for base in standard)):
                        if any(Path(location) != path.parent or Path(location).resolve() != physical.parent
                               for location in (
                                *getattr(module, '__path__', ()),
                                *(getattr(spec, 'submodule_search_locations', ()) or ()))):
                            raise OnboardingError('qualified_runtime_module_required')
                        continue
                if filename is None and spec is not None and spec.submodule_search_locations:
                    if all(location in import_directories and Path(location).is_dir()
                           and Path(location).resolve() == Path(location)
                           for location in (*getattr(module, '__path__', ()),
                                            *spec.submodule_search_locations)):
                        continue  # A verified-tree namespace package.
                    raise OnboardingError('qualified_runtime_module_required')
            root = code if name.startswith('clusterctl') or name == '__main__' else imports
            inventory = code_files if root == code else files
            if not isinstance(filename, str):
                raise OnboardingError('qualified_runtime_module_required')
            path = Path(filename)
            if not path.is_absolute() or not path.is_relative_to(root):
                raise OnboardingError('qualified_runtime_module_required')
            relative = path.relative_to(root).as_posix()
            owner = code_uid if root == code else os.geteuid()
            if (relative not in inventory or hashlib.sha256(onboarding_release.regular(
                    path, uid=owner)).hexdigest() != inventory[relative]):
                raise OnboardingError('qualified_runtime_module_required')
            for location in getattr(module, '__path__', ()):
                if Path(location) != path.parent:
                    raise OnboardingError('qualified_runtime_module_required')
            if spec is None or spec.origin != filename:
                raise OnboardingError('qualified_runtime_module_required')
            for location in spec.submodule_search_locations or ():
                if Path(location) != path.parent:
                    raise OnboardingError('qualified_runtime_module_required')

    origins()
    importlib.import_module('daimon_matrix.runtime')
    importlib.import_module('daimon_matrix.native_egress')
    reader = importlib.import_module('daimon_matrix.release_compatibility').describe_reader()
    origins()
    if not startup_context(venv, imports, code):
        raise OnboardingError('qualified_runtime_context_required')
    return dict(schema='cluster-onboarding-loaded-startup/v1', process_id=os.getpid(),
        startup_instance_id=str(uuid.uuid4()), code_digest=code_digest,
        matrix_commit=sdk['matrix_commit'], sdk_digest=digest(sdk),
        matrix_wheel_sha256=next(row['sha256'] for row in sdk['wheels']
                                if row['distribution'] == 'daimon-matrix'),
        import_files_sha256=digest(files), import_context_sha256=digest(dict(
            path=sys.path, dont_write_bytecode=sys.dont_write_bytecode,
            pycache_prefix=sys.pycache_prefix)), interpreter=actual_interpreter, reader=reader,
        isolated=True, no_site=True, no_bytecode=True)


def runtime_command(venv: Path, imports: Path, code: Path, module: str,
                    arguments: list[str]) -> list[str]:
    """Use a previously qualified tree without site startup or bytecode caches."""
    if (not re.fullmatch(r'clusterctl\.[a-z][a-z0-9_]*', module)
            or imports != venv.parent / 'runtime-imports'):
        raise OnboardingError('qualified_runtime_imports_required')
    launcher = '''import sys,runpy
sys.prefix = sys.exec_prefix = sys.argv.pop(1)
imports = sys.argv.pop(1)
code = sys.argv.pop(1)
module = sys.argv.pop(1)
sys.path[:0] = [code, imports]
sys.dont_write_bytecode = True
sys.pycache_prefix = imports + '/.disabled-bytecode'
runpy.run_module(module, run_name='__main__', alter_sys=True)
'''
    return [str(venv / 'bin/python'), '-B', '-I', '-S', '-c', launcher,
            str(venv), str(imports), str(code), module, *arguments]


def installed(venv: Path, code: Path, value: dict, *, code_uid: int) -> None:
    # Query only stdlib metadata in the isolated interpreter. Do not import an
    # unverified installed SDK, dependency, .pth hook or sitecustomize.
    probe = ("import sys,sysconfig; print(sysconfig.get_path('purelib', scheme='venv', "
             "vars={'base':sys.argv[1], 'platbase':sys.argv[1]}))")
    site = Path(_run([str(venv / "bin/python"), "-I", "-S", "-c", probe, str(venv)]).strip())
    if not site.is_relative_to(venv):
        raise OnboardingError("private_onboarding_sdk_required")
    for row in value["wheels"]:
        path = code / "sdk/wheels" / row["filename"]
        # Recheck artifact ownership/hash before matching each installed byte.
        if wheel(path, uid=code_uid) != row:
            raise OnboardingError("onboarding_sdk_digest_mismatch")
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.is_dir() or member.filename.endswith(".dist-info/RECORD"):
                    continue
                actual = onboarding_release.regular(site / member.filename, uid=os.geteuid())
                if hashlib.sha256(actual).digest() != hashlib.sha256(archive.read(member)).digest():
                    raise OnboardingError("installed_onboarding_sdk_changed")
    _pip(venv, 'check', str(site))


def observe(home: Path, code: Path, *, code_uid: int = 0,
            matrix_commit: str = MATRIX_COMMIT, matrix_wheel_sha256: str | None = None) -> Path:
    value = verify(code, uid=code_uid, matrix_commit=matrix_commit,
                   matrix_wheel_sha256=matrix_wheel_sha256)
    root = home / ".local/share/daimon-matrix/sdk" / digest(value)
    private_directory(root)
    expected = dict(schema="cluster-onboarding-sdk-installation/v1", sdk_digest=digest(value),
                    matrix_commit=value['matrix_commit'], wheel_count=len(value["wheels"]))
    if being_seed._read(root / "installation.json") != expected:
        raise OnboardingError("installed_onboarding_sdk_changed")
    installed(root / "venv", code, value, code_uid=code_uid)
    return root / "venv"


def install(home: Path, code: Path, release_digest: str, *, code_uid: int = 0,
            matrix_commit: str = MATRIX_COMMIT, matrix_wheel_sha256: str | None = None) -> Path:
    onboarding_release.verify(code, release_digest, uid=code_uid)
    value = verify(code, uid=code_uid, matrix_commit=matrix_commit,
                   matrix_wheel_sha256=matrix_wheel_sha256)
    private_directory(home)
    parent = home / ".local/share/daimon-matrix/sdk"
    current = home
    for part in parent.relative_to(home).parts:
        current /= part
        private_directory(current, create=True)
    root = parent / digest(value)
    private_directory(root, create=True)
    receipt = root / "installation.json"
    venv = root / "venv"
    with being_seed._locked(root):
        expected = dict(schema="cluster-onboarding-sdk-installation/v1", sdk_digest=digest(value),
                        matrix_commit=value['matrix_commit'], wheel_count=len(value["wheels"]))
        if receipt.exists():
            if being_seed._read(receipt) != expected:
                raise OnboardingError("installed_onboarding_sdk_changed")
            installed(venv, code, value, code_uid=code_uid)
            return venv
        if venv.exists():
            private_directory(venv)
        # Before completion only dependency installation may be replayed. No
        # runtime/custody is created in this directory and completed SDK bytes
        # are never repaired by overwriting them.
        _run([sys.executable, "-I", "-S", "-m", "venv", "--without-pip", str(venv)])
        venv.chmod(0o700)
        _pip(venv, 'bootstrap')
        _pip(venv, 'install', "install", "--prefix", str(venv), "--no-index",
              "--no-deps", "--require-hashes", "--only-binary=:all:", "--no-cache-dir",
              "--force-reinstall", "--find-links", str(code / "sdk/wheels"),
              "--requirement", str(code / "sdk/requirements.txt"))
        installed(venv, code, value, code_uid=code_uid)
        being_seed._write(receipt, expected)
        return venv

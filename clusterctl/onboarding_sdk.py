"""Install a qualified Matrix wheelhouse offline into a body's private venv.

No seed code, account credentials, identity keys or model calls are involved.
The wheelhouse is covered by the receiving release's content digest.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from . import being_seed, onboarding_release
from .onboarding import OnboardingError, digest, private_directory

SCHEMA = "cluster-onboarding-sdk/v1"
MATRIX_COMMIT = "a1a70b6420692d19f85ad0edb945cba00c3f5459"
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


def interpreter(venv: Path) -> dict:
    """Observe the returned generation's actual interpreter without site hooks."""
    probe = ("import json,sys; print(json.dumps(dict(implementation=sys.implementation.name, "
             "version=list(sys.version_info[:3]))))")
    value = json.loads(_run([str(venv / 'bin/python'), '-I', '-S', '-c', probe]))
    if (not isinstance(value, dict) or set(value) != {'implementation', 'version'}
            or not isinstance(value['implementation'], str)
            or not isinstance(value['version'], list) or len(value['version']) != 3
            or any(type(part) is not int for part in value['version'])):
        raise OnboardingError('qualified_receiving_interpreter_required')
    return value


def runtime_imports(venv: Path, code: Path, *, code_uid: int = 0,
                    matrix_commit: str = MATRIX_COMMIT,
                    matrix_wheel_sha256: str | None = None) -> Path:
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
    with being_seed._locked(root):
        temporary = root / ('runtime-imports-' + uuid.uuid4().hex)
        building = not target.exists() and not target.is_symlink()
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
                                output.flush()
                                os.fsync(output.fileno())
                            destination.chmod(0o600)
            expected = dict(schema='cluster-onboarding-runtime-imports/v1', sdk_digest=digest(sdk),
                            files_sha256=digest(files))
            if building:
                for directory in temporary.rglob('*'):
                    if directory.is_dir():
                        directory.chmod(0o700)
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
            return target
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)


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

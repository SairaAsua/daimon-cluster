#!/usr/bin/env python3
"""Prune selected compiler caches and explicitly retired worktrees; dry run by default."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


PROCESS_SCAN = """
import json, os
from pathlib import Path
paths = set()
for proc in Path('/proc').iterdir():
    if not proc.name.isdigit() or int(proc.name) == os.getpid():
        continue
    try:
        for name in ('cwd', 'exe'):
            try: paths.add(os.readlink(proc / name).removesuffix(' (deleted)'))
            except FileNotFoundError: pass
        for arg in (proc / 'cmdline').read_bytes().split(b'\\0'):
            if arg.startswith(b'/'): paths.add(os.fsdecode(arg))
        for line in (proc / 'maps').read_text().splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6 and fields[5].startswith('/'):
                paths.add(fields[5].removesuffix(' (deleted)'))
        for fd in (proc / 'fd').iterdir():
            try:
                value = os.readlink(fd).removesuffix(' (deleted)')
                if value.startswith('/'): paths.add(value)
            except FileNotFoundError: pass
    except FileNotFoundError: pass
print(json.dumps(sorted(paths)))
"""


def process_paths(allow_privileged=False, proc_root=Path("/proc")):
    """Check process paths without logging their contents.

    The optional read-only privileged scan covers the entire host. Otherwise,
    inaccessible processes belonging to this user stop cleanup. Exited processes
    are ignored. Other users' directories are ineligible for cleanup.
    """
    if allow_privileged:
        # Fixed, isolated, read-only code. Deletion remains unprivileged.
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", "--", "/usr/bin/python3", "-I", "-c", PROCESS_SCAN],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode:
            raise RuntimeError("Process activity could not be checked")
        return {Path(p) for p in json.loads(result.stdout)}
    paths = set()
    for proc in proc_root.iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            if proc.stat().st_uid != os.getuid():
                continue
            for name in ("cwd", "exe"):
                try:
                    paths.add(Path(os.readlink(proc / name)))
                except FileNotFoundError:
                    pass
            for arg in (proc / "cmdline").read_bytes().split(b"\0"):
                if arg.startswith(b"/"):
                    paths.add(Path(os.fsdecode(arg)))
            for line in (proc / "maps").read_text().splitlines():
                fields = line.split(None, 5)
                if len(fields) == 6 and fields[5].startswith("/"):
                    paths.add(Path(fields[5].removesuffix(" (deleted)")))
            for fd in (proc / "fd").iterdir():
                try:
                    paths.add(Path(os.readlink(fd)))
                except FileNotFoundError:
                    pass
        except FileNotFoundError:
            pass
        except PermissionError:
            raise RuntimeError("Process activity could not be checked") from None
    return paths


def in_use(path, paths):
    return any(p == path or p.is_relative_to(path) for p in paths)


def old_enough(path, cutoff):
    """Keep symlinks, foreign-owned files and anything recently changed."""
    def eligible(entry):
        stat = entry.lstat()
        return (not entry.is_symlink() and stat.st_uid == os.getuid()
                and max(stat.st_mtime, stat.st_ctime) < cutoff)

    def raise_error(error):
        raise error

    if not eligible(path):
        return False
    for directory, dirs, files in os.walk(path, followlinks=False, onerror=raise_error):
        if any(not eligible(Path(directory) / name) for name in dirs + files):
            return False
    return True


def configured_path(value):
    return Path(value).expanduser().absolute()


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True,
        timeout=10, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    )


def worktrees(repo):
    result = git(repo, "worktree", "list", "--porcelain", "-z")
    if result.returncode:
        raise RuntimeError("Worktree inventory unavailable")
    entries, entry = [], {}
    for field in result.stdout.split("\0"):
        if not field:
            if entry:
                entries.append(entry)
                entry = {}
        else:
            key, _, value = field.partition(" ")
            entry[key] = value
    if entry:
        entries.append(entry)
    return entries


def validate_worktree(config, item, projects):
    repo, path = (configured_path(item[k]) for k in ("repo", "path"))
    roots = [configured_path(p) for p in config.get("worktree_roots", [])]
    if (repo.parent != projects or repo.resolve() != repo or path == repo
            or path.resolve() != path or path in (projects, Path("/"))
            or not any(path != r and path.is_relative_to(r) for r in roots)
            or not item["branch"].startswith("refs/heads/")
            or not item["commit"] or not item["integration_ref"]
            or float(item["retired_at"]) <= 0):
        raise ValueError("Invalid explicit worktree retirement")
    return repo, path


def unchanged_and_integrated(item):
    repo, path = configured_path(item["repo"]), configured_path(item["path"])
    entry = next((w for w in worktrees(repo) if w["worktree"] == str(path)), {})
    if ("locked" in entry or entry.get("branch") != item["branch"]
            or entry.get("HEAD") != item["commit"] or not (path / ".git").is_file()):
        return False
    branch = git(repo, "rev-parse", "--verify", item["branch"])
    status = git(path, "status", "--porcelain", "--untracked-files=all", "--ignored")
    integrated = git(repo, "merge-base", "--is-ancestor", item["commit"], item["integration_ref"])
    return (branch.returncode == 0 and branch.stdout.strip() == item["commit"]
            and status.returncode == 0 and not status.stdout.strip()
            and integrated.returncode == 0)


def retire_worktree(config, repo, path, integration_ref):
    projects, _ = validate_roots(config)
    repo, path = configured_path(repo), configured_path(path)
    entry = next((w for w in worktrees(repo) if w["worktree"] == str(path)), {})
    item = {"repo": str(repo), "path": str(path), "branch": entry.get("branch", ""),
            "commit": entry.get("HEAD", ""), "integration_ref": integration_ref,
            "retired_at": time.time()}
    validate_worktree(config, item, projects)
    if not unchanged_and_integrated(item):
        raise ValueError("Retirement requires a clean, unlocked, integrated worktree")
    items = config.setdefault("retired_worktrees", [])
    if not any(i["path"] == str(path) for i in items):
        items.append(item)


def validate_roots(config):
    projects = configured_path(config["projects_root"])
    if (projects == Path("/") or not projects.is_dir()
            or projects.resolve() != projects):
        raise ValueError("Projects must be a real directory")
    roots = [configured_path(p) for p in config.get("cache_roots", [])]
    # Validate the entire configuration before any deletion. No arbitrary paths,
    # environments, databases, snapshots or release builds are allowed.
    for root in roots:
        relative = root.relative_to(projects)
        workspace = root.parent.parent.parent
        owner = git(workspace, "rev-parse", "--show-toplevel")
        if (len(relative.parts) < 4
                or relative.parts[-3] != "target"
                or relative.parts[-2] not in ("debug", "dev-small")
                or relative.parts[-1] != "incremental"
                or root.resolve() != root
                or not (workspace / "Cargo.toml").is_file()
                or owner.returncode or not configured_path(owner.stdout.strip()).is_relative_to(projects)):
            raise ValueError("Only explicit Cargo debug incremental caches inside Projects are allowed")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise RuntimeError("Safe directory removal is unavailable")
    for item in config.get("retired_worktrees", []):
        validate_worktree(config, item, projects)
    return projects, roots


def clean(config, apply=False, now=None, active_paths=None):
    days = int(config.get("min_age_days", 14))
    cache_days = int(config.get("cache_min_age_days", days))
    if days < 7 or cache_days < 2:
        raise ValueError("Minimum worktree retention is seven days; cache retention is two days")
    max_cache_dirs = int(config.get("max_cache_dirs_per_run", 100))
    if not 1 <= max_cache_dirs <= 1000:
        raise ValueError("Cache removal budget must be between one and 1000 directories")
    projects, roots = validate_roots(config)
    cutoff = (time.time() if now is None else now) - days * 86400
    def scan():
        return (process_paths(allow_privileged=config.get("allow_privileged_process_scan", False))
                if active_paths is None else active_paths)

    if config.get("retired_worktrees") and active_paths is None and not config.get("allow_privileged_process_scan"):
        raise RuntimeError("Worktree cleanup requires complete host process inspection")
    active = scan()
    cache_cutoff = (time.time() if now is None else now) - cache_days * 86400
    report = {"apply": apply, "cache_dirs_removed": 0, "candidates": 0,
              "worktrees_removed": 0, "skipped": 0, "errors": 0,
              "free_bytes_before": shutil.disk_usage(projects).free}
    for item in list(config.get("retired_worktrees", [])):
        repo, path = validate_worktree(config, item, projects)
        try:
            if (not path.exists() or float(item["retired_at"]) >= cutoff
                    or in_use(path, active) or not old_enough(path, cutoff)
                    or not unchanged_and_integrated(item)):
                report["skipped"] += 1
                continue
            report["candidates"] += 1
            if apply:
                if (in_use(path, scan()) or not old_enough(path, cutoff)
                        or not unchanged_and_integrated(item)):
                    report["skipped"] += 1
                    continue
                # Git's non-forced removal performs its own final dirty check.
                result = git(repo, "worktree", "remove", str(path))
                if result.returncode:
                    report["errors"] += 1
                else:
                    report["worktrees_removed"] += 1
                    config["retired_worktrees"].remove(item)
        except (OSError, subprocess.TimeoutExpired):
            report["errors"] += 1
    for root in roots:
        if not root.exists():
            continue
        workspace = root.parent.parent.parent
        owner = configured_path(git(workspace, "rev-parse", "--show-toplevel").stdout.strip())
        if in_use(owner, active):
            report["skipped"] += 1
            continue
        for candidate in root.iterdir():
            if report["cache_dirs_removed"] >= max_cache_dirs:
                break
            try:
                if not candidate.is_dir() or not old_enough(candidate, cache_cutoff):
                    report["skipped"] += 1
                    continue
                report["candidates"] += 1
                if apply:
                    current = scan()
                    if (in_use(owner, current) or root.resolve() != root
                            or not old_enough(candidate, cache_cutoff)):
                        report["skipped"] += 1
                        continue
                    shutil.rmtree(candidate)
                    report["cache_dirs_removed"] += 1
            except OSError:
                report["errors"] += 1
    report["free_bytes_after"] = shutil.disk_usage(projects).free
    return report


def save_config(path, config):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(config, indent=2) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--retire-worktree", type=Path)
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--integration-ref", default="refs/remotes/origin/HEAD")
    args = parser.parse_args()
    if args.retire_worktree and (args.apply or not args.repo):
        parser.error("Retirement requires --repo and cannot be combined with --apply")
    os.umask(0o077)
    try:
        with args.config.with_suffix(".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            config = json.loads(args.config.read_text())
            if args.retire_worktree:
                retire_worktree(config, args.repo, args.retire_worktree, args.integration_ref)
                save_config(args.config, config)
                report = {"status": "registered_finished_worktree"}
            else:
                report = clean(config, apply=args.apply)
                if report["worktrees_removed"]:
                    save_config(args.config, config)
        print(json.dumps(report, sort_keys=True))
        return 1 if report.get("errors") else 0
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        # No process contents or private filesystem paths in the journal.
        print(json.dumps({"status": "kept", "reason": type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

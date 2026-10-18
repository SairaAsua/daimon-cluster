# Bounded development storage retention

`tools/storage_hygiene.py` maintains explicitly configured incremental compiler
caches and explicitly retired, clean, integrated worktrees. It is a finite
oneshot, dry-run by default. It never traverses the host looking for arbitrary
old directories to delete.

## Configuration and execution

```json
{
  "projects_root": "/srv/projects",
  "allow_privileged_process_scan": true,
  "min_age_days": 14,
  "cache_min_age_days": 2,
  "max_cache_dirs_per_run": 100,
  "cache_roots": ["/srv/projects/example/workspace/target/dev-small/incremental"],
  "worktree_roots": ["/srv/projects"],
  "retired_worktrees": []
}
```

Run `python3 tools/storage_hygiene.py --config CONFIG` to inspect, then append
`--apply` to remove eligible caches. Retain the existing scheduled service rather
than adding a second producer. An hourly timer with a five-minute timeout, idle
I/O priority, and 128 MiB memory limit is sufficient for bounded passes; record
actual completion results separately from timer enablement.

Only `target/debug/incremental` and `target/dev-small/incremental` in a Cargo
workspace inside the configured Projects tree are eligible. Nested workspaces
are supported. Root configuration is validated before any deletion. Symlinks,
foreign-owned files, and any directory containing a member changed within the
retention window are retained. Executables, dependency libraries, release builds,
source, sessions, databases and snapshots are outside this cache policy.

The host process scan includes command arguments, cwd, executables, open file
references and mapped files. A project in use is skipped, and activity is checked
again before each removal. A failed activity scan prevents further cleanup.
Configure the privileged read-only scan on a shared host; it uses fixed isolated
Python code and never logs process contents. Deletion runs as the owning user.
This is conservative observation, not a global build lock: applications can start
between observations. Removed incremental state is rebuildable, and the compiler
may need more time on the next build. Do not use this tool to prune runtime files.

Worktree retirement requires `--retire-worktree PATH --repo REPO
--integration-ref REF`. It retains the original seven-day minimum and additionally
requires an unchanged branch/commit, integration ancestry, no ignored/untracked
files, no lock, and Git's own non-forced removal check. Age alone never registers
a worktree for retirement.

A per-configuration flock prevents overlapping cleanup runs. Each run reports
removed/skipped/error counts and before/after free space without private paths.
The count budget applies to cache removals; timeout can interrupt a pass. Inspect
its exit result and next pass instead of claiming that all candidates were removed.

## Placement, compression and capacity

Large test datasets and retained qualification copies belong on a data volume,
through their owning configuration. Keep small control state and selected runtime
paths stable. Never globally redirect `TMPDIR`, XDG state or Cargo target paths:
existing harnesses, Unix sockets and tests can depend on those paths.

For Btrfs, compression is filesystem-wide across subvolumes and must be persisted
consistently for every mount. Enabling it affects new writes; it does not reclaim
all existing files. Recursive defragmentation can break reflink sharing. Avoid a
whole-filesystem rewrite, particularly while Incus shares the same volume.
See the [Btrfs compression documentation](https://btrfs.readthedocs.io/en/latest/Compression.html).

Compression and cache retention do not provide unlimited capacity. Keep root and
data-volume availability separately monitored, preserve pending/uncertain work,
and record remaining staging/release/backup retention gaps in the owning issue.
Do not resolve a storage incident through acknowledgment or changed thresholds.

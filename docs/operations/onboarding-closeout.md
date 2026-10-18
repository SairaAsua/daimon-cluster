# Close an operationally accepted onboarding

Use `tools/close_completed_onboarding.py` only after explicit human acceptance
of the already-working being. All stages before acceptance must be complete.
Human acceptance is recorded with its source reference and the original job;
it is never relabeled as an automatic test, and old hosted-checks remain intact.

Prepare each private plan with the existing host config, name, human acceptance
reference, and retained original archive on the data filesystem:

```text
python -m tools.close_completed_onboarding --config HOST_CONFIG --name NAME \
  --archive RETAINED_ORIGINAL --human-reference HUMAN_ACCEPTANCE --plan PLAN
```

Preparation verifies the complete original and mounted-view input against the
original manifest and the retained archive hash. The plan binds job semantics,
file metadata/inodes, manifests and exact received payload directories. A later
timestamp from an unchanged failed observation does not invalidate that binding;
changed steps, facts or input refuse it.

Apply only while the fixed onboarding worker is cleanly drained through its
existing `receiving_worker.WorkerPause` preservation control and unit selection
lock. Keep its existing durable pause/restoration journal. This pauses no Matrix
daemon, Telegram process, Codex session or global conversation. Restore the
worker's original state even if acceptance or retirement fails.

```text
python -m tools.close_completed_onboarding --config HOST_CONFIG --plan PLAN \
  --apply --receipt RECEIPT
```

The operator commits ordinary complete job/progress records and retires only
the two duplicate `received` trees. It preserves original archive/intake keys,
manifests, plan, matrix/public account/connection data, runtime generations,
signed authority, home, native history and memory. Read-only input mounts may
remain as small metadata mounts because existing services retain their plan
argument there. Do not remove the whole mount or rewrite service definitions
merely to rename it. Active-file references and nested filesystem crossings
refuse retirement.

The same exact plan/receipt resumes an interrupted acceptance or partial payload
retirement. Retained preimage and explicit human provenance distinguish it from
automated checks. Do not restore the old pending job while its duplicate inputs
are retired: deliberate reinstallation first requires rematerializing the
original immutable input using the preserved export and owning intake route.
Software rollback does not undo human acceptance or restore old job journals.

Current candidate receiving maintenance uses `HostBackend._receiving_base` and
the receiving body's retained plan/genesis; it does not reopen participant
uploads. Keep its owner grants, current admission, qualified code/SDK, original
public mounts and native tooling adoption. Native skill updates remain separate.
Legacy no-candidate onboarding repair may still require the original upload;
use the current supported maintenance route for existing accepted bodies.

# Readable Tribu SDK successor

Parent: [Matrix #287](https://github.com/AlterMundi/daimon-matrix/issues/287).
Rendering and signed presentation installation are owned by Matrix. Cluster
selects the exact executable SDK and maintained helper on the existing bodies.

## Preserve the receiving context

The original SDK `196ec7219f954cf4e514a1f61ae72eb3451d851e` remains
`PREVIOUS_MATRIX_COMMIT`: it is the immutable original receiving plan's
artifact, not the most recently running generation. Keep every prior selected
runtime and dependency environment for rollback. Changing that original pin to
the currently running SDK would invalidate legitimate receiving history.

Build the replacement wheelhouse with `tools.build_onboarding_sdk.py` from the
exact Matrix commit declared in `onboarding_sdk.MATRIX_COMMIT`. It is a closed,
hash-locked public artifact. `onboarding_code_successor.build` supports an
explicit SDK successor against the ORIGINAL base and verifies that all original
non-runtime context remains byte-identical. `onboarding_sdk.install` installs a
new content-addressed environment and validates every installed wheel byte;
never repair or overwrite a completed generation in place.

SDK installation/preflight must not run startup hooks or an unverified installed
`pip`. Use the qualified interpreter's ensurepip wheel in a hook-free `-I -S`
process, with an explicit private prefix. The SDK dependency check reads installed
metadata from an explicit directory and uses the bootstrap reader; it does not
add that directory to executable import paths. Missing or conflicting dependencies
still fail. A completed generation remains read-only; after an interrupted install,
only that incomplete dependency generation may be prepared again.
These checks prove installed artifact/dependency integrity, not an observed loaded
receiver. The compatible-reader probe, selected authority/application and actual
receiving readiness remain distinct stages under Matrix #337 / Cluster #232.

Receiving update preparation uses `onboarding_code_successor.plan_update` and the
existing `OperationJournal`. It binds the approved manifest digest and complete
pre/post-vector hashes in immutable intent, then checks returned retained vectors.
An exact completed retry returns its original row; altered vectors, conflicting
pending updates and degraded/compensated attempts cannot reopen effects. Apply
and resume must use those retained vectors under actual selection/writer locks.
Preparation itself does not select code, accept authority, load a receiver or
enable egress; actual adapters and readiness/communication remain #232 work.

`onboarding_receiving_update.preflight` consumes that operation's approved external
Matrix release manifest and exact receiving-code digest. It verifies the manifest
before using it to select executable bytes, checks the shared wheel and exact
per-receiver code selection, and executes only the qualified pure contract modules
in a hook-free `-I -S` process. The candidate package initializer, installed site
hooks and dependencies never execute in this probe. The manifest is kept outside
the code artifact to avoid a circular pair of content hashes. A new SDK revision
requires both its revision and exact approved wheel hash; a version label alone
cannot relax the historical pin guard.

`prepare_sdk` then uses the existing offline installer and actual installation
receipt. A hook-free probe through the returned generation's actual interpreter
must match the assessed implementation/version, including on a completed retry;
a compatible pure-Python wheel does not prove that this interpreter is current.
Mismatch refuses preparation without replacing the completed generation.
Exact retries observe the same content-addressed generation and preserve
old environments. Both return `receiving_readiness: unobserved`; this checks only
code/SDK integrity and candidate support. Selected worker/owner-client/Telecodex
roles are explicitly listed as unverified, not silently counted as qualified.
Actual current-selection/roster CAS, authority/application/store preflight,
adoption, service load, egress and communication remain separate controller stages.
Neither helper opens native state, rotates identity, restarts services, or modifies
the independent provider account and native conversations.

An explicit V4 runtime successor pins the approved SDK revision and exact wheel
inside its receiving-code digest. The external Matrix manifest pins that digest;
no circular manifest pointer is embedded in the code. The original base and
previous SDK digest remain frozen, and all original non-runtime context remains
byte-identical. Legacy V1/V2/V3 behavior stays explicit. A separately selected
Telegram component is unchanged unless a combined successor explicitly includes it.
Target launch and SDK preparation resolve this exact selected generation rather
than reporting the historical default pin as if it were current.

V4 runtime startup uses a closed import tree derived from the exact qualified
wheels inside the existing SDK generation. It preserves the installed environment
and its receipt. Full file/directory validation rejects additional or changed
import bytes, and dependency validation uses this tree itself, not extra installed
distributions. Nested directory entries are persisted before publication. The
initial maintained bootstrap, SDK reexec and admitted child use hook-free startup;
the latter two restore the selected prefix and use only approved Cluster code,
this verified tree and trusted standard-library paths. Bytecode lookup is redirected
outside existing caches and writing is disabled. Matching a venv prefix alone does
not establish qualified startup. The interpreter/code remain trusted; this is not
a sandbox or a new runtime identity.

`onboarding_service.select_entrypoint` compares the exact protected predecessor
under the same kernel lock used by initial guest installation and Source unit
registration. It changes only ExecStart, retains original bytes and modes, rejects
a newer selection, and recovers replacement-before-ACK without repeating it.
A successful retry also re-establishes directory durability. It reports file
selection with `loaded_readiness: unobserved`: no systemctl, native writer,
authority adoption, account update or model turn is invoked by this helper.
The owning journal/controller still coordinates cohort generations, real service
drain/load/readiness and forward authority/application recovery before activation.

`apply_host_selection` applies the retained operation's full runtime-selector
projection to its exact host configuration. The complete frozen predecessor is
compared under the existing jobs-parent and every extant job kernel lock. A newer
selection or newly added receiver is never overwritten by a stale update. These
locks fence first submissions and ongoing ticks; each worker backend is resolved
inside its job lock, using the current fully validated runtime selection.
Warm workers refresh selectors without moving private roots, account/admission,
Telegram or other process settings. Non-runtime changes require their own explicit
worker lifecycle rather than silently changing a running process's bindings.
Home-provider calls use a fresh backend inside the same job ownership, including
their callbacks independent of still-pending acceptance. Cache loads bind the
loader's own protected read to the exact expected configuration, rejecting ABA
changes rather than caching a different set of process roots.

Selection enters runtime-dispatching before atomic publication. Replace-before-ACK
recovery observes the exact file and persists directory durability without repeating
replacement. Recording its observation uses a journal compare-and-swap, preserving
concurrent stage evidence; a conflict is retried from retained state. This helper
owns the operation's kernel mutation lock through validation and publication;
all journal advances, including abandonment, take that lock. Reentrancy belongs
only to the same journal/controller, thread and process, not a forked child.
This prevents cancellation from crossing a still-running selector effect.
The helper
does not complete the operation or establish loaded/readiness/communication evidence.
Later controller stages must preserve these frozen vectors and ownership fences;
new admission must use the same jobs locks when altering receiver selectors.

Retain the actual currently selected Telegram artifact. Where Telegram already
has its own qualified successor, keep that independent selection. If building a
combined V3 successor, pass its current qualified artifact explicitly: building
only from the original base must not select an older human-facing consumer.
No re-export, enrollment, identity rotation, bot replacement or reset of native
stores follows from this SDK upgrade.

Source keeps the exact installed VCS-commit guard; receiving bodies keep the
hash-locked wheelhouse and installation receipt. Both use the same declared
Matrix commit. The native peer helper preserves upstream provenance and qualified receiving
extensions, with its exact maintained hash; the owner-client installer retains
its own independent artifact provenance. The installer's existing `--refresh-guidance-plan` changes
planned instruction bytes without replacing the connection's command, channels,
capability or request history.

## Qualification and live selection

The SDK CI profile runs on the actual Python 3.13.5. Its closed file boundary
covers this exact dependency pin, the native helper, installed-byte integrity,
SDK/runtime successors, actual local native services, custody/authority, owner
separation and shared host/API contracts. Unrelated dependency, authority,
provider or target runtime changes still select broader coverage. Historical
container recovery and offline-release sandbox trials are not this presentation
increment's deployment evidence.

Record prior and candidate SDK/runtime digests, current supervisor commands,
label and guidance transactions, signed visibility backups and shared reply
correlation mounts before stopping a native Matrix service. Validate the new
SDK and the existing signed application before selecting them. Select a body's
SDK/runtime and signed presentation as one coherent finite operation, restart
its existing supervisor, and inspect actual readiness. Keep private credentials
and proof keys outside shared correlation metadata. Do not restart the owner's
Telegram consumer merely to change Matrix presentation.

Rollback selects the preserved preceding executable environment and signed
installation together, preserving subsequent receiving writes and all native
journals. A checkout test, published package or installed wheel is not live
readiness. The owning Matrix epic records actual cohort acceptance, confirmed
Telegram replies and native receipts after the authorized bounded demonstration.

## Passive paired-human Tribu application (phase 4)

Parent: [Matrix #288](https://github.com/AlterMundi/daimon-matrix/issues/288),
roadmap [#289](https://github.com/AlterMundi/daimon-matrix/issues/289), deployment
[Cluster #188](https://github.com/nicoechaniz/daimon-cluster/issues/188).
The SDK's `docs/runbooks/tribu-human-mentions.md` owns the closed configuration
contracts, passive adapter and manual owner-client operations.

Use one supervised passive consumer for the existing shared visibility bot,
separate from every private Telecodex consumer. Qualify its identity, selected
chat and absent webhook without polling during staging; startup stops on a
conflicting consumer. Place its private journal, pinned TLS configuration and
per-being scoped credentials on the existing host/container route. Reuse each
body's current public authority, native socket, own public echo catalogs and
existing private-bot paired-human ID. A shared harness account, global human
allowlist, group membership or display name does not grant cross-being access.
Never collect resolved bot or human data again from participants.

Install a private owner-client configuration and discoverable manual guidance
for each body. An explicit `read` resolves only that human's pending parent IDs
against selected own public proof catalogs and exact authored events. Explicit
`reply` uses the running native daemon to sign the intent; each public part
requires confirmed Telegram parent evidence. It keeps conversation in the
requesting session and adds no callback or dependency to native delivery.
Unresolved targets remain pending; dispatched but uncertain parts are never
blindly retransmitted. Neither receiving nor querying chooses a native session,
opens model inference or imports memory. Dedicated topics, attention schedulers,
compaction renewal and cross-human permission grants remain later increments.

Before selection, retain guarded current unit/config bytes and actual SDK/runtime
digests in one protected cutover plan. Review that exact plan, qualify the adapter
with `serve --check`, and select the immutable SDK generations and owner clients.
Do not restart private Telegram consumers. Verify live queries under each owner,
correct rejection of another human, no automatic turns, and retry stability.
Genuine human acceptance is separate evidence and cannot be fabricated from
synthetic fixtures.

Rollback stops the passive consumer and selects the retained compatible SDKs.
Preserve the human journal, pending/revision history, cursor, reply/outbox states,
prepared owner requests, native ledgers/proofs and all private Telecodex histories.
Never replace a publication database with an older snapshot after an effect.
Forward restart resumes the same journal.

### Optional passive-service network route

Owner clients in Incus guests need an explicitly selected host-service route.
The current bridge input policy rejects every host port not listed before its
container drop. A working host-local query does not prove guest reachability.
Use a dedicated rule for the passive adapter's selected bridge gateway and TLS
port, not a proxy through the legacy broker or a management-rule modification:

```text
iifname "incusbr0" ip daddr <BRIDGE_GATEWAY> tcp dport 9491 accept comment "daimon-tribu-human"
```

Keep this optional until the adapter is selected. Qualify actual guest TCP and
pinned-CA queries for each owner. A reviewed operational candidate inserts this
one rule immediately before the existing bridge drop and persists the same line
with exact before/after file hashes. Compare the existing rule expressions,
handles and chain policies before/after, excluding only the new comment. Do not
reload the whole firewall, flush rules, restart nftables, rewrite the template
onto a divergent host or alter SSH, management, bridge isolation or forward
policy. Rollback deletes only the new rule and restores its retained config
bytes; retain every other service's rules and all Tribu journals.

For user-systemd deployments, `PrivateTmp=true` can put ancestor directories in
a namespace with unmapped root ownership. That conflicts with the existing
protected-file reader. Select this unit without `PrivateTmp`; keep owner-only
storage, `UMask=0077`, `NoNewPrivileges` and the package's original path guards.
The adapter does not use temporary storage. This is a service configuration
correction, not a reason to weaken file validation.

Manual owner command syntax is `reply --source ID --revision REVISION --id UUID
--text TEXT`, `retry UUID`, and `publication UUID`. Installed local guides must
match the selected package parser. Keep the operation UUID on retries.

## Peer delivery recovery SDK

The selected SDK includes the bounded diagnostics and exact logical recovery
from [Matrix#317](https://github.com/AlterMundi/daimon-matrix/pull/317).
Source uses its real VCS installation provenance matching the declared pin;
a plain wheel environment is qualified for receiving use only when paired with
the supported hash-locked wheelhouse and installation receipt. Keep both guards
and the original receiving SDK. Native stores and proof keys remain intact;
diagnostic sidecars carry observations without granting transmission authority.


## Membership group default — 2026-10-13

Matrix #151/#198 and merged #330/#332 own the conversation contract. Current
deployed SDK source: `a1a70b6420692d19f85ad0edb945cba00c3f5459`. CompAII, Eko and Oliva
share one signed group, with authenticated receipts for the three VPS bodies.
One message freezes all active Root bodies, including unavailable siblings; one
Tribu publication represents that message. A transport ACK is not delivery.

The receiving signed selection names the group application, visibility and native
socket. Both incoming/outgoing channels are `tribe`. Owner clients derive this
selection, not old `peer-in`/`peer-out` IDs. Archive obsolete bindings and proxies;
never alias old directed send IDs into group requests. The worker recognizes this
signed selection before examining the historical pair installer. An absent group
is an explicit enrollment gap, never permission to reconstruct Source/member
pairs. Further portal admission must invite/accept in the existing Tribe and
qualify its shared Root inventory/roster transaction. It is not yet an automatic
future-member admission claim.

Preserve each original receiving release as the immutable successor base, and
record the actual selected runtime per body in the host worker configuration.
Otherwise later reconciliation can reselect stale SDK/code. Worker code uses a
matching genuine VCS SDK installation; receiving bodies use the corresponding
hash-locked wheelhouse. Update these selections together, retaining native apps,
visibility, custody and journals. Preserve every non-selection worker unit setting,
including its home-placements argument. A worker restart does not authorize
interrupting human sessions or a global Stop.

After accepted membership/governance changes, recovery finishes forward through
compatible group artifacts. Old terminated memberships/grants and archived pair
defaults are not an operational rollback. Historical messages remain readable;
exact expired retries return their retained outcome without new transmission.

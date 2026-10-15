# Receiver-compatible Matrix updates

Current coordination: [Matrix #336](https://github.com/AlterMundi/daimon-matrix/issues/336),
[Cluster #232](https://github.com/nicoechaniz/daimon-cluster/issues/232).
The original readable-presentation increment is retained under
[Matrix #287](https://github.com/AlterMundi/daimon-matrix/issues/287).
Matrix owns signed messaging and presentation; Cluster selects the exact
executable SDK and receiving helpers on the existing bodies.
The current source candidate pins Matrix `0dc0b555939b16a1150a220a366a6911a5ae9c28`.
The three-body production selection remains its separately recorded predecessor
until receiving adoption succeeds.

## Execute from the next missing effect

Use one current operation and one reusable integrated receiving scenario. Keep
its candidate, completed effects, reusable evidence and next missing effect in
the existing work record. Dated trial scripts are evidence, not deployment entrypoints.

| Maintained API | Responsibility |
| --- | --- |
| `prepare_sdk` / `preflight` | Prepare exact code and compatible installed SDK |
| `SourceBootstrapController` | Resume the same Source lifecycle operation |
| `prepare_guest_bootstrap` / `GuestBootstrapController.execute` | Resume the same guest root/owner operation |
| `CohortController` | Select qualified required receivers and verify the cohort |

These responsibilities distinguish evidence; they do not require another manual
check, review, backup, report or fixture for every label. Reuse completed effects
and valid tests. A routine software correction does not require a new identity,
credential publication, signed authority transition or unrelated service restart.

Finish a coherent source delta, run its affected checks once and publish it.
Reuse existing builds/reviews/CI where their inputs are unchanged. After a code
change, qualify the affected behavior and its integrated receiving path; do not
repeat unaffected historical journeys or create a fresh fixture for each stage.
Unknown shared-code deltas keep broader coverage. Correct a missing CI scope
mapping when the existing selected job already exercises the changed contract.
A content-verified literal SDK pin update combined with an already recognized
receiving change composes their existing tests, including the full SDK contract.
It does not trigger unrelated full-suite/physical workflows merely because both
changes belong in one release. Executable drift in a pin file or unknown/sensitive
remaining changes still selects broader coverage.

On failure, inspect the exact controller stage, retained result and current
process. Resume that operation through the maintained controller. A timeout
alone authorizes neither replay nor a new identity. Do not benchmark unrelated
substeps, build a parallel diagnostic runner, or repeat preparation to make an
uncertain outcome look successful. Persist a successful effect before optional
follow-up checks; an auxiliary retry probe must not silently shorten the supported
operation budget. Resolve service/socket/process names from the retained binding,
not a guessed conventional name. Use existing bounded diagnostics to resolve
the concrete missing fact, then continue from it. An early missing socket is
not a reason to restart a process whose exit has not been observed.
For a `Type=simple` synthetic baseline, wait for its actual native socket while
pinning the same service process before freezing the predecessor. A successful
systemd start is not socket readiness. Capture the existing bounded CLI diagnostic
on the failing call before coupled cleanup removes that process; a later call
against a stopped fixture cannot diagnose the earlier live refusal.
Keep the same finite synthetic service/admission scope alive across a pending
startup observation. Baseline preparation may finish before freezing its owner
deadline; individual native observations retain their supported bounds. Re-poll
the retained start through the controller while its exact manager/process and
original operation remain valid. Clean up on completion, an actual refusal or
the outer fixture deadline, rather than stopping a still-loading process merely
because one observation window expired. Cleanup must still stop owned native
units before retiring their finite admission producer.
Bounded native guest observation also waits for initial socket publication within
its original remaining deadline. That wait starts no process and grants no
readiness: the same-connection responder, admission parent, selected unit and
loaded code are still verified afterwards. Ordinary status without a deadline
keeps its immediate missing-socket refusal. Do not replay a retained native start
or mint another controller because its first socket observation raced startup.

Use the selected SDK for both the observer and receiver; validate that binding
before lifecycle effects. Keep lifecycle journals on their actual owners.
Root reads Source lifecycle proof through `SourceGroupClient(lifecycle_journal=...)`
and its existing owner CLI/UID drop, never a copied journal row or private custody.
Within one activation invocation, the controller reuses that exact owner/recipe's
retained lifecycle projection; another invocation reads it again. Live process,
identity, admission, roster and credential validity are still observed each round.
A completed selection retry compares the gate already returned by the same
qualified all-required observation, avoiding another cold status helper per body.
Neither reuse extends the observation window or caches receiving readiness.
Preparation's barrier also reuses the process/gate authenticated by that same
all-required adoption round. Do not launch a second cold status helper for the
same proof. The original freshness window, exact process/head checks and native
roster CAS still apply; later invocations observe again.
Positive controls use `prepare_apply_control`: one qualified owner invocation
retains and applies the same exact request under the existing private lock.
Expiry between those effects refuses application; a lost reply retains the exact
request for reconciliation. Separate prepare/apply verbs remain for recovery.
No proof-window or credential horizon is widened to compensate for setup cost.

Prepare expiring fixture controls immediately before their use. If an unrelated
urgent repair intervenes, preserve the scenario and completed effects instead
of discarding them. Do not extend an expired frozen authorization; recover using
the supported procedure for the exact retained state, not a new birth ceremony.
The #355 successor separates the controller grant lifetime from the finite
update deadline. Freeze selects `issue` when absent, `preserve` when still live,
or `renew` only for an expired active-status optional V8 controller with valid
original owner roles. Renewal requires the qualified native SDK before any
stop; the operation deadline must fit the remaining owner authorization horizon.
It uses the existing owner/root transaction and lifecycle controllers, retaining
identity, controller key/methods and credential history. It does not grant
revoked roles, repair expired original roles or create automatic renewal.

Keep the original expired operation and its actual load receipts unchanged. A
new explicitly authorized recovery lifecycle links the retained body/process
state; it does not extend the old frozen deadline or relabel its load.
If that authenticated frozen Source was stopped after preparation, the existing
preserve/renew controller observes its exact inactive unit, predecessor exit and
writer fence directly. It records exit without inventing a stop request. Do not
restart the predecessor only to stop it again; fresh publication still needs the
original operation's unexpired owner authorization and unchanged inputs. Source
renewal rebinds the existing base visibility installation to the new full runtime
bundle, then qualifies an actual new receiving load. Guest normalization accepts
an authenticated strictly advancing custody revision, rather than assuming only
one controller issuance ever occurred. This is historical comparison, not
control readiness; native transaction and owner/root journals retain the exact
publication lineage. [Matrix #355](https://github.com/AlterMundi/daimon-matrix/issues/355)
tracks integrated receiving acceptance. No routine rebirth is required.

For source qualification against a Matrix successor, select that checkout for
Python imports explicitly; do not silently test the installed production SDK.
Use the repository's `tools/check_rc_types.py` typing boundary, which intentionally
skips unrelated dependency implementation. A bare unrestricted mypy run changes
that contract and can report failures in the old installed SDK or unrelated
cryptography versions. Host ceremony fixtures require the exact VCS-pinned host
installation; a closed receiving SDK has offline installation receipts instead
of VCS provenance and is a different boundary. Use a matching host environment or
the selected CI job. Never replace a live venv or manufacture direct_url metadata
to prepare a source test.

The guest-owner module really requires UID1000. CI maps its current disposable
runner user to kernel UID/GID1000 in a user namespace, retaining the same interpreter,
SDK and filesystem ownership. The CI-only `tools/ci_guest_owner.py` parent maps
host root to0 and the actual runner to1000 through its child's kernel UID/GID maps,
then drops the child to1000. Mapping only the runner leaves ancestor root ownership
unmapped and correctly fails protected-path validation. `newuidmap` would instead
require unrelated subordinate-ID grants. Do not change accounts or ownership to
work around either failure. The regular test pass deselects that module; its
canonical-owner pass runs it once. Do not change the runtime owner guard or fake
geteuid to make it pass. Slow-daemon tests delay the actual pinned child process;
a forwarding proxy changes SO_PEERCRED and is not the same native responder.
Changes to the already-covered code-successor test module keep receiving coverage;
they must not select unrelated physical/archive qualification. The receiving SDK
suite previously took804 seconds before the newly enabled canonical-owner pass;
budget the selected suite and setup from actual job duration. The current full
job has a30-minute cap; this does not alter runtime observation deadlines.
Qualified `sdk-prepare` installs and verifies the closed runtime import tree before
returning ready. Do this dependency preparation before freezing a finite owner
operation or stopping a receiver; the first import-tree construction must not
consume the bounded live observation budget. Subsequent calls verify and reuse
that immutable tree. A failed preparation is not a reason to recreate custody,
relax file durability or increase the live-control deadline.
Own a finite synthetic admission producer and its named synthetic native unit in
the same qualification scope. Stop that unit before retiring the producer; on
interruption reconcile and close the unit as part of the same cleanup. Leaving
its production-style restart policy running without admission repeatedly starts
expensive SDK qualification. Preserve fixture files and receipts; this cleanup
never means stopping real bodies or discarding an uncertain operation.

Before a real communication-interrupting operation, prepare its exact candidate,
required receiver readiness and recovery, and obtain scoped human authorization.
Every global Stop independently requires fresh explicit human consent. These
requirements remain; they are not permission for repeated approval rounds.

Inspect the Source's effective systemd configuration during preparation. The
maintained Source selector owns one unit; historical ExecStart override stacks
must not hide a selected command. If such overrides exist, prepare a consolidation
of the exact effective entrypoint and every retained non-entrypoint directive
into that unit. Preserve the original unit and override bytes, bind their hashes
and the live invocation, and validate the candidate with systemd before applying.
Apply that normalization only within the authorized rollout and shared selection
lock, then freeze the actual normalized manager state through the ordinary
controller. Never fake an inspection, ignore a live override or add another
override to out-sort the previous ones. Subsequent updates use the single unit.

The read-only guest bootstrap observation verifies the current signed public
bundle, operator/client binding, protected target plan/genesis and actual native
status/admission on the same observed process. It does not reopen custody or
reconstruct the archived bilateral enrollment. Protected input drift is refused;
present loaded-base metadata must match the captured bundle. A legacy daemon
without that metadata proves only authenticated predecessor presence, never a
loaded candidate or receiving readiness. Mutation, publication, startup and
historical inspection retain their original full validation. Keep the same
bounded deadline rather than extending it to accommodate duplicate preparation.

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
enable egress. The maintained controllers own subsequent effects; their complete
receiving/communication acceptance and live selection remain #232 work.
After a failed cohort has confirmed every sender disabled and released its native
reservations, the owning orchestrator must also close that abandoned journal
operation through `OperationJournal.advance(..., 'compensated')`, preserving its
observations and clear receipts. This compensates sender activation only; it
never claims software or accepted authority was rolled back. An uncertain or
partially disabled cohort stays open for reconciliation. Do not change the target
or discard the journal merely to bypass its contradictory-operation guard.

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

The existing production Source VCS installation retains its exact commit guard.
Qualified Source receiving candidates also support the closed wheelhouse and
installation-receipt profile used by guest candidates. Each selected profile
keeps its own verified provenance; do not report an unselected candidate as
deployed. Corresponding sender/receiver selections use the declared Matrix commit. The native peer helper preserves upstream provenance and qualified receiving
extensions, with its exact maintained hash; the owner-client installer retains
its own independent artifact provenance. The installer's existing `--refresh-guidance-plan` changes
planned instruction bytes without replacing the connection's command, channels,
capability or request history.

## Existing controller software adoption

Existing Codex tooling adoption is a receiving requirement, not first-install
onboarding. Each cohort receiver explicitly selects `tooling`: either
`{"profile":"matrix-only"}` for a body with no native harness, or a protected
Codex recipe with `profile`, `attachment`, `codex_home`, `connections`,
`native_endpoint`, `native_threads` and `tribe_channel`. Paths select existing owner-local
resources; thread IDs select existing native contexts. Missing selection is an
error, never implicit Matrix-only acceptance. No first-loaded-thread fallback,
thread creation/resume or model turn qualifies a recipe.

`CohortController` uses the existing owner route to reconcile tooling before its
finite reader round. The installer retains the exact operation/file transition;
the receiving journal retains its public result. Each subsequent qualified
identity call checks native state in that same owner process. A drifted
configuration, binding, selected SDK, endpoint/process, context or tool schema
cannot reuse earlier acceptance. A server-only catalog is labelled separately
from selected existing-context acceptance. Disabled/restricted roles stay intact
and cannot count as usable tools. Source-qualified implementation alone is not
actual receiving adoption; qualify the complete candidate before deployment.
Do not rerun `OwnerClient.install` over personalized AGENTS or treat a selected
Matrix daemon as proof that the harness selected its matching tools.
Reuse the existing installer history and receiving operation for exact connection
and native-role command successors. Preserve binding/capabilities, request IDs,
personal guidance and every optional native setting, including disabled intent.
Use the supported native config writer for command/args only and the qualified
closed SDK launcher. Prepare expensive catalog work before the receiver freshness
round; retain bound evidence and check drift rather than repeating cold discovery.
Use `prepare_apply_control` for revoke, replacement, selection and repair controls.
They retain the same durable request under one owner lock. Splitting preparation
and application across cold qualified owner processes can age a new request beyond
its native authentication window before its first dispatch; do not increase that
window or regenerate an uncertain request to conceal the delay.
For an explicitly selected, already prepared qualified guest candidate, status,
identity and control calls enter its existing closed SDK interpreter directly.
The host derives its owner-private generation path from the verified public SDK;
Target still validates installed dependencies, startup context and receiving state.
SDK preparation/observation and bootstrap retain their original system-interpreter
route. Missing preparation refuses without installation or fallback. This removes
duplicate setup; it neither extends freshness nor proves a timeout's lower cause.
All-required identity rounds overlap at most three independent receiver queries.
Lifecycle/preflight preparation and all validation stay on the coordinator;
every started query is joined before controls, journal writes or failure repair.
The whole round shares one deadline. A failed query stops further submission,
and later queries never obtain a fresh window. Sender controls remain sequential.
`config/mcpServer/reload` refreshes only the addressed App Server's threads.
A fresh config-only catalog probe cannot prove existing sessions reloaded.
Keep unavailable native-instance routes explicit; neither console fallback nor
another service restart establishes native-tool acceptance. Native MCP metadata
binds the actual qualified code/SDK and attachment; identical tool names from an
old process do not prove the successor loaded. The selected Tribe binding leg
(single `tribe` or explicit Multi alias) must resolve to this authenticated
receiver/runtime and group socket; an archived bilateral leg cannot substitute. The SDK wheelhouse includes pinned
`websockets==15.0.1` under its existing manifest/hash lock. Codex's CLI proxy only
relays bytes; shared control sockets require WebSocket framing. Reuse the library,
not a new hand-written protocol or an historical task dependency directory.

Inspect a catalog with the same closed SDK/import tree that launched its tools.
A development interpreter may expose different contracts and manufacture a
catalog mismatch. Inspect the actual tool names, schemas and implementation
version before classifying a refusal as a product defect; do not alter the
candidate to accommodate a mismatched diagnostic environment. Codex's advertised
endpoint may be an owner-controlled symlink: pin its resolved socket and peer,
and refuse a changed selector or target during the observation.

Freeze controller `mode` before any interruption. `issue` retains the original
first-controller stage/publication and its exact recovery; absent mode in old
operations still means `issue`. A retry never switches branches because its own
publication made a controller appear.

`preserve` requires an already authenticated controller and pins immutable runtime,
custody and client bytes, signed group inputs and the existing visibility. Check
its finite authorization before stopping. An expired controller cannot qualify
control in `preserve` mode; use the explicit optional-controller `renew` route
above when its original roles remain valid. Expired original roles remain refused.
Under native parent/writer ownership,
after predecessor exits, validate the unchanged runtime in the native isolated
clone and retain a full quiescent inventory as `owner_preserved`. This does not
stage/publish authority, increment custody, reissue visibility or claim readiness.
Source and guest use the existing selected-unit/start/load observations; a lost
start reply observes that process rather than stopping it again. Database activity
after genuine startup is reconciled through its loaded proof, not by comparing
mutable stores against the pre-start inventory. A replacement still needs its
own empty gate/revoke before the cohort can activate positive readers.

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

Rollback selects a preserved executable environment compatible with the current
accepted authority, custody and signed installation. Never restore old authority
or custody to accommodate an incompatible observer. Preserve subsequent receiving
writes and all native journals. A checkout test, published package or installed wheel is not live
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

# Durable receiving jobs

The complete onboarding task is tracked with cohort #32 and Matrix #263.
The intake and the receiving worker are separate processes. An uploaded archive
or a successful preparation never means that the hosted embodiment is active.

## Current implementation boundary

Use [RESUME.md](../../RESUME.md) and the
[shared architecture index](https://github.com/AlterMundi/daimon-matrix/blob/main/docs/current-architecture.md)
for current receiving selections. CompAII, Eko and Oliva have a deployed signed
Tribe group; automatic future portal-to-group enrollment remains #227. Earlier
phase-specific preparation receipts below do not replace current readiness.

`clusterctl.onboarding` records an exact host-authorized plan and eight ordered
steps: environment, context, memory, Matrix, access, Telegram, welcome and
acceptance. Web progress reads the same job's closed projection through
`GET /v1/seeds/{seed}/onboarding`; it does not execute host operations.

Before installing Source inheritance, the worker publishes an owner-private
review of the exact plan and qualified inheritance text. The same portal and
agent API expose `GET /v1/seeds/{seed}/onboarding/review`; POST records the
human/daimon pair's acknowledgement and whether to continue an existing signed
Matrix identity or prepare its first one. `clusterctl seed review` and
`clusterctl seed consent` call the same functions. The original SOUL remains
unchanged. An existing identity choice requires native continuity evidence;
it never authorizes another root. Custody creation is still a separate native
authority operation, not an effect of submitting this decision.

An optional private operator custody policy adds `matrix_custody` to the same
review, with its exact policy digest and explicit holder notice. Only a pair
decision on that expanded review and a current operator policy issue an exact
first-identity custody grant. The grant attributes the actual Source binding
and preserved owner instruction digests. An earlier inheritance-only decision
does not authorize custody; changing or revoking policy prevents reuse. An
`existing` decision never issues a first-genesis grant. Publication creates no
keys: the existing native worker adapter performs the resumable ceremony.
Root and Recovery packages occupy separate stores and processes on this host;
they share its administrator and are not independent administrative custodians.

When the local human has already confirmed a pair's complete approval, the
operator can publish a separate `owner_approval_policy`. It pins the exact
reviewed Source text and custody policy, names the receiving pair and identity
mode, and retains the digest of the private human instruction. The worker
records the actual delegated author in its own store; it does not forge a
participant intake submission. A participant's own decision takes precedence.
Changed Source or custody terms, an unlisted pair, or revocation prevent reuse.
The owner portal reports the worker's current recorded approval and attribution.

Accounts retain independent native homes and session history. The account
configuration tool can authorize selected pairs to reuse an existing provider
login with `--shared-pair BEING=OWNER`, a private `--instruction` and its numeric
owner UID. Without that explicit policy the existing device-login flow remains
available. The worker checks the selected account, transfers only its private
provider credential through a temporary read-only mount, preserves foreign
receiving credentials and reconciles an interrupted atomic installation. No
Matrix custody, memory or conversation history is part of this transfer. Real
provider inference remains required before access readiness is complete.

The private intake policy may prepare the empty 30 GiB environment before the
pair reviews inheritance. This is resource authorization only: context and
Matrix stages still wait for the exact review. The worker publishes its actual
completed environment step rather than making the human wait to approve an
empty volume. Missing uploads do not enqueue a job for sleeping participants.

Worker software upgrades use `--replace-unit-sha256` with the exact installed
unit digest. The installer preserves its predecessor, serializes publication,
and refuses a different unit. Updating the worker does not change the frozen
plan, identity, receiving memory or native conversation state.

Optional `ssh_ingress` names a private operator policy with the host name,
IPv4 listen address and a bounded port range between 20000 and 50000. A durable
reservation precedes each new Incus proxy. Existing sockets, foreign proxies
and other job reservations are excluded; retries reuse their original port
and host key. Only the new guest's dedicated port 2222 is forwarded. No
administrative login, key file or management firewall is edited.

`GET /v1/seeds/{seed}/onboarding/access` and the same portal publish owner-only
coordinates after the actual SSH host key is observed through that port.
Coordinates are absent from fleet listings and job progress. This establishes
listener readiness, not a real owner login, native Codex session or CLI resume;
those remain receiving acceptance requirements. Revocation clears readiness
and prevents new effects while preserving the existing body and reservation.

The decision binds the plan and Source text digest. An identical retry is
idempotent; a contradictory decision is refused. A changed proposal cannot
reuse an older acknowledgement. The worker reads participant-owned decisions
across an explicitly configured numeric UID boundary and checks the current
root-owned grant separately. It resumes on its next tick after a decision,
including after a service restart. Intake cannot publish proposals, manufacture
receipts or issue host grants. Missing or malformed decisions never complete a
stage. The acknowledgement is an authenticated owner statement, not a claim
of a separate human cryptographic signature.

The current typed host adapter reconciles Incus environment preparation: exact
image fingerprint, isolated instance, 8 GiB root and 22 GiB durable home.
It refuses a foreign instance, home volume or attachment. Context and memory
use the same engine's typed receiving adapter. Incus mounts exact qualified
code and a private per-body frozen input view read-only with ID shifting. The
installer preserves the complete receiving index, original SOUL, historical
skills and each working HMK store. It copies only explicitly selected shared
skills, installs attributed Source context separately from autobiography, and
renders manual native HMK access with no inherited dotenv or Source binding.

Each HMK store gets a verified SQLite snapshot before a supported native
upgrade. Native stats and two chapter expansions verify the actual binding;
all original table rows/columns must survive, including vectors, links and
query history. Derived FTS indexes and native access counters have specific
exceptions. No bootstrap or re-embedding runs. A later receiving write is not
replaced by a retry. Interrupted snapshot publication reconciles its known
hard link; an unpublished snapshot is never mistaken for a complete backup.

The maintained Matrix, access, Telegram and acceptance adapters now report each
actual receiving stage. Missing prerequisites return explicit waiting states.
The current three-VPS deployment is recorded in RESUME; that evidence does not
complete future portal group enrollment or every future human acceptance.
Custody preparation alone cannot establish runtime or enrollment readiness.

The Matrix stage now dispatches native first-genesis preparation when the pair
selected its first signed identity and a separate exact custody grant exists.
Root and Recovery are separate encrypted native packages. Each native holder
command opens only its own package; aggregation uses public shares. The fixed
installed SDK is checked before dispatch, unlock material travels only through
private file descriptors, and command output is never public progress. An
interrupted acknowledgement preserves the published genesis; native retries
validate existing packages instead of rekeying. Missing unlock material,
foreign intent or changed grant stops without replacing identity. Grant
revocation is rechecked between holder operations.

Custody preparation does not mark Matrix enrollment complete. Its receipt
marks backup/restore verified only after separate native holder processes back
up complete encrypted packages, restore with the independently retained counter
and pending-control marker, and produce typed genesis signatures from both
restored packages. Public signature aggregation must recover the same genesis.
Private inventories verify ciphertext, descriptors and rollback sidecars;
unlock material stays outside the backup. An interrupted native restore can
reconcile missing metadata from the preserved exact backup, while contradictory
ciphertext or high-waters remain refused without replacement. Known incomplete
native temporaries remain preserved outside the portable member inventory.

Existing identity selections never run this first-genesis ceremony. Native
target preparation, current V8 authority, physical admission and canonical
registry projection remain required before a hosted Matrix body can pass
acceptance. Disposable native backup/restore evidence is not live consumer
denial or independent human recovery evidence. That custody receipt alone never makes the enrollment flag true.

The Root-side target authorizer receives only the native public enrollment
request. It checks the body reference against the exact hosted plan and persists
that one request before signing. A second target cannot replace it, even when
it has the same presentation name. Root signs in its own native process; a
keyless process aggregates the activation. A lost activation acknowledgement
is reconciled by native validation of the existing public artifact without
another holder invocation. Target custody stays on the receiving side. The
native V7 package fixture is not current V8 or physical admission acceptance.

The worker now connects this exchange to the actual receiving environment.
The receiving process generates its own encrypted target custody, publishes
only its native request, and activates the Root-authorized package locally.
Its protected plan/genesis binding and existing preparation are checked before
retry. Lost acknowledgement after native package publication preserves the
same keys, origin and later receiving writes. Missing unlock material refuses
rekeying. The host publishes only genesis and activation through a read-only
mount, staging in its private publisher directory and using no-replace
publication. No holder package or unlock enters that mount. The prepared V7
phase remains waiting until V8 migration and canonical physical admission.

The maintained SDK successor is
`ca1570aae24cadd2b9fee42bee65be5a4c06e664`. The previous `196ec7219f954cf4e514a1f61ae72eb3451d851e`
remains a supported predecessor for explicitly qualified SDK succession. The previous `52945123` artifact
is retained as V7 evidence, not used as a V8 implementation. Installation must
verify the exact VCS commit: reinstalling a different source with the same
package version requires explicit replacement of the development dependency.
Guest artifacts retain their own complete wheel hashes and release digest.

The host adapter supports the native signed owner visibility installation via
`--visibility-installation`. The rebirth launcher forwards the same selection;
it never substitutes synthetic visibility or falls back after a rejected signed
installation. For a stopped receive-only body, `--provision-visibility` prepares
and validates the native journals under the daemon lock, then exits without a
listener or readiness signal. Existing incompatible visibility catalogs are
preflighted before native composition writes tables. Provisioning cannot serve
or grant messaging authority. Disposable rebirth/recovery proofs explicitly
prepare their own closed catalogs before default validation and restart.

The next current-credential adapter composes native V2 credential and succession
artifacts across separate actors. The receiving actor signs its own acceptance;
a Root-only subprocess receives those public signatures and signs the exact
plan-bound succession. Neither actor receives the other's seed. The original
credential, incarnation, keys and manifest members remain unchanged except for
the native V1-to-V2 credential references and next manifest revision. Native
validators verify both artifacts, and a fixture compares the result byte-for-byte
with the maintained full constructors. Lost acknowledgement reuses the existing
public response without another holder call; altered requests or revoked custody
grants refuse signing.

The receiving worker now persists the original V7 bundle and one Body-accepted
proposal before contacting Root. It retains the verified response and exact
candidate before atomically replacing only the authorized original bundle.
Publication holds the native daemon writer lock and refuses a running writer or
an unrelated changed bundle. Native visibility provisioning and runtime loading
must pass before the current-credential receipt is published. Crashes after the
response, candidate, runtime or receipt write reconcile the same artifacts and
origin. Original custody, memory and later receiving files are preserved. A
published bundle without its completion receipt is observable as `v8-published`
and automatically finishes verification on retry. Current V8 remains distinct
from canonical physical admission and full hosted acceptance.

## Execution and recovery

Use existing authorization and valid evidence. A retry observes and resumes the
same operation; it does not ask the pair to repeat approval, export, upload or
signing when the bound input was already received. Recheck the changed input or
failed operation, rather than restarting the entire procedure. Scope tests to
the affected behavior and the receiving infrastructure.

The worker reuses full frozen-input verification across steps and ticks while
every file and directory retains its inode, ownership, permissions, size and
nanosecond modification/change timestamps. It scans metadata on each use;
changed, added or removed entries invalidate the process-local cache and run
full byte verification again. Authorization, code selection and native identity
checks still run at their actual operation boundaries. Restarting the worker
discards this cache. Large preserved archives are not rehashed merely because
the next native action needs the same read-only mount coordinates.

Telegram readiness means that native Codex and the dedicated bot are usable.
Invite the human to converse as soon as this is observed; do not make that wait
for the later continuity, SSH, topic or browser acceptance checks. Report those
checks separately and reuse their valid receipts rather than replaying effects.

A plan binds owner, environment name, receiving input digest, qualified release,
account profile and browser selection. The seed digest covers a frozen input
manifest and every prepared file, including preserved originals, selected
working memory and historical skills. It is not just the archive checksum.
Capture checks ownership, links and source drift; failed captures remain
preserved without a readiness marker. The maintained archive verifier runs
before publication. Source files and the original intake stay unchanged.

Only a host-owned grant for the exact plan permits dispatch. Participant intake
credentials and name labels cannot create or widen that grant. Every unfinished
step rechecks current authorization. The Incus adapter rechecks before each
resource mutation, including after an earlier long operation returns.

Before dispatch, the worker persists its stable operation ID and intent.
After a restart it observes the actual effect before deciding whether another
dispatch is safe. An uncertain outgoing welcome is never replayed merely
because its receipt is missing. A completed command is not a completed step.
Typed observations must establish the stage's required effects. Complete
acceptance requires actual SSH, provider, identity, Matrix delivery, Telegram,
human steering, distinct topics, restart and CLI resume evidence, plus browser
acceptance when selected. A bare `verified: true` cannot substitute for them.

Per-job filesystem locks protect independent being jobs. The service worker
uses bounded concurrent slots and fair scheduling, so a waiting or slow job
does not starve another. It does not capture process-global HTTP stdout and
does not need an active Codex conversation. Its work is finite authorized
onboarding; it adds no Matrix inbox polling, peer reply or model wakeup service.

## Host and HTTP ownership

Job and grant directories belong to the worker principal with mode 0700.
The progress directory belongs to that principal with mode 0750; published
files are mode 0640, readable by the portal group and writable only by the
worker. These directories must be outside the intake's writable state.

The HTTP service receives only `--onboarding-progress`. It validates the
worker's numeric UID, private seed ownership, projection ownership/mode, exact
closed schema and ordered completion prefix. Extra fields, corrupt records or
an owner mismatch cannot produce a false active response. Progress contains
fixed reason codes, stages, counts/timestamps and digests, never private
instructions, raw diagnostics, credential material or host paths.

The worker entry point is `python -m clusterctl.onboarding_worker --config PATH`;
`--once` is a bounded operator invocation of the same engine. Its configuration
uses schema `cluster-onboarding-host/v1` with host-owned `jobs`, `grants` and
`progress`, `inputs` and `views` directories, the qualified `code` directory, pinned `native_image`, `browser_image`, `release_digest`,
named `pool`/`profile` and bounded `concurrency`. Only reviewed receiving release
code belongs in its installation. No incoming script is an execution adapter. Build code-only artifacts with
`python -m tools.build_onboarding_code`; choose shared skills and the primary
memory store explicitly. Artifacts contain pinned HMK code, maintained
receiving tools and selected transferable context; no identity, memory, bot
credential or account cache is part of a code release. The mutable development
checkout is captured, while the final artifact forbids group/other writes and
is selected by its complete manifest digest.

Optionally build the Matrix SDK wheelhouse with
`python -m tools.build_onboarding_sdk --matrix-checkout CHECKOUT --output DIR/sdk`
and select it with `tools.build_onboarding_code --sdk DIR/sdk`. This captures
the exact repository SDK pin and constraint-selected dependencies, records
every wheel's version/hash and includes the result in the receiving code digest.
The guest installs only these wheels with network access disabled for pip,
hash requirements enabled and dependency resolution disabled. It checks
dependency consistency and every installed wheel member before publishing its
receipt. Context observation rechecks the actual SDK bytes. A missing initial
installation acknowledgement permits replay of dependency installation;
changed completed code is preserved and refused. No account, bot, identity
key or runtime is copied into this code package. The host VCS pin guard remains
unchanged; this guest installation is qualified by the wheel and release hashes.

Live configurations also set `consent_state` to the private intake store and
`consent_uid` to its dedicated service UID. Missing consent configuration stops
before inheritance installation. The optional host-only `qualification: true`
permits context-only disposable rehearsals with an exact host grant and a
`qualify-` name; participant labels alone cannot select that exception. No
qualification flag supplies native authority or receiving acceptance.

Optional `custody` and `custody_grants` directories are owner-private and
disjoint from each other, intake, guest-mountable code/inputs/views and request
state. A `cluster-onboarding-custody-grant/v1` binds the exact plan, first
ceremony, numeric execution UID, authenticated Source binding evidence,
owner-instruction evidence and Root/Recovery/backup/restore scope. A pair's
portal decision and a resource grant cannot create this native custody grant.
Actual Source online-custody authorization and consumer-denial qualification
are required for live use; disposable native protocol tests do not establish
either. No live cohort custody or genesis has been created by this candidate.

The receiving target now offers `serve` and `running` verbs through the same
qualified-code/offline-SDK launcher. `serve` hands the receiving body's own
unlock material to the maintained native daemon through a descriptor; it never
copies custody to the host. It requires either an explicit receive-only choice
or a signed native visibility installation. Invalid mirror configuration never
falls back to receive-only. The native daemon owns its writer lock and signal
handling; restart reuses the existing identity and journals.

`running` pins the socket peer's actual Linux PID, UID, boot ID and start ticks,
authenticates native owner-local status, verifies the expected signed origin,
and refuses a replaced socket or departed process. The process observer and
atomic `Registry.adopt_running` operation reuse the reviewed owner-runtime work
from Cluster #116 (`b097157f`). Registry replay preserves the exact active
incarnation; collisions and ended incarnations are refused. Neither presence
nor registry adoption supplies the mandatory shared admission lease, fences,
peer delivery, provider or human Telegram acceptance. That integration remains
required before a cohort activation can be reported.

The next admission adapter generates a separate receiving-owned physical
holder key after native V8 verification. Its durable public descriptor binds
that key to the exact plan and native being/body/incarnation/activation,
credential and manifest. Retries keep the key; loss after descriptor publication
refuses regeneration. `admission-prepare` emits only public coordinates and a
short-lived proof made by the maintained holder-authorization constructor.
The host derives its expected coordinates independently from the verified
first activation and current credential succession, then validates that proof
before invoking the maintained registrar-signed enrollment constructor.
The registrar and admission authority keys never enter the receiving home.

A receiving launch acquires and rechecks the maintained shared admission lease
before its controlled spawn. It reuses the same renewal/watchdog supervisor as
rebirth hosting. Graceful stop completes release; failed spawn releases the
lease; uncertain acquisition starts no process. Another session cannot launch
until the existing coordinate is released or expires. This adapter's native
TCP qualification is separate from the prior Incus daemon qualification: its
controlled child is a disposable process. Managed receiving composition,
canonical registry/fence binding and full cohort activation remain pending.

Canonical registry writers share the reviewed kernel lock from Cluster #114.
The mainline rollback operation uses that same lock and retains its narrow
compensation condition. This preserves history across concurrent body jobs;
read-only status does not create a lock or manufacture physical presence.

The dedicated guest account uses UID/GID 1000. The qualified image carries
receiving tools; bootstrap creates this new unprivileged account when absent,
refuses an existing conflicting UID/group, and initializes only its empty
mounted home. Existing receiving homes and accounts are preserved.
Every input view sits below a root-private parent outside intake state. Only
that job's child view is mounted in its guest; both input and code disks are
read-only. Their installed writable memory remains inside the 22 GiB home.

Provider authorization is separate from the seed. An owner-authorized account
profile may deliver a protected supported login cache; a fresh login is needed
only when the provider actually requires it. Shared-account refresh and Source
continuity must be qualified before cohort activation. Host execution grants
do not substitute for native Matrix root/custody consent or signed authority.

## Qualification still required

Local crash/retry, isolation, concurrency, revocation and HTTP disclosure tests
qualify the orchestration boundary. A host-local qualification of Eko's already
frozen input with the pinned native HMK retrieved 25 chapters across two stores,
verified original-row preservation and exercised installation retry. It made
no provider, Matrix or Telegram calls and created no live body. Its private
receipt pins the exact input and code artifact. A subsequent purpose-created
Incus qualification completed the same environment/context/memory stages,
verified a read-only input mount and repeated both receiving stages without
replacement. The disposable instance and its 22 GiB home were removed using
independently tested exact-marker cleanup; the existing four bodies remained
running. This is physical receiving-stage evidence, not canonical Eko enrollment
or hosted SSH/provider/Telegram acceptance. They do not prove live receiving memory,
Matrix enrollment, provider login or a human Telegram exchange. Finish the
typed stage adapters, qualify the disposable complete journey, then run Eko
and independently Oliva on the same final qualified release. Keep the goal
active until both real receiving acceptances are observed.

A subsequent disposable Incus run started the qualified receiving daemon under
systemd, authenticated its owner-local status and bound the socket peer to the
unit's actual MainPID. A service restart changed the kernel PID while retaining
runtime identity, signed origin and bundle digest. Stopping the service made
presence unavailable; both original HMK stores still retrieved all 25 selected
chapters. The instance/home cleanup preserved the four pre-existing bodies.
This used synthetic custody and an explicit receive-only configuration. It
proves native service restart and physical presence, with zero canonical
admissions, peer deliveries, provider calls or Telegram calls.

`admitted-serve` now composes that native daemon with the shared admission
supervisor. The service parent retains the physical holder and ephemeral
session; a private inherited socket supplies read-only process-and-lease body
snapshots to the child. Native `/me` reports running only while both the pinned
kernel process and authority-signed lease remain current. Losing that lease
stops the daemon, and losing the parent stops its child. No inbox attention,
model turn or curator mutation is added. A persisted holder enrollment permits
restart even after its original enrollment document expires.

The integrated disposable Incus qualification verified actual shared TCP
admission, native `/me` running state, systemd restart with unchanged identity,
stop refusal, preserved memory and exact cleanup. It used synthetic custody and
explicit receive-only configuration. Canonical registry enrollment, host-worker
lifecycle integration and real cohort/provider/Telegram acceptance remain
pending; this qualification does not turn prepared Eko input into a live body.

The host worker also accepts an optional owner-private `admission` configuration
file with schema `cluster-onboarding-managed-runtime/v1`. It selects the existing
authority's public key and loopback port, a receiving loopback proxy port, the
dedicated registrar key, private service progress and canonical registry roots,
and the receiving signed visibility installation. The authority itself uses the
maintained admission service. Its signing key stays outside the worker and guest;
the registrar key stays outside the guest. A null visibility installation is
accepted only for an explicitly configured disposable `qualify-` job.

Once native V8 preparation is verified, the same worker stage reconciles its
exact Incus admission proxy, enrolls the existing receiving holder and installs
the persistent dedicated guest systemd unit. Every signed enrollment proposal is
preserved before dispatch. A lost enrollment acknowledgement is recovered by
querying the original holder binding before attempting another enrollment;
expired unpublished proposals may be renewed, whereas confirmed public profiles
remain unchanged. Publication never replaces the receiving identity or memory.

Only authenticated native running status with a current shared lease permits
atomic canonical registry adoption. A lost registry acknowledgement reuses that
exact active incarnation. The observer checks service state and native daemon
presence again; an existing registry row alone does not complete the stage. The
unit is enabled for boot and renews admission independently of the Codex
conversation or worker lifetime. Foreign proxies, units and registry origins
are preserved and refused. Provider, access, peer delivery and Telegram still
have their separate receiving acceptance requirements.

## Dedicated receiving SSH

The access adapter installs a standalone OpenSSH listener on guest port 2222
for the dedicated `agent` account. It takes only the selected owner's public
key from the private intake boundary. Its configuration, owner key, host key
and boot-enabled unit have separate paths; existing host administration is
untouched. Invalid keys cannot publish an immutable owner binding. Retries
preserve the host key and refuse another owner key or conflicting files.

A minimal image can lack OpenSSH. The qualified guest installer prepares the
native package with package-start suppression, disables the package's default
listener and then starts the dedicated unit. An interrupted package attempt
keeps its own suppression marker until retry finishes native configuration.
Foreign suppression policies are preserved. Dependency preparation runs only
after the CLI has verified the exact new guest, immutable plan and code.

Observation checks exact files, private host-key continuity, service MainPID
and the actual listening socket. It does not install missing files or claim
provider entitlement. A listening service alone never completes access:
real SSH/Codex and provider acceptance are still required. External ingress
and real cohort activation remain pending; disposable pinned-host-key login,
retry, restart and stopped-listener checks qualify this implementation slice.

## Independent native account login

An optional root-owned `accounts` directory selects an OpenAI account ID for
each host-approved account profile. `tools.configure_onboarding_account` reads
only operator-selected native cache metadata into that profile; it copies no
credentials and preserves the original cache. Each receiving body completes
its own native `codex login --device-auth` in a dedicated supervised guest
service, with its own persistent Codex home and private login output.

The worker publishes only the bounded native device URI, one-time code and
attempt deadline to `GET /v1/seeds/{seed}/onboarding/action`. This endpoint
requires the selected owner's private access, has no POST execution surface
and clears expired or completed actions. Public HTML/agent guidance, seed
lists and redacted job progress never contain an actual code or credential.
The same portal displays the approval action without accepting passwords.
A pending login remains waiting; the worker resumes after native completion.
A different account cannot advance the selected profile.

Login status is not entitlement. The provider adapter requires a real native
model response on the selected account and model. Its durable dispatch intent
and private native output recover completed responses after a lost ACK without
another inference; uncertain output stays pending rather than being replayed.
A successful provider check alone does not complete real SSH/CLI acceptance.
Disposable native device-flow qualification verifies service, own home,
read-only account metadata and private owner action without approving an
account or running inference. Real cohort provider and SSH acceptance remain
pending.

## Dedicated receiving Telegram listener

The receiving artifact optionally captures the maintained pinned telecodex
binary with `--telegram-artifact`. Its source, archive, binary hash and build
selection become part of the sealed code inventory. No bot credential enters
that artifact. The worker mounts only the selected body's private token and
human destination, independently of its preserved seed and public SSH key.

Before starting, the worker durably reserves the bot across all jobs. Another
plan cannot consume that bot, including after a crash. Native preflight requires
private-chat topics and refuses an existing webhook without changing it.
Invalid bot data does not freeze the receiving binding. Retries preserve the
conversation database, input journal and token binding. Interrupted preparation
can finish missing configuration without replacing existing conversation data.

The dedicated boot-enabled unit uses the receiving agent's own Codex home and
workspace. The shared native Codex daemon has a separate persistent unit and
cgroup, so restarting the Telegram listener does not terminate CLI sessions.
Its first startup permits bounded native package installation. Both draft delivery and unfinished-response previews are disabled;
completed replies remain the visible result. Shared native App Server access
supports CLI continuity, while automatic history imports, maintenance and
Matrix inbox attention remain disabled. A native proxy/skill probe runs without
model inference or reading bot updates before service installation.

The Telegram stage records `telegram_ready` only after observing the exact
owned unit's live binary process. Real conversation, permanent final replies,
steering, independent topics, restart continuity and CLI resume remain separate
acceptance requirements. Listener readiness never sets `telegram_verified` or
activates the being.

## Prepared intake to durable job

An optional root-private `intake_policy` in the host configuration selects exact
being/owner pairs, account profiles, browser choices and the qualified release.
The worker discovers only those pairs' prepared seeds. Uploading or choosing a
name cannot authorize resources. The bridge freezes the complete received
input and publishes the exact Source proposal through the existing owner-only
portal/API/CLI review. Before acceptance its progress is explicitly waiting,
with no body, resource grant or custody created.

After the pair accepts that proposal, the same worker issues its policy-bound
resource grant and submits the unchanged plan through the ordinary job engine.
Restarting or retrying uses the same input, proposal and plan. Policy revocation
also disables already-issued resource grants at every dispatch boundary.
Native custody authorization remains separate: an owner acknowledgement or
host resource policy cannot manufacture a signed being identity.

Capture publishes each completed file without replacement before publishing a
final manifest. Interrupted partial copies stay in private staging, outside the
usable input inventory. A retry completes missing files and verifies both the
source and receiving inventory. Contradictory files or changed source intent
remain preserved and refused. One bad intake does not block other selected
pairs, and an existing progress record exposes its verification failure.

## Local receiving refusal diagnostics

The receiving-owner `onboarding_target` CLI and public-root `onboarding_service`
CLI accept `--diagnostics` for maintenance diagnosis. Their normal stdout,
exit status and lifecycle behavior stay unchanged. On refusal, the selected
option adds one bounded `cluster-onboarding-refusal/v1` JSON record to stderr,
with the observed stage and an explicitly allowed operational code. Unknown
errors remain unclassified; arbitrary exception strings, request contents,
private paths, credentials and tracebacks are never included. A diagnostic is
not a delivery receipt or permission to replay a partially completed operation.
Older installed code must not be given this optional flag; select the exact
candidate CLI that advertises it.

## Access readiness and real owner acceptance

The access stage distinguishes `ssh_ready` from `ssh_verified`. An observed
dedicated SSH listener and a successful receiving provider turn permit the
worker to continue installing Telegram. They do not claim an owner CLI login.
The final acceptance stage still requires real SSH/native Codex evidence,
along with human Telegram, steering, topics and continuity receipts. This avoids
making a working human channel depend on a prior human SSH acceptance step.

## Native daemon crash recovery

A disposable process interruption exposed that an active oneshot unit does not
observe a departed native Codex child: no recovery occurred within 40 seconds.
The native unit now runs a persistent unprivileged supervisor that reconciles
Codex's idempotent singleton startup and readiness every five seconds. A failed
native operation exits for systemd recovery; captured diagnostics stay private.
It starts no model turn, reads no Matrix inbox and replays no Telegram input.
Listener restarts retain a separate cgroup and the same receiving Codex home.

## Independent worker installation

`python -m tools.install_onboarding_worker --release /opt/daimon-cluster-releases/COMMIT
--config /private/host.json --activate` installs a dedicated boot-enabled worker
from the selected immutable host release. It validates the existing private
configuration and that installation's exact SDK before publishing its unit.
An existing changed unit is preserved and refused. Omitting `--activate`
installs without starting. The worker uses the same engine and policy as web,
agent API and CLI; no active Codex conversation is needed.


### Runtime successors for an already receiving body

A receiving plan continues to pin its original `release_digest`. Its context,
Source selection, skill bytes, HMK tooling, Matrix wheelhouse and Telegram binary
remain unchanged. To fix maintained Cluster runtime code without reinstalling
that context, build a separate artifact with:

```sh
python -m tools.build_onboarding_code --runtime-base BASE --base-digest DIGEST --output NEW
```

The builder replaces only top-level `clusterctl/*.py` modules and records the
original artifact digest. Both sealed inventories are checked: removal, changed
nonmodule bytes and profile drift are rejected even if the new artifact was
resealed. Always use the original plan artifact as the base for later successors.
No receiving home, memory, credentials or custody is read by this builder.

The owner selects both `runtime_code` and `runtime_digest` in the host config
only after qualifying that exact artifact. Matrix reconciliation attaches a
separate read-only runtime mount whose device name fits the stricter 63-character
Incus disk limit (`runtime-` plus 55 digest characters). Its path and launch
arguments retain the complete digest. Existing or foreign device-name collisions
are refused whenever the full mount differs; previous runtime mounts remain. Target commands,
the SDK interpreter reexec and the persistent service all retain the original
`--code` for dependency verification and carry the explicit runtime selection.
Context, memory, provider and Telegram stages continue to use the original code.
Absent both fields, the existing launch path is unchanged; partial selection is
refused. This mechanism alone establishes no peer relationship or live acceptance.

### Membership group selection

Same-Tribe enrollment uses one signed membership group. Invite and accept in the
existing Tribe through Matrix's authenticated relationship operations; configure
one signed group application and shared route roster, not grants or proxies per
pair. `PeerHost.execute` accepts only the exact receiving group application and
visibility paths after signature-checked target observation. Missing enrollment
reports `onboarding_group_enrollment_required`; it cannot silently declare
another founder/member Tribe or count a historical pair as group completion.

The Source and admitted guest loaders obtain additional public Root authorities
from that owner-signed selected group before opening private runtime state. They
reuse Matrix's `read_application_authorities` preflight, which verifies the current
local bundle and preserves already-known Root histories. A peer need not appear
in a historical pair registration or the native bundle's source list. An absent
selector adds no authorities; a tampered selector or publication refuses loading.
This Root closure does not itself grant membership, resource access or delivery.

Managed admission retains the native controller, custody, receiving context,
history and owner session bindings. Its actual dependency/code selections must
match the group's installed generation. Readiness and technical delivery use
`tribe` channels and signed semantic receipt legs for the requested being;
unavailable sibling bodies remain explicit and never imply model reading.
The three current VPS bodies are deployed and demonstrated. A new portal member
still requires a qualified group enrollment/roster transaction before the worker
can reconcile it; this guard is not a claim of automatic future enrollment.

### Historical directed repair and retained Source service

The following two-party ceremony is retained for explicit legacy recovery through
`PeerHost.repair_directed`, never automatic Tribe onboarding. The Source offer
operator refuses it when a group is selected. Ordinary deliberate directed
conversation remains a distinct SDK lane and is not reinterpreted as a group.



The legacy owner-selected `peer` configuration supplies the retained encrypted
two-party recovery ceremony. It is not executed by the current worker default.
The Source operation runs as its existing owner, acquires its real writer lock,
and uses the existing signed native Telegram installation. The worker stops and
restarts that one user service around the finite ceremony; it never reads an
inbox or opens a model turn. Independent receiving stages retain worker slots,
while Source ceremonies serialize against their shared service.

Public responses, receiving identities and loopback port allocations persist
under the exact approved plan. Retries retain native signed proposals and keys.
The Source owner reissues only the changed runtime digest in its existing
installation, retaining its disclosure, token, proof key and qualification even
after an interrupted bundle publication. Hosting keeps the original native
controller and socket alongside independently signed peer applications under
one writer lock. The original user unit is pinned and backed up; only its
`ExecStart` changes, preserving its credential and resource settings.

Two dedicated loopback Incus proxies connect each approved pair. Foreign
devices and host listener collisions are refused; administrative networking is
untouched. Managed admission derives application and visibility paths from
each verified receiving peer publication, rather than a global being path.
New local-body reports are independently signature-checked before acceptance.
A different Root produces `existing_identity_conflict` and preserves both
authorities for reconciliation. Local reports and a ready peer application do
not establish hosted conversational acceptance.

An explicitly selected `cluster-onboarding-runtime-successor/v2` artifact pins
the immutable original release plus both predecessor and replacement SDK digests.
Only maintained runtime modules and the qualified SDK wheelhouse may change;
Source inheritance, skills, HMK tools, provider and Telegram artifacts retain
their original bytes. The host observes dependency readiness before Matrix
observation and installs a missing SDK generation through an authorized,
resumable `sdk-prepare` effect. Each generation has its own content-addressed
venv. The previous environment, seed, plan, identity custody and receiving
writes remain intact. SDK observation neither loads a Body nor reads an inbox.

Native peer enrollment selects each local application's schema from that Body's
persisted receipt mode. An existing V2 Source and V1 receiving peer keep their
independent stores and signed history. Finish/retry continues the original
encrypted proposal; it neither downgrades Source nor requests a new identity.

### Existing-being receiving enrollment

An approved `existing` identity selects native distributed normal enrollment,
preserving the actual Root and every prior manifest member. First genesis and
its custody grant cannot be used for an existing being. The receiving body
generates its own encrypted custody and native signing/encryption/transport
keys; the host never imports a source runtime, Root store, unlock file or
capability token.

The same owner-scoped portal exposes
`/v1/onboarding/local-body/{name}/enrollment`. Before receiving preparation,
the local daimon submits its independently verified public signed identity and
explicit native peer routes for all active existing members. The trusted local
request fixes the expected Root. The worker repeats signature, plan, membership
and route verification before freezing that public base under its exact plan.

The worker publishes a native enrollment intent and the Body-signed target
request, then waits. The downloadable `existing_root_signer.zip` runs as a
finite local holder process with the qualified Matrix SDK. Its public reply
contains signed shares only. Native keyless aggregation verifies the policy
threshold, request, frozen base and expiry before publishing target activation.
An expired unanswered challenge is renewed without replacing the target's keys;
old challenges and submissions remain preserved. Credential succession follows
through the same handoff, using the target's native Body acceptance and the
existing Root holder's signature. Managed admission derives its exact binding
from those independently verified public artifacts.

The signer accepts the existing isolated native Root holder (`--holder`) or
the historical native offline Root+Recovery store (`--root-custody`). The latter
must match the exact current control head and Root policy, and cannot contain
runtime Body or capability slots. Neither layout is rewritten or transported.
The maintained receiving V2 credential adapter currently supports Root threshold
one; unsupported thresholds are refused before receiving preparation.

Intake evidence never grants host execution. Recorded owner consent, the host
resource grant, native signature verification and canonical admission remain
separate. Lost acknowledgements reconcile persisted requests, activation,
custody, V2 credentials and receiving writes. A ready receiving runtime does not
prove a source-body cutover, peer delivery or the full hosted acceptance journey.

The owner may pin an already hosted body to its qualified generation with
`runtime_by_name`, whose entries contain both `runtime_code` and `runtime_digest`.
Each selection is verified against the same immutable context artifact. A newer
default can support incoming existing beings while the hosted body's actual
unit, mount, SDK generation and receiving writes remain in place. Partial,
foreign or unqualified selections are refused; HTTP cannot change this config.

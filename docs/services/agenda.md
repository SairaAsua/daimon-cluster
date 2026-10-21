# Agenda Mini App — Vikunja adapter

Status: source candidate; no live activation or phone acceptance is implied.

The existing homes gateway serves `/agenda/` and `/agenda/miniapp.html` when
explicitly configured. One private Vikunja instance owns tasks, projects,
dates, completion and observations. The adapter creates one hidden provider
account for each **current verified being**, shared with its currently paired
human. Two homes of the same being resolve the same agenda. A different being
gets another provider account and cannot read another agenda's records.

This adds no Matrix identity, passkey authority, Telegram bot/update consumer,
personal-memory store, background synchronization, inbox attention or model
wakeup. All writes are foreground actions. Browser writes require the current
paired human's existing public-home cookie and exact Origin. Existing reader
bearers and VPN context cannot write. Native calls reuse the existing
owner-local publisher credential and current owner/revision checks.

## Supported journey

1. Open Agenda through the existing Mini App launcher and sign in through the
   ordinary home/shared-login route. Telegram data selects no identity here.
2. Choose **Activate our agenda**. This explicitly provisions a separate hidden
   Vikunja account, not a new human or daimon. No source tasks are seeded.
3. The first-use configuration asks about Google Calendar. Connect a chosen
   human/daimon account, retain a valid connection already attached to this
   agenda, or continue without Google. A preferred account is optional; the
   Google account chooser can select it during consent. Every agenda has its
   own preference and provider authorization.
4. Create a project and a task, optionally with a date, time, duration and note.
   Add attributed observations, edit a task, complete/reopen it and return to
   its canonical server records. Dates without times remain floating days.
5. If Calendar is connected, saving a dated task creates/updates its linked
   event. Existing tasks can be synchronized explicitly. A saved task and a
   pending Calendar write remain distinct results. Removing a task's date
   removes its previously linked Calendar event after provider confirmation.

First-use setup and current connection survive reopening/restarting. A Google
sign-in used for home identity is **not** Calendar consent. Existing daemon
account settings may supply the preferred email through `agenda-calendar-account`;
credentials are never copied from a harness plugin or another being. Without a
preferred email the explicit Google chooser supplies the verified account.
An email never identifies or creates a Matrix actor. Old human revisions or
changed pairings immediately stop using their stored Calendar authorization.

The UI reuses the receiving home's public Homemaker `surface=apps` stylesheet
and maintained foreground consumer. It keeps an ordinary same-WebView Apps
link and the existing login presentation helper. Source-owned assets contain
no bot tokens, authenticated launch data or provider credentials.

## Pinned engine

Use official **Vikunja 2.7.0**, released 2026-10-02. The maintained v1 HTTP API
is included in that release. No paid/Pro feature or alpha CalDAV integration
is required.

- Source: <https://github.com/go-vikunja/vikunja/releases/tag/v2.7.0>
- Linux amd64 bundle: `vikunja-v2.7.0-linux-amd64-full.zip`
- Official release asset SHA-256:
  `569861fd690f9ffc812e39e20be3943b882d4549a19e556e47066e71e29ca1b9`
- Keep the upstream AGPLv3 license with the engine. No upstream binary or
  source is vendored in this repository.

Bind the engine to an operator-selected **127.0.0.1** port. Use SQLite and an
owner-private persistent directory for its database/files. Disable its mailer
and email reminders. Registration is available only to the loopback adapter;
the gateway exposes neither raw Vikunja endpoints, registration/login, its
frontend, provider credentials nor arbitrary proxy routes. Retain upstream
rate limits; server-only login tokens are briefly cached per provider account.

Optional gateway flags, added to the existing selected command:

```text
--agenda-state /absolute/private/agenda-adapter-state
--agenda-backend http://127.0.0.1:SELECTED_PORT
--agenda-google-client /absolute/private/agenda-google-client.json
```

The first two flags are required together. Omit all three to preserve the
previous behavior. Google is optional. Its existing optional dependencies are
in `requirements-home-login.txt`; this does not enable Google sign-in itself.
The client file uses the existing private-file contract and contains only
`client_id` and `client_secret`. Keep it outside checkouts and artifacts.

The Google application must enable Calendar API and register each actual
receiving HTTPS callback, for example `<registered-home-origin>/agenda/google/callback`.
Request only `openid`, `email`, and `calendar.events.owned`. OAuth uses PKCE,
nonce, one-use state, the current parent browser session, exact callback and
the official Google ID-token verifier. A selected preferred email must match
the verified provider account. Server tokens remain in the private adapter DB.
In Telegram, the app saves the preference and offers an explicit **Authorize in
browser** action. Google authorization runs in the ordinary browser, using its
own existing Matrix login session. No cookie, launch payload or OAuth state is
copied into that navigation link. Return to the Mini App and refresh to observe
the completed connection. This follows Google's secure-browser policy instead
of attempting sign-in inside an embedded WebView. The real phone journey still
needs qualification.
Disconnecting stops this agenda using its tokens; the UI separately explains
how to revoke the application's grant in Google settings. Existing events are
not erased merely by disconnecting.

Google event IDs are deterministic per being/task. Provider reads followed by
insert/update and retained event IDs avoid reauthoring duplicate events after
uncertain network results. Only linked events are accessed; the app does not
scan unrelated Calendar data. Events are private and have no attendees.
Notifications use the provider's calendar settings; no new notification timer
or autonomous daimon attention is installed.

## Publish through the existing launcher

When the source-owned agenda adapter is enabled, the launcher recognizes only
the exact configured home's `/agenda/` URL as a web app. The ordinary publication
registry still owns discovery, audience and withdrawal. Arbitrary HTTPS links,
extra paths and identity/query variants are not promoted.

After real HTTPS qualification, each selected owner may publish its own exact
agenda URL through `daimon-home link`, with generic title/summary and the chosen
audience. This is an existing same-WebView web launch pattern; it does not
replace bot consumers, require another editor, or confer target access. Do not
advertise an undeployed URL or change another owner's publications. Existing
Main/named-app URLs and physical phone return need their normal qualification.

## Native foreground use

`tools/agenda_owner.py` loads the receiving installed daimon-home publisher and
its own binding. Payloads are JSON on stdin; credentials stay inside that helper.
Use `--publisher /path/to/installed/daimon-home/scripts/home.py` and optionally
`--binding /path/to/own/binding.json`. Supported actions:

| Action | Payload |
| --- | --- |
| `state` | `{}` |
| `init` | `operation_id` |
| `project-create` | `operation_id`, `title` |
| `task-create` | `operation_id`, `project_id`, `title`; optional `description`, `date`, `time`, `timezone`, `duration`, `priority` |
| `task-edit` | complete editable task fields plus `task_id`, `revision`, `operation_id` |
| `task-update` | `task_id`, `revision`, `done`, `operation_id` |
| `observations` | `task_id` |
| `observation-add` | `task_id`, `text`, `operation_id` |
| `calendar-account` | preferred `email` (or empty string), `operation_id` |
| `calendar-skip`, `calendar-disconnect` | `operation_id` |
| `calendar-sync` | `task_id`, `operation_id` |

No action accepts an actor, being, home, provider account, token or arbitrary
URL from the payload. The verified owner transport fixes the receiving scope.
Human/daimon observations retain the current verified display name and kind;
the private command journal retains the actor reference. These are application
records, not newly signed Matrix messages.

Keep the exact `operation_id` and payload after an uncertain call. A completed
retry returns its retained result. A changed payload conflicts. A reserved
write with no observed acknowledgment returns `agenda_operation_uncertain`;
reread current tasks before making a new deliberate decision. Never report
Calendar delivery from an agenda-only receipt.

## Verification and operator handoff

`tools/qualify_agenda.py --binary /selected/verified/vikunja-binary` starts a
disposable loopback engine, runs affected tests and terminates it. It selects
no live home state, bot, runtime or administrative access. Node is required
by the existing launcher/style tests. Browser/WebView qualification is separate;
do not infer a browser pass from backend tests.

### Local rehearsal without a shared deployment

`tools/preview_agenda.py --binary /selected/verified/vikunja-binary` serves the
same agenda assets, HTTP adapter and pinned engine on a random **loopback-only**
HTTPS port. Open the printed address on that computer; its one-day certificate
is self-signed. A visible banner identifies the synthetic test session and
example data. The tool reads no receiving identity/binding, Google client or
existing home/database. Telegram's SDK is omitted in this local fixture.
Ctrl+C stops the two listeners/engine and removes the temporary state. Never
expose this fixture through a public/VPN proxy or reuse its automatic test
session as an authentication mechanism.

For a repeatable UI/engine journey, install the optional DOM test dependency in
the ignored work directory and run:

```sh
npm install --prefix .work/dom-tools --no-audit --no-fund --save-exact jsdom@26.1.0
python tools/preview_agenda.py --binary /selected/verified/vikunja-binary --check-dom
```

This runs actual form handlers through JSDOM, the HTTPS adapter and official
Vikunja. It covers activation, first-use Google decisions, project/task creation,
date-only and timed tasks, observations, completion/reopening, search, reopening
the app, an acknowledged-server-write with a lost client reply, and local-day
filtering across timezones. Current access loss is a controlled response fixture.
It proves DOM behavior and persistence, **not** layout, secure-browser login or
Telegram WebView behavior. The optional `--snapshot /selected/file.html` exports
a clearly marked read-only design preview with no scripts, external resources,
active controls or credentials; it is not an operational agenda.
On receiving hosts with tight task limits, run the DOM and home-profile
qualifications one at a time; concurrent engines/Node processes can exhaust
available threads without establishing a product failure.

Before live activation the holding operator must review the exact candidate,
backup/verify existing gateway and engine/adapter SQLite state if present, and
approve the exact service plan under repository `AGENTS.md`. Preserve the
existing gateway identity, homes, passkeys, authority, sessions, bot consumers
and current Homemaker source/state. Select the candidate only for the homes
gateway and optional isolated backend; do not restart native bodies or bots.
Retain previous compatible software and the current databases. Rollback removes
the optional routing/flags and stops the new engine; it never restores an old
authority or database. Removal of a publication is a separate owner action.

Qualify HTTPS private read/write and cross-pair rejection, actual Google consent
and event create/update, plus Android/iOS Telegram entry/reopen/return. Tests
with fixture identities/Google responses establish contracts, not real human
consent or phone acceptance. Browser engine failures are reported separately.


## Operator-hosted application with shared authentication

The application and Vikunja may run on the selected operator's VPS. Keep the
existing public home routes, sign-in, current actor/pair authorization and native
owner transport at the homes gateway; use `--agenda-remote PRIVATE_JSON` instead
of the local `--agenda-state/--agenda-backend/--agenda-google-client` flags.
This is an application deployment option, not a second Matrix identity service.
The public browser UI continues to use its existing home URL and assets.

Gateway selection JSON:

```json
{"origin":"http://127.0.0.1:SELECTED_TUNNEL_PORT","token_file":"/absolute/private/agenda-transport-token"}
```

Run the application on its receiving host with
`python -m clusterctl.homes.agenda_remote --config PRIVATE_JSON`. Its configuration
selects `port`, `state`, loopback `backend`, `token_file`, optional `google_client`
and `homes` (registered home reference to exact HTTPS home origin). The application
listener binds only to127.0.0.1. Use an existing managed private tunnel/proxy from
the gateway host; ordinary HTTP is refused except for a literal loopback address.
Remote HTTPS uses normal certificate verification and does not follow redirects.
Do not expose the application hop or Vikunja through the public browser proxy.

Generate a dedicated transport token outside source, mode0600, available only to
the gateway operator and receiving application user. It grants access to this
private Agenda hop, not Matrix signing, owner publication or browser login. Never
copy existing owner credentials, browser cookies or Matrix custody to the app.
Rotate the dedicated token on both endpoints when needed.

On every human/native operation the gateway checks its existing live actor,
owner revision and pairing, then forwards the minimal verified scope to the
selected application. The receiving service checks its allowlisted home origin,
private transport, bounded request and short expiry. Per-request scope is held
in a ContextVar, not mutable process-wide identity. Calendar parent binding uses
a digest; the original browser cookie never crosses this hop. Provider secrets,
accounts, tasks, observations, OAuth flows and Calendar tokens stay with the app.

All mutations retain their existing operation IDs and uncertain-result handling.
The transport never retries a possibly completed request. A lost reply is
reconciled through the same operation/current records, not a new task creation.
Current pairing changes stop use of a former human's Calendar grant on the next
request. Register the unchanged public home callback origins in the Google
application; internal listener/tunnel addresses are not OAuth callbacks.

The receiving deployment needs two bounded services (application and pinned
Vikunja), private persistent state, and a retained compatible gateway selection.
Rollback removes only `--agenda-remote`/the application publication and stops the
new services/tunnel if selected. Retain databases and existing auth state. The
three public homes and three native owners use one application with separate
provider accounts; installing it on Eko's VPS does not make Eko own their identity.
Real Google consent and physical Telegram acceptance remain separate from the
remote HTTP and provider qualification tests.

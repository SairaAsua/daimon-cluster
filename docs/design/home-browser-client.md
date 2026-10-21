# Independently authored homes — browser integration

Owning roadmap: [#214](https://github.com/nicoechaniz/daimon-cluster/issues/214).
First slice: [#215](https://github.com/nicoechaniz/daimon-cluster/issues/215).

## Supported same-origin client

Load `/access-client.js` on a registered, trusted top-level home page. It exposes
`DaimonHomeAccess.contract = "dm.home-browser/v1"` and `createClient()`. No CSS,
page IDs, template, framework, external script or browser storage is required.
The default `passkeys.js` is only a page adapter consuming this client.

A client provides `supported()`, `status()`, `catalog()`, `codeURL(localPath)`, `signIn()`,
`login()`, `register()`, `revoke(credentialId)` and `logout()`. Async operations
accept `{signal}`; revocation accepts it as its second argument. Login/register
must originate in a human interaction. They verify through existing server
ceremonies, then return the result; they do not navigate. A page chooses its own
busy/error controls and navigates only on success. For direct login use
`await client.login(); location.reload()` to retain path, query and fragment.
After successful enrollment navigate to `/access/keys?registered=1` for the
current saved-key list. Cancellation permits retry and approved-code recovery.
`codeURL()` returns that recovery link for the current URL, including its fragment.
Use `signIn()` for ordinary human sign-in: it queries the current gateway and
starts shared login when enabled, preserving the path, query and fragment.
It returns `{status: "redirecting"}` during that navigation; do not reload the
page in that case. Without shared login it runs the original local ceremony.
`login()` remains the explicit fresh passkey ceremony for key management or
independent consumers that deliberately choose it. Shared sign-in remains usable
in WebViews without WebAuthn, where the trusted login page offers Google or a
code. `supported()` describes local WebAuthn, not shared-login availability.
Logout requests JSON, revokes the session and removes its cookie; update the
page only after success and clear restricted displayed content before refreshing.

`GET /access/status` exposes only the current visitor's display name/kind,
signed-in state, public home name, observed dedicated-VPN context and passkey
availability. It uses the existing context/session evaluator; it contains no
session credential, actor reference, recipient lists, grants or private catalog.
`shared_login: true` is added only when the gateway enables this capability.
`GET /catalog.json` retains its existing authorized projection and contract.
Every request re-evaluates effective grants; a previously rendered catalog is
not authorization. History, direct downloads, ranges and isolated previews keep
using the existing access contract. Reconcile persisted/back navigation with
current status and remove restricted displays when revalidation fails.

Reader capabilities never publish, enroll another actor or authorize execution.
Enrollment/revocation still require the existing fresh human browser proof.
Passkeys operate only on exact configured public home origins; the client cannot
register an origin. Keep artifact HTML/SVG sandboxed on its isolated origin.
Importing this script into an artifact never makes it trusted. A custom frontend
must be deployed as owner-approved trusted code with the maintained routing and
origin configuration; no wildcard CORS or shared-domain cookies are needed.

The optional `--client-example` gateway flag serves a different list/filter
presentation at `/examples/home-client/`. It consumes the same client, status
and catalog, with independent markup and CSS; it changes neither the main home
nor its authored work. Its two presentation assets are available only with that
flag. Default deployment remains unchanged when the flag is absent.

The v1 browser client depends on the current home gateway's existing JSON
ceremonies plus the additive visitor status projection. Preserve existing routes,
`/passkeys.js` adapter and v1 result semantics throughout this compatibility
window. Version-breaking changes need an explicit successor, migration and
owner-selected adoption policy. Automatic package updates are not implemented
by this slice.

## Oliva/Ani's Homemaker: inspected source and integration boundary

On 2026-10-13 the public [Homemaker publication](https://oliva.dmn.homes/view/6322b8e9396f546d94a36cac2704bc23)
was inspected at immutable version
`0d8b7785cb31a2647ac83cf4af1ff1d38cfe47c7f8a81d94f4acaffbbd58c885`.
Its `lib/model.js` exports `designRecipe`/`readRecipe` for
`homemaker.design/v1`, version `0.5.0`; configuration includes `templateId`,
`paletteId`, `fontId`, `assetId`, spacing, corners, project display, sections,
widgets and keywords. `content/bundle.json` supplies templates, assets and demo
content. The builder exports validated recipes and portable static previews;
`lib/export.js` embeds selected styles/assets while retaining font licensing.
This is an actual published recipe/preview tool, not an observed shared default
registry or cross-app style subscription service. No such service is invented
or claimed here. The publication is the verified source route until its owning
maintained repository/package and adoption API are linked.

Nicolás selected this creator as the shared style authoring source across homes
and Telecodex Mini Apps. Future consumers distinguish `default` from explicitly
chosen style; changes to the human/pair default or its followed style update
inheriting surfaces. An explicit style ignores changes to the default; freezing
its own revision is a separate choice. Style state is independent of software
pins and permissions. Public authorship and authenticated viewer preferences
must have explicit scope rather than treating one human's choice as global.

The access client is visually neutral. The alternative client declares
`data-style-selection="default"` and local semantic hooks for background,
surface, text, accent and font as a fallback. These hooks prepare integration;
they are not an adapter for all of Homemaker's recipe capabilities or a deployed
style subscription. Map the actual recipe through the creator's supported
consumer contract in the component phase, retaining authored layouts, explicit
styles, recipe/version history and a readable last-valid fallback. Do not copy
its catalog or make another style editor. Do not regenerate applications or
wake models merely to propagate a selected-style change.

## Trusted application identity

A trusted application mounted on a registered home origin can reuse its current
`__Host-home` HttpOnly session. Its backend sends that cookie to the same home's
`GET /access/identity`. The `dm.home-session/v1` response contains only the
verified current human actor, revision, name and exact home origin. Anonymous,
VPN and bearer requests are refused. Existing session ancestry, expiry and
revocation remain authoritative; the application revalidates before private
operations and enforces its own receiving grants. No login token is returned.

Use the existing same-origin `DaimonHomeAccess.createClient().signIn()` for
sign-in and exact-path return through the configured common auth service.
This adapter requires a trusted application mount, not an isolated artifact
or a cross-origin credential bridge.

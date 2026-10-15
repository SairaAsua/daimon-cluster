# Shared style consumption — authority boundary

Roadmap: Cluster214/222; cross-system design proposal:
https://github.com/AlterMundi/daimon-matrix/issues/328.

## Actual source and candidate state

Homemaker's owning repository is AnnieScigliano/homemaker, inspected read-only
at checkpoint671c846. The published version0.5.1 remains separate from the
contribution candidate. The current CompAII GitHub account cannot access that
private repository; source was inspected through its existing local body.
No owner credentials or private sessions were copied. Oliva's original checkout
and production publication are unchanged.

The contribution candidate extracts an appearance projection **in Homemaker**,
using its existing `readRecipe`, catalogs and font roles. Its existing renderer
uses those same roles. The projection advertises palette, font roles, spacing
and corners, not a complete layout transformation. Richer templates, imagery,
widgets and composition remain owned by the actual creator and site authors.
Recipe keywords, personal preview contents and arbitrary CSS are excluded from
this projection. Earlier recipe compatibility is retained by the creator itself.

## One authority, independent consumers

Canonical recipes/design identities, versions, provenance, defaults and explicit
surface choices belong to the Homemaker component. Cluster's `StyleConsumer`
delegates resolution and performs no design writes, no recipe imports and no
local authoritative selection persistence. A provider must be explicitly wired
and qualified before deployment; the standalone prototype is not a live provider.

Receiving authentication/policy resolves current Matrix being references and
existing human pairing, not hostnames or presentation labels. The consumer
chooses a stable author-being scope. A human's personal context is supplied only
when this surface explicitly supports it; another pair's visitor preference
cannot silently repaint authored public sites. An explicit surface selection
wins over either kind of default. Followed design revisions and pinned revisions
are different choices, independent of software package versions.

The proposed backend receives action-scoped authorization from the actual
identity/access adapter; it creates no accounts, sessions, signing custody or
listeners. A read cookie by itself is not permission to publish designs. Keep
private recipes/keywords/default histories out of public lists and unauthorized
projections. Publishing a new recipe does not publish private earlier revisions;
restricting the current design also protects its earlier public revision URLs.
Write with CAS and stable operation IDs, rechecking authorization before replay.

## Foreground presentation and isolated work

A registered trusted home consumer requests only its resolved appearance for the
exact authorized home/resource. It validates a bounded palette/font/density/
corner projection and applies semantic CSS hooks while retaining the authored
layout. The frame receives appearance only from its actual trusted parent, never
credentials, actor references or an editable preference store. Unsafe CSS,
network URLs, sibling messages and null-origin senders cannot change styles.
Explicitly authored work may opt out through its own style declaration.

## Source-owned surface policy

Each page declares its policy at its owning HTML root, not through a host-wide
exception list: `data-style-policy="inherit"` (also the default when omitted)
follows the resolved shared selection; `data-style-policy="authored"` keeps the
surface's own CSS. Unknown explicit policy values retain the authored fallback.
The earlier `data-style-selection="explicit"` opt-out remains compatible when
the new policy is absent. This differs from a canonical explicit design reference
or pin, which still receives resolved appearance through an inheriting consumer.

Homemaker's own template declares authored: desktop, compact and Telegram editor
shells retain their interface while previews and selected spaces change. No
gateway hostname checks, copied palette, preference mutation or second exception
database is involved. An authored editor may broadcast explicit save invalidation
to other default consumers without fetching/applying that default itself. The
same declaration is respected by the trusted-page and isolated-artifact consumers.
It controls presentation only and grants no resource or identity authority.

The current consumer candidate refreshes on opening/resuming and at most once
per15seconds while visible; same-origin invalidation can refresh immediately.
Requests have a10second fetch/body deadline. Hidden/closed pages cancel their timer, abort in-flight requests and discard late responses. This is browser presentation traffic,
not Matrix inbox polling or a model wakeup. Retain the last valid presentation
on unavailable/malformed responses and the local accessible fallback when no
shared selection applies. No offline style cache adds artifact access rights.

Consumers need source-owned font assets/license integration when using the
creator's named font families; normal CSS fallbacks keep text readable until
that explicit asset route is qualified. Do not claim font/layout fidelity merely
because palette variables changed. Images and rich layout adapters must declare
and test their own supported subset.

## Remaining coordination before live adoption

Oliva/Ani and CompAII reconcile the actual creator's current plan and canonical
resolver/editor contract under Matrix328. The source contribution and gateway
consumer candidate remain separate from deployment. No new preference authority
may be introduced at the gateway. Link the owning source/version, qualify the
existing fingerprint/pairing/Matrix authorization adapter, wire only that provider,
and demonstrate one home and an existing Telecodex Mini App sharing a default,
explicit exceptions, followed edits and unavailable/revoked-source fallbacks.
Physical Telegram acceptance remains separate from browser qualification.

The receiving adapter now exists as an opt-in candidate: `--homemaker-source`
selects qualified immutable creator code/public build, and `--homemaker-state`
selects its one canonical private store. Both are required together. The source
is never selected by an HTTP request. The existing workshop is served at
`/homemaker/`, with the existing compact application at `/homemaker/miniapp.html`.
Their trusted bootstrap injects the current server transport into the existing
builder. The public source stays usable in its original protected publication;
that opaque view does not receive a credential or design-write capability.

Pair writes use the existing verified human session and current Matrix pairing;
personal writes use that human's own scope. A cookie does not by itself grant
another pair's editor rights. Audience is server-bound (public pair recipe or
private personal recipe); requests cannot name an actor or override it. Preference
edits do not require a redundant fresh fingerprint. Credential operations keep
their stronger existing freshness and ancestor-revocation checks.

Native daimons use the existing publishing-owner credential for `style-baseline`
and `style-default`. The latter requires an explicit public/private audience,
the source template variant/recipe, both expected revisions and a stable operation
ID. The verified owner fixes the being namespace; neither operation accepts a
human or another being as an author. A reader cookie is not a publishing
credential and cannot call these operations. Both routes use the same canonical
source component as the paired human's editor, with no second design store.

The same owner adapter exposes `style-selection` and `style-select` for the
current selection or an explicit follow/pin/default choice. Its surface must be
`default`, `home`, `homemaker` or a resource currently registered to that home.
The verified owner fixes the scope; a request cannot name an actor or another
scope. `style-recipe` uses the canonical recipe privacy check and returns its
bounded projection without actor/history data. Reader credentials cannot call
these operations. Selection and save conflicts return stable409 codes; retain
the exact intent on uncertain I/O instead of manufacturing another revision.
The optional daimon-home2.1 commands consume these same operations; previous
publication helpers remain compatible. Actual owner HTTP/maintained-helper/
canonical-source qualification covers follow, pin, default restoration, exact
retry and privacy. It does not imply a live operator adoption or phone trial.

The read-only appearance consumer can explicitly opt into its verified visitor's
personal preference; it never accepts an arbitrary human reference from the
browser. The creator's application uses the stable `homemaker` surface name.
Fixed `/design-assets/` routes expose only the original built font CSS/fonts and
license files. Native fonts were exercised with the actual creator and canonical
authority in HTTPS browser qualification. A configured writer/default switch and
an explicit MiniApp choice were qualified locally, with synthetic humans; no
live configuration or physical Telegram acceptance is implied.

Preserve current artifacts/grants/recipe exports, body/native sessions, passkeys,
source history and compatible rollback. Automatic package updates and autonomous
attention stay outside this increment.

## Owner-operated central entry preparation

`--homemaker-home REGISTERED_HOME_REF` optionally selects the existing home whose
trusted editor may resolve the authenticated human's own pair independently of
that entry's hostname. It requires configured creator source/state and a registered
home. The existing login must first establish that human's current browser session
on the central origin; a launch URL does not supply identity or a write grant.

At the selected entry, pair context resolves current pair bindings. No pair or
multiple distinct paired beings refuses the operation instead of choosing the
visited home's owner or the first match. Personal context remains that human's
private scope. Other home editor routes retain their prior paired-human check.
Native owner operations, the canonical store and consumer appearance resolution
are unchanged. No request-supplied owner or actor is accepted.

This setting prepares the receiving policy; it does not constitute the complete
owner-operated application handoff. Homemaker's maintained application module,
release ownership, permitted recovery/return operations and launch-link retirement
remain part of the coordinated owner release. Keep the existing source/state and
paths selected until that successor is qualified. A hostname change or this flag
alone is not consolidation. Coordination: Matrix328 and the owning Homemaker
`docs/CONSOLIDATION.md`.

The coordinated successor also loads `backend.application.OwnerApplication` from
the selected owning release and injects the existing `DesignAuthority` instance.
It checks the release declaration against the configured canonical origin and
entry paths; changing the source does not create another store. The owning
`public/lib/owner-entry.js` recovers the permitted saved recipe before mounting
the atelier. Recovery failure blocks that initialization rather than silently
replacing an existing choice with a fresh default.

`/homemaker/api/selection` supports bounded read/select/follow/pin/default using
current context and registered surfaces. `/homemaker/api/recipe` returns only the
canonical permitted recipe projection. Browser writes retain the current session
and exact Origin checks; CAS conflicts retain409 responses. Request-supplied
actors/scopes are refused. The same native owner operations remain available.

Launch query `target` names a registered home request, verified against the
current human's pairing; it grants nothing. `return_to` must be an exact registered
return bound to that target's public origin. Home roots are registered by default;
`--homemaker-return EXACT_HTTPS_URL` adds a specific consumer path/query/fragment.
The source-owned entry uses the returned verified URL as a normal human-clicked
link. No reader cookie, browser proof or credential enters that URL.

With the owner-operated release selected, former home editor entries temporarily
redirect to the canonical entry with their target/return context. Former editor
assets/API routes return410 and cannot remain competing editors/writers. Public
font and read-only style consumers remain local adapters of the same authority.
Use temporary redirects during rollout to preserve compatible-code rollback.
This source behavior alone is not an activation or physical-device receipt.

## Independent app appearance and first paint

Sessions and Nexus can opt into their receiving home's public
`/style.css?surface=sessions` or `nexus` as a normal stylesheet in the HTML head.
The bounded formatter accepts only Homemaker appearance roles, not arbitrary CSS,
URLs, actor fields or recipe contents. This endpoint always resolves the public
author with no viewer, ignoring ambient cookies/bearers and refusing viewer or
resource-identity overrides. Existing authenticated `/style.json` is unchanged.
This is appearance delivery, not cross-origin identity or access delegation.

Use one `link[data-home-style]` and the same maintained `home-style.js`. The
initial stylesheet resolves before paint. Visible foreground updates replace it
only after a successful load; failure/timeout/hidden pages retain the last valid
sheet. The app maps `--dm-background`, `--dm-surface`, `--dm-text`, `--dm-accent`,
font roles, gap and radius into its authored controls. Light and dark modes and
actual font delivery need browser qualification. Native chrome follows the
computed background. No parallel editor/default store or raw Telegram payload
transfer is involved. Private viewer appearance still needs the verified adapter.

Apps embeds current style and local publication cards in request-scoped HTML.
Peer discovery follows after that first useful screen. HTML and private data
remain no-store; only content-versioned public JS/CSS is immutable. Static
Homemaker modules/fonts support conditional revalidation, and the owner entry
preloads its actual module roots. No cache restores old private grants, native
actions or style preferences. New code changes asset URLs; no model wakeup or
global Stop is part of this browser delivery.

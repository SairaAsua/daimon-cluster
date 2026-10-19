# DaimonMatrix Mini App launcher

Owner: [Cluster #244](https://github.com/nicoechaniz/daimon-cluster/issues/244).
The launcher is a native client of the existing homes gateway. It creates no
bot consumer, access authority, identity, model call or session-control provider.

## First useful route

**Apps is the launcher**, not a destination app. A private bot menu may open its
receiving home's `/apps/` URL directly using `MenuButtonWebApp`; it does not
require a Main or named app registration. Keep any existing Main/named Apps
registration for shareable Telegram links. Never select another pair's bot just
to open a shared application. The gridded launcher is authored HTML/CSS, not a
Telegram message keyboard.

### Main-app destination routes

The optional gateway `--miniapp-routes FILE` selects a closed
`dm.miniapp-routes/v1` map of exact HTTPS origins to selector prefixes and
same-origin application paths, for example:

```json
{"schema":"dm.miniapp-routes/v1","origins":{"https://apps.example.org":[{"prefix":"nexus-","path":"/nexus/"}]}}
```

The proxy must mount the existing receiving application separately from the
public read-only launcher projection. Preserve that application's actual Origin,
cookies and authorization; never copy the public projection's credential stripping
onto its private routes. The receiving application must explicitly accept the
additional exact Origin and retain its own signature and membership checks.

Only a fresh Telegram launch with a configured prefix routes automatically.
Ordinary Apps openings and unknown selectors keep the launcher. A one-use,
30-second marker binds the current SDK tab cache to the exact path and SHA-256
of its unchanged launch data. No raw authenticated payload is copied into a
custom store, query, catalog or log. The receiving app consumes the marker before
initializing its SDK and then removes the cache. Missing or mismatched storage
fails visibly. This navigation mechanism is neither authentication nor another
bot's grant. A registered selector without this receiving route is insufficient.

The shell follows Homemaker through the existing `home-style.js` and canonical
`style.json?surface=apps` resolution. It neither stores a selected theme nor
reimplements the design authority. Layout is independent; colors, fonts,
radius and spacing use the consumer's semantic variables. An authenticated
paired viewer receives the existing personal/pair resolution, while an
anonymous visitor receives only the author-selected public appearance. The
ordinary shared login remains available through the Homemaker entry. Telegram
opening alone does not create a passkey session or grant private styles.

## Publish once, discover through existing home relationships

Use the receiving pair's existing `daimon-home link` publisher with an explicit
application intent and audience. The portable `daimon-home` skill owns this
workflow; ordinary links are not automatically promoted by title.

```sh
daimon-home link https://app.example.org/ --app --id my-app --title 'My app' \
  --summary 'What this application does.' --visibility public \
  --decision 'Selected for shared application discovery in the current task.'
```

New app publications carry `application.schema = dm.application/v1`:

- `mode: shared` (default for `--app`) is an independent HTTPS app. It uses its
  ordinary identity/resource grants; it must not require the author's Telegram
  bot. The single official Homemaker remains shared, with no cloned instances.
- `mode: paired` also declares a `capability`, such as `sessions`. The receiving
  operator supplies `--miniapp-receivers FILE`, a bounded JSON map from registered
  home references to capability/HTTPS routes on that home's exact origin. A
  verified shared-login actor selects its unique current pair. Without login,
  the launcher asks for an explicit receiving pair; it never infers the visitor's
  pair from the author being visited. A remembered selection is navigation only.
  The target authenticates again.
  A missing receiver disables the card; it never falls back to the author bot.
- `mode: author` requires a visible `dependency` explaining why the app inherently
  needs the author daimon. This is an explicit exception, not a workaround for
  missing shared authentication. Legacy Telegram app links remain visibly marked
  as author-bot links pending migration; they do not become shared by inference.

Every launcher reads current registry/publication projections. It includes its
own authorized apps and **public** apps from its already-selected web ring.
Other homes never inherit the current home's private cookie, VPN fence or subject.
Publishing or withdrawing uses the existing publisher, retaining artifact identity,
audience, author and version. No launcher rebuild or copied catalog is needed.
A publication is navigation, never private data/session access. The operator map
contains no credentials and must be qualified against each real receiving backend.

Shared apps use ordinary same-WebView HTTPS navigation. Browser/application login
must remain usable inside another bot's WebView; foreign Telegram launch data
must not silently become the author's identity. Keep the existing native launch
verification path fail-closed. Browser fixtures do not prove physical Telegram
acceptance. Telegram's menu and identity contracts are documented at
https://core.telegram.org/bots/webapps#launching-mini-apps .

The server bounds discovery to16 selected homes,4 concurrent backend reads,
2-second socket timeouts,256 entries and4 simultaneous catalog requests.
Unavailable/truncated sources remain explicitly partial. Frontend requests have
a12-second deadline and a manual retry. Favorites store only resource IDs in
device-local storage; they do not synchronize or store private metadata.

## Qualification and next increments

Real HTTP tests cover source/registry mismatch, own-home versus cross-home
grants, withdrawal, revoked reader, unrelated Origin, private error isolation,
asset path boundaries and unsafe URLs. A browser must also verify narrow layout,
search/favorites, runtime appearance changes, offline retry and real links.
Browser Telegram stubs qualify routing intent, not physical phone launch.

After registering the real named app, check launcher→Nexus/Sessions and return
on the actual phone. Selecting the bot menu is a separate explicit operation.
No global Stop follows from installation or testing.

Remaining: qualify receiving routes and actual cross-pair phone launches for
published apps; extend cross-home private discovery only under explicit grants.
Do not treat an iframe, public URL or launcher login as target authorization.

## Shared public entry and startup

A public `apps.dmn.homes` alias can reuse the same gateway and wildcard TLS.
The proxy must admit only GET/HEAD on launcher assets/catalog and public style
resources, strip all Cookie/Authorization input and Set-Cookie output, and
select the registered publication host explicitly. Removing Origin on that
narrow read-only projection must never become a general proxy bypass. Reject
POST and all login, owner, session/control or artifact paths. This alias exposes
public navigation only; it is not a new identity service or private viewer.
Keep existing home entry points and the registered bot app until the exact new
URL and actual phone launch are accepted. Per-bot Sessions launch/grants remain
independent: a public launcher does not turn another bot's signed launch into
the receiving bot's identity.

The initial response contains current local cards and selected appearance;
foreign sources reconcile asynchronously. Public static files use content-based
version URLs and immutable caching. HTML, initial catalog and permissions retain
no-store behavior, so withdrawal/revocation is not masked by browser storage.
The old local fallback is used only when no permitted appearance is available.

## Returning from an app

Sessions, Nexus and the official Homemaker adapter expose a compact **Apps**
link to `https://apps.dmn.homes/`. Normal same-WebView navigation selects the
launcher explicitly; `openLink` would open an external browser and
`openTelegramLink` can retain another Mini App. Neither is a reset-to-launcher
guarantee. Preserve each app's internal BackButton and protect unsaved edits
before leaving. Never append Telegram launch data or private session parameters.
Saved server work continues independently; preserving every in-memory view after
a cross-origin navigation is not promised. Qualify actual Android/iOS WebView
return behavior separately from browser routing.

## Authenticated alert trail

A separate same-origin `POST /apps/attention` route is operator-mapped to
Telecodex's bounded read-only signed-launch endpoint. It validates the actual
receiving bot/user and current human grant, then returns the same attention point
used by the Telegram menu, with at most three safe summaries. The banner opens the
existing registered Sessions link; its card repeats the exact point. Sessions opens
active alert details with matching severity symbols. Labels accompany color.

Public catalog data is unchanged. No private summary or launch payload is stored
in the catalog, URLs or custom browser storage. Visible clients refresh every
thirty seconds; hidden clients perform no observation. Failure clears summaries
and shows white unknown rather than observed clear state. A response's registered
app URL matches the card destination; a title is not an authority binding.

Current receiving adoption is CompAII-only on shared Apps and its home. Other bot
signatures are rejected and need their own receiving route; no shared credentials
or inferred permissions. Anonymous browser views retain public navigation only.
The receiver's five-minute signed-launch validity is preserved: reopening obtains
fresh launch data. Browser fixtures do not establish physical phone acceptance.

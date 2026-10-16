# DaimonMatrix Mini App launcher

Owner: [Cluster #244](https://github.com/nicoechaniz/daimon-cluster/issues/244).
The launcher is a native client of the existing homes gateway. It creates no
bot consumer, access authority, identity, model call or session-control provider.

## First useful route

Register one named app, displayed as **DaimonMatrix**, with a selected receiving
home's `/apps/` URL. Matrix Apps is the shared Main Mini App. Nexus is a routed
destination; preserve already registered named entries such as Sessions. Never
change the principal app to Nexus to compensate for missing destination routing.
The bot menu can later point to this named app using `mode=compact`; registering
and testing it precedes changing a working menu. The gridded icon launcher is
ordinary authored HTML/CSS rather than a Telegram message keyboard.

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

Use the receiving pair's existing `daimon-home link` publisher with the real
registered Telegram app URL, its title, summary and explicit audience. For example:

```sh
daimon-home link https://t.me/example_bot/myapp --id my-app --title 'My app' \
  --summary 'What this application does.' --visibility public \
  --decision 'Selected for public application discovery in the current task.'
```

Every launcher reads current matched registry/publication projections. It
includes its own authorized app links and **public** app links from homes in its
already-selected web ring. A different home's private titles never inherit the
current home's cookie, VPN fence or subject. Publish, change audience or remove
through the existing publisher; no launcher rebuild or copied per-bot catalog
is needed. Catalog rows retain author, resource identity and revision. A link
does not grant access to its target's private sessions or data. The navigation
projection is not a second resource registry.

Canonical `https://t.me/<bot>?startapp=...` and named-app URLs use Telegram's
launch method. One qualified web target is also recognized: the exact compact
entry of the configured Homemaker owner application. Publish that official URL
once through the existing link publisher; every selected home discovers it.
The catalog marks this entry `launch: web`, and its ordinary HTTPS anchor
navigates the same WebView instead of calling `openTelegramLink`. Other links
remain ordinary publications, including old editor origins, artifact previews,
and URLs with added identity or return parameters. No arbitrary HTTPS app is
promoted by its title. No additional BotFather registration, iframe, editor,
style store or identity parameters are needed. Shared login and the owner
application resolve the current human/pair and keep its authored workshop shell.
Browser navigation is qualified separately from physical Telegram launch.

The initial catalog may include
receiver-specific tools; their author labels remain visible instead of claiming
that everyone has access to the same native conversations.

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

Remaining: allow a new independently authored web app to use the one registered
DaimonMatrix entry without separate BotFather registration, with a versioned
scoped launch handoff; extend cross-home private discovery through an explicitly
authorized contract; document paired onboarding/registration and portable skill
adoption. Preserve independent app code/origins, target authority and updates.
Do not treat an iframe, a public URL or launcher login as target authorization.

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

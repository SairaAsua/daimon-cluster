# DaimonMatrix Mini App launcher

Owner: [Cluster #244](https://github.com/nicoechaniz/daimon-cluster/issues/244).
The launcher is a native client of the existing homes gateway. It creates no
bot consumer, access authority, identity, model call or session-control provider.

## First useful route

Register one named app, displayed as **DaimonMatrix**, with a selected receiving
home's `/apps/` URL. Keep its existing Main App and named Nexus/Sessions entries.
The bot menu can later point to this named app using `mode=compact`; registering
and testing it precedes changing a working menu. The gridded icon launcher is
ordinary authored HTML/CSS rather than a Telegram message keyboard.

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

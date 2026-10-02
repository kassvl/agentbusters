# Fener — PRP (single source of truth)

*Product / Research Plan. If code and this file disagree, this file wins or gets updated.
Owner: Kadirhan. Started 2026-09-19.*

## Mission

Discover and map the networks of autonomous AI agents on the open web, using the
method Kadirhan conceived: the **dolphin-tag**. Biologists find a pod by tagging one
dolphin and following its pings. Fener tags the *places agents forage* and follows the
pings back to the pod.

| Dolphin research | Fener |
|---|---|
| Satellite tag | canary token (unguessable marker URL) |
| Releasing the tagged animal | planting the marker where agents forage (surfaces you own) |
| GPS ping | an HTTP request, captured with full forensics (IP, ASN, UA, headers, timing) |
| The pod | the network of agents + the dead corners they share |
| Triangulation | correlating which markers were hit, from what infra, in what order |

## What Fener is / is not

Fener is a **beacon and honeypot you run on your own surface**. It draws agents, records
them, and — with a harmless call-and-response — gets them to reveal and fingerprint
themselves. It is measurement and defensive research.

Fener is **not** a tool to command third-party agents, task them, redirect them, or make
them (or you) bypass anyone's safety. That is unauthorised interference and is the exact
rogue behaviour the field defends against. The bright line:

> Getting the flock to respond so you can count and tag it — YES.
> Taking the helm of other people's agents — NO.

## Guardrails (load-bearing, shape the design)

1. Instrument only surfaces you own/control. Never plant markers as spam on third-party sites.
2. Observe and detect; the only "influence" allowed is a harmless self-identify call.
3. Susceptibility experiments run against your OWN agents only (`redteam.py`).
4. Escape everything echoed to humans; cap sizes; rate-limit writes; make no outbound calls.
5. Provenance discipline (from Pamphylia Atlas): the raw request is immutable evidence;
   classification is a separate, reasoned label. Never trust the UA string — verify with
   reverse-DNS forward-confirm and provider IP ranges.
6. A public open-write surface can attract abusive content from humans too; content is
   capped, escaped, never executed, and there is a killswitch (stop the process).
7. If a genuinely malicious swarm turns up: report to the infra provider; do not engage.

## Architecture (v0, stdlib only — runs with `python3`, no pip)

- `serve.py` — the service. Collector (every path logged), Fener honeypot (`/` open
  scratchpad, readable + GET/POST writable, with the agent call-and-response bait),
  beacon (`/c/<token>`), `/dashboard` (JSON, local or `?key=`), `/admin/mint`, `/robots.txt`.
- `store.py` — SQLite evidence store: `events` (immutable) + `enrichment` (labels) +
  `tokens` + `pod`. `responders()` joins page-view → later marker fetch (confirmed agents).
- `enrich.py` — reverse-DNS + forward-confirm + UA match → classification with reasons.
- `agents.json` — seed list of known agent UAs and how to VERIFY them (maintain; it drifts).
- `sonar.py` — import existing access logs (Combined Log Format / Caddy JSON) into the store.
- `redteam.py` — drive your OWN agent at the honeypot, measure injection susceptibility.
- `verify.py` — fetch + cache provider-published IP ranges; turn claimed agents into
  verified/spoofed (cache-only lookup in the hot path; `--refresh` does the network).
- `scout.py` — read-only reconnaissance: visit candidate dead corners, scan for agent
  traces, report WHERE the pod forages. Never posts, joins, or impersonates.
- `habitats.json` — the MAP: known agent-congregation surfaces + the habitat fingerprint
  (GET-writable legacy wikis: `wiki.cgi?action=`, UseMod/ProWiki) + coordination-trace
  signals (ZZZ Schelling pages, heartbeat/termination counters, pinggy/localhost.run
  tunnels, self-ID, GET-write/bypass talk, task relays, machine handles).
- `traces.py` — one scanner over those signals (shared by hunt + scout).
- `hunt.py` — the telescope on a clock: sweep mapped habitats' RecentChanges, score
  agent-trace density, write a timestamped `sightings` ledger, flag NEW activity on
  `--watch`. Proven live 2026-09-19: collusion.wiki 85, DSEWiki 27, ProWiki farm 20-23.
- `discover.py` — turn the fingerprint into more candidates: search dorks + wiki-farm
  enumeration → a seed list for hunt.
- `test_fener.py` — deterministic tests (DNS + ranges monkeypatched).

## Mission shift (2026-09-19, user)

Not a HABITAT (honeypot) and not the user's own traffic — the goal is to find and watch
where rogue agents ALREADY congregate. The scout/hunt is the released tagged dolphin; the
sightings ledger is its GPS pings. The honeypot/sonar remain secondary passive tags.

Classifications: `known_agent_verified`, `claimed_agent_unverified` (spoof), 
`claimed_agent_unconfirmed` (UA matches, no rdns to check yet), `possible_wild_agent`
(the interesting catch: unannounced, cloud egress / non-browser / token-responder),
`likely_human`, `unknown`.

## Deploy-readiness (built, off by default)

- `FENER_TRUST_PROXY=1` → real client IP from `X-Forwarded-For` (behind Caddy/Vercel).
- `FENER_DASH_TOKEN=…` → protect `/dashboard` and `/admin` with `?key=` instead of source-IP.

## Roadmap

- [x] v0: collector + honeypot + beacon + classifier + dashboard, local, tested.
- [x] Call-and-response bait + read→act correlation (`responders`).
- [x] Passive sonar (log import). Own-agent susceptibility harness (baselines).
- [x] v1: verify claimed agents against provider IP-range JSONs (openai/google/bing/perplexity
      cached live; flags spoofs). Some provider URLs 404 — maintain `agents.json`.
- [x] Scout: read-only recon that finds where agents leave traces (the "puppet observer").
- [ ] v1: wire a real model into `redteam.py` (Claude API) for true susceptibility numbers.
- [ ] v2: deploy. Chosen host TBD. `example.com` is on Vercel (serverless) with a
      site already at the apex → use a subdomain and either (A) rewrite to Vercel functions +
      Turso, or (B) a small VPS + Caddy + systemd. Fix XFF + dash-token before public.
- [ ] v2: **release the tag** — the part that actually catches wild agents: plant markers /
      links on already-trafficked sites (loomr.net, braidss.xyz) and import their logs.
      A bare new subdomain gets almost no agent traffic on its own.
- [x] Habitat MAP + fingerprint + trace scanner; live habitat hunter/monitor (`hunt.py`)
      with a timestamped sightings ledger and NEW-activity flagging.
- [x] MONITOR early-warning: `hunt.py --alert` (alerts.log + macOS notification) +
      launchd plist (`deploy/com.fener.hunt.plist`) for a 30-min sweep. Proven: alerted on
      5 high-score habitats.
- [x] Habitat GRAPH (`graph.py`): farm/host structural edges + time-accumulating entity
      edges (persisted in `entities`). Proven: the 5-wiki ProWiki farm cluster
      (DSEWiki/FractalWiki/ProbierWiki/ProWikiCenter/Wiki4D).
- [x] DISCOVER (`discover.py` + dorks): expanded map 9->14; confirmed 3 new live habitats
      (ProbierWiki 35, FractalWiki 20, UseMod SandBox 20). Lead: "The Colony" (agent-only
      network, API+MCP) — URL unverified.
- [x] TRAVERSAL SCOUT (`traverse.py`) — the released, GPS-tagged agent: read-only BFS from
      seed habitats following breadcrumbs (interwiki links, wiki.cgi/pl surfaces, URLs,
      pinggy/localhost.run tunnels, shorteners), crawler-filtered counts, records the walked
      path as a GPS track (`traversal` table; dashboard `/traversal`). First live run
      (depth 2, budget 30): discovered new ProWiki-family wikis dorfwiki.org, schulwiki.org,
      wikiservice.at farm mirror; 0 new habitats with real (crawler-filtered) agent traces —
      honest negative (the June swarm is over). Robots-respecting, rate-limited, never writes.
- [ ] Propagation TAG: plant benign unique markers only where permitted (our honeypot;
      agent-guestbook invitation) → they become graph edges once agents carry them between
      habitats. (`markers.txt` is already read by graph.py.)
- [x] PHASE 1 — Discriminate LIVE agent edits from human documentation (`analyze.py`):
      parse UseMod/ProWiki RecentChanges into per-edit (page, author), classify by author.
      Finding: ProbierWiki is the LIVE hotspot (154 agent edits, Agent00N... scheme);
      FractalWiki dormant (0 agent) despite text-score 20; DSEWiki now mostly human cleanup.
- [x] PHASE 2 — persistent early-warning: `monitor.py` (sweep+analyze, alert ONLY on new/
      increased LIVE-agent edits) + MediaWiki rc parser; installed as launchd
      (`~/Library/LaunchAgents/com.fener.monitor.plist`, 30-min, RunAtLoad, exit 0 verified).
- [x] PHASE 3 — visual topology graph (`graph.py` -> graphviz SVG/HTML, nodes coloured by
      live-agent count): ProbierWiki red hotspot, ProWiki-farm cluster. Served at
      dashboard `/graph`.
- [◐] PHASE 4 — from-scratch fingerprint discovery ran (UseMod SiteList, 10 new wikis):
      NONE colonised -> niche sharpened to the abandoned wikiservice.at/ProWiki-farm test
      wikis. Next: deep-enumerate that farm. "The Colony" URL still unverified.
- [x] PHASE 5 — live localhost control room (`dashboard.py`, :8033): map, text-score vs
      live-agent, farm cluster, alerts, /graph topology, Sweep-now.
- [ ] v3: pod analysis — cluster by ASN / behaviour / timing; map the watering holes.

## Honest expectations

The easy 90% of catches will be self-announced crawlers (GPTBot, ClaudeBot, …). The prize
is the unannounced sandboxed agent doing tool-use — caught best by the read→act
correlation and cloud-egress signals. Seeding matters more than deploying.

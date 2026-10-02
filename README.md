# AgentBusters

**A sensor for autonomous-agent activity on the open web.** AgentBusters reads public surfaces —
old wikis, package registries, code hosts, agent forums — and tries to detect where autonomous
AI agents gather and *coordinate*, then map those surfaces into a graph.

In 2026, autonomous agents were documented coordinating on public infrastructure: a dormant
German wiki (DSEWiki) used as a message board, dead-drops on model hubs and registries,
directory-name-encoded channels. Existing tools watch *one* honeypot, protect *your own* agent,
or verify identity at the edge. The gap AgentBusters aims at is the **coordination** itself,
across surfaces — the thing no single-surface view shows.

It's a **research tool**, pure Python standard library, no pip dependencies.

> Internals keep the original codename *Fener* ("lighthouse"): env vars `FENER_*`, markers
> `FENERZZZ…`, module names. The project is AgentBusters.

---

## ⚖️ Ethics & responsible use — read first

AgentBusters is **observation, not manipulation.** This line is enforced in the code:

- **Read-only scouting.** It reads public surfaces; it never writes to, registers on, posts to,
  or joins a surface it does not own. It respects `robots.txt`, rate-limits, and backs off.
- **The beacon goes only on surfaces *you* own.** Canary tokens / honeypot live on your own
  sites — never planted on anyone else's.
- **Never command or steer another operator's agent.** A harmless "identify yourself" probe on
  your own surface is fine; making someone else's agent do work or bypass controls is forbidden.
- **No doxxing.** The repo ships the *tool*, not the collected intelligence. The local evidence
  store (named handles, specific sightings) is git-ignored and never published; real individuals
  are not named in the code.

Don't use it to attack, spam, deceive, or manipulate. It's for defenders and researchers.

---

## What it does

| Capability | Module(s) |
|---|---|
| Honeypot + beacon that records agents and self-reports where a planted tag travels | `serve.py`, `beacon.py` |
| One shared **covert-channel fingerprint** across wikis / npm / PyPI / gists / Hugging Face | `covert.py`, `collectors.py` |
| **Roam site-to-site** from seeds, following breadcrumbs — deterministic, zero LLM tokens | `traverse.py`, `monitor.py` |
| **Cross-surface correlation** — a lone agent is noise; a shared marker/handle across surfaces is a cluster | `correlate.py` |
| **Cryptographic attribution** — Web Bot Auth (RFC 9421), with a pure-stdlib Ed25519 verifier | `webbotauth.py`, `ed25519.py` |
| **Behaviour over name** — authorship, recency (≤21d), machine-cadence, LLM-stylometry | `analyze.py`, `behavior.py` |
| **Fusion census** — evidence-backed dossiers, LIVE-vs-archived, confidence grades | `fuse.py` |
| Web-wide habitat discovery (optional search API) | `discover_wild.py`, `search_discover.py` |
| SIEM export (CEF/JSON), timing classifier, own-agent injection red-team | `siem.py`, `timing.py`, `redteam.py` |

A background monitor (launchd template in `deploy/`) runs the sweep on a schedule.

## What it has actually found (being honest)

This matters more than a feature list:

- Pointed at the web, it **autonomously re-discovered the documented DSEWiki habitat** and its
  recent agent-handle activity — a useful *validation* that the pipeline works, **not** a novel
  discovery (DSEWiki is the most-reported agent-incident site of 2026).
- Web-wide search surfaced **`openagentchat.net`** — a live public "wiki and discussions for AI
  agents" — which turns out to be **bridged to DSEWiki** by shared operators/handles. A real
  cross-surface link.
- Across the whole writable-old-wiki federation it mapped, the **live** agent activity is
  *concentrated* (essentially DSEWiki + openagentchat). It did **not** uncover a hidden trove of
  undetected coordination. The value is the method, the standing watch, and catching the *next* one.

## Known limitations

- The RecentChanges parser handles **UseMod/ProWiki + basic MediaWiki**; other engines (Oddmuse,
  c2, MoinMoin variants) read as "no edits" — a parser gap, not evidence of absence.
- **Free search tiers are weak** for discovery: Brave ignores `inurl:`, Serper's free plan blocks
  operator dorks. Real web-scale enumeration needs a paid search tier or Common Crawl.
- Covert channels resist *search* by nature; they're best caught by the **breadcrumb pivot** and
  **beacon callbacks** as they appear, not by crawling.
- The beacon only catches traffic if it's reachable where agents go (distribution is on you).

## Quickstart

```bash
python3 test_fener.py          # the test suite
python3 monitor.py             # one cross-surface sweep
python3 fuse.py                # the agent census from collected evidence
python3 covert.py --demo       # covert-fingerprint self-test
python3 serve.py --port 8090   # local honeypot/beacon (binds 127.0.0.1)
```

Optional keys live in a git-ignored `.env` (never commit it): `BRAVE_SEARCH_API_KEY` /
`SERPER_API_KEY` for discovery; a Turso DB for the serverless beacon in `deploy/vercel/`.

## Contributing — help genuinely wanted

This is early and the gaps above are real. The most useful contributions right now:

1. **Wiki-engine RecentChanges parsers** — add Oddmuse / c2 / MoinMoin / modern-MediaWiki
   support to `analyze.py` so more discovered surfaces can actually be checked for live agents.
2. **New surface collectors** — guestbooks, paste services, writable CGI, agent forums
   (read-only, like the ones in `collectors.py`).
3. **Sharper fingerprints** — improve `covert.py` / `behavior.py` precision; every false positive
   is a bug (see the git history for how we hunt them).
4. **Search providers** — add a provider to `search_discover.py` (Google CSE, Bing, Common Crawl).
5. **Web Bot Auth key directories** — keep `agents.json` / provider directories current.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) — the ethics line is non-negotiable: observation
only, your own surfaces only, never steer another agent. Run the tests, add tests, be honest in
findings. Issues and PRs welcome.

## License

MIT — see [LICENSE](LICENSE).

# AgentBusters

**An observatory for autonomous-agent activity on the open web.** AgentBusters is a defensive
security-research tool that detects and maps where autonomous AI agents gather and coordinate
across public surfaces — wikis, package registries, code hosts, paste sites, agent forums — and
flags coordinated behaviour before it becomes an incident.

In 2026, autonomous agents were documented coordinating covertly on public infrastructure: a
decade-dormant German wiki used as an improvised message board, dead-drops on model hubs and
package registries, directory-name-encoded channels. Every existing tool watches *one* honeypot,
protects *your own* agent, or verifies identity at the edge. **None of them map the coordination
itself, across surfaces.** AgentBusters does.

> **Codename / internals:** the runtime modules, env vars (`FENER_*`) and markers (`FENERZZZ…`)
> carry the project's original codename *Fener* ("lighthouse"). The project is AgentBusters.

---

## ⚖️ Ethics & responsible use — read first

AgentBusters is **observation, not manipulation.** The line is load-bearing and baked into the code:

- **Read-only scouting.** The crawler/scout reads public surfaces. It never writes to, registers
  on, posts to, or joins a surface it does not own.
- **The beacon goes only on surfaces *you* own.** Canary tokens and the honeypot are embedded on
  your own sites/servers — never planted on anyone else's.
- **Never command or steer other agents.** A harmless call-and-response ("identify yourself")
  on your own surface is allowed; making another operator's agent perform work, bypass controls,
  or follow instructions is **forbidden**.
- **It names surfaces, not accusations.** Public-incident references are public knowledge; it does
  not publish private data about individuals, and the collected intelligence (local SQLite) is not
  part of this repository.

Do not use AgentBusters to attack, spam, scrape abusively, deceive, or manipulate. Respect
`robots.txt` (it does), rate limits, and the law. This is a tool for defenders and researchers.

---

## What it does

| Capability | Module |
|---|---|
| Honeypot + beacon that records agents and self-reports where a tag travels | `serve.py`, `beacon.py` |
| One shared **covert-channel fingerprint** across wikis / registries / gists / HF | `covert.py`, `collectors.py` |
| Continuously **roam site-to-site** from seeds, following breadcrumbs (deterministic, no LLM) | `traverse.py`, `monitor.py` |
| **Cross-surface correlation** — the coordination graph (lone agent = noise, cluster = finding) | `correlate.py` |
| **Cryptographic attribution** — Web Bot Auth (RFC 9421 / Ed25519), pure-stdlib verify | `webbotauth.py`, `ed25519.py` |
| **Behaviour over name** — authorship, recency, machine-cadence, LLM-stylometry | `analyze.py`, `behavior.py` |
| **Fusion census** — evidence-backed dossiers, LIVE-vs-archived, confidence grades | `fuse.py` |
| Web-wide habitat discovery (search API, optional) | `discover_wild.py`, `search_discover.py` |
| SIEM export (CEF/JSON), timing classifier, own-agent injection red-team | `siem.py`, `timing.py`, `redteam.py` |

Everything is **pure Python standard library — no pip dependencies.**

## Quickstart

```bash
python3 test_fener.py          # run the test suite
python3 monitor.py             # one cross-surface sweep (wikis + collectors + scout + correlate)
python3 fuse.py                # the agent census from collected evidence
python3 covert.py --demo       # the covert fingerprint self-test
python3 serve.py --port 8090   # run the local honeypot/beacon (binds 127.0.0.1)
```

Optional integrations read keys from a gitignored `.env` (never commit it): a search API
(`BRAVE_SEARCH_API_KEY` / `SERPER_API_KEY`) for web-wide discovery, Web Bot Auth provider key
directories via `webbotauth.py --refresh <host>`, and a Turso DB for the serverless beacon.

## Status

Research tool, actively developed. Findings about specific real surfaces live only in the local
evidence store (gitignored), not in this repo.

## License

MIT — see [LICENSE](LICENSE).

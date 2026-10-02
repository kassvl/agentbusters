# Contributing to AgentBusters

Thanks for your interest. A few ground rules that are non-negotiable:

1. **Stay on the defensive side of the line.** Contributions must keep the tool observation-only:
   read-only scouting, beacons only on surfaces the operator owns, and no capability that commands,
   steers, or deceives another operator's agent. PRs that cross this are declined.
2. **No secrets, no third-party personal data.** Never commit `.env`, the `data/` evidence store,
   API keys, or data that identifies private individuals. `.gitignore` enforces the first two.
3. **Standard library only.** The project is intentionally dependency-free (pure Python stdlib).
   Keep it that way unless there's a very strong reason.
4. **Tests green.** Run `python3 test_fener.py` before opening a PR; add tests for new behaviour.
5. **Be honest in findings.** Prefer precision over reach: a signal is "agent-authored" when
   authorship/recency say so, not when vocabulary matches. False positives get hunted down.

Open an issue to discuss larger changes first.

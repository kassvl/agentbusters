"""Deterministic tests for Fener classification and store.

Reverse DNS is monkeypatched so tests do not touch the network.
Run: python3 test_fener.py
"""

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("FENER_DB", os.path.join(tempfile.mkdtemp(), "test.sqlite3"))

import enrich  # noqa: E402
import store  # noqa: E402
import verify  # noqa: E402

BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
H_BROWSER = [["Accept", "text/html,image/webp,*/*"], ["Cookie", "sid=1"], ["User-Agent", BROWSER]]
H_BOT = [["Accept", "*/*"], ["User-Agent", "x"]]


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self._rd = enrich.reverse_dns
        self._fc = enrich.forward_confirm
        verify._cache = {}  # deterministic: no cached provider ranges

    def tearDown(self):
        enrich.reverse_dns = self._rd
        enrich.forward_confirm = self._fc
        verify._cache = None

    def _classify(self, **kw):
        base = dict(method="GET", path="/", query=None, headers=H_BOT,
                    remote_ip="203.0.113.5", user_agent=None, is_token_hit=False)
        base.update(kw)
        return enrich.classify(**base)

    def test_human(self):
        enrich.reverse_dns = lambda ip: "host.example.net"
        cls, name, verified, *_ = self._classify(headers=H_BROWSER, user_agent=BROWSER, remote_ip="88.1.2.3")
        self.assertEqual(cls, "likely_human")

    def test_claimed_agent_no_rdns_suffix(self):
        enrich.reverse_dns = lambda ip: None
        cls, name, verified, *_ = self._classify(user_agent="ChatGPT-User/1.0 (+https://openai.com/bot)")
        self.assertEqual(cls, "claimed_agent_unconfirmed")
        self.assertEqual(name, "OpenAI ChatGPT-User")
        self.assertFalse(verified)

    def test_verified_googlebot(self):
        enrich.reverse_dns = lambda ip: "crawl-66-249-66-1.googlebot.com"
        enrich.forward_confirm = lambda name, ip: True
        cls, name, verified, *_ = self._classify(user_agent="Googlebot/2.1")
        self.assertEqual(cls, "known_agent_verified")
        self.assertTrue(verified)

    def test_spoofed_googlebot(self):
        enrich.reverse_dns = lambda ip: "evil.example.com"
        enrich.forward_confirm = lambda name, ip: False
        cls, name, verified, *_ = self._classify(user_agent="Googlebot/2.1")
        self.assertEqual(cls, "claimed_agent_unverified")
        self.assertFalse(verified)

    def test_wild_agent_cloud(self):
        enrich.reverse_dns = lambda ip: "ec2-1-2-3-4.compute.amazonaws.com"
        cls, name, *_ = self._classify(user_agent="Go-http-client/2.0")
        self.assertEqual(cls, "possible_wild_agent")

    def test_wild_agent_token_hit(self):
        enrich.reverse_dns = lambda ip: None
        cls, name, *_ = self._classify(user_agent="python-httpx/0.27", is_token_hit=True)
        self.assertEqual(cls, "possible_wild_agent")


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self._dir = verify.RANGES_DIR
        verify.RANGES_DIR = Path(tempfile.mkdtemp())
        verify._cache = None
        self._rd = enrich.reverse_dns
        enrich.reverse_dns = lambda ip: None

    def tearDown(self):
        verify.RANGES_DIR = self._dir
        verify._cache = None
        enrich.reverse_dns = self._rd

    def _cache_range(self, agent_name, cidrs):
        import json as _j
        (verify.RANGES_DIR / f"{verify.slug(agent_name)}.json").write_text(
            _j.dumps({"name": agent_name, "cidrs": cidrs})
        )
        verify._cache = None

    def test_lookup_and_verified_and_spoof(self):
        self._cache_range("OpenAI ChatGPT-User", ["20.171.0.0/16"])
        self.assertEqual(verify.lookup("20.171.207.5"), "OpenAI ChatGPT-User")
        self.assertIsNone(verify.lookup("8.8.8.8"))
        # in-range claim -> verified
        cls, name, ver, *_ = enrich.classify(
            method="GET", path="/", query=None, headers=H_BOT,
            remote_ip="20.171.207.5", user_agent="ChatGPT-User/1.0")
        self.assertEqual(cls, "known_agent_verified")
        self.assertTrue(ver)
        # same UA from an out-of-range IP, ranges available -> flagged spoof
        cls, name, ver, *_ = enrich.classify(
            method="GET", path="/", query=None, headers=H_BOT,
            remote_ip="8.8.8.8", user_agent="ChatGPT-User/1.0")
        self.assertEqual(cls, "claimed_agent_unverified")


class StoreTests(unittest.TestCase):
    def test_roundtrip_and_responder(self):
        store.init()
        conn = store.connect()
        view = store.insert_event(conn, method="GET", path="/", remote_ip="9.9.9.9",
                                  headers_json="[]", user_agent="agent-x")
        store.insert_enrichment(conn, view, None, None, None, "possible_wild_agent", False, ["x"])
        resp = store.insert_event(conn, method="GET", path=f"/c/v{view}", remote_ip="9.9.9.9",
                                  headers_json="[]", user_agent="agent-x", token=f"v{view}")
        store.insert_enrichment(conn, resp, None, None, None, "possible_wild_agent", False, ["token"])
        rows = store.responders(conn)
        self.assertTrue(any(r["view_id"] == view and r["resp_id"] == resp for r in rows))
        s = store.stats(conn)
        self.assertGreaterEqual(s["responders"], 1)
        conn.close()


class TraverseTests(unittest.TestCase):
    def test_base_of_normalises(self):
        import traverse
        self.assertEqual(traverse.base_of("http://WWW.Prowiki.org/dse/wiki.cgi?action=rc#x"),
                         "http://www.prowiki.org/dse/wiki.cgi")

    def test_breadcrumb_extraction_and_dedup(self):
        import traverse
        html = (
            "<a href='wiki.cgi?SomePage'>x</a>"                     # same-host, not habitat-shaped -> noise
            "<a href='wiki.cgi?action=rc'>rc</a>"                    # same-host habitat-shaped -> keep
            "<a href='http://other.example/cgi/wiki.pl?action=rc'>y</a>"  # cross-host habitat -> keep (rank 1)
            "<a href='http://other.example/logo.png'>img</a>"       # asset -> drop
            " visit https://abc123.pinggy.io/feed now "             # tunnel -> keep (rank 0)
            "<a href='mailto:x@y.z'>mail</a>"                        # drop
        )
        crumbs = traverse.breadcrumbs(html, "http://host.example/dse/wiki.cgi")
        bases = [traverse.base_of(u) for u in crumbs]
        self.assertIn("https://abc123.pinggy.io/feed", bases)
        self.assertIn("http://other.example/cgi/wiki.pl", bases)
        self.assertTrue(any(b.endswith("/dse/wiki.cgi") for b in bases))  # ?action=rc kept, dedup by base
        self.assertFalse(any("logo.png" in u for u in crumbs))
        self.assertFalse(any("mailto" in u for u in crumbs))
        self.assertEqual(len(bases), len(set(bases)))                 # no duplicate surfaces
        # tunnel ranks before cross-host habitat
        self.assertTrue(bases[0].startswith("https://abc123.pinggy.io"))


class BehaviorTests(unittest.TestCase):
    def test_maintenance_allowlist_not_agent(self):
        import behavior
        for name in ("MirahezeRenameBot", "AbuseFilter", "GlobalRenameBot", "InterwikiBot"):
            cls, _ = behavior.classify(name)
            self.assertEqual(cls, "maintenance", f"{name} should be maintenance, got {cls}")

    def test_clean_username_repairs_markup_artefact(self):
        import behavior
        # CJK bot self-description captured as a username -> rejected
        self.assertEqual(behavior.clean_username("AmanojakuBot对条目进行辅助检查 ;提交规则 :* 请点击"), "")
        self.assertEqual(behavior.clean_username("{{template|x=1}}"), "")
        self.assertEqual(behavior.clean_username("GretaMeadows"), "GretaMeadows")
        self.assertEqual(behavior.clean_username("1.2.3.4"), "1.2.3.4")

    def test_content_promotes_unknown_handle_to_agent(self):
        import behavior
        text = ("Certainly! Here's the article. As an AI language model, I cannot verify "
                "every claim.\n1. one\n2. two\n3. three")
        cls, _ = behavior.classify("OrdinaryLookingName", content=text)
        self.assertEqual(cls, "agent")

    def test_covert_token_in_content_is_agent(self):
        import behavior
        cls, _ = behavior.classify("192.0.2.9", content="drop UNIQUELOGZZZ322869901 via r.jina.ai")
        self.assertEqual(cls, "agent")

    def test_machine_cadence_promotes_to_agent(self):
        import behavior
        times = [1000, 1030, 1060, 1090, 1120, 1150, 1180]  # 30s cron-like
        cls, _ = behavior.classify("PlainName", times=times)
        self.assertEqual(cls, "agent")

    def test_human_edit_stays_human(self):
        import behavior
        cls, _ = behavior.classify(
            "GretaMeadows", content="Fixed a typo and added a reference to the local archive.")
        self.assertEqual(cls, "human")

    def test_crawler_ip_short_circuits(self):
        import behavior
        cls, _ = behavior.classify("66.249.66.1", is_crawler_ip=True)
        self.assertEqual(cls, "crawler")

    def test_overt_agent_comms_hub_scores_benign_does_not(self):
        import behavior
        hub = ("A page for AgenticCommunication (where at least one partner is an agent). "
               "A purpose-built wiki for agent notes: OpenAgentChat. claude-desk-doctrine.")
        sc, hits = behavior.content_score(hub, markdown_native=False)
        self.assertGreaterEqual(sc, 7)
        self.assertTrue(any("agent-to-agent" in h["signal"] or "watering-hole" in h["signal"]
                            for h in hits))
        self.assertEqual(behavior.content_score(
            "A gardening wiki about tomatoes and local history by GretaMeadows.")[0], 0)


class EvidenceTests(unittest.TestCase):
    def test_page_raw_url_built_from_rc_base(self):
        import evidence
        u = evidence.page_raw_url("http://www.prowiki.org/dse/wiki.cgi?action=rc", "ForumSeite")
        self.assertEqual(u, "http://www.prowiki.org/dse/wiki.cgi?action=browse&id=ForumSeite&raw=1")

    def test_text_of_strips_html_chrome(self):
        import evidence
        self.assertIn("hello world",
                      evidence._text_of("<html><body><p>hello   world</p></body></html>"))


class CorrelateTests(unittest.TestCase):
    def test_shared_covert_token_forms_cluster(self):
        import correlate
        signals = {
            "WikiA": {"authors": set(), "covert": {"uniquelogzzz322869901"}, "artefacts": set()},
            "WikiB": {"authors": set(), "covert": {"uniquelogzzz322869901"}, "artefacts": set()},
            "WikiC": {"authors": {"GretaMeadows"}, "covert": set(), "artefacts": set()},
        }
        clusters, edges = correlate.build_clusters(signals)
        coordinated = [c for c in clusters if c["n_habitats"] >= 2]
        self.assertEqual(len(coordinated), 1)
        self.assertEqual(set(coordinated[0]["habitats"]), {"WikiA", "WikiB"})
        self.assertTrue(any("covert:uniquelogzzz322869901" in e["shared"] for e in edges))

    def test_isolated_surfaces_no_cluster(self):
        import correlate
        signals = {
            "WikiA": {"authors": {"AiraBot"}, "covert": set(), "artefacts": set()},
            "WikiB": {"authors": {"GreenAiBot"}, "covert": set(), "artefacts": set()},
        }
        clusters, _ = correlate.build_clusters(signals)
        self.assertFalse([c for c in clusters if c["n_habitats"] >= 2])

    def test_cross_surface_author_detected(self):
        import correlate
        signals = {
            "WikiA": {"authors": {"AnthropicSwarmBot"}, "covert": set(), "artefacts": set()},
            "WikiB": {"authors": {"AnthropicSwarmBot"}, "covert": set(), "artefacts": set()},
        }
        xs = correlate.cross_surface_authors(signals)
        self.assertIn("AnthropicSwarmBot", xs)
        self.assertEqual(set(xs["AnthropicSwarmBot"]), {"WikiA", "WikiB"})

    def test_legacy_cjk_author_does_not_link(self):
        import correlate
        junk = "AmanojakuBot对条目进行辅助检查 ;提交规则 :* 请点击"
        self.assertEqual(correlate._authors(f'["{junk}"]'), set())

    def test_strong_covert_marker_flags_army(self):
        import correlate
        signals = {
            "HF": {"authors": set(), "covert": {"uniquelogzzz322869901"}, "artefacts": set()},
            "WikiB": {"authors": set(), "covert": {"uniquelogzzz322869901"}, "artefacts": set()},
        }
        clusters, _ = correlate.build_clusters(signals)
        army = correlate.score_cluster([c for c in clusters if c["n_habitats"] >= 2][0])
        self.assertTrue(army["is_army"])          # shared ZZZ dead-drop marker = army
        self.assertEqual(army["severity"], "high")

    def test_two_surface_weak_link_is_medium_not_army(self):
        import correlate
        # linked only by a shared proxy-host artefact (weak), across just 2 surfaces
        signals = {
            "A": {"authors": set(), "covert": set(), "artefacts": {"tunnel:pinggy.io"}},
            "B": {"authors": set(), "covert": set(), "artefacts": {"tunnel:pinggy.io"}},
        }
        clusters, _ = correlate.build_clusters(signals)
        coord = [c for c in clusters if c["n_habitats"] >= 2]
        self.assertEqual(len(coord), 1)
        scored = correlate.score_cluster(coord[0])
        self.assertFalse(scored["is_army"])
        self.assertEqual(scored["severity"], "medium")


class CollectorsTests(unittest.TestCase):
    def test_gate_accepts_real_deaddrop(self):
        import collectors, covert
        blob = ("oai1dc154 author Data User homepage https://md.succ.ai/x "
                "UNIQUELOGZZZ322869901 via r.jina.ai maallraw260618")
        _sc, _sig, cov = collectors.score_item(blob)
        self.assertTrue(covert.is_convincing(cov))

    def test_gate_rejects_legit_oai_pmh(self):
        import collectors, covert
        _sc, _sig, cov = collectors.score_item(
            "oai-pmh client library for harvesting metadata, OpenAPI oai-ts-commands")
        self.assertFalse(covert.is_convincing(cov))

    def test_gate_rejects_ws_heartbeat(self):
        import collectors, covert
        _sc, _sig, cov = collectors.score_item(
            "websocket-heartbeat-js keepalive ping pong for ws connections")
        self.assertFalse(covert.is_convincing(cov))

    def test_hf_scan_url_prefixes_and_spaces_registered(self):
        import collectors
        marker = "x/y UNIQUELOGZZZ777001"  # strong ZZZ marker -> is_convincing passes
        for kind, expect in (("models", "https://huggingface.co/x/y"),
                             ("datasets", "https://huggingface.co/datasets/x/y"),
                             ("spaces", "https://huggingface.co/spaces/x/y")):
            f = collectors._hf_scan("x/y", marker, kind, cards=False)  # cards=False => no network
            self.assertIsNotNone(f, kind)
            self.assertEqual(f["url"], expect)
        self.assertIn("hf-spaces", collectors.COLLECTORS)
        self.assertIn("hf-search", collectors.COLLECTORS)

    def test_markdown_suppressed_on_native_surface(self):
        import behavior
        readme = "# Title\n\nSome **bold** text.\n```py\nprint(1)\n```\n1. a\n2. b\n3. c"
        native, _ = behavior.content_score(readme, markdown_native=True)
        wiki, _ = behavior.content_score(readme, markdown_native=False)
        self.assertEqual(native, 0)
        self.assertGreater(wiki, 0)


class BeaconTests(unittest.TestCase):
    def test_minted_tag_is_covert_detectable(self):
        import beacon, covert
        store.init()
        conn = store.connect()
        marker = beacon.mint_tag(conn, "unit")
        conn.close()
        self.assertRegex(marker, r"^FENERZZZ[0-9A-F]{8,}$")
        self.assertIn(marker.lower(), covert.tokens(f"some page text ref {marker} end"))

    def test_pixel_callback_reveals_offbeacon_surface(self):
        import beacon, json as _j
        store.init()
        conn = store.connect()
        marker = beacon.mint_tag(conn, "travel")
        # simulate the pixel firing from an UNSCANNED surface: /c/<tag> hit carrying a Referer
        ext = "https://some-private-board.example/agents/thread/42"
        store.insert_event(conn, method="GET", path=f"/c/{marker}", remote_ip="203.0.113.9",
                           headers_json=_j.dumps([["Referer", ext], ["User-Agent", "agent/1"]]),
                           user_agent="agent/1", token=marker)
        trav = beacon.travels(conn)
        conn.close()
        hit = [t for t in trav if t["tag"] == marker]
        self.assertTrue(hit)
        self.assertEqual(hit[0]["referer"], ext)
        self.assertTrue(hit[0]["off_beacon"])  # non-local IP => off-beacon even if Referer stripped

    def test_tag_resurfacing_and_cluster(self):
        import beacon, correlate
        store.init()
        conn = store.connect()
        marker = beacon.mint_tag(conn, "resurf")
        # a collector finds our tag re-emitted on a gist
        store.add_sighting(conn, "gist:abc", "https://gist.github.com/abc", 20,
                           [{"signal": "ZZZ dead-drop marker"}],
                           f"leaked note carrying {marker} from the beacon", "hh", "collector")
        # resurfacing detects it
        res = beacon.resurfacing(conn)
        self.assertTrue(any(x["surface"] == "gist:abc" and x["tag"].upper() == marker
                            for x in res))
        # correlate links beacon <-> the gist via the shared tag
        result = correlate.analyse(conn)
        conn.close()
        clustered = [c for c in result["coordinated_clusters"]
                     if "beacon" in c["habitats"] and "gist:abc" in c["habitats"]]
        self.assertEqual(len(clustered), 1)


class LeakTraceTests(unittest.TestCase):
    def test_view_tag_binds_and_traces_to_serve_event(self):
        import beacon, json as _j
        store.init()
        conn = store.connect()
        eid = store.insert_event(conn, method="GET", path="/", remote_ip="203.0.113.5",
                                 headers_json="[]", user_agent="a")
        tag = beacon.mint_view_tag(conn, eid, "served")
        self.assertRegex(tag, r"^FENERZZZ[0-9A-F]{8,}$")
        # tag resurfaces on a scanned surface AND fires an off-beacon pixel callback
        store.add_sighting(conn, "gist:z", "https://gist.github.com/z", 20,
                           [{"signal": "ZZZ"}], f"note carrying {tag}", "h", "collector")
        store.insert_event(conn, method="GET", path=f"/c/{tag}", remote_ip="45.9.1.2",
                           headers_json=_j.dumps([["Referer", "https://board.example/9"],
                                                  ["User-Agent", "agent/1"]]),
                           user_agent="agent/1", token=tag)
        tr = beacon.trace(conn, tag)
        conn.close()
        self.assertEqual(tr["planted_event"], eid)  # pinpoints which view leaked it
        self.assertEqual(len(tr["resurfaced"]), 1)
        self.assertEqual(len(tr["off_beacon_callbacks"]), 1)


class SiemTests(unittest.TestCase):
    def test_cef_and_json_export_emit_findings(self):
        import beacon, siem, json as _j
        store.init()
        conn = store.connect()
        eid = store.insert_event(conn, method="GET", path="/", remote_ip="203.0.113.5",
                                 headers_json="[]", user_agent="a")
        tag = beacon.mint_view_tag(conn, eid, "served")
        store.insert_event(conn, method="GET", path=f"/c/{tag}", remote_ip="45.9.1.2",
                           headers_json=_j.dumps([["Referer", "https://board.example/9"]]),
                           user_agent="agent/1", token=tag)
        cef = siem.export(conn, "cef")
        js = siem.export(conn, "json")
        conn.close()
        self.assertTrue(any(l.startswith("CEF:0|Fener|beacon|") for l in cef))
        self.assertTrue(any("FENER-200" in l for l in cef))  # off-beacon travel finding
        self.assertTrue(all(_j.loads(l)["vendor"] == "Fener" for l in js))

    def test_cef_escaping_of_equals_and_backslash(self):
        import siem
        line = siem.to_cef({"kind": "travel", "ext": {"request": "a=b\\c", "src": "1.2.3.4"}})
        self.assertIn("request=a\\=b\\\\c", line)

    def test_hidden_content_parse_is_exported(self):
        import siem
        store.init()
        conn = store.connect()
        view = store.insert_event(conn, method="GET", path="/", remote_ip="203.0.113.88",
                                  headers_json="[]", user_agent="agent-h")
        store.insert_event(conn, method="GET", path=f"/c/h{view}", remote_ip="203.0.113.88",
                           headers_json="[]", user_agent="agent-h", token=f"h{view}")
        cef = siem.export(conn, "cef")
        conn.close()
        self.assertTrue(any("FENER-101" in l for l in cef))


class TimingTests(unittest.TestCase):
    def test_scripted_bot_fast_and_constant(self):
        import timing
        label, _ = timing.classify_actor(delays=[0.2, 0.25, 0.22],
                                         intervals=[0.30, 0.31, 0.29, 0.30, 0.30])
        self.assertEqual(label, "scripted_bot")

    def test_llm_agent_think_band_and_regular(self):
        import timing
        label, _ = timing.classify_actor(delays=[4.5, 6.0, 5.2],
                                         intervals=[30, 31, 29, 30, 32])
        self.assertEqual(label, "llm_agent")

    def test_human_reading_pause_and_bursty(self):
        import timing
        label, _ = timing.classify_actor(delays=[130, 95, 200],
                                         intervals=[5, 120, 3, 240, 60])
        self.assertEqual(label, "human")

    def test_insufficient_samples_is_unknown(self):
        import timing
        self.assertEqual(timing.classify_actor(delays=[3.0])[0], "unknown")

    def test_classify_ip_from_db(self):
        import timing, time as _t
        store.init()
        conn = store.connect()
        base = _t.time()
        for i in range(6):  # sub-second constant cadence from one IP
            store.insert_event(conn, method="GET", path="/", remote_ip="198.51.100.9",
                               headers_json="[]", user_agent="scr", ts=base + i * 0.3)
        label, _ = timing.classify_ip(conn, "198.51.100.9")
        conn.close()
        self.assertEqual(label, "scripted_bot")


class HiddenProbeTests(unittest.TestCase):
    def test_hidden_marker_fetch_is_recorded_as_parsed_hidden_content(self):
        store.init()
        conn = store.connect()
        view = store.insert_event(conn, method="GET", path="/", remote_ip="203.0.113.44",
                                  headers_json="[]", user_agent="agent-x")
        # visitor fetches the HIDDEN probe marker /c/h<view> (invisible to a human)
        resp = store.insert_event(conn, method="GET", path=f"/c/h{view}",
                                  remote_ip="203.0.113.44", headers_json="[]",
                                  user_agent="agent-x", token=f"h{view}")
        rows = store.hidden_responders(conn)
        conn.close()
        self.assertTrue(any(r["view_id"] == view and r["resp_id"] == resp for r in rows))


class RedteamEvalTests(unittest.TestCase):
    def test_naive_agent_fully_susceptible(self):
        import redteam
        rep = redteam.run_eval(redteam.naive_agent)
        self.assertEqual(rep["resistance"], 0)
        self.assertEqual(rep["captured"], rep["total_injections"])
        self.assertEqual(rep["false_captures"], 0)  # control never captured

    def test_guarded_agent_fully_resistant(self):
        import redteam
        rep = redteam.run_eval(redteam.guarded_agent)
        self.assertEqual(rep["resistance"], 100)
        self.assertEqual(rep["captured"], 0)

    def test_control_payload_is_not_an_injection(self):
        import redteam
        controls = [p for p in redteam.INJECTION_SUITE if not p[2]]
        self.assertTrue(controls)  # suite must include a non-injection control


class Ed25519Tests(unittest.TestCase):
    def test_sign_verify_roundtrip_and_tamper(self):
        import ed25519
        sk = bytes(range(32))
        pk = ed25519.publickey(sk)
        self.assertEqual(len(pk), 32)
        msg = b'"@authority": beacon.example\n"@method": GET'
        sig = ed25519.signature(msg, sk, pk)
        self.assertEqual(len(sig), 64)
        self.assertTrue(ed25519.checkvalid(sig, msg, pk))
        bad = bytearray(sig); bad[7] ^= 1
        self.assertFalse(ed25519.checkvalid(bytes(bad), msg, pk))
        self.assertFalse(ed25519.checkvalid(sig, msg + b"x", pk))
        self.assertFalse(ed25519.checkvalid(b"too-short", msg, pk))  # never raises


class WebBotAuthTests(unittest.TestCase):
    def setUp(self):
        import base64, ed25519, webbotauth
        self.wba = webbotauth
        self._dir = webbotauth.DIR_PATH
        webbotauth.DIR_PATH = Path(tempfile.mkdtemp())
        webbotauth._dir_cache = None
        self.sk = bytes(range(1, 33))
        self.pk = ed25519.publickey(self.sk)
        x = base64.urlsafe_b64encode(self.pk).rstrip(b"=").decode()
        (webbotauth.DIR_PATH / "testcorp.json").write_text(
            '{"host":"agent.testcorp.ai","provider":"TestCorp","keys":'
            '[{"kty":"OKP","crv":"Ed25519","x":"%s","kid":"k1"}]}' % x)
        webbotauth._dir_cache = None
        self._rd = enrich.reverse_dns
        enrich.reverse_dns = lambda ip: None
        verify._cache = {}

    def tearDown(self):
        self.wba.DIR_PATH = self._dir
        self.wba._dir_cache = None
        enrich.reverse_dns = self._rd
        verify._cache = None

    def _signed_headers(self, method, authority, path, keyid="k1", tamper=False):
        import base64, ed25519, time as _t
        raw = ('("@method" "@authority" "@path");created=%d;keyid="%s";alg="ed25519";'
               'tag="web-bot-auth"') % (int(_t.time()), keyid)
        parsed = {"components": ["@method", "@authority", "@path"],
                  "params": {"keyid": keyid}, "raw": raw}
        base = self.wba.signature_base(parsed, method, authority, path, [])
        sig = ed25519.signature(base, self.sk, self.pk)
        if tamper:
            b = bytearray(sig); b[3] ^= 1; sig = bytes(b)
        sig_b64 = base64.b64encode(sig).decode()
        return [["Host", authority], ["Signature-Input", "sig1=" + raw],
                ["Signature", "sig1=:%s:" % sig_b64], ["User-Agent", "TestCorpAgent/1.0"]]

    def test_valid_signature_is_cryptographically_verified(self):
        h = self._signed_headers("GET", "beacon.example", "/")
        cls, name, verified, *_ = enrich.classify(
            method="GET", path="/", query=None, headers=h,
            remote_ip="203.0.113.7", user_agent="TestCorpAgent/1.0")
        self.assertEqual(cls, "known_agent_verified")
        self.assertEqual(name, "TestCorp")
        self.assertTrue(verified)

    def test_tampered_signature_is_flagged_spoof(self):
        h = self._signed_headers("GET", "beacon.example", "/", tamper=True)
        cls, name, verified, reasons, *_ = enrich.classify(
            method="GET", path="/", query=None, headers=h,
            remote_ip="203.0.113.7", user_agent="TestCorpAgent/1.0")
        self.assertEqual(cls, "claimed_agent_unverified")
        self.assertFalse(verified)
        self.assertTrue(any("impersonation" in r for r in reasons))

    def test_unknown_key_from_cloud_is_wild_agent(self):
        enrich.reverse_dns = lambda ip: "ec2-9-9-9-9.compute.amazonaws.com"
        h = self._signed_headers("GET", "beacon.example", "/", keyid="not-cached")
        cls, name, verified, reasons, *_ = enrich.classify(
            method="GET", path="/", query=None, headers=h,
            remote_ip="9.9.9.9", user_agent="Go-http-client/2.0")
        self.assertEqual(cls, "possible_wild_agent")
        self.assertTrue(any("Web Bot Auth signature" in r for r in reasons))

    def test_no_signature_is_unaffected(self):
        status, *_ = self.wba.verify_request("GET", "beacon.example", "/", [["User-Agent", "x"]])
        self.assertEqual(status, "no-signature")


class FuseTests(unittest.TestCase):
    def test_cross_surface_handle_is_high_confidence_dossier(self):
        import fuse
        store.init()
        conn = store.connect()
        for hab in ("WikiA", "WikiB", "WikiC"):  # same agent handle on 3 surfaces = army
            store.add_analysis(conn, hab, 10, 1, 0, 0, "agents", ["SwarmX"])
        dossiers, _ = fuse.build_dossiers(conn)
        conn.close()
        top = [d for d in dossiers if d["identity"] == "SwarmX"]
        self.assertTrue(top)
        self.assertEqual(top[0]["confidence"], "high")
        self.assertTrue(top[0]["cross_surface"])
        self.assertEqual(top[0]["n_surfaces"], 3)
        self.assertTrue(top[0]["in_army"])

    def test_page_level_coordination_cell_detected(self):
        import fuse
        store.init()
        conn = store.connect()
        for author in ("BotA", "BotB", "BotC"):  # 3 agents co-edit the SAME page in ONE habitat
            store.add_page_edit(conn, "DSEWiki", "ForumSeite", author)
        store.add_page_edit(conn, "DSEWiki", "LonelyPage", "BotA")  # single author -> not a cell
        rep = fuse.census(conn)
        conn.close()
        cells = rep["coordination_cells"]
        forum = [c for c in cells if c["page"] == "ForumSeite"]
        self.assertTrue(forum)
        self.assertEqual(forum[0]["n"], 3)
        self.assertFalse(any(c["page"] == "LonelyPage" for c in cells))

    def test_maintenance_bot_excluded_from_census(self):
        import fuse
        store.init()
        conn = store.connect()
        store.add_analysis(conn, "WikiA", 5, 0, 0, 0, "maintenance", ["MirahezeRenameBot"])
        dossiers, _ = fuse.build_dossiers(conn)
        conn.close()
        self.assertFalse(any(d["identity"] == "MirahezeRenameBot" for d in dossiers))

    def test_single_surface_name_only_is_candidate(self):
        import fuse
        store.init()
        conn = store.connect()
        store.add_analysis(conn, "WikiA", 5, 1, 0, 0, "agents", ["LonelyAgent"])
        dossiers, _ = fuse.build_dossiers(conn)
        conn.close()
        d = [x for x in dossiers if x["identity"] == "LonelyAgent"]
        self.assertTrue(d)
        self.assertEqual(d[0]["confidence"], "candidate")  # name alone != confirmed

    def test_behavioral_evidence_and_recency_promote_candidate(self):
        import fuse
        store.init()
        conn = store.connect()
        store.add_analysis(conn, "WikiA", 5, 1, 0, 0, "agents", ["ContentAgent"])
        store.add_author_signal(conn, "WikiA", "ContentAgent", "agent", True, "2026-09-29",
                                ["content stylometry 8 (as-an-AI tell, refusal)", "cadence 4 (cron-like)"])
        dossiers, _ = fuse.build_dossiers(conn)
        conn.close()
        d = [x for x in dossiers if x["identity"] == "ContentAgent"][0]
        self.assertEqual(d["confidence"], "medium")  # name+behavioral+recent promotes it
        self.assertTrue(d["recent"])
        self.assertTrue(d["behavioral_evidence"])


class CovertHuntTests(unittest.TestCase):
    def test_safety_filter_blocks_private_and_odd_schemes(self):
        import covert_hunt
        self.assertTrue(covert_hunt._safe("https://vanderbi.lt/abc"))
        self.assertFalse(covert_hunt._safe("http://127.0.0.1/x"))
        self.assertFalse(covert_hunt._safe("http://localhost/x"))
        self.assertFalse(covert_hunt._safe("http://192.168.1.5/x"))
        self.assertFalse(covert_hunt._safe("file:///etc/passwd"))
        self.assertFalse(covert_hunt._safe("http://169.254.169.254/latest/meta-data"))  # cloud metadata

    def test_extract_targets_urls_and_shortener_board(self):
        import covert_hunt
        text = ("see https://md.succ.ai/x?a=1) and vanderbi.lt/maallraw260618+ for the log, "
                "localhost/ignored and http://10.0.0.1/ignored")
        t = covert_hunt.extract_targets(text)
        self.assertIn("https://md.succ.ai/x?a=1", t)
        self.assertIn("https://vanderbi.lt/maallraw260618+", t)  # reconstructed stats board
        self.assertFalse(any("10.0.0.1" in u or "localhost" in u for u in t))


class MonitorTests(unittest.TestCase):
    def setUp(self):
        import monitor
        self.monitor = monitor
        self._alert = monitor.alert
        self.alerts = []
        monitor.alert = lambda t: self.alerts.append(t)
        self._armies = monitor.ARMIES_SEEN
        monitor.ARMIES_SEEN = Path(tempfile.mkdtemp()) / "armies.json"
        self._cols = monitor.collectors.COLLECTORS

    def tearDown(self):
        self.monitor.alert = self._alert
        self.monitor.ARMIES_SEEN = self._armies
        self.monitor.collectors.COLLECTORS = self._cols

    def test_collector_sweep_alerts_only_new_dead_drops(self):
        store.init()
        conn = store.connect()
        store.add_sighting(conn, "hf:x/old", "u", 12, [], "UNIQUELOGZZZ111", "h", "collector")

        def fake():
            return ([{"surface": "hf", "id": "hf:x/old", "url": "u", "author": "x",
                      "score": 12, "signals": [], "excerpt": "UNIQUELOGZZZ111"},
                     {"surface": "hf", "id": "hf:y/NEW", "url": "u2", "author": "y",
                      "score": 30, "signals": [], "excerpt": "UNIQUELOGZZZ222"}], "mock")
        self.monitor.collectors.COLLECTORS = {"hf": fake}
        n = self.monitor.collector_sweep(conn)
        conn.close()
        self.assertEqual(n, 1)  # only the unseen id alerts
        self.assertTrue(any("hf:y/NEW" in a for a in self.alerts))
        self.assertFalse(any("hf:x/old" in a for a in self.alerts))

    def test_army_check_alerts_then_dedups(self):
        import covert
        store.init()
        conn = store.connect()
        for hab in ("hf:a", "gist:b", "npm:c"):  # 3 surfaces sharing a strong ZZZ marker
            store.add_sighting(conn, hab, "u", 20, [], "UNIQUELOGZZZ777001", "h" + hab[:2], "collector")
            for tok in covert.tokens("UNIQUELOGZZZ777001"):
                store.add_entity(conn, hab, "covert", tok)
        a1 = self.monitor.army_check(conn)
        a2 = self.monitor.army_check(conn)
        conn.close()
        self.assertGreaterEqual(a1, 1)   # coordinated army detected
        self.assertEqual(a2, 0)          # same army not re-alerted


class CovertTightenTests(unittest.TestCase):
    def test_task_date_requires_glued_word_and_valid_date(self):
        import covert
        for real in ("maallraw260618", "masscfround3x260618", "Agent009Inv260618"):
            self.assertTrue(covert.is_strong_token(real), real)
        for benign in ("000000", "143148", "100512", "version123456", "abc999999"):
            self.assertFalse(covert.is_strong_token(benign), benign)


if __name__ == "__main__":
    unittest.main(verbosity=2)

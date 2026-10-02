# Fener beacon — public deploy (VPS + Caddy)

Goal: run `serve.py` on a public host so the dolphin-tag **callback pixel** catches real
off-surface travel (Referer + IP of wherever an agent carries our tag) and the watering-hole
honeypot can attract agents. `serve.py` runs **unchanged** — it was built for this.

## What only you can do (provisioning)
1. **A cheap VPS** — Hetzner CX22 (~€4/mo) or DigitalOcean/Vultr ($5/mo). Ubuntu 24.04.
2. **A subdomain you control** — e.g. `beacon.example.com`. Add a DNS **A record**
   → the VPS IPv4 (and AAAA → IPv6 if it has one). Wait for it to resolve (`dig +short beacon.example.com`).
3. If you use a different subdomain, change it in `deploy/Caddyfile` and `deploy/fener-beacon.service`.

## One-time server setup (run on the VPS as root, or with sudo)
```sh
# 1. base packages + Caddy (official repo)
apt update && apt install -y python3 git debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install -y caddy

# 2. a dedicated unprivileged user + code
useradd --system --create-home --home-dir /opt/fener --shell /usr/sbin/nologin fener
git clone <your fener remote> /opt/fener        # or: rsync your ~/fener to /opt/fener
mkdir -p /opt/fener/data && chown -R fener:fener /opt/fener

# 3. the dashboard secret (NOT committed)
printf 'FENER_DASH_TOKEN=%s\n' "$(openssl rand -hex 24)" > /opt/fener/deploy/beacon.env
chown fener:fener /opt/fener/deploy/beacon.env && chmod 600 /opt/fener/deploy/beacon.env
cat /opt/fener/deploy/beacon.env      # save this token; you need it for /dashboard?key=...

# 4. the beacon service
cp /opt/fener/deploy/fener-beacon.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now fener-beacon
systemctl status fener-beacon --no-pager

# 5. Caddy (auto-HTTPS once DNS resolves)
cp /opt/fener/deploy/Caddyfile /etc/caddy/Caddyfile
mkdir -p /var/log/caddy
systemctl reload caddy
```

## Verify it's live
```sh
curl -s https://beacon.example.com/ | grep -o 'FENERZZZ[0-9A-F]*'   # tag embedded
curl -s https://beacon.example.com/robots.txt                       # Allow: /
# dashboard (token-protected):
curl -s "https://beacon.example.com/dashboard?key=<TOKEN>" | head
```

## Operate (from your Mac, pointing at the server DB, or on the server)
```sh
python3 beacon.py --mint "launch"     # mint a tag; serve.py embeds the latest automatically
python3 beacon.py --status            # responders + tag resurfacing + OFF-BEACON callbacks
python3 collectors.py                 # widen scanned surfaces, feed the same DB
python3 correlate.py                  # cluster across surfaces + beacon
```

## Ethics (unchanged, load-bearing)
Observation only. The beacon attracts and records; it never commands agents, never manipulates
them, and the canary pixel is embedded **only on our own surface**. Keep the command/manipulation
line intact. `serve.py` rate-limits writes, escapes all echoed content, and makes no outbound calls.

## Notes
- serve.py listens on 127.0.0.1:8090; only Caddy is exposed. A firewall allowing 80/443/22 is enough.
- The monitor (`monitor.py` + launchd) keeps running on your Mac against the same habitat list;
  the VPS beacon is the *active* half. Both write the same schema, different DB files.
- To catch real travel the pixel must be reachable publicly — that is exactly what this deploy gives.

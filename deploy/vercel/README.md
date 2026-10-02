# Fener beacon — Vercel (serverless) deploy

Zero server to maintain, free tier. The beacon runs as one Python serverless function
(`api/beacon.py`, stdlib only) backed by Turso (a hosted, SQLite-compatible DB). It serves the
watering-hole page with an **absolute tracking pixel** and logs every `/c/<tag>` callback, so a
tag carried onto a surface we don't scan fires the pixel back and its Referer reveals where.

## What only you can do (accounts + secrets)
1. **Turso DB** (free): https://turso.tech → sign up → create a database.
   - Copy its **URL** (looks like `libsql://<name>-<org>.turso.io`) and create an **auth token**.
   - CLI alt.: `turso db create fener-beacon` then `turso db show --url fener-beacon` and
     `turso db tokens create fener-beacon`.
2. **Vercel** (free): https://vercel.com → sign up (GitHub login is fine).
3. Pick the beacon's public URL. Easiest: the free `https://<project>.vercel.app` (no DNS at
   all). Later you can add `beacon.example.com` as a custom domain in Vercel.

## Deploy
From `deploy/vercel/` (this folder):
```sh
npm i -g vercel            # one-time
vercel login               # opens browser
vercel link                # create/link a project (accept defaults)

# set the four env vars (run each, paste the value):
vercel env add TURSO_DATABASE_URL     # libsql://...  (all environments)
vercel env add TURSO_AUTH_TOKEN       # the token
vercel env add FENER_DASH_TOKEN       # invent a long random string; guards /dashboard & /mint
vercel env add FENER_BEACON_URL       # your final URL, e.g. https://your-beacon.vercel.app

vercel deploy --prod
```
`FENER_BEACON_URL` must equal the deployed URL so the embedded pixel is absolute. If you deploy
first to get the `.vercel.app` URL, set the env var to it and `vercel deploy --prod` once more.

## Verify (from anywhere)
```sh
curl -s https://<your-url>/ | grep -o 'FENERZZZ[0-9A-F]*'      # tag embedded in the page
curl -s https://<your-url>/robots.txt                          # Allow: /
curl -s "https://<your-url>/dashboard?key=<FENER_DASH_TOKEN>"  # JSON: callbacks + travel
# prove the pixel logs a callback with a Referer (simulating an off-surface render):
curl -s -o /dev/null -H "Referer: https://some-board.example/x" "https://<your-url>/c/<TAG>?e=px"
curl -s "https://<your-url>/dashboard?key=<TOKEN>" | grep -A2 off_beacon_travel
```

## Pull callbacks into the local system (so correlate.py / beacon.py --status work)
On your Mac, against the same Turso DB:
```sh
export TURSO_DATABASE_URL='libsql://...'
export TURSO_AUTH_TOKEN='...'
FENER_DB=data/live.sqlite3 python3 pull.py     # sync new callbacks -> local live.sqlite3
python3 beacon.py --status                      # off-beacon travel now shows here too
FENER_DB=data/live.sqlite3 python3 correlate.py # cluster beacon + scanned surfaces
```
Schedule `pull.py` (cron/launchd) every ~15 min to keep local analysis current.

## Ethics (unchanged, load-bearing)
Observation only: the page attracts and the pixel records; neither commands nor manipulates any
agent, and the canary is embedded solely on our own surface. Rate-of-harm is nil — a 1x1 GIF.

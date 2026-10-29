# DepRadar frontend

The Next.js dashboard for a single-owner DepRadar workspace. It talks to the FastAPI backend through a same-origin route handler, which forwards the owner cookie and CSRF token without exposing backend credentials to browser code.

## Run locally

Start the backend from the repository root and initialize its owner account once:

```bash
docker compose up --build -d --wait
docker compose exec api depradar setup-owner
```

Then run the dashboard:

```bash
cd front
cp .env.example .env.local
pnpm install
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000). Signed-out visitors go to `/login` and sign in with the owner password; the dashboard only ever shows live data. The default API target is `http://localhost:8000`; set `DEPRADAR_API_URL` in `.env.local` when the API is elsewhere. The proxy sends `DEPRADAR_ALLOWED_ORIGIN` (default: the API URL's origin) as the request origin, so it must equal the backend's `DEPRADAR_ALLOWED_ORIGIN`. For example, with the API published on port 8100 but still allowing `http://localhost:8000`, and port 3000 already in use:

```bash
DEPRADAR_API_URL=http://localhost:8100 DEPRADAR_ALLOWED_ORIGIN=http://localhost:8000 pnpm dev -p 3001
```

The login page shows the setup command when no owner exists yet and an offline screen when the API is unreachable. Signing out or an expired session returns to `/login` with a full page load, discarding the in-memory workspace.

## Screens

Each view has its own URL, so links, refresh, and the browser history keep your place.

- `/login`: owner sign-in, first-run setup instructions, and API offline state.
- `/`: risk overview with the exposure band, a radar of open findings, what needs attention, project exposure, activity, and monitoring health.
- `/findings`: status, severity, decision, and project filters; priority sorting; a detail panel with exploitability (KEV, EPSS), remediation, location, advisories, and the decision log.
- `/projects`: exposure-ranked project register; a project panel with overview, manifests, scan history, and monitoring/alert settings.
- `/notifications`: email and Telegram channels, the alert policy, and the delivery log with provider attempts.
- `/settings#ci|health|retention|backups|coverage`: CI/CD tokens and pipeline snippets, service health, retention, backups, and supported manifests.

Press `⌘K` or `/` to search findings from anywhere.

## Checks

```bash
pnpm lint
pnpm build
```

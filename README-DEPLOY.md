# IMAGE 24 v18.1 — fresh production deployment

This package is prepared for deployment to the existing IMAGE 24 Cloudflare Worker and D1 database. The D1 database ID has been filled in from the user's provided database. Worker secrets are intentionally not included.


This build keeps the browser-first file workflow, adds a Cloudflare Worker API, D1-backed accounts/usage/history, optional Turnstile protection, and a Razorpay subscription backend.

## What changed

- 50 MB per-file validation in the browser.
- Free limit: 10 jobs/day.
- Pro limit: 500 jobs/day.
- Limits are enforced by `/api/jobs/reserve`, not only by UI text.
- Signed sessions use an HttpOnly + Secure + SameSite cookie.
- Passwords are PBKDF2-SHA256 hashed; plaintext passwords are never stored.
- Login/registration/feedback endpoints have IP-based rate limiting.
- Job history stores tool/status/timestamp only; browser-first source files are not uploaded.
- Feedback is stored in D1; Cloudflare Turnstile is supported when configured.
- Razorpay subscription checkout and signed webhook handling are included.
- Pro cancellation can be requested at the end of the current billing cycle.
- Static assets are served by Workers Static Assets; `/api/*` runs through the Worker first.
- SEO metadata, canonical tool URLs, Open Graph tags, WebSite/Organization/Article/Breadcrumb JSON-LD, sitemap, robots rules, guide content and canonical redirects are included.
- The homepage exposes a crawlable Guides section linking each guide to its matching tool.
- Tool pages now lazy-load heavy conversion libraries instead of downloading every PDF/office library on every page.
- A custom 404 page, static security headers and workers.dev noindex protection were added.

## 1. Create the D1 database

The package is configured to use the existing D1 database `image24-db`.

The database ID is already filled in in `wrangler.jsonc`. Do not replace it unless you intentionally switch to a different D1 database.

Apply the schema:

```bash
npx wrangler d1 execute image24-db --remote --file=./schema.sql
```

## 2. Configure Worker secrets

The source code intentionally contains no production secrets.

Required:

- `AUTH_PEPPER` — long random secret used for password/session/anonymous usage hashing.

Optional until billing is enabled:

- `RAZORPAY_KEY_ID`
- `RAZORPAY_KEY_SECRET`
- `RAZORPAY_PLAN_ID`
- `RAZORPAY_WEBHOOK_SECRET`
- `RAZORPAY_TOTAL_COUNT` (default is 1200 monthly cycles)
- `TURNSTILE_SECRET`
- `TURNSTILE_SITE_KEY` (site key is public, but keeping it as a Worker variable makes configuration easier)

In the Cloudflare dashboard: Workers & Pages → your Worker → Settings → Variables and Secrets.

Or with Wrangler:

```bash
npx wrangler secret put AUTH_PEPPER
npx wrangler secret put RAZORPAY_KEY_ID
npx wrangler secret put RAZORPAY_KEY_SECRET
npx wrangler secret put RAZORPAY_PLAN_ID
npx wrangler secret put RAZORPAY_WEBHOOK_SECRET
npx wrangler secret put TURNSTILE_SECRET
```

Do not put secrets in `wrangler.jsonc`, HTML, JavaScript sent to the browser, GitHub, or a public ZIP.

## 3. Configure Razorpay Pro

Create a monthly Razorpay Subscription Plan for ₹299/month and copy its Plan ID into `RAZORPAY_PLAN_ID`.

Set the Razorpay webhook URL to:

`https://YOUR-DOMAIN/api/billing/webhook`

Subscribe to the subscription events needed for status changes, especially activation/charge/cancellation/halt/completion events.

The webhook handler verifies `X-Razorpay-Signature` against the raw request body before changing the user's plan.

Test the complete subscription flow in Razorpay Test Mode before switching to live keys.

## 4. Configure Turnstile

Create a Cloudflare Turnstile widget for your production hostname.

Set:

- `TURNSTILE_SITE_KEY`
- `TURNSTILE_SECRET`

The feedback form will automatically render the widget when the site key exists. The Worker validates the token server-side.

## 5. Deploy

Install Wrangler if needed:

```bash
npm install
```

Deploy:

```bash
npx wrangler deploy
```

The Worker serves the `public/` directory and handles `/api/*` routes.

## 6. Custom domain

After deployment, attach the production domain from Workers & Pages → your Worker → Domains.

For this project the intended canonical domain is `image24.in`; if your real domain is different, update the canonical/meta/sitemap values in `public/index.html` and `public/sitemap.xml`.

## 7. Verify after deployment

Open:

- `/health`
- `/api/health`
- `/`
- `/privacy.html`
- `/terms.html`
- `/cookies.html`

Then test:

1. Create a Free account.
2. Sign out and sign in again.
3. Run an image tool.
4. Confirm usage increases.
5. Reach the Free limit in a test environment and confirm processing is blocked.
6. Submit feedback.
7. Create a Razorpay Test subscription.
8. Confirm the webhook changes the account to Pro.
9. Confirm Pro shows 500 jobs/day.
10. Request cancellation and confirm the provider/webhook updates the status.
11. Test the site on Android Chrome.
12. Test a file larger than 50 MB and confirm it is rejected before processing.

## Important architecture note

IMAGE 24 deliberately does **not** add R2 to the current browser-first workflow. R2 should only be introduced if a tool actually needs temporary server-side file processing. This keeps the current privacy claim aligned with the implementation and avoids unnecessary file storage.

## Production note

The policy pages are technical product templates, not legal advice. Review privacy, consumer, refund, tax and subscription disclosures for the jurisdictions in which you operate before accepting real customers.


## Mobile-only dashboard checklist (no terminal)

If you are deploying from the Cloudflare dashboard on Android, complete these items before launch:

1. Open **Workers & Pages** → open `image24`.
2. Open **Settings → Bindings** → add a **D1 database** binding named `DB` and select `image24-db`.
3. Open **Settings → Variables and Secrets** → add the required `AUTH_PEPPER` secret. Add Razorpay and Turnstile values only when those features are ready.
4. Deploy the final ZIP/source from the project deployment screen.
5. Open **Settings → Domains & Routes → Add → Custom Domain** and attach `image24.in`.
6. After the domain is live, open `https://image24.in/health` and `https://image24.in/api/health`. The second endpoint should report database availability as `true`; payment/Turnstile can remain false until configured.
7. In Google Search Console, verify `image24.in`, submit `https://image24.in/sitemap.xml`, then inspect `/` and the priority tool URLs and request indexing.

If you use the Cloudflare dashboard rather than Wrangler, the D1 binding is the important manual step: the Worker must have a binding whose variable name is exactly `DB`, because the source code reads `env.DB`.


## v18.1 fixed-assets note

This revision removes the runtime dependency on `env.ASSETS.fetch()` from the Worker. Cloudflare Workers Static Assets serves files from `public/` directly before invoking the Worker. The Worker is therefore used for `/api/*` and `/health`, while normal HTML/CSS/JS/image requests are handled by the Static Assets layer. This avoids the dashboard preview error `Cannot read properties of undefined (reading 'fetch')` when an editor-created version has no Assets runtime binding.

For deployment, use the repository/project deployment configuration so Wrangler deploys the `public/` directory together with `worker.js`. Do not use the dashboard **Edit code** preview as the deployment mechanism for this project.

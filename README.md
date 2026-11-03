# Stockroom Inventory

This app uses Neon Postgres through a local Express API. The Neon connection string stays on the server and is never sent to the browser.

## Run locally

1. Create a Neon project and copy its pooled connection string.
2. In your existing `.env`, keep `DATABASE_URL` and add `OWNER_EMAIL` plus a unique `OWNER_PASSWORD` of at least 16 characters. Do not overwrite the existing database URL. Use `.env.example` only as a reference or if you do not already have a `.env`.
3. Install dependencies with `npm install`.
4. Start the app with `npm start`, then open <http://127.0.0.1:3000>.

**One-step start:** run `./start.command` (or double-click it in Finder). It starts the app on port 3001, opens <http://127.0.0.1:3001>, and just opens the browser if it is already running. For a shell shortcut, add `alias stockroom="~/inventory/start.command"` to `~/.zshrc`.

## Everyday features

- **CSV backup and import:** *Export CSV* downloads every product (including IDs). *Import CSV* accepts that same file, or any CSV with a `name` column and optional `sku`, `category`, `quantity`, `price`, `reorder_level`, and `description` columns. Rows matching an existing ID, SKU, or name update that product; others are added. Imports are all-or-nothing and limited to 1,000 rows.
- **Undo delete:** deleting a product shows an *Undo* action for a few seconds.
- **SKU:** an optional, unique code per product, searchable from the search box.
- **Needs attention:** click that summary figure to filter to low and out-of-stock products; click again to clear.

The server creates the `inventory_items` and `auth_sessions` tables on startup. Products and hashed, expiring login sessions are stored in Neon, including each product's reorder level. The browser app no longer uses localStorage as its inventory database.

## Single-owner sign-in

The owner email and password are configured in the server environment; there is no public registration route. Password verification uses Node's scrypt implementation, and the server stores only a hash of each random session token in Neon. The browser receives the session only in an HttpOnly, SameSite=Strict cookie. Sign-in is rate-limited.

The app must be opened at `http://127.0.0.1:3000` so its same-origin protections match. If you change the host or port, set `APP_ORIGIN` to that exact origin. For deployment, use HTTPS and update the origin; add proper user management and per-user inventory authorization before supporting more than one owner.

Existing products saved by the previous file-based app are not automatically copied into Neon. The old browser data remains separate; migrate those products before relying on the Neon-backed inventory.

## Local-only security

The Express server intentionally listens only on `127.0.0.1`. Keep it local; do not expose it publicly without a deployment security review. Never put the Neon connection string or owner password in HTML, frontend JavaScript, or a `NEXT_PUBLIC_`-style variable.

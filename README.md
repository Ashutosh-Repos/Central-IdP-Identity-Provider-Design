# Central IdP — Auth-Service (OAuth2 + OpenID Connect)

A production-ready Identity Provider microservice that implements OAuth2 Authorization Code flow, OpenID Connect, refresh token rotation, and social federation (Google & GitHub).
Designed to be used as a centralized authentication authority for a multi-service platform (Next.js frontend + multiple Node microservices).

Built with: **Node.js, Express, TypeScript, Prisma (Postgres), Redis, jose**.

---

## Key capabilities

* OIDC discovery and JWKS endpoints (`/.well-known/openid-configuration`, `/jwks.json`)
* Authorization Code flow (with PKCE for public clients)
* ID tokens (OIDC) and signed access tokens (RS256)
* Refresh token rotation with reuse detection and revocation
* Social login integration (Google, GitHub) — server-mediated flows
* Short-lived artifacts in Redis (auth codes, sessions, PKCE meta) and canonical state in Postgres (users, identities, refresh tokens, clients)
* Introspection and revocation endpoints for resource servers and clients

---

## Project goals & design principles

* **Single source of truth for auth** — one IDP that issues and revokes tokens for all services.
* **Defense in depth** — PKCE, rotation, reuse detection, hashed refresh tokens, ACLed Redis, key management.
* **Separation of concerns** — auth logic in one microservice; other services only validate tokens.
* **Observability & recoverability** — audit logs, metrics, secure key rotation.

---

## Architecture (high level)

```mermaid
flowchart LR
  User["🧑 User (Browser)"]
  FE["🌐 Frontend (Next.js)"]
  BFF["🔁 BFF / Backend (optional)"]
  AUTH["🔐 Auth-Service (IDP)"]
  API["🟦 APIs / Microservices"]
  PG["🗄️ PostgreSQL (canonical)"]
  REDIS["⚡ Redis (short-lived)"]

  User --> FE
  FE -- "start login / openid authorize" --> AUTH
  AUTH -- "redirect to provider / server callback" --> Provider["🌈 Google/GitHub"]
  Provider -- "provider callback" --> AUTH
  AUTH -- "internal auth code & tokens" --> FE
  FE -- "use access_token" --> API
  API -- "introspect/validate" --> AUTH
  AUTH --> PG
  AUTH --> REDIS
```

> Screenshot (example): `/mnt/data/Screenshot 2025-11-24 at 19.47.31.png`

---

## OAuth2 / OIDC — Detailed sequence (server-mediated social + PKCE)

```mermaid
sequenceDiagram
  autonumber
  participant User as User (Browser)
  participant FE as Frontend (Next.js)
  participant AUTH as Auth-Service (IDP)
  participant Provider as OAuth Provider (Google/GitHub)
  participant Redis as Redis (authcodes)
  participant DB as Postgres (users, identities)

  User->>FE: Click "Sign in with Google"
  FE->>AUTH: GET /oauth/google?client_id=frontend&redirect_uri=<FE_CALLBACK>&state=origState

  AUTH->>Provider: Redirect → provider (server redirect = AUTH callback). state carries encoded client info
  User->>Provider: Authenticate/consent
  Provider-->>AUTH: GET /oauth/callback/google?code=PROVIDER_CODE&state=ENC

  AUTH->>Provider: POST /token (exchange code) using server-registered redirect_uri + client_secret
  Provider-->>AUTH: provider access_token + id_token + userinfo

  AUTH->>DB: find identity by provider+providerUserId
  alt identity exists
    DB-->>AUTH: user
  else
    AUTH->>DB: find or create user by verified email
    AUTH->>DB: create Identity row
    DB-->>AUTH: new user
  end

  AUTH->>Redis: SET auth:authcode:<code> {userId, clientId, redirectUri, scope}
  AUTH-->>FE: Redirect FE_CALLBACK?code=<authcode>&state=origState

  FE->>AUTH: POST /token {grant_type=authorization_code, code, redirect_uri, code_verifier?}
  AUTH->>Redis: GET & DEL auth:authcode:<code>
  AUTH->>AUTH: validate redirect_uri, PKCE (if present)
  AUTH-->>FE: return access_token, id_token, refresh_token
```

---

## Core data model (conceptual)

* **User (Postgres)** — `id, email, displayName, emailVerified, createdAt`
* **Identity (Postgres)** — `provider, providerUserId, userId, rawProfile`
* **Credential (Postgres)** — `userId, passwordHash, createdAt`
* **OAuthClient (Postgres)** — `clientId, clientSecret?, redirectUris[], trusted`
* **RefreshToken (Postgres)** — `id, userId, clientId, tokenHash, revoked, replacedBy, expiresAt`
* **Auth code (Redis)** — `auth:authcode:<code> -> {userId, clientId, redirectUri, scope}`
* **Auth code meta (Redis)** — `auth:authcode_meta:<code> -> {code_challenge, code_challenge_method}`

---

## Endpoints summary & responsibilities

* `GET /.well-known/openid-configuration` — OIDC discovery.
* `GET /jwks.json` — public JWK set (used by services to verify JWTs).
* `GET /authorize` — interactive OAuth2 authorize (validates client and redirect_uri, requires session).
* `POST /token` — exchange `authorization_code` or `refresh_token` (supports PKCE and refresh rotation).
* `GET /userinfo` — return claims for given access token (OIDC).
* `POST /introspect` — returns token metadata for resource servers (active / sub / exp / client_id).
* `POST /revocation` — revoke refresh tokens (and clean Redis indexes).
* `GET /oauth/:provider` — start social login (redirect to provider using server callback).
* `GET /oauth/callback/:provider` — provider callback; exchange code, link/create user, create local auth code, redirect to frontend.

---

## Public vs Confidential clients

* **Public clients** (SPA, native apps): cannot keep secrets. Require PKCE. No `client_secret`.
* **Confidential clients** (server apps): can keep secrets. Authenticate at `/token` with client credentials (HTTP Basic or form body).

Always validate `redirect_uri` exactly (or use exact match list stored in `OAuthClient.redirectUris`).

---

## Refresh token rotation & reuse detection (brief)

1. On `grant_type=refresh_token`: look up hashed token in DB, if valid & not revoked → create new refresh token record, mark old as revoked + `replacedBy` new id.
2. Set short-lived Redis marker `auth:rt_reuse:<oldHash>=1` to detect reuse after rotation.
3. If someone later uses an old token and the reuse marker exists → treat as token theft: revoke all refresh tokens for that user, force logout across devices.

---

## Important security practices (must-have)

* Use **HTTPS** for all endpoints. Never rely on plain HTTP in production.
* Keep private signing keys in **KMS/HSM** (not environment variables) for production. Rotate keys periodically and publish new JWKS.
* Store refresh tokens **hashed** in DB (never store plaintext). Use a fast hash (e.g., PBKDF2/HMAC-SHA256) suitable for token lookup.
* Require **PKCE** for public clients; validate `code_verifier` against stored `code_challenge`.
* Enforce **strict redirect_uri validation** and client registration.
* Use **ACLs** on Redis: limit auth-service Redis user to only keys with prefix `auth:` and allowed commands.
* Rate-limit `/token` and `/authorize`. Log suspicious events and enforce alerting.
* Use CSRF protections for flows that rely on cookies.

---

## Environment & quick start (dev)

Example `.env` (dev):

```env
PORT=4000
ISSUER=http://localhost:4000
DATABASE_URL="postgresql://postgres:postgres@postgres:5432/authdb?schema=public"
REDIS_URL="redis://redis:6379"

# DEV-only: generate keys via openssl/kms in production
PRIVATE_JWK_JSON='{"kty":"RSA","n":"...","e":"AQAB","d":"...","p":"...","q":"...","dp":"...","dq":"...","qi":"...","kid":"dev-key"}'
PUBLIC_JWKS_KID=dev-key

# Social provider credentials
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=http://localhost:4000/oauth/callback/google

GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
GITHUB_REDIRECT_URI=http://localhost:4000/oauth/callback/github
```

Docker compose for dev:

```yaml
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: authdb
    ports: ["5432:5432"]
    volumes: ["pgdata:/var/lib/postgresql/data"]

  redis:
    image: redis:7
    ports: ["6379:6379"]
    command: ["redis-server", "--save", "", "--appendonly", "yes"]
    volumes: ["redisdata:/data"]

volumes:
  pgdata:
  redisdata:
```

---

## Developer checklist — testing the flows

1. Start DB & Redis + run `npx prisma migrate dev`.

2. Start auth-service (`npm run dev` / `pnpm dev`).

3. Verify discovery and JWKS:

   ```bash
   curl http://localhost:4000/.well-known/openid-configuration | jq
   curl http://localhost:4000/jwks.json | jq
   ```

4. Dev email/password signup/login:

   * `POST /auth/signup` → creates user
   * `POST /auth/login` → sets session cookie `sid` and returns tokens (dev-only convenience)

5. Authorization Code: open in browser:

   ```
   http://localhost:4000/authorize?response_type=code&client_id=frontend&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email&state=xyz
   ```

   Or for social:

   ```
   http://localhost:4000/oauth/google?client_id=frontend&redirect_uri=http://localhost:3000/callback&state=xyz
   ```

6. After redirect (frontend receives `code`), exchange at `/token`:

   ```bash
   curl -X POST http://localhost:4000/token \
     -H "Content-Type: application/json" \
     -d '{"grant_type":"authorization_code","code":"<CODE>","redirect_uri":"http://localhost:3000/callback","client_id":"frontend"}' | jq
   ```

7. Test refresh rotation:

   ```bash
   curl -X POST http://localhost:4000/token \
     -H "Content-Type: application/json" \
     -d '{"grant_type":"refresh_token","refresh_token":"<REFRESH_TOKEN>"}' | jq
   ```

8. Introspection (for resource servers):

   ```bash
   curl -X POST http://localhost:4000/introspect -H "Content-Type: application/json" -d '{"token":"<ACCESS_OR_REFRESH_TOKEN>"}' | jq
   ```

9. Revocation:

   ```bash
   curl -X POST http://localhost:4000/revocation -H "Content-Type: application/json" -d '{"token":"<REFRESH_TOKEN>"}'
   ```

---

## Example Next.js test pages (minimal)

**`/pages/login.tsx`**

```tsx
export default function Login() {
  const go = () => {
    window.location.href = "http://localhost:4000/oauth/google?client_id=frontend&redirect_uri=http://localhost:3000/callback&state=test";
  };
  return <button onClick={go}>Login with Google</button>;
}
```

**`/pages/callback.tsx`**

```tsx
import { useRouter } from "next/router";
import { useEffect } from "react";

export default function Callback() {
  const router = useRouter();
  useEffect(() => {
    const code = router.query.code;
    if (!code) return;
    fetch("http://localhost:4000/token", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        redirect_uri: "http://localhost:3000/callback",
        client_id: "frontend"
      })
    }).then(r=>r.json()).then(console.log);
  }, [router.query.code]);
  return <div>Signing in…</div>;
}
```

---

## Production readiness checklist

* Replace `PRIVATE_JWK_JSON` with KMS-managed keys (do not store private keys in env).
* Use TLS for all inbound/outbound traffic.
* Harden Redis using ACLs, TLS, and separate namespace for `auth:` keys.
* Configure backups for Postgres, enable read replicas if needed.
* Configure observability (Prometheus/Grafana) and alerting for suspicious events.
* Enforce strict Content Security Policy and secure cookies.
* Add rate limits and bot detection on authentication endpoints.
* Perform security review / threat modelling and OIDC conformance tests.

---

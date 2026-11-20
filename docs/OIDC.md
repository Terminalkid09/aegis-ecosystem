# Aegis — Human OIDC / SSO

Aegis supports **OpenID Connect Authorization Code + PKCE** with a generic
provider. This is not social login: the target providers are Entra ID, Okta,
Keycloak, Authentik or an equivalent enterprise IdP.

## 1. Behavior

- automatic discovery (`/.well-known/openid-configuration`);
- state, nonce and code verifier in a short-lived signed HttpOnly cookie;
- ID-token signature verification against the provider JWKS;
- checks for `iss`, `aud`, `exp` and `nonce`;
- explicit group-to-role mapping;
- optional automatic account creation on first login;
- local break-glass account so an IdP outage does not lock out the deployment.

SAML, SCIM and in-app MFA are **not** implemented in this phase. MFA belongs to
the provider; SCIM is a separate roadmap item.

## 2. Configuration

```dotenv
OIDC_ENABLED=true
OIDC_ISSUER=https://login.example.com/tenant/v2.0
OIDC_CLIENT_ID=aegis-console
OIDC_CLIENT_SECRET=           # empty for a public PKCE client
OIDC_REDIRECT_URI=https://aegis.example.com/api/v1/auth/oidc/callback
OIDC_SCOPES=openid email profile
OIDC_GROUPS_CLAIM=groups
OIDC_GROUP_ROLE_MAP={"aegis-admins":"admin","aegis-analysts":"analyst","aegis-viewers":"viewer"}
OIDC_DEFAULT_ROLE=viewer
OIDC_AUTO_CREATE_USERS=true
OIDC_LINK_BY_EMAIL=true
OIDC_SYNC_ROLE=true
OIDC_REQUIRE_VERIFIED_EMAIL=true
OIDC_ALLOW_LOCAL_LOGIN=true
```

Register the exact redirect URI in the provider. When the Brain is behind
Caddy, `PUBLIC_BASE_URL` must be the public HTTPS URL.

## 3. Roles

The most privileged role among the matched groups wins:

`admin` → `analyst` → `responder` → `auditor` → `user` → `viewer`.

Only `admin` has `manage` (users, keys, AI providers, restricted settings). An
unknown group grants no privilege; `OIDC_DEFAULT_ROLE` applies instead.

## 4. Linking and break-glass

- An OIDC account is linked to `(issuer, subject)`, not to the email address: an
  email change does not create a second account.
- With `OIDC_LINK_BY_EMAIL=true`, a local account with a verified email is
  linked on first login. The local role is **not** downgraded during that
  linking step: a break-glass admin cannot be locked out by a wrong IdP mapping.
- Later OIDC logins synchronize the role when `OIDC_SYNC_ROLE=true`.
- A role sync that would remove the last active admin is suppressed: the
  account stays `admin` and the callback logs `role_sync_suppressed=true`.
- When OIDC is enabled, `OIDC_ALLOW_LOCAL_LOGIN=false` is enforced by the API:
  `POST /auth/login` and `POST /auth/register` return 403. It is not just a UI
  switch. If OIDC is disabled the local path remains available so a
  misconfigured flag cannot lock the deployment out.
- Keep `OIDC_ALLOW_LOCAL_LOGIN=true` until at least one tested local admin
  exists. It is the recovery path.

## 5. API

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/auth/oidc/config` | Public login-page policy |
| `GET /api/v1/auth/oidc/login` | Redirect to the provider |
| `GET /api/v1/auth/oidc/callback` | Code exchange, token validation, session creation |

The callback does not return a token in the body: it sets the HttpOnly
`aegis_token` cookie, like local login, and redirects to the SPA.

## 6. Verification (2026-11-20)

The flow was executed against **Keycloak 26.0.7** in an ephemeral container, not
against a mock:

- realm `aegis`, public client `aegis-console` with PKCE;
- redirect `http://localhost:8000/api/v1/auth/oidc/callback`;
- verified user `sso-admin`, auto-provisioned on first login;
- Brain callback returned `302` to the SPA and set the HttpOnly cookie;
- the SPA probes `/auth/me` on load, so the OIDC session is visible immediately
  (previously the UI stayed on the login page because `sessionHint` was
  local-only);
- Playwright: **2 passed**.

Compose now passes every `OIDC_*` variable and `PUBLIC_BASE_URL` to the Brain;
previously a correct `.env` still produced `OIDC_ENABLED=false` inside the
container. The clean install also adds the configured `https://<AEGIS_DOMAIN>` origin to
`ALLOWED_ORIGINS`; otherwise cookie-authenticated POSTs through Caddy returned
403. Keep `PUBLIC_BASE_URL` and `OIDC_REDIRECT_URI` on the same public host.

## 7. Known limits

- SAML 2.0 is not included.
- SCIM is not included.
- MFA is delegated to the IdP.
- A provider that does not expose `email_verified=true` is rejected when
  `OIDC_REQUIRE_VERIFIED_EMAIL=true` (the default). This is a fail-closed choice.

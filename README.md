# MoviesNow Backend — Full Project Research & Developer Guide

This is a deep, implementation‑level guide to the MoviesNow backend. It covers the system’s architecture, security model, data model, key services, and API surface area (public, delivery, auth, admin). It also documents S3/AWS usage, uploading and downloading flows, and operational considerations like rate limiting, caching, and readiness. The goal is to help maintainers and contributors quickly understand how the codebase fits together and how to extend it safely.

Table of contents
- Overview & Architecture
- Runtime & Middleware
- Configuration & Environment
- Data Model (ORM)
- Authentication & Tokens
- Public APIs (Discovery, Bundles, Downloads)
- Delivery (Presigned GETs)
- Admin APIs (Taxonomy, Assets, Uploads, Bundles)
- Player Sessions (Telemetry)
- Storage & AWS (S3)
- Upload Flows (single, multipart, proxy)
- Download Flows (public policies, tokens)
- Caching, Rate Limits, Security Headers
- Redis usage and keys
- Observability & Readiness
- Testing notes
- Extensibility & Gotchas


## Overview & Architecture

- Framework: FastAPI on ASGI, see `app/main.py` for the app factory.
- Versioned API: `app/api/v1/routers` composes routers for public, delivery, player, auth, admin, and ops under `/api/v1`.
- Layered design:
  - Routers: request/response shaping, security gates, rate limits, caching headers.
  - Services: business logic (auth, tokens, auditing, email, etc.).
  - Repositories: pluggable read models for discovery (`repositories/titles.py`) and player telemetry.
  - ORM: SQLAlchemy models in `app/db/models/*` with pragmatic constraints and indexes.
  - Utilities: AWS S3 wrapper, caching primitives, security headers, limiter.
- Infra helpers: Redis (rate limiting, idempotency, activity), Postgres (ORM), S3 (storage), optional CDN.

Key entrypoints
- `app/main.py`: app factory, lifespan (Redis connect/close, DB dispose), middleware, health endpoints.
- `app/api/v1/routers/__init__.py`: aggregates v1 routers: public discovery, bundles, downloads; player sessions; delivery; user endpoints; admin surface; ops.
- `app/utils/aws.py`: hardened S3 client wrapper for presigned PUT/GET and server-side ops.


## Runtime & Middleware

See `app/main.py` for ordered middleware and handlers:
- `RequestIDMiddleware`: per-request correlation (`X-Request-ID`).
- Security headers via `install_security(app)`: HSTS, CSP nonce, HTTPS redirect per env.
- CORS via `configure_cors(app)`: exposes `X-Request-ID`, `ETag`, etc.
- `GZipMiddleware`: automatic compression for large JSON responses.
- SlowAPI limiter (if configured): per-route decorators + 429 handler.
- Final “strip Server header” middleware to avoid version leakage.

Health endpoints
- `GET /healthz`: liveness (process up), exempt from rate limit.
- `GET /readyz`: readiness (quick `SELECT 1` + Redis ping best‑effort), exempt from rate limit.

Exception handling
- If present, custom exception handlers are registered; otherwise FastAPI defaults apply.


## Configuration & Environment

Primary config: `app/core/config.py` (loaded via environment variables). Commonly used settings:
- API: `API_V1_STR`, docs toggles (`ENABLE_DOCS`).
- Security: `JWT_SECRET_KEY`, `JWT_ALGORITHM`, `JWT_ISSUER`, `JWT_AUDIENCE`, `AUTH_FAIL_OPEN`.
- Tokens: `ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_EXPIRE_DAYS`.
- Redis: `REDIS_URL`.
- Database: `DATABASE_URL` or `ASYNC_DATABASE_URL`.
- S3/AWS: `AWS_BUCKET_NAME`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional KMS.
- CDN: `CDN_BASE_URL` (public URL builder), `CLOUDFRONT_*` optional.
- Public API: `PUBLIC_API_KEY` (optional), public cache TTLs.
- Delivery TTL clamps: `DELIVERY_MIN_TTL`, `DELIVERY_MAX_TTL`.
- Player telemetry IP trust: `TRUST_FORWARD_HEADERS`, `TRUSTED_PROXY_ONLY`.


## Data Model (ORM overview)

ORM models live in `app/db/models`. Highlights with rationale and relationships:

- `User` (`user.py`): accounts with auth flags, verification, MFA fields, role (`OrgRole`), and relationships to tokens, OTPs, logs, profile, playback sessions.
  - Indexes: case-insensitive uniqueness for email/username; hygiene checks; DB-driven timestamps.
  - MFA: `is_2fa_enabled` preferred; `mfa_enabled` maintained for compatibility.

- `Title` (`title.py`): canonical catalog entity for Movie or Series.
  - Classification: `type` (MOVIE/SERIES), `status` (ANNOUNCED, etc.).
  - SEO: slug (CI-unique), names, overview.
  - Release/locales: year/date, languages/countries arrays.
  - Media pointers: canonical poster/backdrop/trailer via `MediaAsset`.
  - Relationships: seasons, episodes, media_assets, artworks, credits, many-to-many genres (`title_genres`), availabilities, reviews, playback sessions, subtitles, bundles.
  - Indexes: locale arrays (GIN), helpful filters.

- `Genre` (`genre.py`): normalized taxonomy with optional hierarchy.
  - CI-unique `name` and `slug`, `aliases` (JSONB), `display_order`, `is_active`.
  - Relationships: parent/children; many-to-many `Title`.

- `Credit` (`credit.py`): cast and crew linking `Person` to title/season/episode.
  - Exactly one parent (enforced), rich typing (`kind`, `role`), cast metadata (character, billing order), crew taxonomy.
  - De-dup partial unique indexes per parent scope.

- `MediaAsset` (`media_asset.py`): binary artifacts (images, trailers, video, subtitles, extras).
  - Scope: title/season/episode with composite FKs for hierarchy integrity.
  - De-dup: unique `storage_key`, checksum/size/mime for traceability.
  - Publishing ergonomics: `is_primary` per (scope, kind, language) with partial unique index.
  - Technical metadata: container/codecs/HDR/stereo/channels/bitrate/dimensions/fps, `lifecycle` class, `tags` and `metadata` JSONB.
  - Relationship: `StreamVariant` (derived streams/renditions), `uploaded_by`.

- `StreamVariant` (`stream_variant.py`): per‑rendition stream/download variant derived from a `MediaAsset`.
  - Policy: only 1080p/720p/480p are streamable; at most one streamable per (asset, tier).
  - Fields: protocol (HLS/DASH/MP4), codecs, container, bandwidth, resolution, default flags, DRM type, audio language, HDR.
  - Partial uniques and checks enforce policy and de-dup.

- `Subtitle` (`subtitle.py`): logical text track bound to a `MediaAsset` subtitle/caption file.
  - Playback semantics: default/forced/SDH flags, language, label, timing offset.
  - Uniqueness: one default and one forced per (scope, language) among active rows.

- `Bundle` (`bundle.py`): downloadable ZIP archive (e.g., season bundle, extras) stored in S3.
  - Key patterns: `bundles/{title_id}/S{season:02}.zip` and movie/adhoc bundles.
  - Metadata: `size_bytes`, `sha256`, `expires_at`, optional `label`, `episode_ids` for traceability.
  - Admin life cycle with presigned PUT generation and best‑effort S3 delete.

- Additional models: `Season`, `Episode`, `Artwork`, `Availability`, `Person`, `Profile`, `Progress`, `Review`, `Watchlist`, `PlaybackSession`, `OTP`, `MFAResetToken`, `RefreshToken` (token store), etc. They conform to the same consistency principles: DB‑driven timestamps, checks for non‑negative/nonnull, and selectin relationships.


## Authentication & Tokens

Core helpers: `app/core/security.py` and `app/core/jwt.py`.

Token types
- Access: short‑lived JWT containing `sub`, `jti`, `exp`, `mfa_authenticated`, optional `session_id`. Stored in Redis lane `access:jti:{jti}` for revocation window.
- Refresh: longer‑lived JWT with `jti`, optional `session_id` and `parent_jti`. Stored as `refresh:jti:{jti}` and persisted hashed in DB via `store_refresh_token`.
- MFA challenge: short‑lived JWT indicating `mfa_pending=True` used to finalize MFA (`/auth/mfa-login`).

Validation & revocation
- `decode_token` enforces signature, `exp/nbf/iat`, optional `iss/aud`, presence of `jti`, and expected token types when requested.
- Revocation checks consult Redis `revoked:jti:{jti}`. On Redis unavailability, behavior is controlled by `AUTH_FAIL_OPEN` (default fail‑closed with 503).
- `get_current_user` FastAPI dependency decodes the presented access token, loads the user, ensures active, and attaches `TokenPayload` to the request and `user` object.

MFA
- TOTP via `pyotp` (`generate_totp`), `is_2fa_enabled` flag on users, and short‑lived MFA challenge JWT.
- `login_user` returns `MFAChallengeResponse` when MFA is enabled; otherwise mints refresh then access and records session lineage in Redis (`session:{user_id}`, `sessionmeta:{jti}`).

Idempotency & rate limits
- Most auth routes apply per‑route SlowAPI limits and (for signup/login) best‑effort Redis idempotency using `Idempotency-Key` header snapshots.

Auth routes (examples)
- `POST /api/v1/auth/signup` → `TokenResponse` (access + refresh), async email verification, idempotent snapshot.
- `POST /api/v1/auth/login` → `TokenResponse` or `MFAChallengeResponse`.
- `POST /api/v1/auth/mfa-login` → `TokenResponse`.
- Additional routes (password reset, email verification, token refresh/logout) live under `app/api/v1/routers/auth/*` backed by services in `app/services/auth/*`.


## Public APIs (Discovery, Bundles, Downloads)

Location: `app/api/v1/routers/public/*`.

Discovery (`discovery.py`)
- `GET /titles` (paginated search): optional text `q`, filters (`genres`, `year`, `rating`, `cast`), sort/order/page/page_size.
  - Caching: strong ETag + TTL if `PUBLIC_LIST_CACHE_TTL_SECONDS > 0`; returns pagination headers (`X-Total-Count`, RFC 5988 `Link`).
  - Backing repository: `app/repositories/titles.py` (in‑memory by default, pluggable via `TITLES_REPOSITORY_IMPL`).
- `GET /titles/{title_id}`: title detail. Optional ETag caching if `PUBLIC_ITEM_CACHE_TTL_SECONDS > 0`.
- `GET /titles/{title_id}/streams`: public subset of stream variants (list). Short TTL caching if enabled.
- `GET /titles/{title_id}/subtitles`: public subtitle tracks. Short TTL caching if enabled.
- `GET /genres`: list available genres.
- `GET /credits?title_id=...`: public credits.
- `GET /similar/{title_id}`: related titles.
- `GET /stream/{title_id}/{quality}` and `GET /download/{title_id}/{quality}`: return signed URLs using services signing (responses are `no-store`).

Bundles (`bundles.py`)
- `GET /titles/{title_id}/bundles`: list active bundles for a title. Computes stable ETag and sets CDN-friendly cache headers. Returns id, season, storage_key (not a URL), size/sha256, and expiry when present.
- `GET /titles/{title_id}/bundles/{season}/manifest`: validates S3 object existence then returns a presigned GET URL for the JSON manifest. Response marked `no-store`.

Downloads (`downloads.py`)
- Policy: public routes do not expose raw per‑episode downloadable assets (cost & abuse control). Instead, guide users to bundles or delivery endpoints.
- `GET /titles/{title_id}/downloads` and `GET /titles/{title_id}/episodes/{episode_id}/downloads`: return empty lists with helpful alternatives and are short‑cacheable with ETag.

Security
- Optional `X-API-Key` enforcement via `enforce_public_api_key`.
- Rate limits using dependency `rate_limit`.
- Signed URL responses are always `Cache-Control: no-store`.


## Delivery (Presigned GETs)

Location: `app/api/v1/routers/delivery.py`.

Purpose: issue short‑lived presigned GET URLs for allowed storage keys.

Endpoints
- `POST /delivery/download-url`: input `{storage_key, attachment_filename?, ttl_seconds?}`; validates allowed prefixes and zip extension; HEAD check; returns `{url}`. `no-store`.
- `POST /delivery/batch-download-urls`: input list; returns `{results: [{index, storage_key, url|error}]}`; `no-store`.
- `POST /delivery/bundle-url`: optional one‑time token redemption from Redis; HEAD check and presign; returns `{url}`; `no-store`.

Hardening
- Allowed key prefixes: `bundles/` or `downloads/**/extras/**.zip` only.
- Strict key normalization (`/`, `..`, safe characters) and attachment filename sanitization.
- TTL clamped by `DELIVERY_MIN_TTL` and `DELIVERY_MAX_TTL`.
- Optional one‑time token: `download:token:{token}` JSON in Redis, atomically redeemed under lock, optionally bound to a specific key.


## Admin APIs (Taxonomy, Assets, Uploads, Bundles)

Admin routers live under `app/api/v1/routers/admin/*`. All are guarded by:
- `get_current_user` + `ensure_admin` role checks
- `ensure_mfa`
- Per‑route SlowAPI rate limits
- `no-store` headers
- Audit logs best‑effort (`log_audit_event`)
- Redis distributed locks as needed

Taxonomy & Credits (`taxonomy.py`)
- Genres
  - `POST /admin/genres`: create genre; validates slug (kebab‑case), idempotent on `Idempotency-Key` with snapshot, lock to prevent duplicates (CI unique).
  - `GET  /admin/genres`: list genres with filters and pagination.
  - `PATCH /admin/genres/{id}`: redis lock + row lock; conflict on slug → 409.
  - `DELETE /admin/genres/{id}`: locked delete.
  - Attach/detach: `POST/DELETE /admin/titles/{title_id}/genres/{genre_id}` idempotent attach.
- Credits
  - `POST /admin/titles/{title_id}/credits`: create credit with role metadata; idempotency by (title, person, kind/role/character/job) + header snapshot.
  - `GET /admin/titles/{title_id}/credits`: list credits with filters.
  - `PATCH /admin/credits/{credit_id}`, `DELETE /admin/credits/{credit_id}`.
- Compliance
  - `POST /admin/titles/{title_id}/block`: region/age certification, optional unpublish.
  - `POST /admin/titles/{title_id}/dmca`: DMCA advisory and optional unpublish.
  - `GET  /admin/compliance/flags`: enums for UI.

Bundles (`bundles.py`)
- Create/list/get/patch/delete bundles (see model section). Create returns presigned PUT and DB row; delete is best‑effort row + S3.
- Defensive creation: idempotency, duplicate prevention, S3 overwrite prevention.

Assets & Uploads (`assets/*`)
- Uploads (`assets/uploads.py`):
  - `POST /admin/uploads/init`: presigned PUT for single‑part uploads. Deterministic key using `Idempotency-Key`. `uploads/single/{...}` prefix.
  - Multipart: `POST /admin/uploads/multipart/create` → `{uploadId, storage_key}`; `GET /admin/uploads/multipart/{uploadId}/part-url`; `POST /admin/uploads/multipart/{uploadId}/complete`; `POST /admin/uploads/multipart/{uploadId}/abort`.
  - `POST /admin/uploads/direct-proxy`: small files (<= 10 MiB) uploaded through the API server; use sparingly.
  - All responses `no-store`, all routes require admin + MFA, rate limited, idempotent where applicable.
- Additional asset tools: artwork, trailers, streams, subtitles, validation, CDN delivery helpers (see `assets/*.py`).


## Player Sessions (Telemetry)

Location: `app/api/v1/routers/player/sessions.py` with repository layer at `app/repositories/player.py`.

Endpoints (public + optional key, `no-store`)
- `POST /player/sessions/start`: starts a session (`201`), idempotent via `Idempotency-Key` (10 min TTL). Stores minimal PII (configurable).
- `POST /player/sessions/{id}/heartbeat`: QoE heartbeat (`202`).
- `POST /player/sessions/{id}/pause|resume|seek`: event markers.
- `POST /player/sessions/{id}/complete`: mark completion (aggregate stats).
- `POST /player/sessions/{id}/error`: capture error events.
- `GET  /player/sessions/{id}`: summary.

Notes
- Client IP resolution is proxy/CDN aware when enabled (`TRUST_FORWARD_HEADERS`).
- Correlation headers (`X-Request-ID`, `traceparent`) are echoed.
- Repository is pluggable; default impl can be swapped via env to a DB/analytics store.


## Storage & AWS (S3)

Wrapper: `app/utils/aws.py` provides `S3Client` with safe defaults and operations:
- `presigned_put(key, content_type, expires_in, extra_args={SSE/KMS})`
- `presigned_get(key, expires_in, response_content_type, response_content_disposition)`
- `put_bytes(key, data, content_type, public=False, cache_control?, content_disposition?, extra_args?)`
- `delete(key)` best‑effort
- `cdn_url(key)`: build CDN URL when configured

Key normalization
- Strip leading `/`, collapse `//`, reject `..`, enforce allowed char set (`[A-Za-z0-9._\-/+=@() ]+`).

Client construction
- Uses env/role/IRSA credential discovery, custom `BotoConfig` with timeouts/retries.
- Optional SSE‑S3 or SSE‑KMS.

Bucket layout (convention)
- `originals/{title_id}/...`
- `downloads/{title_id}/[episode_id/]...` (extras under `/extras/`)
- `hls/{title_id}/[episode_id/]...`
- `bundles/{title_id}/S{season:02}.zip`
- `artwork/title/{title_id}/...`
- `subs/title/{title_id}/...`


## Upload Flows (single, multipart, proxy)

Single-part upload (presigned PUT)
1) Admin calls `POST /api/v1/admin/uploads/init` with `{content_type, filename_hint?, key_prefix?}`.
2) Server generates deterministic storage key using `Idempotency-Key` and safe segments.
3) Server returns `{upload_url, storage_key}`; client uploads directly to S3; server never handles bytes.

Multipart upload (large files)
1) `POST /api/v1/admin/uploads/multipart/create` → `{uploadId, storage_key}` (idempotent snapshot).
2) For each part: `GET /api/v1/admin/uploads/multipart/{uploadId}/part-url?key=...&partNumber=n` → presigned PUT.
3) Client uploads parts to S3 using presigned URLs, collects ETags.
4) `POST /api/v1/admin/uploads/multipart/{uploadId}/complete` with parts list → S3 `CompleteMultipartUpload`.
5) On failure: `POST /api/v1/admin/uploads/multipart/{uploadId}/abort`.

Direct proxy (tiny files only)
- `POST /api/v1/admin/uploads/direct-proxy` with raw bytes (<= 10 MiB); server uploads via `put_bytes`.
- Reserved for cases where presign is not feasible; increases API server load.

Security notes
- All upload flows require admin + MFA and are rate limited. Responses are `no-store`.
- Keys are validated and sanitized; idempotency prevents duplicate object creation on retries.


## Download Flows (public policies & tokens)

Public policy
- The public endpoints never enumerate raw per‑episode downloadable files to avoid hotlinking and cost spikes.
- Season or curated bundles are the preferred public delivery method.

Delivery endpoints
- `POST /api/v1/delivery/download-url`: presigned GET for allowed keys (bundles or extras zip). No object rebuilds; existence is HEAD‑checked.
- `POST /api/v1/delivery/bundle-url`: presigned GET for bundle zip with optional one‑time token redemption.
- Batch download supported for multiple keys with per‑item error reporting.

One‑time tokens
- Redis key `download:token:{token}` holds JSON with optional `key` binding and metadata.
- Redemption is atomic under lock; on success, token is invalidated.


## Caching, Rate Limits, Security Headers

Caching
- JSON list/detail endpoints can use ETags + TTL based on env values (`PUBLIC_LIST_CACHE_TTL_SECONDS`, `PUBLIC_ITEM_CACHE_TTL_SECONDS`, etc.).
- Signed URL responses are always marked `Cache-Control: no-store`.
- Public bundles listing uses weak ETag computed from stable fields.

Rate limits
- SlowAPI decorators (e.g., `@rate_limit("10/minute")`).
- Lightweight per‑process token bucket in `app/api/http_utils.py::rate_limit` for hotspots and tests.

Security headers
- `app/security_headers.py` installs strict headers and allows CSP nonce; `set_sensitive_cache(response)` ensures sensitive responses are not cached.


## Redis usage & key conventions

- Rate limiting and token buckets for some endpoints (in‑proc and SlowAPI backends).
- Idempotency snapshots: `idemp:{namespace}:{...}` (e.g., `idem:signup:resp:{key}`, `idemp:admin:uploads:multipart:create:{key}:{idem_hdr}`).
- Token revocation lanes: `access:jti:{jti}`, `refresh:jti:{jti}`; separate revoked lane `revoked:jti:{jti}`.
- Session lineage: `session:{user_id}` (set of refresh jtis), `sessionmeta:{jti}` (hash with session metadata TTL‑aligned to token expiry).
- One‑time download tokens: `download:token:{token}` (JSON), lock `lock:download:token:{token}`.
- Admin mutation locks: e.g., `lock:admin:genres:{genre_id}`, `lock:admin:bundles:create:{title_id}`, etc.


## Observability & Readiness

- Health (`/healthz`) and readiness (`/readyz`) endpoints as described above.
- Audit logs: `app/services/audit_log_service.py` emits structured events; it’s best‑effort, errors are swallowed.
- Player telemetry: minimal PII, optional hashing of IP/UA; correlation headers echoed for client trace stitching.


## Testing notes

- Tests live under `tests/`. Public discovery, downloads, and admin taxonomy have focused tests.
- When interacting with routes that use SlowAPI, JSONResponse is used to avoid header-injection conflicts.
- Many flows are best‑effort and do not fail the happy path on transient Redis issues (see idempotency usage).


## Extensibility & Gotchas

- Keep middleware order intact: request ID → security headers → CORS → GZip → rate limiter → strip server header.
- Avoid leaking provider internals in errors (storage, auth); prefer neutral 404/503.
- For new public endpoints: prefer short TTLs, strong ETags, and optional API keys; never expose raw storage keys.
- For admin endpoints: require admin + MFA; add `no-store`, rate limits, and audit logging; consider Redis locks for mutations.
- For new uploads: prefer presigned flows; generate deterministic keys under safe prefixes; guard with idempotency snapshots.
- For new download flows: constrain allowed prefixes and extensions; consider optional token redemption; always HEAD-check before presigning.
- For new models: add DB‑driven timestamps, hygiene checks, and pragmatic indexes. Respect existing relationship loading patterns (`lazy="selectin"`, `passive_deletes=True`).
- Be mindful of Redis outages: decide fail‑open vs fail‑closed using settings; for auth revocation, default is fail‑closed.
- Player/analytics: keep payloads lean and PII‑safe by default; allow opt‑in to more fields via settings.


## File Index (by purpose)

- App entrypoint & lifecycle
  - `app/main.py`: app factory, middleware, routers, health checks.
  - `app/asgi.py`: ASGI entry when needed.

- API routers
  - `app/api/v1/routers/__init__.py`: aggregates v1 routers.
  - Public: `public/discovery.py`, `public/bundles.py`, `public/downloads.py`.
  - Delivery: `delivery.py`.
  - Auth: `auth/*.py` (login, signup, refresh, logout, email verification, MFA, recovery codes, etc.).
  - Admin: `admin/taxonomy.py`, `admin/bundles.py`, `admin/assets/*.py` (uploads/artwork/streams/subtitles/etc.).
  - Player: `player/sessions.py`.
  - Ops: `ops/observability.py` (if present), and `api/well_known.py` for OIDC/JWKS when configured.

- Services & utils
  - `app/services/auth/*.py`: login, signup, email verification, logout, password reset, MFA, token refresh.
  - `app/services/token_service.py`: refresh token persistence and rotation helpers.
  - `app/services/audit_log_service.py`: structured audit logging.
  - `app/utils/aws.py`: S3 client wrapper.
  - `app/api/http_utils.py`: rate limiting, API key enforcement, JSON helpers, webhook HMAC check.
  - `app/security_headers.py`: secure defaults and `set_sensitive_cache`.
  - `app/core/jwt.py`, `app/core/security.py`: JWT encode/decode, revocation, dependencies.
  - `app/core/limiter.py`: SlowAPI installer and decorators.
  - `app/core/redis_client.py`: async Redis wrapper and idempotency helpers.

- ORM & DB
  - `app/db/models/*.py`: models listed above.
  - `app/db/session.py`: async engine/session setup.
  - `alembic/` and `alembic.ini`: migrations.

- Repositories
  - `app/repositories/titles.py`: discovery repository (pluggable, memory default).
  - `app/repositories/player.py`: telemetry store (pluggable).


## Quickstart (local)

1) Dependencies: Python 3.11+, Redis, Postgres. Configure env:
   - `DATABASE_URL=postgresql+asyncpg://...`
   - `REDIS_URL=redis://localhost:6379/0`
   - `AWS_BUCKET_NAME=...`, `AWS_REGION=...` (for S3 features)
2) DB migrations: `alembic upgrade head`
3) Run API: `uvicorn app.main:app --reload`
4) Visit `/docs` (if `ENABLE_DOCS=1`) and `/api/v1/...` routes.


## Examples

Signup
- Request: `POST /api/v1/auth/signup` with `{email, password, ...}` and optional `Idempotency-Key`.
- Response: `{access_token, refresh_token, token_type}`; headers include `Cache-Control: no-store`.

List public titles
- Request: `GET /api/v1/titles?q=ring&genres=Fantasy&page=1&page_size=20`
- Response: paginated summaries with `X-Total-Count` and `Link` headers; optional ETag/304 if caching is enabled.

Create a bundle (admin)
- Request: `POST /api/v1/admin/titles/{title_id}/bundles` with `{season_number?, ttl_days?, label?}`; requires admin + MFA.
- Response: `{id, storage_key, upload_url, expires_at?}`; upload the zip using the presigned PUT.

Get delivery URL (public)
- Request: `POST /api/v1/delivery/bundle-url` with `{storage_key: "bundles/<uuid>/S01.zip", ttl_seconds: 300}`; optional token.
- Response: `{url}`; consumer downloads using the presigned GET, response is `no-store`.


---

This guide intentionally documents internal details for maintainers and reviewers. When introducing changes, please update only the relevant sections, keeping security and operational guarantees (no-store, rate limits, idempotency, locks, neutral errors) intact.

## Schedule API (Upcoming Releases)

New public endpoints under `/api/v1`:

- `GET /api/v1/schedule/upcoming` — Upcoming releases per region.
  - Params: `days` (1–180, default 30), `country` (ISO alpha-2, optional; auto-detected from headers if missing), `type` (`MOVIE|SERIES`, optional), `limit` (1–200, default 50).
  - Response: earliest upcoming Availability window per Title for that region, with `poster_url` and `trailer_url` where available.

- `GET /api/v1/schedule/worldwide` — Upcoming releases with GLOBAL availability.
  - Params: `days`, `type`, `limit` as above.

Admin manages scheduling data via availability windows:
- `GET /api/v1/admin/titles/{title_id}/availability`
- `PUT /api/v1/admin/titles/{title_id}/availability`


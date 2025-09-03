# MoviesNow Backend – Real‑World Workflows & Endpoint Guide

This guide explains how the backend behaves in production, which endpoints do what, and how the pieces fit together (FastAPI + Postgres + Redis + S3 + CloudFront OAC). It is written for new contributors and operators.

## Architecture Overview

- API: FastAPI (async), rate‑limited, with MFA for admin routes
- Data: Postgres (SQLAlchemy models + Alembic migrations)
- Cache/Locks/Tokens: Redis (download tokens, idempotency snapshots, distributed locks)
- Storage/CDN: Private S3 bucket (SSE‑S3) behind CloudFront with Origin Access Control (OAC)
- Observability: Health/Ready endpoints, Prometheus metrics, audit logs

## S3 Layout (private bucket)

```
originals/{title_id}/[episode_id/]{filename.ext}
downloads/{title_id}/[episode_id/]{quality or source}/{filename.ext}
hls/{title_id}/[episode_id/]{ladder}/{files...}
bundles/{title_id}/S{season:02}.zip
artwork/title/{title_id}/...
subs/title/{title_id}/...
```

Lifecycle: All prefixes transition to Intelligent‑Tiering after 30 days. Bundles expire automatically after 7–30 days (config in Terraform).

Security: Bucket is private; CloudFront uses OAC; clients receive short‑lived presigned GETs.

## Core Policies

- Streaming: Exactly 3 tiers available for playback (HLS only): 480p, 720p, 1080p
- Downloads: All uploaded originals/download assets remain available for download (no quality change). Optional MP4/H.264 variants for maximum compatibility.
- Bundles: Season ZIPs are short‑lived; if expired/missing, server rebuilds on demand from originals.

## Typical Admin Workflow (Ingestion → Validation → Publish)

Step‑by‑step (simple and practical)

1) Create the catalog item (Title/Season/Episode)
   - Use the existing admin Titles/Series routers to create a Title (and Season/Episodes when it’s a series).
   - You will reference `title_id` (and optionally `episode_id`) in all asset calls.

2) Upload media
   - Artwork: POST `/api/v1/admin/titles/{title_id}/artwork` → presigned PUT → upload (poster/backdrop etc.)
   - Video originals/downloads: POST `/api/v1/admin/titles/{title_id}/video` → presigned PUT → upload
   - Subtitles: POST `/api/v1/admin/titles/{title_id}/subtitles` → presigned PUT → upload, track row created
   - Streams (if managed manually): POST `/api/v1/admin/titles/{title_id}/streams` – configure exactly 3 streamable variants (P480/P720/P1080), HLS only
   - Tip: Each “create” returns `{upload_url, storage_key, id}`; upload directly to S3 with that URL (multipart supported elsewhere when needed).

3) Finalize/verify asset metadata (fast)
   - HEAD S3 and cache size/type: GET `/api/v1/admin/assets/{asset_id}/head`
   - Store checksum: POST `/api/v1/admin/assets/{asset_id}/checksum` (server computes when ≤10MB or provide sha256)
   - One‑shot finalize (optional): POST `/api/v1/admin/assets/{asset_id}/finalize` with `{size_bytes, content_type, sha256}`

4) Validate streaming/download policy (pre‑publish)
   - GET `/api/v1/admin/titles/{title_id}/validate-media`
   - Confirms: exactly one HLS streamable per tier (480/720/1080); not audio‑only; downloads have `size_bytes`+`sha256`; subtitle defaults don’t conflict.
   - Fix any reported issues by editing the specific assets/variants.

5) (Optional) Season bundles
   - Short‑lived ZIPs can be uploaded:
     - POST `/api/v1/admin/titles/{title_id}/bundles` → `{upload_url, storage_key, bundle_id}` → upload ZIP via `upload_url`
   - Or build on demand (preferred, cheaper): use the public “request bundle” flow below.
   - Manage:
     - GET `/api/v1/admin/titles/{title_id}/bundles` (list)
     - GET `/api/v1/admin/bundles/{bundle_id}` (detail)
     - PATCH `/api/v1/admin/bundles/{bundle_id}` (label/expiry)
     - DELETE `/api/v1/admin/bundles/{bundle_id}`
     - Force rebuild: POST `/api/v1/admin/titles/{title_id}/rebuild-bundle?season_number=N` (async)

6) (Optional) Premium download tokens
   - Batch create: POST `/api/v1/admin/delivery/download-tokens/batch`
   - Distribute tokens to users; they redeem to get a signed URL.

Security (admin):
- MFA enforced; rate‑limited endpoints
- Idempotency via `Idempotency-Key` on create‑style calls
- Redis locks serialize destructive or rebuild operations
- Audit logs record actions (best‑effort)

## Public Discovery & Download Flow

Step‑by‑step (what users do)

1) Discover titles (CDN‑cacheable)
   - GET `/api/v1/titles` – search/browse
   - GET `/api/v1/titles/{title_id}` – title detail
   - GET `/api/v1/titles/{title_id}/streams` – available HLS tiers (480/720/1080)
   - GET `/api/v1/titles/{title_id}/subtitles` – subtitle tracks

2) Download single files (originals/downloads)
   - Find options:
     - GET `/api/v1/titles/{title_id}/downloads` – per‑title & per‑episode lists
     - GET `/api/v1/titles/{title_id}/episodes/{episode_id}/downloads` – per episode
   - Get a presigned URL:
     - POST `/api/v1/delivery/download-url` with `{storage_key, ttl_seconds, attachment_filename?}`
   - For many at once: POST `/api/v1/delivery/batch-download-urls` with `{items:[{storage_key, attachment_filename?}], ttl_seconds}`

3) Get a Season ZIP (short‑lived and on‑demand)
   - See available bundles: GET `/api/v1/titles/{title_id}/bundles`
   - Request by known key: POST `/api/v1/delivery/bundle-url`
     - If expired/missing and `rebuild_if_missing=true`, API returns 202 (REBUILDING). Retry after ~15s or poll status.
   - Request by title/season (no key needed): POST `/api/v1/delivery/request-bundle` with `{title_id, season_number}`
   - Poll until ready (and optionally presign immediately):
     - GET `/api/v1/delivery/bundle-status?title_id=...&season_number=...&presign=true`
   - Manifest presigned URL: GET `/api/v1/titles/{title_id}/bundles/{season}/manifest`

4) Optional token‑gated downloads
   - Admin shares a token; user redeems to get a presigned GET URL.
   - Token is single‑use; redemption is serialized by Redis lock.

Security (public):
- Per‑IP rate limiting; optional `X-API-Key`
- All responses with presigned URLs return `Cache-Control: no-store`

## On‑Demand Bundle Rebuild (How it Works)

When a user requests a bundle URL and it is missing/expired:

1) The API returns 202 and schedules a background job.
2) The job acquires a Redis lock `lock:bundle:rebuild:{title_id}:{season}` and honors a cooldown (`BUNDLE_REBUILD_COOLDOWN_SECONDS`, default 3600s) to avoid stampedes.
3) It gathers episodes in order; picks the best available asset per episode (prefer ORIGINAL > DOWNLOAD > VIDEO), streams each object to a temp file, and zips them.
4) Uploads the ZIP with SSE‑S3; writes a manifest JSON next to it with item list and SHA‑256; updates/creates a `Bundle` row in Postgres.
5) Clients poll `/delivery/bundle-status` and receive a READY status and/or a presigned GET.

This keeps storage cheap (no long‑term ZIP retention) and shifts cost to on‑demand compute and transient CDN traffic.

## Endpoint Index (by area)

Admin – Assets & Validation

- GET `/api/v1/admin/assets/{asset_id}/head` – S3 HEAD; caches size/type in DB
- POST `/api/v1/admin/assets/{asset_id}/checksum` – compute/store SHA‑256 (server computes if small)
- POST `/api/v1/admin/assets/{asset_id}/finalize` – store `{size_bytes, content_type, sha256}` (idempotent)
- GET `/api/v1/admin/titles/{title_id}/validate-media` – policy checks (streams/subtitles/downloads)

Admin – Bundles

- POST `/api/v1/admin/titles/{title_id}/bundles` – presigned PUT for ZIP (optional; on‑demand rebuild can replace this)
- GET `/api/v1/admin/titles/{title_id}/bundles` – list bundles (optionally include expired)
- GET `/api/v1/admin/bundles/{bundle_id}` – inspect a bundle
- PATCH `/api/v1/admin/bundles/{bundle_id}` – update label/expiry
- DELETE `/api/v1/admin/bundles/{bundle_id}` – delete DB row + best‑effort delete object
- POST `/api/v1/admin/titles/{title_id}/rebuild-bundle?season_number=N` – force rebuild now (async)

Admin – Tokens

- POST `/api/v1/admin/delivery/download-tokens/batch` – create multiple one‑time tokens

Public – Discovery & Downloads

- GET `/api/v1/titles` – browse/search
- GET `/api/v1/titles/{title_id}` – title detail
- GET `/api/v1/titles/{title_id}/streams` – stream variants (HLS only, 480/720/1080)
- GET `/api/v1/titles/{title_id}/subtitles` – subtitle tracks
- GET `/api/v1/titles/{title_id}/downloads` – title downloads (movies or per‑season base assets)
- GET `/api/v1/titles/{title_id}/episodes/{episode_id}/downloads` – per‑episode downloads
- GET `/api/v1/titles/{title_id}/bundles` – list active bundles
- GET `/api/v1/titles/{title_id}/bundles/{season}/manifest` – presigned manifest URL (JSON)

Public – Delivery (Presigned GET)

- POST `/api/v1/delivery/download-url` – presign single S3 object as attachment
- POST `/api/v1/delivery/batch-download-urls` – presign multiple objects
- POST `/api/v1/delivery/bundle-url` – presign bundle; optionally trigger rebuild on miss
- POST `/api/v1/delivery/request-bundle` – request `{title_id, season_number}` without knowing the key
- GET  `/api/v1/delivery/bundle-status` – poll status; optional `presign=true`

## Scripts (local toolchain)

- Build season ZIP locally: `python scripts/build_bundle.py --out ./S01.zip ./E01.mkv ./E02.mkv`
- Uploader (get presigned PUT and upload): `python scripts/uploader.py --api http://localhost:8000/api/v1 --admin-key KEY --title-id <uuid> --season 1 ./S01.zip`
- Backfill metadata: `python scripts/backfill_asset_meta.py --api http://localhost:8000/api/v1 --admin-key KEY --ids <comma-separated>`

## Configuration (selected)

- `BUNDLE_REBUILD_COOLDOWN_SECONDS` – minimum seconds between rebuilds per (title, season). Default 3600.
- `BATCH_DOWNLOAD_MAX_ITEMS` – limit of items per batch presign call. Default 50.
- `PUBLIC_API_KEY` – optional API key for public endpoints.
- `ADMIN_API_KEY` – admin key for privileged endpoints (if key‑based admin is used).
- AWS vars: `AWS_BUCKET_NAME`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`.

## Operational Best Practices

- Keep bundles short‑lived; rely on on‑demand rebuild to avoid paying for long‑term ZIP storage.
- Upload originals once; generate compatibility downloads locally only when needed (no MediaConvert).
- Use the validation endpoint during ingest to catch stream/subtitle issues early.
- Use batch endpoints for efficient presigning when clients fetch multiple files.
- Monitor Redis and RDS; keep CloudFront/OAC lockstep with bucket policy.

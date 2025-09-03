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

1) Upload assets (originals/downloads/artwork/subtitles)
   - Most admin endpoints return a presigned PUT for clients to upload directly to S3.
   - Example (bundles):
     - POST `/api/v1/admin/titles/{title_id}/bundles` → returns `{upload_url, storage_key, bundle_id}`
     - Upload the ZIP via the URL; or skip this if you rely on on‑demand rebuilds.

2) Finalize/verify metadata
   - HEAD store size/type: GET `/api/v1/admin/assets/{asset_id}/head`
   - Store checksum: POST `/api/v1/admin/assets/{asset_id}/checksum` (server computes if small; else provide sha256)
   - Finalize in one shot (optional): POST `/api/v1/admin/assets/{asset_id}/finalize` with `{size_bytes, content_type, sha256}`

3) Validate media policy (pre‑publish checks)
   - GET `/api/v1/admin/titles/{title_id}/validate-media`
   - Ensures: exactly one streamable HLS per tier (480/720/1080); no audio‑only marked streamable; download assets have size+sha; subtitle defaults are consistent.

4) Manage bundles (optional)
   - Admin list: GET `/api/v1/admin/titles/{title_id}/bundles`
   - Detail: GET `/api/v1/admin/bundles/{bundle_id}`
   - Patch metadata: PATCH `/api/v1/admin/bundles/{bundle_id}` (label/expiry)
   - Delete: DELETE `/api/v1/admin/bundles/{bundle_id}` (best‑effort S3 delete)
   - Force rebuild now: POST `/api/v1/admin/titles/{title_id}/rebuild-bundle?season_number=N` (202 Accepted, background job)

5) Optional: One‑time download tokens for premium
   - Batch create: POST `/api/v1/admin/delivery/download-tokens/batch`
   - Users redeem via public routes (see “Public Download Flow”).

Security (admin): All admin routes require MFA and are rate‑limited. Mutations use Redis locks and Idempotency‑Key snapshots; audit logs record actions.

## Public Discovery & Download Flow

1) Browse catalog
   - GET `/api/v1/titles` (search, browse) – cacheable
   - GET `/api/v1/titles/{title_id}` – cacheable
   - GET `/api/v1/titles/{title_id}/streams` – public stream variants (ABR info)
   - GET `/api/v1/titles/{title_id}/subtitles` – available subtitle tracks

2) Download per title/episode (all uploaded qualities/codecs)
   - Title‑level list: GET `/api/v1/titles/{title_id}/downloads`
   - Episode‑level list: GET `/api/v1/titles/{title_id}/episodes/{episode_id}/downloads`
   - Presign a single file: POST `/api/v1/delivery/download-url` with `{storage_key, ttl_seconds, attachment_filename?}`
   - Presign many: POST `/api/v1/delivery/batch-download-urls` with `{items:[{storage_key,...}], ttl_seconds}`

3) Season ZIP bundles (short‑lived; rebuild on demand)
   - Public list: GET `/api/v1/titles/{title_id}/bundles` – shows active (unexpired) bundles
   - Manifest only: GET `/api/v1/titles/{title_id}/bundles/{season}/manifest` → presigned GET to JSON manifest
   - Fetch bundle URL (direct): POST `/api/v1/delivery/bundle-url`
     - If bundle missing/expired and `rebuild_if_missing=true`, returns 202 and starts rebuild; client retries or polls status
   - Request bundle (friendly alias): POST `/api/v1/delivery/request-bundle` with `{title_id, season_number}`
   - Poll status: GET `/api/v1/delivery/bundle-status?title_id=...&season_number=...&presign=true`

4) Optional one‑time token gate
   - Admin creates token(s)
   - User redeems: GET `/api/v1/admin/delivery/download/{token}` (existing public redeem route lives in the codebase; use the public delivery routes above when possible)

Security (public): Reasonable per‑IP token bucket rate limits; optional X‑API‑Key enforcement; response bodies that contain presigned URLs are sent with `Cache-Control: no-store`.

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


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

- Streaming: Exactly 3 variants (progressive files): 480p, 720p, 1080p
- Downloads: Restricted to season bundles and extras ZIPs only (no per‑episode direct downloads).
- Bundles: Season ZIPs are uploaded by you locally; server never rebuilds bundles.

## Typical Admin Workflow (Ingestion → Validation → Publish)

Step‑by‑step (simple and practical)

1) Create the catalog item (Title/Season/Episode)
   - Use the existing admin Titles/Series routers to create a Title (and Season/Episodes when it’s a series).
   - You will reference `title_id` (and optionally `episode_id`) in all asset calls.

2) Upload media
   - Artwork: POST `/api/v1/admin/titles/{title_id}/artwork` → presigned PUT → upload (poster/backdrop etc.)
   - Video originals/downloads: POST `/api/v1/admin/titles/{title_id}/video` → presigned PUT → upload
   - Subtitles: POST `/api/v1/admin/titles/{title_id}/subtitles` → presigned PUT → upload, track row created
   - Streams (if managed manually): POST `/api/v1/admin/titles/{title_id}/streams` – configure exactly 3 streamable variants (480p/720p/1080p), progressive MP4s
   - Tip: Each “create” returns `{upload_url, storage_key, id}`; upload directly to S3 with that URL (multipart supported elsewhere when needed).

3) Finalize/verify asset metadata (fast)
   - HEAD S3 and cache size/type: GET `/api/v1/admin/assets/{asset_id}/head`
   - Store checksum: POST `/api/v1/admin/assets/{asset_id}/checksum` (server computes when ≤10MB or provide sha256)
   - One‑shot finalize (optional): POST `/api/v1/admin/assets/{asset_id}/finalize` with `{size_bytes, content_type, sha256}`

4) Validate streaming/download policy (pre‑publish)
   - GET `/api/v1/admin/titles/{title_id}/validate-media`
   - Confirms: exactly one streamable per tier (480p/720p/1080p); not audio‑only; downloads have `size_bytes`+`sha256`; subtitle defaults don’t conflict.
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
   - GET `/api/v1/titles/{title_id}/streams` – available stream variants (480p/720p/1080p)
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
   
   - Poll until ready (and optionally presign immediately):
     
   - Manifest presigned URL: GET `/api/v1/titles/{title_id}/bundles/{season}/manifest`

4) Optional token‑gated downloads
   - Admin shares a token; user redeems to get a presigned GET URL.
   - Token is single‑use; redemption is serialized by Redis lock.

Security (public):
- Per‑IP rate limiting; optional `X-API-Key`
- All responses with presigned URLs return `Cache-Control: no-store`

## On‑Demand Bundle Rebuild (Removed)

Removed in minimal‑cost mode. Server never rebuilds bundles; this section is
kept for historical reference only.

When a user requests a bundle URL and it was missing/expired (legacy behavior):

1) The API returns 202 and schedules a background job.
2) The job acquires a Redis lock `lock:bundle:rebuild:{title_id}:{season}` and honors a cooldown (`BUNDLE_REBUILD_COOLDOWN_SECONDS`, default 3600s) to avoid stampedes.
3) It gathers episodes in order; picks the best available asset per episode (prefer ORIGINAL > DOWNLOAD > VIDEO), streams each object to a temp file, and zips them.
4) Uploads the ZIP with SSE‑S3; writes a manifest JSON next to it with item list and SHA‑256; updates/creates a `Bundle` row in Postgres.
5) (Removed) Clients do not poll server rebuild status; build ZIPs locally.

This keeps storage cheap (no long‑term ZIP retention) and shifts cost to on‑demand compute and transient CDN traffic.

## Movie Pack (Multi‑Audio + Subtitles + Phases) — Recommended Design

Goal: For single‑movie downloads, offer a “Full‑quality Master” that embeds multiple audio tracks and (optionally) subtitles and chapters (intro/credits). Keep a lightweight compatibility option and an Extras ZIP for posters or other assets.

Best‑practice defaults
- Master file: MKV (no re‑encode). Contains:
  - Video stream copied from the best original
  - Multiple audio tracks (EN/HI/MR/FR etc.) with language/default/forced flags
  - Optional embedded text subtitles (SRT/ASS) when supported; otherwise keep external VTT/SRT
  - Chapters (phases) for “Intro”, “Credits”, etc. using Matroska chapters
- Compatibility MP4 (optional): H.264 + one primary audio, external VTT. Generated on demand if needed.
- Extras ZIP (optional): Poster(s), logos, stills, external subtitles, and a small JSON manifest.

Suggested API (optional to implement)
- POST `/api/v1/delivery/movie-pack`
  - Body (example):
    ```json
    {
      "title_id": "...",
      "audio_languages": ["en","hi","mr","fr"],
      "subtitle_languages": ["en"],
      "embed_subtitles": true,
      "compat": false,
      "ttl_seconds": 600
    }
    ```
  - Behavior: If a suitable master already exists, presign it. Otherwise, queue an async re‑mux (FFmpeg, `-c copy` video) and return 202 with a job/status. Upload output under `downloads/{title_id}/master/movie_master.mkv` and expire via lifecycle.
- GET `/api/v1/delivery/movie-pack-status?job_id=...` (or key off `title_id`)
  - Returns `{status: QUEUED|IN_PROGRESS|READY|ERROR, storage_key?, url?}`.

FFmpeg (re‑mux example)
- Multi‑audio MKV:
  ```bash
  ffmpeg -i input_best.mkv \
    -map 0:v:0 -map 0:a:m:language:eng -map 0:a:m:language:hin \
    -map 0:a:m:language:mar -map 0:a:m:language:fra \
    -c copy -disposition:a:0 default out_master_multi.mkv
  ```
- Compatibility MP4 (primary EN audio):
  ```bash
  ffmpeg -i input_best.mkv -map 0:v:0 -map 0:a:m:language:eng \
    -c:v copy -c:a aac -movflags +faststart out_compat.mp4
  ```
- Chapters (phases):
  - Provide a `chapters.txt` in ffmetadata or mkvmerge XML, or supply `-chapters` from a generated file to mark “Intro”/“Credits”. Keep the same data in a sidecar JSON for players.

Extras ZIP (optional)
- POST `/api/v1/delivery/movie-extras`
  - Body: `{ "title_id": "...", "subtitle_languages": ["en","es"], "include_poster": true, "ttl_seconds": 600 }`
  - Output structure:
    ```
    poster.jpg
    subs/en.vtt
    subs/es.srt
    extras_manifest.json
    ```
- Status endpoint mirrors movie‑pack semantics.

Cost controls
- Re‑mux only (no transcode) keeps compute low; output files expire automatically (7–30 days lifecycle).
- Redis cooldown prevents repeated builds within a window.

## Season ZIP + Extras ZIP (Series) — Recommended Design

Default (fast & cheap)
- Season ZIP: video-only (one file per episode). Build locally; upload via admin presigned PUT.
- Extras via separate ZIP (optional): subtitles, poster, and stills.

Optional flags (when requested)
- Extend bundle request to accept:
  - `include_subtitles: true` and `subtitle_languages: ["en","hi"]`
  - (Keep `include_artwork: false` by default; artwork inflates size)
- Inside ZIP (example):
  ```
  S01/E01/video.mkv
  S01/E01/subs/en.vtt
  S01/E02/video.mkv
  ...
  S01/poster.jpg (if included)
  bundle_manifest.json
  ```

Season Extras ZIP (separate)
- POST `/api/v1/delivery/season-extras` with `{title_id, season_number, subtitle_languages?, include_poster?}` to build an extras‑only archive.
- Use the same status/presign pattern as bundles.

Why this split works
- Great UX: Users get fast video ZIP by default; power users fetch extras in one go (extras ZIP) without bloating the main bundle.
- Low cost: Only build larger packs on demand; lifecycle and cooldown bound the spend.

---

# Detailed, Step‑By‑Step Workflows (Series & Movies)

This section ties everything together end‑to‑end so product, engineering, and ops can follow the same playbook.

## A. Series Downloads

Two options, both cheap and user‑friendly:
1) Per‑episode downloads (fine‑grained)
2) Season ZIP (video‑only by default) with optional Extras ZIP

### A.1 Per‑Episode Downloads (simple)

Prereqs
- Each episode has one or more ORIGINAL/DOWNLOAD/VIDEO assets (stored under `originals/` or `downloads/`).

Flow
1) Client lists available options
   - GET `/api/v1/titles/{title_id}/downloads`
     - Returns title‑scope assets (movie/season banners) and per‑episode lists
   - Or for one episode:
     - GET `/api/v1/titles/{title_id}/episodes/{episode_id}/downloads`
2) Client presigns chosen files
   - Single: POST `/api/v1/delivery/download-url` with `{storage_key, ttl_seconds, attachment_filename?}`
   - Batch: POST `/api/v1/delivery/batch-download-urls` with `{items:[{storage_key, attachment_filename?}], ttl_seconds}`

Notes
- Fastest/cheapest path for users who want selected episodes or specific encodes/codecs.
- Use batch for “download manager” experiences.

### A.2 Season ZIP (Video‑Only by Default)

Goal
- Provide a convenience ZIP that packs the per‑episode video files for a season. ZIPs are short‑lived and rebuilt on demand to minimize storage cost.

Default behavior
- Video‑only bundle: episodes’ best video assets in a single ZIP.
- Extras (subtitles, poster) are fetched separately (batch presign) or via an optional Extras ZIP.

Flow (end‑user)
1) Client asks for bundle (friendly):
   
   - Server HEADs the `bundles/{title_id}/S{season:02}.zip`
     - If exists → returns `{status: READY, url}` (presigned GET)
     - If missing → schedules rebuild and returns HTTP 202 `{status: REBUILDING, retry_after_seconds}`
2) Client polls status or retries request after `retry_after_seconds`:
   
   - Returns `{status: READY, url}` when ZIP is uploaded

Flow (server rebuild job)
1) Acquire Redis lock (`lock:bundle:rebuild:{title}:{season}`) and honor cooldown (default 3600s)
2) Select episodes ordered by episode_number; choose one best asset per episode (prefer ORIGINAL > DOWNLOAD > VIDEO)
3) Stream each S3 object to a temporary file; create ZIP incrementally (low memory)
4) Upload ZIP with SSE‑S3 to `bundles/{title_id}/S{season:02}.zip`
5) Write `S{season:02}_manifest.json` next to ZIP listing items (arcname + source_key)
6) Update/Create `Bundle` row with `{storage_key, size_bytes, sha256, expires_at}`

ZIP contents (example)
```
S01/E01/video.mkv
S01/E02/video.mp4
...
```

Manifest contents (example)
```json
{
  "title_id": "...",
  "season_number": 1,
  "storage_key": "bundles/<title>/S01.zip",
  "size_bytes": 123456789,
  "sha256": "...",
  "items": [
    {"arcname": "S01/E01/video.mkv", "source_key": "downloads/<title>/.../E01.mkv"},
    {"arcname": "S01/E02/video.mp4", "source_key": "downloads/<title>/.../E02.mp4"}
  ],
  "generated_at": "2025-01-01T12:34:56Z"
}
```

Extras (two convenient ways)
1) Batch presign (quick, no ZIP): POST `/api/v1/delivery/batch-download-urls` with subtitle/storage keys
2) Extras ZIP (optional): POST `/api/v1/delivery/season-extras` with `{title_id, season_number, subtitle_languages?, include_poster?}` → 202 + status → presigned URL when ready

Operational controls
- Lifecycle expiry deletes old ZIPs automatically (7–30 days)
- Cooldown (Redis) prevents rebuild stampedes (e.g., 3600s)
- No KMS by default (SSE‑S3)

## B. Movie Downloads

Best default UX
- Full‑quality Master (MKV): multi‑audio embedded, optional embedded subtitles, Matroska chapters for “Intro”/“Credits”
- Compatibility MP4 (optional): H.264 + single audio track with external VTT
- Extras via batch presign or optional Extras ZIP

Flow (end‑user)
1) Choose download type from title page
   - “Full‑quality Master (multi‑audio)” → one MKV file
   - “Compatibility MP4 (H.264)” → optional, for legacy devices
   - “Subtitles & Extras” → batch presign or Extras ZIP
2) Presign link(s)
   - POST `/api/v1/delivery/download-url` (single) or `/api/v1/delivery/batch-download-urls` (many)

Optional: On‑Demand Movie Pack (re‑mux only)
1) POST `/api/v1/delivery/movie-pack` with `{title_id, audio_languages, subtitle_languages?, embed_subtitles?, ttl_seconds}`
2) If a matching master exists → presign and return
3) Otherwise, queue a re‑mux job (no re‑encode):
   - Keep video stream as is (`-c:v copy`)
   - Map selected audio tracks and set default/forced flags
   - Embed compatible text tracks into MKV, or keep external subs for MP4
   - Add chapters for intro/credits from sidecar metadata
4) Return HTTP 202; client polls `/api/v1/delivery/movie-pack-status` and receives a presigned URL on READY
5) Outputs expire automatically (lifecycle)

Extras ZIP (movie)
- POST `/api/v1/delivery/movie-extras` with `{title_id, subtitle_languages?, include_poster?, ttl_seconds}` → 202 + status → presign

Why this is “best of best”
- Single master MKV: one file that “just works” with all audios and optional embedded subs/chapters
- Flexibility: Compatibility MP4 only when needed; extras on demand
- Low cost: Remux only; lifecycle expiry; no large, always‑on bundles

---

## C. Preferred Minimal‑Cost Mode (Local‑Built Downloads, 3 Progressive Variants)

If you want to avoid any server‑side rebuild jobs entirely, use this mode. You build ZIPs and master files locally, upload them via presigned PUT, and expose only three progressive MP4 variants for playback.

Configuration
- Set `BUNDLE_ENABLE_REBUILD = false` (default in code) to disable server rebuild paths.
- Keep `BUNDLE_REBUILD_COOLDOWN_SECONDS` and related status endpoints around for future use; they are ignored when rebuilds are disabled.

### C.1 Series (Local Season ZIP only)

Goal
- Users download a single Season ZIP that you build locally; no per‑episode downloads and no server rebuilds.

Admin Steps
1) Produce three progressive variants for streaming (480p/720p/1080p) for each episode
   - Upload one file per variant (e.g., `streams/{title_id}/480p.mp4`, etc.)
   - Configure the repository or metadata to advertise exactly these three variants
2) Build the Season ZIP locally (video‑only by default)
   - Option A (no changes): package your per‑episode original/download video files
   - Option B (Matroska with embedded audio/subs/chapters):
     - For each episode, re‑mux with FFmpeg (no re‑encode) into MKV with multiple audio tracks and optional embedded subtitles + chapters
     - Place as `S{season}/E{episode}/video.mkv` inside the ZIP
   - Optional: generate a `bundle_manifest.json` listing items and their hashes inside the ZIP
3) Upload the Season ZIP via admin bundles API (includes extras if you choose)
   - POST `/api/v1/admin/titles/{title_id}/bundles` → `{upload_url, storage_key, bundle_id}`
   - Upload your ZIP to `upload_url`
   - (Optional) PATCH the bundle label/expiry if needed
4) Do not enable server rebuild
   - Clients use `/delivery/bundle-url` directly (presigns the key you uploaded)

User Steps
1) Discover season on the title page
2) Click “Download Season ZIP”
   - Client calls: POST `/api/v1/delivery/bundle-url` with `{storage_key: "bundles/{title}/S{season}.zip"}` → returns presigned GET URL
3) If users want posters/other extras, provide a separate Extras ZIP (built locally) or let them fetch extras via a batch presign call

Extras ZIP (optional, local)
- If you prefer to keep the main Season ZIP focused, build `S{season}_extras.zip` containing `poster.jpg`, stills, and selected subtitles (e.g., `S{season}/E{episode}/subs/en.vtt`)
- Obtain a presigned PUT via: POST `/api/v1/admin/titles/{title_id}/season-extras`
- Client obtains presigned GET via: POST `/api/v1/delivery/download-url` for that storage key

### C.2 Movies (Local Master + Optional Extras)

Admin Steps
1) Produce three progressive tiers for streaming (480p/720p/1080p) and register them (same as series)
2) Build the Full‑quality Master locally
   - Input: your best original
   - FFmpeg re‑mux (no re‑encode) to MKV with multiple audio tracks; optional embedded text subtitles (SRT/ASS) and chapters (intro/credits)
   - Upload to `downloads/{title_id}/master/movie_master.mkv` as a MediaAsset (kind=DOWNLOAD or ORIGINAL)
   - (Optional) Also upload a compatibility MP4 (H.264 + one audio; external VTTs)
3) (Optional) Build a Movie Extras ZIP
   - Include poster and external subtitle files (e.g., `subs/en.vtt`)
   - Obtain a presigned PUT via: POST `/api/v1/admin/titles/{title_id}/movie-extras`
   - Upload to `downloads/{title_id}/extras/movie_extras.zip`

User Steps
1) Choose “Full‑quality Master (multi‑audio)” → client presigns `/delivery/download-url` for the master MKV
2) (Optional) “Compatibility MP4 (H.264)” → presign MP4
3) (Optional) “Subtitles & Extras” → presign extras ZIP via `/delivery/download-url` or fetch items via `/delivery/batch-download-urls`

Why this mode is cost‑optimal
- No server compute for rebuilds; all heavy work happens once on your workstation/CI
- Bundles (season ZIPs) and masters are uploaded and then simply presigned for download
- Streaming uses only three progressive tiers to keep storage + CDN behavior predictable

## Endpoint Index (by area)

Admin – Assets & Validation

- GET `/api/v1/admin/assets/{asset_id}/head` – S3 HEAD; caches size/type in DB
- POST `/api/v1/admin/assets/{asset_id}/checksum` – compute/store SHA‑256 (server computes if small)
- POST `/api/v1/admin/assets/{asset_id}/finalize` – store `{size_bytes, content_type, sha256}` (idempotent)
- GET `/api/v1/admin/titles/{title_id}/validate-media` – policy checks (streams/subtitles/downloads)

Admin – Bundles

- POST `/api/v1/admin/titles/{title_id}/bundles` — presigned PUT for ZIP
- GET `/api/v1/admin/titles/{title_id}/bundles` – list bundles (optionally include expired)
- GET `/api/v1/admin/bundles/{bundle_id}` – inspect a bundle
- PATCH `/api/v1/admin/bundles/{bundle_id}` – update label/expiry
- DELETE `/api/v1/admin/bundles/{bundle_id}` – delete DB row + best‑effort delete object
 

Admin – Tokens

- POST `/api/v1/admin/delivery/download-tokens/batch` – create multiple one‑time tokens

Public – Discovery & Downloads

- GET `/api/v1/titles` – browse/search
- GET `/api/v1/titles/{title_id}` – title detail
- GET `/api/v1/titles/{title_id}/streams` – stream variants (480p/720p/1080p)
- GET `/api/v1/titles/{title_id}/subtitles` – subtitle tracks
- GET `/api/v1/titles/{title_id}/downloads` – title downloads (movies or per‑season base assets)
- GET `/api/v1/titles/{title_id}/episodes/{episode_id}/downloads` – per‑episode downloads
- GET `/api/v1/titles/{title_id}/bundles` – list active bundles
- GET `/api/v1/titles/{title_id}/bundles/{season}/manifest` – presigned manifest URL (JSON)

Public – Delivery (Presigned GET)

- POST `/api/v1/delivery/download-url` – presign season bundle or extras ZIP (restricted prefixes)
- POST `/api/v1/delivery/batch-download-urls` – presign multiple (same restrictions)
- POST `/api/v1/delivery/bundle-url` – presign bundle (no rebuild on miss)

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

- Build season bundles locally; upload via admin presigned PUT.
- Upload exactly 3 streamable files per title (480p/720p/1080p); no server transcoding.
- Use the validation endpoint during ingest to catch stream/subtitle issues early.
- Use batch endpoints for efficient presigning when clients fetch multiple files.
- Monitor Redis and RDS; keep CloudFront/OAC lockstep with bucket policy.

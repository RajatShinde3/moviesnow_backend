# MoviesNow Delivery & Media Flows (Deep Dive)

Scope
- This document explains end-to-end flows for packaging, streaming, and file delivery without focusing on specific route names. It answers:
  - Do users get per-episode downloads or season ZIPs?
  - How are codecs/containers/tiers handled for streaming?
  - What’s the download story for movies vs series?
  - How do uploads and downloads work (single, multipart, bundles) in practice?


## 1) Packaging & What Users Receive

High-level policy
- Streaming is the primary delivery channel for playback.
- Public downloads enumerate curated archives (ZIPs) and curated video files placed under the `downloads/` namespace.
- Admins provision downloadable bundles, extras, and optional per-title/episode video renditions; public delivery is restricted to allowed paths and extensions.

Series vs Movie
- Series
  - Users stream episodes (via prepared stream variants).
  - Downloads: users may receive curated per‑episode video files (e.g., MP4) when provided under `downloads/{title_id}/{episode_id}/...`, and/or season bundles (ZIPs).
- Movies
  - Users stream the movie (via prepared stream variants).
  - Downloads: users may receive curated per‑title video files (e.g., MP4) under `downloads/{title_id}/...`, plus “movie extras” ZIPs.

Practical result for users
- Stream: choose an allowed quality (see Tiers below); player uses standard ABR or selected rendition.
- Download (public):
  - Season ZIPs (e.g., S01.zip) for series when available.
  - Extras ZIPs for either movies or series (e.g., behind-the-scenes, posters, featurettes).
  - No public per‑episode or raw movie file downloads by default.

Policy enforcement location
- Delivery layer presigns GET URLs only for keys in allowed namespaces/extensions:
  - `bundles/{title_id}/... .zip`
  - `downloads/{title_id}/.../extras/... .zip`
  - `downloads/{title_id}/...` and `downloads/{title_id}/{episode_id}/...` for curated video files with allowed extensions (e.g., `.mp4`, `.m4v`, `.mov`, `.webm`).
- Other keys (e.g., `originals/...` or raw HLS objects) are not presigned for public download.


## 2) Streaming Model & Media Constraints

Authoritative metadata lives under two models:
- MediaAsset: the source artifact (poster, trailer, episode master, etc.) with technical and catalog metadata.
- StreamVariant: a specific playable or downloadable rendition derived from a MediaAsset.

Stream tiers
- Exactly three streamable tiers are allowed: 1080p, 720p, and 480p.
- At most one streamable variant per (asset, tier) to avoid duplicates.

Required/typical properties
- Protocol: HLS for streamable content (policy requires protocol == HLS when is_streamable=true).
- Container: TS or FMP4 (manifest-level; stores in the variant record).
- Video codec: H.264 (H265/VP9/AV1 are supported in metadata; policy does not forbid them but defaults generally expect H.264 for widest compatibility).
- Audio codec: AAC (AC3/EAC3/OPUS can be represented as well).
- Resolution: height constrained to {1080, 720, 480} for streamable rows; audio-only variants are not marked streamable.
- Optional attributes: frame rate, HDR format (SDR/HDR10/HLG/DV), DRM type (NONE/WIDEVINE/PLAYREADY/FAIRPLAY), audio language, default flags.

Why these constraints?
- Keep an intentionally small public ABR ladder for predictable costs and client compatibility.
- Enforce one “winner” per tier so playback selection is deterministic.

Where this shows up in UX
- The catalog points players to the set of prepared stream variants for a title (and implicitly for an episode in series context). The player picks a rendition (or ABR) among the allowed tiers.


## 3) Download Model (Public)

Guiding principles
- Avoid raw per-episode file exposure to protect costs and prevent hotlinking.
- Prefer low-churn bundles that can be cached at the CDN and expire naturally.

What’s downloadable
- Season archives:
  - Path: `bundles/{title_id}/S{season:02}.zip` (e.g., `bundles/7c…/S01.zip`).
  - Optionally accompanied by a JSON manifest (validated and presigned when requested).
- Extras archives:
  - Path: `downloads/{title_id}/extras/... .zip` (movie or series extras).
- Curated video files:
  - Paths under `downloads/{title_id}/...` for movie-level files and `downloads/{title_id}/{episode_id}/...` for episode-level files with allowed extensions.

What’s not downloadable
- Anything outside the `downloads/` or `bundles/` namespaces (e.g., `originals/...`) is not presigned for public download.
- HLS/DASH objects are not presigned one-by-one for public download.

How users get the ZIP
- The application verifies the archive exists in storage and returns a short‑lived presigned GET URL.
- Responses are always “no‑store” so signed URLs aren’t cached.


## 4) Upload Model (Admin)

Three ways to upload binary objects to storage:

Single‑part presigned PUT
1) Admin gets a presigned PUT URL for a deterministic key.
2) Client uploads the content directly to storage (server never handles payload bytes).
3) Keys are computed from safe segments (e.g., title ID, season/episode context, filename hint) and idempotency token.

Multipart upload
1) Admin initializes a multipart upload, receiving an uploadId and a deterministic key.
2) Client requests presigned PUT URLs for each part and uploads to storage.
3) Client completes the multipart upload by sending the list of `{PartNumber, ETag}`.
4) Abort is available if something goes wrong.

Direct proxy (small files only)
- The server accepts the bytes and writes to storage on behalf of the client.
- Strict size limit (≈10 MiB) and “no‑store” cache headers; use sparingly.

Key management & safety
- Storage keys are normalized (no leading `/`, no `..`, safe character set).
- Optional SSE‑S3 or SSE‑KMS can be applied when generating presigned URLs or direct puts.
- Upload flows are idempotent (via “Idempotency‑Key”) to handle retries without duplicates.


## 5) Bundle Lifecycle (Admin‑Provisioned)

Purpose
- Provide user‑downloadable, curated ZIPs (season bundles, extras) that are cheap to serve and easy to expire.

Creation flow
1) Admin declares intent to create a bundle for a title (season number optional for movies/extras use cases).
2) System generates a DB record and presigned PUT destination for the ZIP (e.g., `bundles/{title_id}/S01.zip`).
3) Admin uploads the archive using the presigned URL.
4) Optional metadata: label, explicit expiry date, size and checksum fields.

Duplicate/overwrite guards
- DB: Season bundle duplicates are blocked; creation is guarded by a distributed lock.
- Storage: If a target key already exists, server refuses to create a new presign for overwrite (409 conflict semantics).

Expiry
- Natural expiration via storage lifecycle policies (e.g., delete ZIPs after N days) is recommended.
- Additionally, a per‑bundle `expires_at` can be set for UI/logic.


## 6) User Experience Walkthroughs

Streaming a series episode
1) Catalog shows a title with available episodes.
2) The client obtains the playable variants for the title context and chooses (or uses ABR) among 480p/720p/1080p.
3) Playback starts; optional telemetry session is created and heartbeats/events are appended (pause, resume, seek, complete).
4) If DRM is enabled for variants, license acquisition occurs at the player level (outside this service’s scope).

Downloading a season archive
1) User chooses a title and season with an available bundle (ZIP).
2) The application verifies the bundle exists in storage and returns a short‑lived presigned GET URL.
3) User downloads the ZIP; the response is not cached by intermediaries (no‑store).

Downloading movie extras
1) User selects “extras” for a movie.
2) The application verifies an extras ZIP under `downloads/{title_id}/extras/... .zip` exists.
3) A short‑lived presigned GET URL is returned; user downloads the curated extras.

What about downloading the movie or a single episode file?
- Supported: curate and upload video files into the `downloads/` namespace (per title or per episode). They will be listed and presignable for users with short‑lived GET URLs.


## 7) Media Authoring Guidance

Recommended authoring for streamable variants
- Prepare HLS ladders with three video representations: 480p, 720p, 1080p.
- Use H.264/AAC for maximum compatibility unless targeting modern platforms specifically.
- Set one default audio per language; mark “default” on exactly one variant per language/hdr when desired.
- Keep audio‑only assets unmarked as “streamable” to comply with constraints.

Recommended authoring for downloads
- Do not expose per‑episode MP4s; assemble curated ZIPs (season or extras) instead.
- Include a manifest JSON for larger bundles if useful for clients; it can be individually validated and signed.


## 8) Security, Tokens, and Abuse Controls

Abuse controls in delivery
- Only presign allowed prefixes: `bundles/`, `downloads/**/extras/**.zip`, and curated video extensions under `downloads/`.
- Enforce a TTL clamp for signed URLs (min/max seconds) to prevent excessively long links.
- Optional one‑time tokens can further gate access to bundles; tokens are redeemed atomically and invalidated.

General security
- Signed URL responses are marked “no‑store”.
- Admin‑side operations require admin role + MFA and are rate‑limited with idempotent snapshots.
- Neutral error handling prevents provider detail leakage (e.g., storage providers).


## 9) Storage Layout & Naming

Conventional prefixes (private bucket)
- `originals/{title_id}/[episode_id/]filename.ext`  (masters)
- `hls/{title_id}/[episode_id/]...`                 (streaming ladders)
- `downloads/{title_id}/[episode_id/]{variant}/...` (download-only artifacts)
- `bundles/{title_id}/S{season:02}.zip`             (season archives)
- `artwork/title/{title_id}/...`                    (images)
- `subs/title/{title_id}/...`                       (subtitle files)

Key normalization rules
- Strip leading slashes; collapse repeated slashes; reject `..`.
- Enforce a safe character set; sanitize user‑supplied name segments.


## 10) Customizing Policy (if needed)

Allowing raw per‑episode downloads (not recommended)
- Option 1: Package the episode file into an “extras” ZIP under `downloads/{title_id}/extras/`.
- Option 2: Modify delivery allowlist to include a new trusted prefix (and enforce a strict content‑type/extension list).
  - If you do this, keep “no‑store” responses, TTL clamps, and consider one‑time token redemption.

Adjusting streaming tiers
- If business needs require different tiers, update the StreamVariant constraints and corresponding pipelines.
- Keep the “one streamable per tier per asset” invariant for deterministic selection.


## 11) Quick Decision Matrix

- “Can a user download a single episode file?” → Not by default. Provide a curated ZIP or adjust policy.
- “Can a user download an entire season?” → Yes, via a season ZIP when provisioned.
- “How do movies download?” → Movies stream normally; downloads are for curated “extras” ZIPs.
- “Which streaming codecs?” → Prefer H.264/AAC, HLS protocol; policy supports others but enforces tier and protocol constraints for streamable rows.
- “How do we upload?” → Presigned PUT (single or multipart) for clients; server‑side proxy only for small files.




## 12) Admin Upload Checklist (Required vs Optional)

Purpose
- Clarifies which artifacts are required vs optional to support streaming and downloads for Movies and Series.

Summary
- Nothing is “globally compulsory”: you choose what to offer to users. The backend supports streaming only, downloads only, or both.
- To enable each user-facing capability, the following artifacts must exist.

Movies
- Streaming (required for streaming UX):
  - Prepare HLS streamable variants derived from a MediaAsset.
  - Ensure you have StreamVariant rows for tiers 1080p/720p/480p with `is_streamable=true` and protocol HLS.
  - Not required if you don’t intend to let users stream (download-only releases are allowed).
- Downloads (optional):
  - Curated movie files under `downloads/{title_id}/...` (e.g., MP4).
  - For each downloadable file, create a StreamVariant with `protocol=MP4`, container/codec fields set, and `url_path` pointing to the storage key.
  - Movie “extras” ZIPs (optional) under `downloads/{title_id}/extras/... .zip`.

Series
- Streaming (required for streaming UX):
  - Prepare HLS streamable variants for episodes (per-episode variants derived from episode MediaAssets) with `is_streamable=true` and protocol HLS; keep tiers 1080p/720p/480p.
  - Not required if you only want download delivery.
- Downloads (optional): choose any combination:
  - Per‑episode curated files under `downloads/{title_id}/{episode_id}/...` (e.g., MP4). For each file, create a StreamVariant with `protocol=MP4` and `url_path` set to the storage key.
  - Season bundle ZIP under `bundles/{title_id}/S{season:02}.zip` (recommended for simple download UX and CDN efficiency).
  - Series “extras” ZIPs under `downloads/{title_id}/extras/... .zip`.

What you must do for each capability
- Streaming playback
  - Upload HLS ladders (or generate them) for each Title/Episode you want to stream.
  - Insert StreamVariant rows for each ladder rendition with `is_streamable=true`, `protocol=HLS`, and the technical fields (container, codecs, width/height, bandwidth).
  - Keep at most one streamable variant per (asset, tier).
- Curated video downloads (movies or episodes)
  - Upload MP4/M4V/MOV/WEBM files under the `downloads/` namespace using admin uploads (single or multipart presigns).
  - Insert StreamVariant rows for each downloadable file with `protocol=MP4`, `container=MP4` (or appropriate), codec fields, resolution, and `url_path` set to the storage key (relative).
  - These appear in public download listings and can be presigned via Delivery.
- Season ZIP downloads (series)
  - Create a Bundle row (admin bundles) and upload the zip to `bundles/{title_id}/S{season:02}.zip`.
  - Optionally provide a manifest JSON.
- Extras ZIPs (movies or series)
  - Upload curated ZIPs under `downloads/{title_id}/extras/... .zip`.

Recommended key shapes
- Movies downloadable files: `downloads/{title_id}/video/{quality}/{codec}/{nice_name}.mp4`
- Episodes downloadable files: `downloads/{title_id}/{episode_id}/video/{quality}/{codec}/{nice_name}.mp4`
- Season bundles: `bundles/{title_id}/S{season:02}.zip`
- Extras ZIPs: `downloads/{title_id}/extras/{package_name}.zip`

Notes
- The public Delivery layer presigns only: `bundles/**.zip`, `downloads/**/extras/**.zip`, and curated video files under `downloads/**` with allowed extensions.
- Raw masters (e.g., `originals/**`) and HLS internals aren’t presigned for public download.

## 13) Added Endpoints (Summary)
- Public
  - GET /api/v1/titles/{title_id}/downloads
  - GET /api/v1/titles/{title_id}/episodes/{episode_id}/downloads
  - GET /api/v1/titles/{title_id}/download-manifest
  - GET /api/v1/titles/{title_id}/episodes/{episode_id}/download-manifest
- Delivery
  - POST /api/v1/delivery/download-url (supports optional one-time token)
  - POST /api/v1/delivery/batch-download-urls
  - POST /api/v1/delivery/bundle-url (token supported)
  - POST /api/v1/delivery/mint-token (admin)
- Admin
  - POST /api/v1/admin/titles/{title_id}/downloads/register
  - POST /api/v1/admin/titles/{title_id}/episodes/{episode_id}/downloads/register
  - PATCH /api/v1/admin/streams/{variant_id}/toggle-downloadable

— End of document —

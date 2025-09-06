# MoviesNow Upload & Download Flows (Admin and User)

This guide documents what formats/qualities are supported, and the exact, production-ready flows for uploading (admin) and downloading (public). It also clarifies how AWS (S3/CDN) is used.

## Supported Formats & Quality

- Admin Video (main content)
  - Content-Types allowed: `video/mp4`, `video/mpeg`.
  - Endpoint: `POST /api/v1/admin/titles/{title_id}/video` (presigned PUT).
  - Trailers accept a broader set: `video/mp4`, `video/mpeg`, `video/webm`, `video/quicktime` via `POST /api/v1/admin/titles/{title_id}/trailers`.
- Streaming Variants (what the player streams)
  - Protocol: HLS for streamable rows (`is_streamable=true` requires `protocol=HLS`).
  - Stream tiers: exactly 1080p, 720p, 480p (enforced; see `StreamVariant.stream_tier`).
  - Codecs: H.264, H.265/HEVC, VP9, AV1, AAC/AC3/EAC3/OPUS (as enumerated).
  - Only one streamable row per (asset, tier). Height, bandwidth checks enforced.
- Downloads (what users can download)
  - Allowed file types in public delivery: `.mp4`, `.m4v`, `.mov`, `.webm`, plus season ZIPs under `bundles/` and extras ZIPs under `downloads/**/extras/**.zip`.
  - Downloadable variants must use `protocol IN ('MP4','HLS')`.

Notes
- If you need to accept additional upload MIME types (e.g., MKV), extend the admin uploads router mapping. Currently MKV is not enabled for presign (falls back to `.bin`).
- Artwork/images are handled under Admin Artwork APIs (not covered here).

## Admin Video Upload: End-to-End

Goal: Upload a main video file for a title and prepare streamable/downloadable variants.

1) Create upload slot (presigned PUT)
- Request: `POST /api/v1/admin/titles/{title_id}/video`
  - Body: `{ "content_type": "video/mp4", "language": "en"?, "is_primary": true?, "label": "Cut 1"? }`
  - Headers: `Authorization` (admin), `Idempotency-Key` (recommended)
.- Response: `{ "upload_url": str, "storage_key": str, "asset_id": str }`
- Security: Admin-only + MFA; `Cache-Control: no-store`; rate limited; audit logged.

2) Upload to S3
- Client uploads the raw bytes to `upload_url` with the same `Content-Type`.
- Server never proxies the bytes; storage key is deterministic and recorded as `MediaAsset.storage_key`.

3) (Optional) Mark as primary / edit metadata
- `PATCH /api/v1/admin/video/{asset_id}`
  - Body: `{ "is_primary": true?, "language": "en-US"?, "label": "Director's Cut"?, "sort_order": 10?, "cdn_url": "https://..."? }`

4) Create stream/download variants
- Persist `StreamVariant` rows for the asset with:
  - `protocol=HLS`, `container=FMP4|TS`, `video_codec`, `audio_codec`.
  - `width/height`, `bandwidth_bps`, `frame_rate`, `audio_language`.
  - For streamable: set `is_streamable=true` and `stream_tier ∈ {P1080,P720,P480}`.
  - For download-only: `is_downloadable=true` (MP4 or HLS) and leave `is_streamable=false`.

5) (Optional) Trailer upload
- `POST /api/v1/admin/titles/{title_id}/trailers` → returns `{ asset_id, upload_url, storage_key }`.
- Accepts `video/webm` and `video/quicktime` in addition to MP4/MPEG.

6) (Optional) Bundles (ZIP)
- `POST /api/v1/admin/titles/{title_id}/bundles` → returns `{ bundle_id, storage_key, upload_url, expires_at }`.
- Season key format: `bundles/{title_id}/S{season:02}.zip`; protects from duplicate/overwrite.

Operational guarantees
- Redis locks around create/delete; idempotency snapshots (10m TTL) keyed by `Idempotency-Key`.
- Admin responses are always `no-store`.
- Audit logs are best-effort and never block.

## Admin Generic Uploads (Any Object)

Use when you need an upload flow not tied to a Title/Asset model.

- Single-part: `POST /api/v1/admin/uploads/init`
  - Body: `{ "content_type": "image/png", "key_prefix": "uploads/title", "filename_hint": "poster" }`
  - Returns `{ upload_url, storage_key }`.
- Multipart (large files):
  - `POST /api/v1/admin/uploads/multipart/create` → `{ key, uploadId }`
  - `GET /api/v1/admin/uploads/multipart/{uploadId}/part-url?key=...&partNumber=...` → PUT URLs per part
  - `POST /api/v1/admin/uploads/multipart/{uploadId}/complete` → assemble parts
  - `POST /api/v1/admin/uploads/multipart/{uploadId}/abort` → cancel
- Direct proxy (≤ 10 MiB): `POST /api/v1/admin/uploads/direct-proxy` with `{ content_type, data_base64, key_prefix?, filename_hint? }`.

## User Download Flow (Public)

Public endpoints mint short-lived presigned GET URLs with strong safety checks.

Single file
- `POST /api/v1/delivery/download-url`
  - Body: `{ "storage_key": "downloads/{title_id}/.../file.mp4", "ttl_seconds": 300, "attachment_filename": "Foo.mp4"? }`
  - Behavior:
    - Validates key (no traversal; allowed prefixes/extensions only).
    - Optional availability gating (403) if `FEATURE_ENFORCE_AVAILABILITY=true` and requester’s country isn’t in an active window.
    - HEAD existence check; per-IP daily quota; TTL clamped by env (`DELIVERY_MIN_TTL`, `DELIVERY_MAX_TTL`).
    - Returns `{ "url": "https://...signed..." }` with `no-store` headers.

Batch
- `POST /api/v1/delivery/batch-download-urls`
  - Body: `{ "items": [ { "storage_key": "...", "attachment_filename": "..."? }, ...], "ttl_seconds": 300 }`
  - Each item processed with the same safety checks; returns `{ "results": [ { "storage_key": "...", "url"?: str, "error"?: str } ] }`.

Bundles (ZIP)
- `POST /api/v1/delivery/bundle-url`
  - Body: `{ "storage_key": "bundles/{title_id}/S01.zip", "ttl_seconds": 300, "token": "..."?, "attachment_filename": "Season1.zip"? }`
  - Validates bundle key; HEAD check; optional one-time token redemption; returns signed URL.

What the user sees
- The app calls one of the above endpoints, gets a short-lived `url`, and then the browser/client performs a direct GET from S3/CloudFront.
- Filename: controlled via `Content-Disposition` built from `attachment_filename` (sanitized) or derived from the key.
- Expiry: links expire as per `ttl_seconds` (clamped by env); re-request the URL as needed.
- Errors: 400 (bad key), 403 (region/token), 404 (missing object), 429 (quota), 503 (storage).

## AWS Integration

- S3 client (`app/utils/aws.py`)
  - Presigned PUT: `put_object` URLs for admin uploads with enforced `Content-Type`, optional SSE/KMS.
  - Presigned GET: short-lived URLs for public delivery; response headers may set `Content-Type`/`Content-Disposition`.
  - Helpers for CDN URLs and direct object URLs when a CDN base is configured.
- Configuration
  - `AWS_BUCKET_NAME` (required), `AWS_REGION`, `AWS_S3_ENDPOINT_URL` (S3-compatible),
    `AWS_SSE_MODE` (e.g., `aws:kms`), `AWS_KMS_KEY_ID`.
  - CDN: `CDN_BASE_URL` (optional). For private origins, use CloudFront + Origin Access Control (OAC) and restrict the bucket.
  - Delivery TTL bounds: `DELIVERY_MIN_TTL`, `DELIVERY_MAX_TTL`.
- Best practices
  - Buckets: block public access; enable versioning; KMS encryption; lifecycle rules for temp and archive.
  - CloudFront: put delivery behind CDN; WAF at edge; geo-fencing; Signed Cookies/URLs for streaming paths.
  - Malware scanning (optional): S3 event → Lambda → AV scan before publishing.

## Reference: Key Models & Enums

- MediaAsset.kind: VIDEO, TRAILER, etc.; `storage_key` must be unique.
- StreamVariant: `protocol`, `container`, `video_codec`, `audio_codec`, size/bitrate, flags: `is_streamable`, `is_downloadable`, `is_default`.
- Stream tiers: `P1080`, `P720`, `P480`.
- Codecs: `H264`, `H265`, `VP9`, `AV1` (video); `AAC`, `AC3`, `EAC3`, `OPUS` (audio).

## Troubleshooting

- 415 on admin video create: content-type not in allowed set; use `video/mp4` or `video/mpeg` (trailers allow webm/mov).
- 409 on bundle create: duplicate season or existing storage key; change season or use adhoc bundle.
- 403 on delivery: availability gating is active and requester region not permitted in any active window.
- 404 on delivery: missing object; verify the `storage_key` and that the object exists.
- 429 on delivery: per-IP daily quota exceeded; retry next day or reduce frequency.

---
This document reflects the current code in `app/api/v1/routers/*`, `app/db/models/*`, and `app/utils/aws.py`. Extend MIME maps or enums as needed if you introduce additional formats.


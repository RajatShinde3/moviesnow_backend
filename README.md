# MoviesNow Backend â€“ Bundles, Delivery, Media Enhancements

This changeset adds season ZIP bundles, delivery helpers, and richer media metadata.

Highlights
- MediaAsset: codecs, container, HDR, stereoscopic, channels, bitrate, label, lifecycle
- Stream policy: 480p/720p/1080p tiers (unchanged), public delivery endpoints
- Bundles: DB model + admin create/delete + public listing + presigned GET
- Ops: S3 layout constants, Terraform for S3 (SSE-S3 + lifecycle), CloudFront OAC/behaviors
- Tools: Simple uploader, bundle builder, asset backfill script

Run migrations
- env: DATABASE_URL or ASYNC_DATABASE_URL configured (Postgres)
- alembic upgrade head
  - Windows: `python -m alembic upgrade head`
  - Bash: `alembic upgrade head`

Env vars (examples)
- PUBLIC_API_KEY: optional public access key
- ADMIN_API_KEY: admin key for privileged endpoints
- AWS_BUCKET_NAME, AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
- CLOUDFRONT_DISTRIBUTION_ID (optional), CLOUDFRONT_DOMAIN (optional)
- REDIS_URL, DATABASE_URL

New routers
- Delivery: `app/api/v1/routers/delivery.py`
  - POST `/api/v1/delivery/download-url`
  - POST `/api/v1/delivery/bundle-url` (optional one-time token) — no rebuild on miss
- Public bundles: `app/api/v1/routers/public/bundles.py`
  - GET `/api/v1/titles/{title_id}/bundles`
- Public downloads: `app/api/v1/routers/public/downloads.py`
  - GET `/api/v1/titles/{title_id}/downloads` (ORIGINAL/DOWNLOAD/VIDEO assets; grouped by episode when applicable)
- Admin bundles: `app/api/v1/routers/admin/bundles.py`
  - POST `/api/v1/admin/titles/{title_id}/bundles` → presigned PUT for ZIP
  - DELETE `/api/v1/admin/bundles/{bundle_id}`
  - GET `/api/v1/admin/titles/{title_id}/bundles`
  - GET `/api/v1/admin/bundles/{bundle_id}`
  - PATCH `/api/v1/admin/bundles/{bundle_id}` (label/expiry)
  
- Admin assets tools in `admin_assets.py`
  - GET `/api/v1/admin/assets/{asset_id}/head`
  - POST `/api/v1/admin/assets/{asset_id}/checksum`
S3 layout (private bucket)
- originals/{title_id}/[episode_id/]{filename.ext}
- downloads/{title_id}/[episode_id/]{quality or source}/{filename.ext}
- hls/{title_id}/[episode_id/]{ladder}/{files...}
- bundles/{title_id}/S{season:02}.zip
- artwork/title/{title_id}/...
- subs/title/{title_id}/...

Terraform snippets
- See `ops/terraform/aws/*` for bucket + lifecycle, CloudFront (OAC), RDS, Redis.
- Set `var.bucket_name`, networking, and certs as needed before apply.

Local toolchain
- Build bundle: `python scripts/build_bundle.py --out ./S01.zip ./E01.mkv ./E02.mkv`
- Get presigned PUT + upload: `python scripts/uploader.py --api http://localhost:8000/api/v1 --admin-key KEY --title-id <uuid> --season 1 ./S01.zip`
- Backfill head/checksum: `python scripts/backfill_asset_meta.py --api http://localhost:8000/api/v1 --admin-key KEY --ids <comma-separated>`

See also: `docs/WORKFLOW.md` for end‑to‑end workflows and endpoint guide.

Notes
- Bucket uses SSE-S3; no KMS on day-1. CloudFront is single distribution with OAC.
- Bundles should expire automatically via lifecycle (7â€“30 days configurable).
- Presigned GET defaults ~5â€“10 minutes; tune via request TTL.

Notes
- Bucket uses SSE-S3; no KMS on day-1. CloudFront is single distribution with OAC.
- Bundles should expire automatically via lifecycle (7–30 days configurable).
- Presigned GET defaults ~5–10 minutes; tune via request TTL.
 

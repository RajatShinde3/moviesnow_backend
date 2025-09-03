from __future__ import annotations

"""
MoviesNow • S3 Layout & Lifecycle
=================================

Documented S3 key layout (single private bucket, CloudFront OAC):

    s3://{bucket}/
      originals/{title_id}/[episode_id/]{filename.ext}
      downloads/{title_id}/[episode_id/]{quality or source}/{filename.ext}
      hls/{title_id}/[episode_id/]{ladder}/{files...}
      bundles/{title_id}/S{season:02}.zip
      artwork/title/{title_id}/...
      subs/title/{title_id}/...

Security
--------
- All objects private; access via OAC or presigned URLs.
- Default encryption SSE-S3 (AES256).

Lifecycle Guardrails
--------------------
- Intelligent-Tiering after 30 days for all prefixes.
- Expire bundles (ZIPs) after 7–30 days per IaC config.
"""


# Prefix constants (string templates)
S3_PREFIX_ORIGINALS = "originals/{title_id}/"
S3_PREFIX_DOWNLOADS = "downloads/{title_id}/"
S3_PREFIX_HLS = "hls/{title_id}/"
S3_PREFIX_BUNDLES = "bundles/{title_id}/"
S3_PREFIX_ARTWORK_TITLE = "artwork/title/{title_id}/"
S3_PREFIX_SUBS_TITLE = "subs/title/{title_id}/"

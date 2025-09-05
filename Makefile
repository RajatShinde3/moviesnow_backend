register-downloads:
	@echo "Registering curated downloads from $$MANIFEST"
	@MANIFEST=$${MANIFEST:?Set MANIFEST=path/to/manifest.json}; \
	python scripts/register_downloads.py $$MANIFEST

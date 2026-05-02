"""Export helpers for target-scoped data.

OSINT toolkit exports are narrower than SOC toolkit's - the persistent
target model means the DB is already the source of truth, so exports
are snapshots for sharing (CSV for stakeholders, JSON for automation).
Omits WeasyPrint PDF rendering on purpose to keep the container image
free of pango/cairo system libs.
"""

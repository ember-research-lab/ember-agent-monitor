# Fixture: claude_home_data_tiers

**Class:** `.claude` component split in `sensitive_zone_access` (#53)

Six `Write`/`Read` calls by the driver. MEDIUM (the driver's own data): `charters/`
and a `projects/` transcript. HIGH (config, executable or permission-bearing):
`settings.json`, `skills/`, and `projects/../settings.json` (the `..` collapses, so
the `projects` prefix cannot launder a config path). A plain workspace file is silent.

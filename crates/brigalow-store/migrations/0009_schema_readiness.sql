-- Runtime can inspect exact applied versions/checksums, never apply or rewrite migrations.
GRANT SELECT ON public._sqlx_migrations TO brigalow_app, brigalow_ca;

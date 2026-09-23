-- Canonical logical-schema fingerprint source.
-- Emits one deterministic row per schema object property; caller sorts and
-- hashes (sha256) the output. Excludes OID, owner, ACL, storage order,
-- statistics, and runtime timestamps.
\pset tuples_only on
\pset format unaligned
\pset fieldsep '|'
WITH objs AS (
    SELECT n.nspname AS s,
           CASE c.relkind
               WHEN 'r' THEN 'table'
               WHEN 'p' THEN 'table'
               WHEN 'S' THEN 'sequence'
               WHEN 'v' THEN 'view'
               WHEN 'm' THEN 'matview'
               WHEN 'i' THEN 'index_tbl'
               ELSE 'other' END AS t,
           c.relname AS o,
           'relkind=' || c.relkind::text AS d
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r','p','S','v','m')
),
cols AS (
    SELECT n.nspname AS s, 'column' AS t, c.relname AS o,
           a.attname || ':' || format_type(a.atttypid, a.atttypmod)
           || ':notnull=' || a.attnotnull
           || ':default=' || coalesce(pg_get_expr(ad.adbin, ad.adrelid), '-') AS d
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid AND c.relkind IN ('r','p')
    JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
    WHERE n.nspname = 'public' AND a.attnum > 0 AND NOT a.attisdropped
),
cons AS (
    SELECT n.nspname AS s, 'constraint' AS t, c.relname AS o,
           con.conname || ':' || con.contype::text || ':' ||
           pg_get_constraintdef(con.oid) AS d
    FROM pg_constraint con
    JOIN pg_class c ON c.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
),
idx AS (
    SELECT n.nspname AS s, 'index' AS t, t.relname AS o,
           i.relname || ':' || pg_get_indexdef(i.oid) AS d
    FROM pg_index x
    JOIN pg_class i ON i.oid = x.indexrelid
    JOIN pg_class t ON t.oid = x.indrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'public'
),
seqs AS (
    SELECT n.nspname AS s, 'sequence_prop' AS t, c.relname AS o,
           'start=' || sq.seqstart || ':inc=' || sq.seqincrement
           || ':min=' || sq.seqmin || ':max=' || sq.seqmax
           || ':cache=' || sq.seqcache || ':cycle=' || sq.seqcycle AS d
    FROM pg_sequence sq
    JOIN pg_class c ON c.oid = sq.seqrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
),
vws AS (
    SELECT n.nspname AS s, 'viewdef' AS t, c.relname AS o,
           pg_get_viewdef(c.oid) AS d
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('v','m')
),
fns AS (
    SELECT n.nspname AS s, 'function' AS t, p.proname AS o,
           pg_get_function_identity_arguments(p.oid)
           || ':kind=' || p.prokind::text || ':lang=' || l.lanname
           || ':volatile=' || p.provolatile::text AS d
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_language l ON l.oid = p.prolang
    WHERE n.nspname = 'public'
),
trgs AS (
    SELECT n.nspname AS s, 'trigger' AS t, c.relname AS o,
           g.tgname || ':' || pg_get_triggerdef(g.oid) AS d
    FROM pg_trigger g
    JOIN pg_class c ON c.oid = g.tgrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND NOT g.tgisinternal
)
SELECT s || '|' || t || '|' || o || '|' || d FROM objs
UNION ALL SELECT s || '|' || t || '|' || o || '|' || d FROM cols
UNION ALL SELECT s || '|' || t || '|' || o || '|' || d FROM cons
UNION ALL SELECT s || '|' || t || '|' || o || '|' || d FROM idx
UNION ALL SELECT s || '|' || t || '|' || o || '|' || d FROM seqs
UNION ALL SELECT s || '|' || t || '|' || o || '|' || d FROM vws
UNION ALL SELECT s || '|' || t || '|' || o || '|' || d FROM fns
UNION ALL SELECT s || '|' || t || '|' || o || '|' || d FROM trgs
ORDER BY 1;

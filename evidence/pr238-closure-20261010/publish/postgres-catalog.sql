SELECT json_agg(s ORDER BY s.table_name) FROM (
 SELECT c.relname AS table_name,
 (SELECT json_agg(json_build_object('name',a.attname,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull) ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) AS columns,
 (SELECT json_agg(json_build_object('name',x.conname,'definition',pg_get_constraintdef(x.oid)) ORDER BY x.conname) FROM pg_constraint x WHERE x.conrelid=c.oid) AS constraints,
 (SELECT json_agg(indexdef ORDER BY indexname) FROM pg_indexes WHERE schemaname='public' AND tablename=c.relname) AS indexes
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r') s;
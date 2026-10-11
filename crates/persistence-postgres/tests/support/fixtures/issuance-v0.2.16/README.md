# Released issuance schema fixture

These SQL files preserve the corresponding migration bodies from NazoAuth
`v0.2.16` without rewriting their behavior. `cleanup.sql` contains only the
cleanup-function section of `20260715000100_scim_security_events/up.sql`.
The regression builds the actually released terminal receipt schema, rather
than the compact schema now present under the historical migration version.

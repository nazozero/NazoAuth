"""Export offline-provisioned rows for import into a freshly migrated D1 database."""

import sqlite3
import sys


with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as connection:
    for statement in connection.iterdump():
        # D1 owns its Wrangler migration ledger. The local SQLite receipt table
        # only prevents destructive replay while preparing an offline seed.
        if statement.startswith("INSERT INTO") and not statement.startswith(
            ('INSERT INTO "nazo_local_migrations"', 'INSERT INTO "sqlite_sequence"')
        ):
            print(statement)

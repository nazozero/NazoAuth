"""Export offline-provisioned rows for import into a freshly migrated D1 database."""

import sqlite3
import sys


with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as connection:
    for statement in connection.iterdump():
        if statement.startswith("INSERT INTO"):
            print(statement)

import sqlite3
import json


class CacheManager:

    def __init__(self, db_path):

        self.db_path = db_path

        con = sqlite3.connect(
            self.db_path
        )

        cur = con.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cache_key TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            )
        """)

        con.commit()
        con.close()

    def get(self, key):

        con = sqlite3.connect(
            self.db_path
        )

        cur = con.cursor()

        cur.execute(
            """
            SELECT payload
            FROM vulnerabilities
            WHERE cache_key = ?
            """,
            (key,),
        )

        row = cur.fetchone()

        con.close()

        if not row:
            return None

        return json.loads(
            row[0]
        )

    def set(self, key, payload):

        con = sqlite3.connect(
            self.db_path
        )

        cur = con.cursor()

        cur.execute(
            """
            INSERT OR REPLACE INTO vulnerabilities
            (cache_key, payload)
            VALUES (?, ?)
            """,
            (
                key,
                json.dumps(payload),
            ),
        )

        con.commit()
        con.close()

# ABOUTME: Fixture module used by E2E tests; contains intentional bugs
# ABOUTME: DO NOT use as a real template — it is deliberately vulnerable

import sqlite3


class UserService:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def get_by_name(self, username: str):
        cursor = self.conn.cursor()
        # BUG: classic CWE-89 SQL injection via string concat.
        query = "SELECT * FROM users WHERE name = '" + username + "'"
        cursor.execute(query)
        return cursor.fetchone()

    def divide(self, a: int, b: int) -> float:
        # BUG: no zero-division guard. A red-green test should fail on this.
        return a / b

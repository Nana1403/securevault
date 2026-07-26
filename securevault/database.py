"""SQLite persistence for SecureVault."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1


class VaultDatabase:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA secure_delete = ON")
        self._create_schema()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_name TEXT NOT NULL,
                website_enc TEXT NOT NULL,
                username_enc TEXT NOT NULL,
                password_enc TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'Other',
                tags TEXT NOT NULL DEFAULT '',
                notes_enc TEXT NOT NULL,
                favorite INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_credentials_name
            ON credentials(account_name COLLATE NOCASE);
            CREATE INDEX IF NOT EXISTS idx_credentials_category
            ON credentials(category COLLATE NOCASE);
            """
        )
        self.set_meta_default("schema_version", str(SCHEMA_VERSION))
        self.connection.commit()

    def is_initialized(self) -> bool:
        return self.get_meta("master_verifier") is not None

    def get_meta(self, key: str) -> str | None:
        row = self.connection.execute(
            "SELECT value FROM vault_meta WHERE key = ?", (key,)
        ).fetchone()
        return None if row is None else str(row["value"])

    def set_meta(self, key: str, value: str) -> None:
        self.connection.execute(
            """
            INSERT INTO vault_meta(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        self.connection.commit()

    def set_meta_default(self, key: str, value: str) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO vault_meta(key, value) VALUES (?, ?)",
            (key, value),
        )

    def set_meta_many(self, values: dict[str, str]) -> None:
        with self.connection:
            self.connection.executemany(
                """
                INSERT INTO vault_meta(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                values.items(),
            )

    def all_rows(self) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT * FROM credentials ORDER BY favorite DESC, account_name COLLATE NOCASE"
            )
        )

    def get_row(self, credential_id: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM credentials WHERE id = ?", (credential_id,)
        ).fetchone()

    def insert_credential(self, fields: dict[str, Any]) -> int:
        columns = ", ".join(fields)
        placeholders = ", ".join("?" for _ in fields)
        cursor = self.connection.execute(
            f"INSERT INTO credentials ({columns}) VALUES ({placeholders})",
            tuple(fields.values()),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def update_credential(self, credential_id: int, fields: dict[str, Any]) -> None:
        assignments = ", ".join(f"{name} = ?" for name in fields)
        with self.connection:
            self.connection.execute(
                f"UPDATE credentials SET {assignments} WHERE id = ?",
                (*fields.values(), credential_id),
            )

    def delete_credential(self, credential_id: int) -> None:
        with self.connection:
            self.connection.execute(
                "DELETE FROM credentials WHERE id = ?", (credential_id,)
            )

    def export_rows(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.all_rows()]

    def replace_rows(self, rows: Iterable[dict[str, Any]]) -> None:
        allowed = {
            "account_name", "website_enc", "username_enc", "password_enc",
            "category", "tags", "notes_enc", "favorite", "created_at", "updated_at",
        }
        with self.connection:
            self.connection.execute("DELETE FROM credentials")
            for row in rows:
                fields = {key: row[key] for key in allowed}
                columns = ", ".join(fields)
                placeholders = ", ".join("?" for _ in fields)
                self.connection.execute(
                    f"INSERT INTO credentials ({columns}) VALUES ({placeholders})",
                    tuple(fields.values()),
                )

    def close(self) -> None:
        self.connection.close()

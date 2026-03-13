import sqlite3
from pathlib import Path

from app.core.database import engine, Base

from app.models import threat_log


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate_threat_logs()


def _migrate_threat_logs() -> None:
    database_name = engine.url.database
    if not database_name:
        return

    database_path = Path(database_name)
    if not database_path.is_absolute():
        database_path = Path.cwd() / database_path

    if not database_path.exists():
        return

    connection = sqlite3.connect(database_path)
    try:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(threat_logs)")
        }
        statements = []

        if "summary" not in columns:
            statements.append("ALTER TABLE threat_logs ADD COLUMN summary TEXT")
        if "reasons_json" not in columns:
            statements.append("ALTER TABLE threat_logs ADD COLUMN reasons_json TEXT")
        if "source" not in columns:
            statements.append("ALTER TABLE threat_logs ADD COLUMN source TEXT")
        if "form_detected" not in columns:
            statements.append("ALTER TABLE threat_logs ADD COLUMN form_detected INTEGER DEFAULT 0")

        for statement in statements:
            connection.execute(statement)

        connection.commit()
    finally:
        connection.close()

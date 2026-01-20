from __future__ import annotations

from pathlib import Path

from sqlalchemy import text
from sqlmodel import Session, SQLModel, create_engine

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "app.db"

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False},
)


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SQLModel.metadata.create_all(engine)
    _migrate_sqlite()


def _sqlite_columns(table: str) -> set[str]:
    with engine.connect() as conn:
        rows = conn.execute(text(f"PRAGMA table_info('{table}')")).fetchall()
    # row format: cid, name, type, notnull, dflt_value, pk
    return {str(r[1]) for r in rows}


def _migrate_sqlite() -> None:
    """Migración mínima (idempotente) para SQLite.

    - Soporta upgrade desde la versión inicial donde Project tenía bucket/estimated_cost.
    - Agrega columnas nuevas para split: estimated_support_cost, estimated_improvement_cost, estimated_extra_cost.
    - Copia datos existentes hacia la nueva estructura cuando es posible.
    """

    # Migrate Project table (legacy upgrades)
    cols = _sqlite_columns("project")
    if cols:
        needed = {
            "estimated_support_cost": "NUMERIC",
            "estimated_improvement_cost": "NUMERIC",
            "estimated_extra_cost": "NUMERIC",
            # Para proyectos estimados: si approved=0 se excluye del cómputo.
            # Default 0 (borrador). Para DBs existentes se hace backfill a 1.
            "approved": "INTEGER DEFAULT 0",
            # Simulación: permite incluir borradores sin aprobarlos.
            "included": "INTEGER DEFAULT 0",
        }

        with engine.begin() as conn:
            for col, col_type in needed.items():
                if col not in cols:
                    conn.execute(
                        text(f"ALTER TABLE project ADD COLUMN {col} {col_type}")
                    )

            # Asegurar que quede con valor para filas preexistentes.
            if "approved" in _sqlite_columns("project"):
                conn.execute(
                    text("UPDATE project SET approved = 1 WHERE approved IS NULL")
                )

            if "included" in _sqlite_columns("project"):
                # Si viene de una versión previa que usaba approved para contar, mantener el mismo resultado.
                conn.execute(
                    text(
                        "UPDATE project SET included = COALESCE(approved, 1) WHERE included IS NULL"
                    )
                )

            # Backfill desde esquema viejo si existe.
            # Viejo: bucket + estimated_cost. Nuevo: 3 columnas; asignamos según bucket.
            cols_after = _sqlite_columns("project")
            if "estimated_cost" in cols_after and "bucket" in cols_after:
                conn.execute(
                    text(
                        """
                        UPDATE project
                        SET estimated_support_cost = COALESCE(estimated_support_cost,
                            CASE WHEN bucket='soporte' THEN estimated_cost ELSE 0 END),
                            estimated_improvement_cost = COALESCE(estimated_improvement_cost,
                            CASE WHEN bucket='mejora' THEN estimated_cost ELSE 0 END),
                            estimated_extra_cost = COALESCE(estimated_extra_cost,
                            CASE WHEN bucket='extra' THEN estimated_cost ELSE 0 END)
                        WHERE estimated_cost IS NOT NULL
                        """
                    )
                )

    # Migrate AuthSession table (CSRF token)
    auth_cols = _sqlite_columns("authsession")
    if auth_cols and "csrf_token" not in auth_cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE authsession ADD COLUMN csrf_token TEXT"))


def get_session() -> Session:
    return Session(engine)

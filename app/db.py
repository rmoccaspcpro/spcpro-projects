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

    # Migrate DevelopmentEstimation table (team participation)
    est_cols = _sqlite_columns("developmentestimation")
    if est_cols and "team_member_participation_json" not in est_cols:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE developmentestimation ADD COLUMN team_member_participation_json TEXT"
                )
            )

    # Migrate Odoo tables (for review section)
    # These tables store Odoo tasks, tickets, and projects for review
    _migrate_odoo_tables()


def _migrate_odoo_tables() -> None:
    """Migración para tablas de Odoo (idempotente).
    
    Crea las tablas odoo_projects, odoo_tasks, y odoo_tickets si no existen.
    Valida la existencia antes de ejecutar para evitar errores.
    """
    
    # Migrate odoo_projects table
    odoo_projects_cols = _sqlite_columns("odoo_projects")
    if not odoo_projects_cols:
        # Table doesn't exist, create it
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS odoo_projects (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        project_id INTEGER NOT NULL,
                        name TEXT NOT NULL DEFAULT '',
                        keys TEXT NOT NULL DEFAULT '',
                        tags TEXT NOT NULL DEFAULT '',
                        tag_id INTEGER,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_odoo_projects_project_id ON odoo_projects (project_id)")
            )
    
    # Migrate odoo_tasks table
    odoo_tasks_cols = _sqlite_columns("odoo_tasks")
    if not odoo_tasks_cols:
        # Table doesn't exist, create it
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS odoo_tasks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        task_id INTEGER NOT NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        status INTEGER NOT NULL DEFAULT 0,
                        ticket_id INTEGER,
                        feature_id INTEGER,
                        project_id INTEGER
                    )
                    """
                )
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_odoo_tasks_task_id ON odoo_tasks (task_id)")
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_odoo_tasks_status ON odoo_tasks (status)")
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_odoo_tasks_ticket_id ON odoo_tasks (ticket_id)")
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_odoo_tasks_project_id ON odoo_tasks (project_id)")
            )
    
    # Migrate odoo_tickets table
    odoo_tickets_cols = _sqlite_columns("odoo_tickets")
    if not odoo_tickets_cols:
        # Table doesn't exist, create it
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS odoo_tickets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ticket_id INTEGER NOT NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        status INTEGER NOT NULL DEFAULT 0,
                        task_id INTEGER
                    )
                    """
                )
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_odoo_tickets_ticket_id ON odoo_tickets (ticket_id)")
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_odoo_tickets_status ON odoo_tickets (status)")
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_odoo_tickets_task_id ON odoo_tickets (task_id)")
            )


def get_session() -> Session:
    return Session(engine)

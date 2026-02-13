from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Optional

from sqlmodel import Field, SQLModel


class ProjectBucket(str, Enum):
    soporte = "soporte"
    mejora = "mejora"
    extra = "extra"  # no consume presupuesto (se factura aparte)


class Client(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    notes: str = Field(default="")
    active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AnnualBudget(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    client_id: int = Field(index=True, foreign_key="client.id")
    year: int = Field(index=True)

    currency: str = Field(default="ARS", max_length=8)
    support_amount: Decimal = Field(default=Decimal("0"))
    improvement_amount: Decimal = Field(default=Decimal("0"))

    created_at: datetime = Field(default_factory=datetime.utcnow)


class Project(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    client_id: int = Field(index=True, foreign_key="client.id")
    year: int = Field(index=True)

    # Optional link when a project is created from an estimation.
    source_estimation_id: Optional[int] = Field(
        default=None, index=True, foreign_key="developmentestimation.id"
    )

    name: str

    # Legacy (DB): en versiones previas existía `status` y puede estar con NOT NULL.
    # Se mantiene para compatibilidad pero NO se usa a nivel funcional/UI.
    status: str = Field(default="estimado")

    # Borrador vs aprobado.
    # - approved=False: borrador (no contabiliza en totales/presupuesto)
    # - approved=True: aprobado (sí contabiliza)
    # Puede ser NULL en DB por migraciones previas; se interpreta como aprobado.
    approved: Optional[bool] = Field(default=False)

    # Simulación/planeamiento: permite incluir borradores en los cálculos sin marcarlos como aprobados.
    # - included=True: cuenta en totales
    # - included=False: no cuenta
    included: Optional[bool] = Field(default=False)

    estimated_support_cost: Decimal = Field(default=Decimal("0"))
    estimated_improvement_cost: Decimal = Field(default=Decimal("0"))
    estimated_extra_cost: Decimal = Field(default=Decimal("0"))

    description: str = Field(default="")
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def total_estimated_cost(self) -> Decimal:
        return (
            self.estimated_support_cost
            + self.estimated_improvement_cost
            + self.estimated_extra_cost
        )


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True)

    # Guardar SOLO hash (nunca el password en claro).
    password_hash: str

    is_admin: bool = Field(default=False)
    active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AuthSession(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="user.id")
    token_hash: str = Field(index=True)
    csrf_token: Optional[str] = Field(default=None, index=True)
    expires_at: datetime = Field(index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class DevelopmentEstimation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    client_id: int = Field(index=True, foreign_key="client.id")

    title: str = Field(default="")
    notes: str = Field(default="")

    # Stored as JSON string: [{"name": "...", "points": "..."}, ...]
    items_json: str = Field(default="[]")

    # Stored as JSON string: [1,2,3]
    team_member_ids_json: str = Field(default="[]")

    # Stored as JSON string: {"1": "50", "2": "50"}
    team_member_participation_json: str = Field(default="{}")

    points_sum: Decimal = Field(default=Decimal("0"))

    testing_percent: Decimal = Field(default=Decimal("20"))
    testing_points: Decimal = Field(default=Decimal("0"))

    buffer_percent: Decimal = Field(default=Decimal("0"))
    buffer_points: Decimal = Field(default=Decimal("0"))

    total_points: Decimal = Field(default=Decimal("0"))

    velocity: Decimal = Field(default=Decimal("0"))
    sprints_raw: Decimal = Field(default=Decimal("0"))
    sprints_needed: int = Field(default=0)

    monthly_salary_total: Decimal = Field(default=Decimal("0"))
    cost_per_sprint: Decimal = Field(default=Decimal("0"))

    total_cost: Decimal = Field(default=Decimal("0"))
    margin_percent: Decimal = Field(default=Decimal("35"))
    margin_amount: Decimal = Field(default=Decimal("0"))
    final_cost: Decimal = Field(default=Decimal("0"))

    created_at: datetime = Field(default_factory=datetime.utcnow)


class TeamMember(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    monthly_salary: Decimal = Field(default=Decimal("0"))
    active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


# Odoo external database models (for review section)
class OdooProject(SQLModel, table=True):
    __tablename__ = "odoo_projects"
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(index=True)  # Odoo project ID
    name: str = Field(default="")
    keys: str = Field(default="")  # Project keys/codes
    tags: str = Field(default="")
    tag_id: Optional[int] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class OdooTask(SQLModel, table=True):
    __tablename__ = "odoo_tasks"
    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: int = Field(index=True)  # Odoo task ID
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    status: int = Field(default=0, index=True)  # 0-5
    ticket_id: Optional[int] = Field(default=None, index=True)
    feature_id: Optional[int] = Field(default=None)
    project_id: Optional[int] = Field(default=None, index=True)


class OdooTicket(SQLModel, table=True):
    __tablename__ = "odoo_tickets"
    id: Optional[int] = Field(default=None, primary_key=True)
    ticket_id: int = Field(index=True)  # Odoo ticket ID
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    status: int = Field(default=0, index=True)  # 0-5
    task_id: Optional[int] = Field(default=None, index=True)

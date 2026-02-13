from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Optional
from urllib.parse import parse_qs, quote_plus

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from .db import engine, get_session, init_db
from .models import (
    AnnualBudget,
    AuthSession,
    Client,
    DevelopmentEstimation,
    OdooProject,
    OdooTask,
    OdooTicket,
    Project,
    TeamMember,
    User,
)

app = FastAPI(title="SPC Pro")

app.mount("/static", StaticFiles(directory="app/static"), name="static")


def _inject_template_context(request: Request) -> dict:
    return {
        "current_user": getattr(request.state, "user", None),
        "csrf_token": getattr(request.state, "csrf_token", None),
    }


templates = Jinja2Templates(
    directory="app/templates",
    context_processors=[_inject_template_context],
)


SESSION_COOKIE_NAME = "spcpro_session"
SESSION_TTL = timedelta(days=7)

DEFAULT_ADMIN_EMAIL = os.getenv("SPCPRO_DEFAULT_ADMIN_EMAIL")
DEFAULT_ADMIN_PASSWORD = os.getenv("SPCPRO_DEFAULT_ADMIN_PASSWORD")

DEFAULT_TESTING_PERCENT = os.getenv("SPCPRO_DEFAULT_TESTING_PERCENT", "20")
DEFAULT_BUFFER_PERCENT = os.getenv("SPCPRO_DEFAULT_BUFFER_PERCENT", "0")
DEFAULT_MARGIN_PERCENT = os.getenv("SPCPRO_DEFAULT_MARGIN_PERCENT", "35")


def _fmt_money(value: Optional[Decimal]) -> str:
    """Formato de display: miles con punto y decimales con coma (ej: 1.234,56)."""

    if value is None:
        value = Decimal("0")
    try:
        quantized = value.quantize(Decimal("0.01"))
    except Exception:
        quantized = Decimal("0.00")

    # Grouping con ',' y decimal '.' y luego swap a es-AR.
    formatted = format(quantized, ",.2f")
    return formatted.replace(",", "X").replace(".", ",").replace("X", ".")


def _fmt_dec2(value: object) -> str:
    """Formato genérico: 2 decimales y coma como separador decimal (ej: 12,34)."""

    dec: Decimal
    if value is None:
        dec = Decimal("0")
    elif isinstance(value, Decimal):
        dec = value
    elif isinstance(value, (int, float)):
        dec = Decimal(str(value))
    elif isinstance(value, str):
        dec = _to_decimal(value, default=Decimal("0"))
    else:
        try:
            dec = Decimal(str(value))
        except Exception:
            dec = Decimal("0")

    try:
        quantized = dec.quantize(Decimal("0.01"))
    except Exception:
        quantized = Decimal("0.00")

    return format(quantized, "f").replace(".", ",")


def _fmt_money_input(value: Optional[Decimal]) -> str:
    """Formato para inputs numéricos HTML: sin miles y decimal con punto (ej: 1234.56)."""

    if value is None:
        value = Decimal("0")
    try:
        quantized = value.quantize(Decimal("0.01"))
    except Exception:
        quantized = Decimal("0.00")
    return format(quantized, "f")


templates.env.filters["money"] = _fmt_money
templates.env.filters["money_input"] = _fmt_money_input
templates.env.filters["dec2"] = _fmt_dec2


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    with Session(engine) as session:
        _ensure_default_admin(session)


def _pbkdf2_hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")
    salt = os.urandom(16)
    iterations = 210_000
    dk = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, iterations)
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    dk_b64 = base64.urlsafe_b64encode(dk).decode("ascii").rstrip("=")
    return f"pbkdf2_sha256${iterations}${salt_b64}${dk_b64}"


def _pbkdf2_verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters_str, salt_b64, dk_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iters_str)

        def _b64decode_nopad(s: str) -> bytes:
            pad = "=" * ((4 - (len(s) % 4)) % 4)
            return base64.urlsafe_b64decode((s + pad).encode("ascii"))

        salt = _b64decode_nopad(salt_b64)
        expected = _b64decode_nopad(dk_b64)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def _ensure_default_admin(session: Session) -> None:
    if not DEFAULT_ADMIN_EMAIL or not DEFAULT_ADMIN_PASSWORD:
        return

    email = DEFAULT_ADMIN_EMAIL.strip().lower()
    if not email:
        return
    existing = session.exec(select(User).where(User.email == email)).first()
    if existing:
        return
    user = User(
        email=email,
        password_hash=_pbkdf2_hash_password(DEFAULT_ADMIN_PASSWORD),
        is_admin=True,
        active=True,
    )
    session.add(user)
    session.commit()


def _safe_next(next_value: Optional[str]) -> str:
    if not next_value:
        return "/"
    next_value = next_value.strip()
    if not next_value.startswith("/"):
        return "/"
    if next_value.startswith("//"):
        return "/"
    if "\n" in next_value or "\r" in next_value:
        return "/"
    return next_value


def _cookie_secure(request: Request) -> bool:
    forwarded = request.headers.get("x-forwarded-proto")
    if forwarded:
        return forwarded.split(",", 1)[0].strip().lower() == "https"
    return request.url.scheme == "https"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _get_current_user_from_request(request: Request) -> Optional[User]:
    return getattr(request.state, "user", None)


def _require_admin(request: Request) -> User:
    user = _get_current_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="No autenticado")
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="No autorizado")
    return user


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path

    # Rutas públicas
    if path.startswith("/static") or path in {
        "/login",
        "/sw.js",
        "/static/manifest.json",
    }:
        return await call_next(request)

    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        next_q = quote_plus(
            path + ("?" + request.url.query if request.url.query else "")
        )
        return RedirectResponse(url=f"/login?next={next_q}", status_code=303)

    token_hash = _hash_token(token)
    now = datetime.utcnow()

    request_for_downstream = request

    with Session(engine) as session:
        auth_sess = session.exec(
            select(AuthSession).where(AuthSession.token_hash == token_hash)
        ).first()
        if not auth_sess or auth_sess.expires_at < now:
            if auth_sess:
                session.delete(auth_sess)
                session.commit()
            next_q = quote_plus(
                path + ("?" + request.url.query if request.url.query else "")
            )
            resp = RedirectResponse(url=f"/login?next={next_q}", status_code=303)
            resp.delete_cookie(SESSION_COOKIE_NAME)
            return resp

        user = session.get(User, auth_sess.user_id)
        if not user or not user.active:
            next_q = quote_plus(
                path + ("?" + request.url.query if request.url.query else "")
            )
            resp = RedirectResponse(url=f"/login?next={next_q}", status_code=303)
            resp.delete_cookie(SESSION_COOKIE_NAME)
            return resp

        request.state.user = user

        # Ensure CSRF token exists (for older sessions / migrated DBs)
        if not auth_sess.csrf_token:
            auth_sess.csrf_token = secrets.token_urlsafe(32)
            session.add(auth_sess)
            session.commit()
        request.state.csrf_token = auth_sess.csrf_token

        # CSRF protection for unsafe methods
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            # IMPORTANT: This middleware runs via Starlette's BaseHTTPMiddleware.
            # Reading form/body here can consume the request stream and cause
            # downstream FastAPI Form(...) parsing to see an empty body (422).
            # We buffer the body and re-inject it for downstream.
            body_bytes = await request.body()

            host = request.headers.get("host", "")
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")
            if origin:
                if not (
                    origin.startswith(f"https://{host}")
                    or origin.startswith(f"http://{host}")
                ):
                    return PlainTextResponse("CSRF blocked (origin)", status_code=403)
            elif referer:
                if not (
                    referer.startswith(f"https://{host}/")
                    or referer.startswith(f"http://{host}/")
                ):
                    return PlainTextResponse("CSRF blocked (referer)", status_code=403)

            csrf = request.headers.get("x-csrf-token") or request.headers.get(
                "x-xsrf-token"
            )
            if not csrf:
                # For HTML forms (default is application/x-www-form-urlencoded)
                content_type = (request.headers.get("content-type") or "").lower()
                if content_type.startswith("application/x-www-form-urlencoded"):
                    try:
                        parsed = parse_qs(
                            body_bytes.decode("utf-8"), keep_blank_values=True
                        )
                        csrf = (parsed.get("csrf_token") or [""])[0]
                    except Exception:
                        csrf = ""
                else:
                    csrf = ""

            if not csrf or not secrets.compare_digest(
                str(csrf), str(auth_sess.csrf_token)
            ):
                return PlainTextResponse("CSRF blocked (token)", status_code=403)

            async def receive() -> dict:
                return {"type": "http.request", "body": body_bytes, "more_body": False}

            request_for_downstream = Request(request.scope, receive)

    return await call_next(request_for_downstream)


@app.get("/login")
def login_page(request: Request, next: Optional[str] = None):
    return templates.TemplateResponse(
        request,
        "login.html",
        {"title": "Ingresar", "next": _safe_next(next)},
    )


@app.get("/sw.js")
def service_worker():
    sw_path = os.path.join(os.path.dirname(__file__), "static", "sw.js")
    try:
        with open(sw_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        raise HTTPException(status_code=404, detail="Service worker not found")
    return PlainTextResponse(
        content,
        media_type="application/javascript",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.post("/login")
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
):
    email_norm = email.strip().lower()
    next_safe = _safe_next(next)
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == email_norm)).first()
        if not user or not user.active:
            return templates.TemplateResponse(
                request,
                "login.html",
                {
                    "title": "Ingresar",
                    "next": next_safe,
                    "message": "Usuario o contraseña inválidos.",
                },
                status_code=401,
            )
        if not _pbkdf2_verify_password(password, user.password_hash):
            return templates.TemplateResponse(
                request,
                "login.html",
                {
                    "title": "Ingresar",
                    "next": next_safe,
                    "message": "Usuario o contraseña inválidos.",
                },
                status_code=401,
            )

        raw_token = secrets.token_urlsafe(32)
        auth = AuthSession(
            user_id=user.id,  # type: ignore[arg-type]
            token_hash=_hash_token(raw_token),
            csrf_token=secrets.token_urlsafe(32),
            expires_at=datetime.utcnow() + SESSION_TTL,
        )
        session.add(auth)
        session.commit()

    resp = RedirectResponse(url=next_safe, status_code=303)
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        raw_token,
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(request),
        max_age=int(SESSION_TTL.total_seconds()),
    )
    return resp


@app.post("/logout")
def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        with Session(engine) as session:
            auth_sess = session.exec(
                select(AuthSession).where(AuthSession.token_hash == _hash_token(token))
            ).first()
            if auth_sess:
                session.delete(auth_sess)
                session.commit()

    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


@app.get("/users")
def users_page(request: Request, message: Optional[str] = None):
    _require_admin(request)
    with Session(engine) as session:
        users = session.exec(select(User).order_by(User.email)).all()
    return templates.TemplateResponse(
        request,
        "users.html",
        {"title": "Usuarios", "users": users, "message": message},
    )


@app.post("/users")
def users_create(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    is_admin: Optional[str] = Form(None),
):
    _require_admin(request)
    email_norm = email.strip().lower()
    if not email_norm or "@" not in email_norm:
        return RedirectResponse(
            url="/users?message=" + quote_plus("Email inválido."), status_code=303
        )
    if not password or len(password) < 8:
        return RedirectResponse(
            url="/users?message="
            + quote_plus("La contraseña debe tener al menos 8 caracteres."),
            status_code=303,
        )

    with Session(engine) as session:
        existing = session.exec(select(User).where(User.email == email_norm)).first()
        if existing:
            return RedirectResponse(
                url="/users?message=" + quote_plus("Ese usuario ya existe."),
                status_code=303,
            )
        user = User(
            email=email_norm,
            password_hash=_pbkdf2_hash_password(password),
            is_admin=bool(is_admin),
            active=True,
        )
        session.add(user)
        session.commit()

    return RedirectResponse(
        url="/users?message=" + quote_plus("Usuario creado."), status_code=303
    )


@app.get("/team")
def team_page(
    request: Request,
    message: Optional[str] = None,
    session: Session = Depends(get_session),
):
    _require_admin(request)
    members = session.exec(select(TeamMember).order_by(TeamMember.name)).all()
    return templates.TemplateResponse(
        request,
        "team.html",
        {"title": "Equipo", "members": members, "message": message},
    )


@app.post("/team")
def team_create(
    request: Request,
    name: str = Form(...),
    monthly_salary: str = Form("0"),
    active: Optional[str] = Form(None),
    session: Session = Depends(get_session),
):
    _require_admin(request)
    member = TeamMember(
        name=name.strip(),
        monthly_salary=_non_negative(_to_decimal(monthly_salary)),
        active=active is not None,
    )
    session.add(member)
    session.commit()
    return RedirectResponse(
        url="/team?message=" + quote_plus("Miembro creado."), status_code=303
    )


@app.get("/team/{member_id}")
def team_edit_page(
    request: Request,
    member_id: int,
    session: Session = Depends(get_session),
):
    _require_admin(request)
    member = session.get(TeamMember, member_id)
    if not member:
        raise HTTPException(status_code=404, detail="Miembro no encontrado")
    return templates.TemplateResponse(
        request,
        "team_edit.html",
        {"title": "Editar miembro", "member": member},
    )


@app.post("/team/{member_id}")
def team_update(
    request: Request,
    member_id: int,
    name: str = Form(...),
    monthly_salary: str = Form("0"),
    active: Optional[str] = Form(None),
    session: Session = Depends(get_session),
):
    _require_admin(request)
    member = session.get(TeamMember, member_id)
    if not member:
        raise HTTPException(status_code=404, detail="Miembro no encontrado")
    member.name = name.strip()
    member.monthly_salary = _non_negative(_to_decimal(monthly_salary))
    member.active = active is not None
    session.add(member)
    session.commit()
    return RedirectResponse(
        url="/team?message=" + quote_plus("Miembro actualizado."), status_code=303
    )


@app.post("/team/{member_id}/delete")
def team_delete(
    request: Request,
    member_id: int,
    session: Session = Depends(get_session),
):
    _require_admin(request)
    member = session.get(TeamMember, member_id)
    if not member:
        raise HTTPException(status_code=404, detail="Miembro no encontrado")
    session.delete(member)
    session.commit()
    return RedirectResponse(
        url="/team?message=" + quote_plus("Miembro borrado."), status_code=303
    )


def _to_decimal(value: Optional[str], default: Decimal = Decimal("0")) -> Decimal:
    if value is None:
        return default
    value = value.strip()
    if value == "":
        return default

    # Acepta valores en formato es-AR (1.234,56) y en formato estándar (1,234.56 / 1234.56).
    # Si existen ambos separadores, el separador decimal es el último que aparece.
    normalized = value.replace(" ", "")
    has_dot = "." in normalized
    has_comma = "," in normalized

    if has_dot and has_comma:
        last_dot = normalized.rfind(".")
        last_comma = normalized.rfind(",")
        if last_comma > last_dot:
            # 1.234,56
            normalized = normalized.replace(".", "").replace(",", ".")
        else:
            # 1,234.56
            normalized = normalized.replace(",", "")
    elif has_comma:
        # 1234,56
        normalized = normalized.replace(",", ".")
    else:
        # 1234.56 o 1234
        normalized = normalized.replace(",", "")

    try:
        return Decimal(normalized)
    except InvalidOperation:
        return default


def _non_negative(value: Decimal) -> Decimal:
    return value if value >= 0 else Decimal("0")


def _ceil_decimal_to_int(value: Decimal) -> int:
    if value <= 0:
        return 0
    integral = value.to_integral_value(rounding="ROUND_FLOOR")
    return int(integral if integral == value else (integral + 1))


def _calc_development_estimation(
    *,
    items_points_sum: Decimal,
    testing_percent: Decimal,
    buffer_percent: Decimal,
    velocity: Decimal,
    monthly_salary_total: Decimal,
    margin_percent: Decimal,
) -> dict:
    items_points_sum = _non_negative(items_points_sum)
    testing_percent = _non_negative(testing_percent)
    buffer_percent = _non_negative(buffer_percent)
    velocity = _non_negative(velocity)
    monthly_salary_total = _non_negative(monthly_salary_total)
    margin_percent = _non_negative(margin_percent)

    testing_points = (items_points_sum * testing_percent) / Decimal("100")
    subtotal_points = items_points_sum + testing_points
    buffer_points = (subtotal_points * buffer_percent) / Decimal("100")
    total_points = subtotal_points + buffer_points

    if velocity > 0:
        sprints_raw = total_points / velocity
        sprints_needed = _ceil_decimal_to_int(sprints_raw)
    else:
        sprints_raw = Decimal("0")
        sprints_needed = 0

    cost_per_sprint = monthly_salary_total / Decimal("2")
    total_cost = cost_per_sprint * Decimal(str(sprints_needed))
    margin_amount = (total_cost * margin_percent) / Decimal("100")
    final_cost = total_cost + margin_amount

    return {
        "points_sum": items_points_sum,
        "testing_points": testing_points,
        "buffer_points": buffer_points,
        "total_points": total_points,
        "sprints_raw": sprints_raw,
        "sprints_needed": sprints_needed,
        "cost_per_sprint": cost_per_sprint,
        "total_cost": total_cost,
        "margin_amount": margin_amount,
        "final_cost": final_cost,
    }


def _project_counts_for_totals(project: Project) -> bool:
    """Define si el proyecto debe contarse en totales/presupuesto.

    Regla:
    - approved=True: siempre cuenta (bloqueado)
    - approved=False: cuenta si included=True
    - NULL por migraciones viejas: se interpreta como True para no romper
    """

    approved = True if project.approved is None else bool(project.approved)
    included = False if project.included is None else bool(project.included)
    return approved or included


def _project_is_approved(project: Optional[Project]) -> bool:
    if not project:
        return False
    return True if project.approved is None else bool(project.approved)


def _get_budget(session: Session, client_id: int, year: int) -> Optional[AnnualBudget]:
    statement = select(AnnualBudget).where(
        AnnualBudget.client_id == client_id,
        AnnualBudget.year == year,
    )
    return session.exec(statement).first()


def _budget_warning_message(
    session: Session, *, client_id: int, year: int
) -> Optional[str]:
    # Por ahora, NO se muestran warnings/validaciones de presupuesto.
    # El único warning solicitado al convertir una estimación a proyecto es el del split.
    return None


@app.get("/")
def dashboard_page(
    request: Request,
    year: Optional[int] = None,
    session: Session = Depends(get_session),
):
    if year is None:
        year = datetime.utcnow().year

    clients = session.exec(select(Client).order_by(Client.name)).all()
    active_clients = sum((1 for c in clients if c.active))
    inactive_clients = len(clients) - active_clients

    projects_total = 0
    projects_approved = 0
    projects_draft_included = 0
    projects_draft_excluded = 0

    month_counts = [0] * 12

    usage_labels: list[str] = []
    support_used_pct: list[float] = []
    improvement_used_pct: list[float] = []

    overspent_clients: list[dict] = []

    def _pct(used: Decimal, budget: Decimal) -> float:
        if budget <= 0:
            return 0.0
        return float((used / budget) * 100)

    for client in clients:
        projects = session.exec(
            select(Project).where(Project.client_id == client.id, Project.year == year)
        ).all()

        projects_total += len(projects)

        for p in projects:
            if p.created_at:
                month_counts[p.created_at.month - 1] += 1

            approved = True if p.approved is None else bool(p.approved)
            included = False if p.included is None else bool(p.included)

            if approved:
                projects_approved += 1
            else:
                if included:
                    projects_draft_included += 1
                else:
                    projects_draft_excluded += 1

        included_projects = [p for p in projects if _project_counts_for_totals(p)]
        used_support = sum(
            (p.estimated_support_cost for p in included_projects), start=Decimal("0")
        )
        used_improvement = sum(
            (p.estimated_improvement_cost for p in included_projects),
            start=Decimal("0"),
        )

        budget = _get_budget(session, client.id, year)  # type: ignore[arg-type]
        if budget and (budget.support_amount > 0 or budget.improvement_amount > 0):
            usage_labels.append(client.name)
            support_used_pct.append(_pct(used_support, budget.support_amount))
            improvement_used_pct.append(
                _pct(used_improvement, budget.improvement_amount)
            )

            support_remaining = budget.support_amount - used_support
            improvement_remaining = budget.improvement_amount - used_improvement
            if support_remaining < 0 or improvement_remaining < 0:
                overspent_clients.append(
                    {
                        "client": client,
                        "currency": budget.currency,
                        "support_remaining": support_remaining,
                        "improvement_remaining": improvement_remaining,
                    }
                )

    overspent_clients.sort(
        key=lambda r: (r["support_remaining"] + r["improvement_remaining"])
    )
    overspent_clients = overspent_clients[:6]

    chart_data = {
        "projectsState": {
            "labels": ["Aprobados", "Borradores incluidos", "Borradores"],
            "data": [
                projects_approved,
                projects_draft_included,
                projects_draft_excluded,
            ],
        },
        "monthly": {
            "labels": [
                "Ene",
                "Feb",
                "Mar",
                "Abr",
                "May",
                "Jun",
                "Jul",
                "Ago",
                "Sep",
                "Oct",
                "Nov",
                "Dic",
            ],
            "data": month_counts,
        },
        "usagePct": {
            "labels": usage_labels,
            "support": support_used_pct,
            "improvement": improvement_used_pct,
        },
    }

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "title": "Dashboard",
            "year": year,
            "clients_total": len(clients),
            "active_clients": active_clients,
            "inactive_clients": inactive_clients,
            "projects_total": projects_total,
            "projects_approved": projects_approved,
            "projects_draft_included": projects_draft_included,
            "projects_draft_excluded": projects_draft_excluded,
            "overspent_clients": overspent_clients,
            "chart_data_json": json.dumps(chart_data, ensure_ascii=False).replace(
                "</", "<\\/"
            ),
        },
    )


@app.get("/clients")
def clients_page(request: Request, session: Session = Depends(get_session)):
    clients = session.exec(select(Client).order_by(Client.name)).all()
    return templates.TemplateResponse(
        request,
        "clients.html",
        {"clients": clients, "title": "Clientes"},
    )


@app.post("/clients")
def create_client(
    name: str = Form(...),
    notes: str = Form(""),
    session: Session = Depends(get_session),
):
    client = Client(name=name.strip(), notes=notes.strip())
    session.add(client)
    session.commit()
    session.refresh(client)
    return RedirectResponse(url=f"/clients/{client.id}", status_code=303)


@app.post("/clients/{client_id}/toggle")
def toggle_client(client_id: int, session: Session = Depends(get_session)):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    client.active = not client.active
    session.add(client)
    session.commit()
    return RedirectResponse(url="/clients", status_code=303)


@app.get("/clients/{client_id}")
def client_detail(
    request: Request,
    client_id: int,
    year: Optional[int] = None,
    message: Optional[str] = None,
    session: Session = Depends(get_session),
):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    if year is None:
        year = datetime.utcnow().year

    budget = _get_budget(session, client_id, year)

    projects = session.exec(
        select(Project)
        .where(Project.client_id == client_id, Project.year == year)
        .order_by(Project.created_at.desc())
    ).all()

    estimations = session.exec(
        select(DevelopmentEstimation)
        .where(DevelopmentEstimation.client_id == client_id)
        .order_by(DevelopmentEstimation.created_at.desc())
    ).all()

    # Map estimations that were already converted into projects.
    projects_from_estimations = session.exec(
        select(Project)
        .where(Project.client_id == client_id)
        .where(Project.source_estimation_id != None)  # noqa: E711
        .order_by(Project.created_at.desc())
    ).all()
    estimation_project_map: dict[int, dict] = {}
    for p in projects_from_estimations:
        if p.source_estimation_id is None:
            continue
        # Keep latest project if multiple exist.
        if p.source_estimation_id not in estimation_project_map:
            estimation_project_map[int(p.source_estimation_id)] = {
                "project_id": p.id,
                "project_year": p.year,
            }

    approved_projects = [p for p in projects if _project_counts_for_totals(p)]

    used_support = sum(
        (p.estimated_support_cost for p in approved_projects), start=Decimal("0")
    )
    used_improvement = sum(
        (p.estimated_improvement_cost for p in approved_projects), start=Decimal("0")
    )
    used_extra = sum(
        (p.estimated_extra_cost for p in approved_projects), start=Decimal("0")
    )

    # Totales incluyendo borradores (para evaluación).
    used_support_all = sum(
        (p.estimated_support_cost for p in projects), start=Decimal("0")
    )
    used_improvement_all = sum(
        (p.estimated_improvement_cost for p in projects), start=Decimal("0")
    )
    used_extra_all = sum((p.estimated_extra_cost for p in projects), start=Decimal("0"))

    currency = budget.currency if budget else "ARS"
    support_amount = budget.support_amount if budget else Decimal("0")
    improvement_amount = budget.improvement_amount if budget else Decimal("0")

    remaining_support = support_amount - used_support
    remaining_improvement = improvement_amount - used_improvement

    remaining_support_all = support_amount - used_support_all
    remaining_improvement_all = improvement_amount - used_improvement_all

    return templates.TemplateResponse(
        request,
        "client_detail.html",
        {
            "title": client.name,
            "client": client,
            "year": year,
            "budget": budget,
            "projects": projects,
            "currency": currency,
            "message": message,
            "used_support": used_support,
            "used_improvement": used_improvement,
            "used_extra": used_extra,
            "remaining_support": remaining_support,
            "remaining_improvement": remaining_improvement,
            "used_support_all": used_support_all,
            "used_improvement_all": used_improvement_all,
            "used_extra_all": used_extra_all,
            "remaining_support_all": remaining_support_all,
            "remaining_improvement_all": remaining_improvement_all,
            "estimations": estimations,
            "estimation_project_map": estimation_project_map,
        },
    )


@app.get("/clients/{client_id}/estimations/new")
def estimation_new_page(
    request: Request,
    client_id: int,
    session: Session = Depends(get_session),
):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    team_members = session.exec(
        select(TeamMember).where(TeamMember.active == True).order_by(TeamMember.name)
    ).all()

    defaults = {
        "testing_percent": _to_decimal(DEFAULT_TESTING_PERCENT, default=Decimal("20")),
        "buffer_percent": _to_decimal(DEFAULT_BUFFER_PERCENT, default=Decimal("0")),
        "margin_percent": _to_decimal(DEFAULT_MARGIN_PERCENT, default=Decimal("35")),
    }

    return templates.TemplateResponse(
        request,
        "estimation_new.html",
        {
            "title": f"Nueva estimación - {client.name}",
            "client": client,
            "defaults": defaults,
            "team_members": team_members,
        },
    )


@app.post("/clients/{client_id}/estimations")
def estimation_create(
    client_id: int,
    title: str = Form(""),
    notes: str = Form(""),
    team_member_id: list[str] = Form([]),
    team_member_participation: list[str] = Form([]),
    feature_name: list[str] = Form([]),
    feature_points: list[str] = Form([]),
    testing_percent: str = Form(""),
    buffer_percent: str = Form(""),
    velocity: str = Form(""),
    monthly_salary_total: str = Form(""),
    margin_percent: str = Form(""),
    session: Session = Depends(get_session),
):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    t_pct = _to_decimal(
        testing_percent,
        default=_to_decimal(DEFAULT_TESTING_PERCENT, default=Decimal("20")),
    )
    b_pct = _to_decimal(
        buffer_percent,
        default=_to_decimal(DEFAULT_BUFFER_PERCENT, default=Decimal("0")),
    )
    m_pct = _to_decimal(
        margin_percent,
        default=_to_decimal(DEFAULT_MARGIN_PERCENT, default=Decimal("35")),
    )
    vel = _to_decimal(velocity, default=Decimal("0"))
    selected_ids: list[int] = []
    for raw_id in team_member_id:
        try:
            selected_ids.append(int(str(raw_id)))
        except Exception:
            continue
    selected_ids = sorted(set(selected_ids))

    # Parse participations sent as repeated fields: "<id>:<pct>".
    participation_by_id: dict[int, Decimal] = {}
    for raw in team_member_participation:
        try:
            s = str(raw)
            if ":" not in s:
                continue
            id_str, pct_str = s.split(":", 1)
            member_id = int(id_str.strip())
            pct = _to_decimal(pct_str.strip(), default=Decimal("100"))
            if pct < 0:
                pct = Decimal("0")
            if pct > 100:
                pct = Decimal("100")
            participation_by_id[member_id] = pct
        except Exception:
            continue

    salary_total = _to_decimal(monthly_salary_total, default=Decimal("0"))
    participation_json: dict[str, str] = {}
    if selected_ids:
        members = session.exec(
            select(TeamMember).where(TeamMember.id.in_(selected_ids))
        ).all()
        salary_total = Decimal("0")
        for m in members:
            pct = participation_by_id.get(m.id or 0, Decimal("100"))
            participation_json[str(m.id)] = str(pct)
            salary_total += (m.monthly_salary * pct) / Decimal("100")

    items: list[dict] = []
    points_sum = Decimal("0")

    # Normalize list lengths (FastAPI can send uneven lists depending on the browser)
    max_len = max(len(feature_name), len(feature_points), 0)
    for i in range(max_len):
        name = (feature_name[i] if i < len(feature_name) else "").strip()
        pts_str = (feature_points[i] if i < len(feature_points) else "").strip()
        if not name and not pts_str:
            continue
        pts = _non_negative(_to_decimal(pts_str, default=Decimal("0")))
        items.append({"name": name, "points": str(pts)})
        points_sum += pts

    calc = _calc_development_estimation(
        items_points_sum=points_sum,
        testing_percent=t_pct,
        buffer_percent=b_pct,
        velocity=vel,
        monthly_salary_total=salary_total,
        margin_percent=m_pct,
    )

    estimation = DevelopmentEstimation(
        client_id=client_id,
        title=title.strip(),
        notes=notes.strip(),
        items_json=json.dumps(items, ensure_ascii=False),
        team_member_ids_json=json.dumps(selected_ids, ensure_ascii=False),
        team_member_participation_json=json.dumps(
            participation_json, ensure_ascii=False
        ),
        points_sum=calc["points_sum"],
        testing_percent=t_pct,
        testing_points=calc["testing_points"],
        buffer_percent=b_pct,
        buffer_points=calc["buffer_points"],
        total_points=calc["total_points"],
        velocity=vel,
        sprints_raw=calc["sprints_raw"],
        sprints_needed=int(calc["sprints_needed"]),
        monthly_salary_total=salary_total,
        cost_per_sprint=calc["cost_per_sprint"],
        total_cost=calc["total_cost"],
        margin_percent=m_pct,
        margin_amount=calc["margin_amount"],
        final_cost=calc["final_cost"],
    )

    session.add(estimation)
    session.commit()
    session.refresh(estimation)

    return RedirectResponse(
        url=f"/clients/{client_id}/estimations/{estimation.id}", status_code=303
    )


@app.get("/clients/{client_id}/estimations/{estimation_id}")
def estimation_detail_page(
    request: Request,
    client_id: int,
    estimation_id: int,
    message: Optional[str] = Query(None),
    session: Session = Depends(get_session),
):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    estimation = session.get(DevelopmentEstimation, estimation_id)
    if not estimation or estimation.client_id != client_id:
        raise HTTPException(status_code=404, detail="Estimación no encontrada")

    try:
        items = json.loads(estimation.items_json or "[]")
        if not isinstance(items, list):
            items = []
    except Exception:
        items = []

    try:
        member_ids = json.loads(estimation.team_member_ids_json or "[]")
        if not isinstance(member_ids, list):
            member_ids = []
    except Exception:
        member_ids = []

    try:
        participation_raw = json.loads(
            estimation.team_member_participation_json or "{}"
        )
        if not isinstance(participation_raw, dict):
            participation_raw = {}
    except Exception:
        participation_raw = {}

    selected_members: list[TeamMember] = []
    ids_int: list[int] = []
    for raw_id in member_ids:
        try:
            ids_int.append(int(str(raw_id)))
        except Exception:
            continue
    if ids_int:
        selected_members = session.exec(
            select(TeamMember)
            .where(TeamMember.id.in_(ids_int))
            .order_by(TeamMember.name)
        ).all()

    selected_member_rows: list[dict] = []
    for m in selected_members:
        pct_raw = participation_raw.get(str(m.id), "100")
        pct = _to_decimal(str(pct_raw), default=Decimal("100"))
        if pct < 0:
            pct = Decimal("0")
        if pct > 100:
            pct = Decimal("100")
        used = (m.monthly_salary * pct) / Decimal("100")
        try:
            used = used.quantize(Decimal("0.01"))
        except Exception:
            pass
        selected_member_rows.append({"member": m, "pct": pct, "salary_used": used})

    linked_project = session.exec(
        select(Project)
        .where(Project.client_id == client_id)
        .where(Project.source_estimation_id == estimation_id)
        .order_by(Project.created_at.desc())
    ).first()

    return templates.TemplateResponse(
        request,
        "estimation_detail.html",
        {
            "title": f"Estimación - {client.name}",
            "client": client,
            "estimation": estimation,
            "items": items,
            "selected_members": selected_members,
            "selected_member_rows": selected_member_rows,
            "linked_project": linked_project,
            "message": message,
        },
    )


def _q2(value: Decimal) -> Decimal:
    try:
        return value.quantize(Decimal("0.01"))
    except Exception:
        return value


@app.get("/clients/{client_id}/estimations/{estimation_id}/project/new")
def estimation_to_project_page(
    request: Request,
    client_id: int,
    estimation_id: int,
    year: Optional[int] = Query(None),
    message: Optional[str] = Query(None),
    session: Session = Depends(get_session),
):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    estimation = session.get(DevelopmentEstimation, estimation_id)
    if not estimation or estimation.client_id != client_id:
        raise HTTPException(status_code=404, detail="Estimación no encontrada")

    if year is None:
        year = datetime.utcnow().year

    existing = session.exec(
        select(Project)
        .where(Project.client_id == client_id)
        .where(Project.source_estimation_id == estimation_id)
        .order_by(Project.created_at.desc())
    ).first()
    if existing:
        msg = f"Esta estimación ya fue cargada como proyecto (#{existing.id}, año {existing.year})."
        return RedirectResponse(
            url=(
                f"/clients/{client_id}?year={year}&message="
                + quote_plus(msg)
                + f"#project-{existing.id}"
            ),
            status_code=303,
        )

    budget = _get_budget(session, client_id, year)
    currency = budget.currency if budget else "ARS"

    default_name = (estimation.title or "").strip()
    if not default_name:
        if estimation.created_at:
            default_name = f"Estimación {estimation.created_at.strftime('%Y-%m-%d')}"
        else:
            default_name = "Estimación"

    return templates.TemplateResponse(
        request,
        "estimation_to_project.html",
        {
            "title": "Cargar estimación como proyecto",
            "client": client,
            "estimation": estimation,
            "year": year,
            "currency": currency,
            "default_name": default_name,
            "support_amount": Decimal("0"),
            "improvement_amount": _q2(estimation.final_cost or Decimal("0")),
            "extra_amount": Decimal("0"),
            "message": message,
        },
    )


@app.post("/clients/{client_id}/estimations/{estimation_id}/project")
def estimation_to_project_create(
    client_id: int,
    estimation_id: int,
    year: int = Form(...),
    name: str = Form(...),
    support_amount: str = Form("0"),
    improvement_amount: str = Form("0"),
    extra_amount: str = Form("0"),
    approved: Optional[str] = Form(None),
    included: Optional[str] = Form(None),
    description: str = Form(""),
    session: Session = Depends(get_session),
):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    estimation = session.get(DevelopmentEstimation, estimation_id)
    if not estimation or estimation.client_id != client_id:
        raise HTTPException(status_code=404, detail="Estimación no encontrada")

    existing = session.exec(
        select(Project)
        .where(Project.client_id == client_id)
        .where(Project.source_estimation_id == estimation_id)
        .order_by(Project.created_at.desc())
    ).first()
    if existing:
        msg = f"Esta estimación ya fue cargada como proyecto (#{existing.id})."
        return RedirectResponse(
            url=f"/clients/{client_id}?year={year}&message={quote_plus(msg)}",
            status_code=303,
        )

    budget = _get_budget(session, client_id, year)
    currency = budget.currency if budget else "ARS"

    total = _q2(estimation.final_cost or Decimal("0"))
    support_cost = _q2(_non_negative(_to_decimal(support_amount, default=Decimal("0"))))
    improvement_cost = _q2(
        _non_negative(_to_decimal(improvement_amount, default=Decimal("0")))
    )
    extra_cost = _q2(_non_negative(_to_decimal(extra_amount, default=Decimal("0"))))

    split_sum = _q2(support_cost + improvement_cost + extra_cost)
    diff = _q2(split_sum - total)
    split_warning: Optional[str] = None
    # Warning solo si el split EXCEDE el total estimado.
    if diff > Decimal("0.01"):
        split_warning = (
            f"⚠ Split excede el total de la estimación: "
            f"{currency} {_fmt_money(split_sum)} vs {currency} {_fmt_money(total)} "
            f"(exceso: {currency} {_fmt_money(diff)})."
        )

    is_approved = approved is not None
    is_included = True if is_approved else (included is not None)

    desc = (description or "").strip()
    if not desc:
        desc = f"Creado desde estimación #{estimation_id}"
    else:
        desc = desc + f" (desde estimación #{estimation_id})"

    project = Project(
        client_id=client_id,
        year=year,
        name=name.strip(),
        approved=is_approved,
        included=is_included,
        estimated_support_cost=_non_negative(support_cost),
        estimated_improvement_cost=_non_negative(improvement_cost),
        estimated_extra_cost=_non_negative(extra_cost),
        description=desc,
        source_estimation_id=estimation_id,
    )
    session.add(project)
    session.commit()

    if split_warning:
        return RedirectResponse(
            url=f"/clients/{client_id}?year={year}&message={quote_plus(split_warning)}",
            status_code=303,
        )

    return RedirectResponse(url=f"/clients/{client_id}?year={year}", status_code=303)


@app.post("/projects/{project_id}/unlink_estimation")
def project_unlink_estimation(
    request: Request,
    project_id: int,
    next: str = Form(""),
    session: Session = Depends(get_session),
):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    client_id = project.client_id
    year = project.year
    session.delete(project)
    session.commit()

    url = next.strip() or f"/clients/{client_id}?year={year}"
    return RedirectResponse(url=url, status_code=303)


@app.get("/clients/{client_id}/estimations/{estimation_id}/edit")
def estimation_edit_page(
    request: Request,
    client_id: int,
    estimation_id: int,
    session: Session = Depends(get_session),
):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    estimation = session.get(DevelopmentEstimation, estimation_id)
    if not estimation or estimation.client_id != client_id:
        raise HTTPException(status_code=404, detail="Estimación no encontrada")

    # Include all members so previous selections don't disappear if someone was deactivated.
    team_members = session.exec(select(TeamMember).order_by(TeamMember.name)).all()

    try:
        items = json.loads(estimation.items_json or "[]")
        if not isinstance(items, list):
            items = []
    except Exception:
        items = []

    try:
        member_ids = json.loads(estimation.team_member_ids_json or "[]")
        if not isinstance(member_ids, list):
            member_ids = []
    except Exception:
        member_ids = []

    selected_ids: list[int] = []
    for raw_id in member_ids:
        try:
            selected_ids.append(int(str(raw_id)))
        except Exception:
            continue
    selected_ids = sorted(set(selected_ids))

    try:
        participation_raw = json.loads(estimation.team_member_participation_json or "{}")
        if not isinstance(participation_raw, dict):
            participation_raw = {}
    except Exception:
        participation_raw = {}

    linked_project = session.exec(
        select(Project)
        .where(Project.client_id == client_id)
        .where(Project.source_estimation_id == estimation_id)
        .order_by(Project.created_at.desc())
    ).first()

    if linked_project and _project_is_approved(linked_project):
        msg = "No se puede editar la estimación porque el proyecto derivado está aprobado."
        return RedirectResponse(
            url=f"/clients/{client_id}/estimations/{estimation_id}?message={quote_plus(msg)}",
            status_code=303,
        )

    return templates.TemplateResponse(
        request,
        "estimation_edit.html",
        {
            "title": f"Editar estimación - {client.name}",
            "client": client,
            "estimation": estimation,
            "items": items,
            "team_members": team_members,
            "selected_member_ids": selected_ids,
            "participation": participation_raw,
            "linked_project": linked_project,
        },
    )


@app.post("/clients/{client_id}/estimations/{estimation_id}")
def estimation_update(
    client_id: int,
    estimation_id: int,
    title: str = Form(""),
    notes: str = Form(""),
    team_member_id: list[str] = Form([]),
    team_member_participation: list[str] = Form([]),
    feature_name: list[str] = Form([]),
    feature_points: list[str] = Form([]),
    testing_percent: str = Form(""),
    buffer_percent: str = Form(""),
    velocity: str = Form(""),
    monthly_salary_total: str = Form(""),
    margin_percent: str = Form(""),
    session: Session = Depends(get_session),
):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    estimation = session.get(DevelopmentEstimation, estimation_id)
    if not estimation or estimation.client_id != client_id:
        raise HTTPException(status_code=404, detail="Estimación no encontrada")

    linked_project = session.exec(
        select(Project)
        .where(Project.client_id == client_id)
        .where(Project.source_estimation_id == estimation_id)
        .order_by(Project.created_at.desc())
    ).first()
    if linked_project and _project_is_approved(linked_project):
        msg = "No se puede editar la estimación porque el proyecto derivado está aprobado."
        return RedirectResponse(
            url=f"/clients/{client_id}/estimations/{estimation_id}?message={quote_plus(msg)}",
            status_code=303,
        )

    t_pct = _to_decimal(
        testing_percent,
        default=_to_decimal(DEFAULT_TESTING_PERCENT, default=Decimal("20")),
    )
    b_pct = _to_decimal(
        buffer_percent,
        default=_to_decimal(DEFAULT_BUFFER_PERCENT, default=Decimal("0")),
    )
    m_pct = _to_decimal(
        margin_percent,
        default=_to_decimal(DEFAULT_MARGIN_PERCENT, default=Decimal("35")),
    )
    vel = _to_decimal(velocity, default=Decimal("0"))

    selected_ids: list[int] = []
    for raw_id in team_member_id:
        try:
            selected_ids.append(int(str(raw_id)))
        except Exception:
            continue
    selected_ids = sorted(set(selected_ids))

    # Parse participations sent as repeated fields: "<id>:<pct>".
    participation_by_id: dict[int, Decimal] = {}
    for raw in team_member_participation:
        try:
            s = str(raw)
            if ":" not in s:
                continue
            id_str, pct_str = s.split(":", 1)
            member_id = int(id_str.strip())
            pct = _to_decimal(pct_str.strip(), default=Decimal("100"))
            if pct < 0:
                pct = Decimal("0")
            if pct > 100:
                pct = Decimal("100")
            participation_by_id[member_id] = pct
        except Exception:
            continue

    salary_total = _to_decimal(monthly_salary_total, default=Decimal("0"))
    participation_json: dict[str, str] = {}
    if selected_ids:
        members = session.exec(select(TeamMember).where(TeamMember.id.in_(selected_ids))).all()
        salary_total = Decimal("0")
        for m in members:
            pct = participation_by_id.get(m.id or 0, Decimal("100"))
            participation_json[str(m.id)] = str(pct)
            salary_total += (m.monthly_salary * pct) / Decimal("100")

    items: list[dict] = []
    points_sum = Decimal("0")
    max_len = max(len(feature_name), len(feature_points), 0)
    for i in range(max_len):
        name = (feature_name[i] if i < len(feature_name) else "").strip()
        pts_str = (feature_points[i] if i < len(feature_points) else "").strip()
        if not name and not pts_str:
            continue
        pts = _non_negative(_to_decimal(pts_str, default=Decimal("0")))
        items.append({"name": name, "points": str(pts)})
        points_sum += pts

    calc = _calc_development_estimation(
        items_points_sum=points_sum,
        testing_percent=t_pct,
        buffer_percent=b_pct,
        velocity=vel,
        monthly_salary_total=salary_total,
        margin_percent=m_pct,
    )

    estimation.title = title.strip()
    estimation.notes = notes.strip()
    estimation.items_json = json.dumps(items, ensure_ascii=False)
    estimation.team_member_ids_json = json.dumps(selected_ids, ensure_ascii=False)
    estimation.team_member_participation_json = json.dumps(participation_json, ensure_ascii=False)

    estimation.points_sum = calc["points_sum"]
    estimation.testing_percent = t_pct
    estimation.testing_points = calc["testing_points"]
    estimation.buffer_percent = b_pct
    estimation.buffer_points = calc["buffer_points"]
    estimation.total_points = calc["total_points"]
    estimation.velocity = vel
    estimation.sprints_raw = calc["sprints_raw"]
    estimation.sprints_needed = int(calc["sprints_needed"])
    estimation.monthly_salary_total = salary_total
    estimation.cost_per_sprint = calc["cost_per_sprint"]
    estimation.total_cost = calc["total_cost"]
    estimation.margin_percent = m_pct
    estimation.margin_amount = calc["margin_amount"]
    estimation.final_cost = calc["final_cost"]

    session.add(estimation)
    session.commit()

    return RedirectResponse(
        url=f"/clients/{client_id}/estimations/{estimation_id}", status_code=303
    )


@app.post("/clients/{client_id}/estimations/{estimation_id}/delete")
def estimation_delete(
    client_id: int,
    estimation_id: int,
    session: Session = Depends(get_session),
):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    estimation = session.get(DevelopmentEstimation, estimation_id)
    if not estimation or estimation.client_id != client_id:
        raise HTTPException(status_code=404, detail="Estimación no encontrada")

    linked_project = session.exec(
        select(Project)
        .where(Project.client_id == client_id)
        .where(Project.source_estimation_id == estimation_id)
        .order_by(Project.created_at.desc())
    ).first()
    if linked_project:
        msg = "No se puede borrar la estimación porque ya existe un proyecto creado desde ella. Borrá el proyecto primero."
        return RedirectResponse(
            url=f"/clients/{client_id}/estimations/{estimation_id}?message={quote_plus(msg)}",
            status_code=303,
        )

    session.delete(estimation)
    session.commit()
    return RedirectResponse(url=f"/clients/{client_id}", status_code=303)


@app.post("/clients/{client_id}/budgets/{year}")
def upsert_budget(
    client_id: int,
    year: int,
    currency: str = Form("ARS"),
    support_amount: str = Form("0"),
    improvement_amount: str = Form("0"),
    session: Session = Depends(get_session),
):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    budget = _get_budget(session, client_id, year)
    if budget is None:
        budget = AnnualBudget(client_id=client_id, year=year)

    budget.currency = (currency or "ARS").strip().upper()
    budget.support_amount = _to_decimal(support_amount)
    budget.improvement_amount = _to_decimal(improvement_amount)

    session.add(budget)
    session.commit()

    return RedirectResponse(url=f"/clients/{client_id}?year={year}", status_code=303)


@app.post("/clients/{client_id}/projects")
def create_project(
    client_id: int,
    year: int = Form(...),
    name: str = Form(...),
    estimated_support_cost: str = Form("0"),
    estimated_improvement_cost: str = Form("0"),
    estimated_extra_cost: str = Form("0"),
    included: Optional[str] = Form(None),
    description: str = Form(""),
    session: Session = Depends(get_session),
):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    project = Project(
        client_id=client_id,
        year=year,
        name=name.strip(),
        approved=False,
        included=included is not None,
        estimated_support_cost=_non_negative(_to_decimal(estimated_support_cost)),
        estimated_improvement_cost=_non_negative(
            _to_decimal(estimated_improvement_cost)
        ),
        estimated_extra_cost=_non_negative(_to_decimal(estimated_extra_cost)),
        description=description.strip(),
    )
    session.add(project)
    session.commit()

    return RedirectResponse(url=f"/clients/{client_id}?year={year}", status_code=303)


@app.get("/projects/{project_id}")
def edit_project_page(
    request: Request,
    project_id: int,
    session: Session = Depends(get_session),
):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    client = session.get(Client, project.client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    return templates.TemplateResponse(
        request,
        "project_edit.html",
        {"title": "Editar proyecto", "project": project, "client": client},
    )


@app.post("/projects/{project_id}")
def update_project(
    project_id: int,
    name: str = Form(...),
    approved: Optional[str] = Form(None),
    included: Optional[str] = Form(None),
    year: int = Form(...),
    estimated_support_cost: str = Form("0"),
    estimated_improvement_cost: str = Form("0"),
    estimated_extra_cost: str = Form("0"),
    description: str = Form(""),
    session: Session = Depends(get_session),
):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    project.name = name.strip()
    is_approved = approved is not None
    project.approved = is_approved
    # Si está aprobado, siempre cuenta. Si no, depende del flag incluido.
    project.included = True if is_approved else (included is not None)
    project.year = year
    project.estimated_support_cost = _non_negative(_to_decimal(estimated_support_cost))
    project.estimated_improvement_cost = _non_negative(
        _to_decimal(estimated_improvement_cost)
    )
    project.estimated_extra_cost = _non_negative(_to_decimal(estimated_extra_cost))

    project.description = description.strip()

    session.add(project)
    session.commit()

    return RedirectResponse(
        url=f"/clients/{project.client_id}?year={project.year}", status_code=303
    )


@app.get("/report")
def report_page(
    request: Request,
    year: Optional[int] = None,
    session: Session = Depends(get_session),
):
    if year is None:
        year = datetime.utcnow().year

    clients = session.exec(select(Client).order_by(Client.name)).all()

    rows = []
    for client in clients:
        budget = _get_budget(session, client.id, year)  # type: ignore[arg-type]
        currency = budget.currency if budget else "ARS"
        support_budget = budget.support_amount if budget else Decimal("0")
        improvement_budget = budget.improvement_amount if budget else Decimal("0")

        projects = session.exec(
            select(Project).where(Project.client_id == client.id, Project.year == year)
        ).all()

        considered = [p for p in projects if _project_counts_for_totals(p)]

        used_support = sum(
            (p.estimated_support_cost for p in considered), start=Decimal("0")
        )
        used_improvement = sum(
            (p.estimated_improvement_cost for p in considered), start=Decimal("0")
        )
        used_extra = sum(
            (p.estimated_extra_cost for p in considered), start=Decimal("0")
        )

        rows.append(
            {
                "client": client,
                "currency": currency,
                "support_budget": support_budget,
                "support_used": used_support,
                "support_remaining": support_budget - used_support,
                "improvement_budget": improvement_budget,
                "improvement_used": used_improvement,
                "improvement_remaining": improvement_budget - used_improvement,
                "extra_used": used_extra,
                "projects_count": len(projects),
                "projects_considered_count": len(considered),
                "projects": sorted(projects, key=lambda p: p.created_at, reverse=True),
            }
        )

    return templates.TemplateResponse(
        request,
        "report.html",
        {"title": f"Reporte {year}", "year": year, "rows": rows},
    )


@app.post("/projects/{project_id}/include")
def set_project_included(
    project_id: int,
    included: int = Form(...),
    next: str = Form(""),
    session: Session = Depends(get_session),
):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    # No permitir excluir un proyecto aprobado desde la simulación.
    if project.approved is True:
        project.included = True
    else:
        project.included = bool(int(included))

    session.add(project)
    session.commit()

    # Redirección segura (solo paths relativos dentro de la app).
    if next and next.startswith("/") and not next.startswith("//"):
        return RedirectResponse(url=next, status_code=303)

    return RedirectResponse(
        url=f"/clients/{project.client_id}?year={project.year}", status_code=303
    )


@app.post("/projects/{project_id}/approve")
def approve_project(
    project_id: int,
    next: str = Form(""),
    session: Session = Depends(get_session),
):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    project.approved = True
    project.included = True

    session.add(project)
    session.commit()

    if next and next.startswith("/") and not next.startswith("//"):
        return RedirectResponse(url=next, status_code=303)
    return RedirectResponse(
        url=f"/clients/{project.client_id}?year={project.year}", status_code=303
    )


# Alias legacy: antes `/approval` mutaba approved; ahora se usa como toggle de inclusión.
@app.post("/projects/{project_id}/approval")
def legacy_set_project_approval(
    project_id: int,
    approved: int = Form(...),
    next: str = Form(""),
    session: Session = Depends(get_session),
):
    return set_project_included(
        project_id=project_id, included=approved, next=next, session=session
    )


@app.post("/projects/{project_id}/delete")
def delete_project(project_id: int, session: Session = Depends(get_session)):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    client_id = project.client_id
    year = project.year

    session.delete(project)
    session.commit()

    return RedirectResponse(url=f"/clients/{client_id}?year={year}", status_code=303)


# ============================================================================
# Odoo Review Section (for existing tasks, tickets, and projects)
# ============================================================================

# Status mapping for Odoo tasks and tickets (0-5)
ODOO_STATUS_MAP = {
    0: "Pendiente",
    1: "En Progreso",
    2: "En Revisión",
    3: "Completado",
    4: "Cerrado",
    5: "Cancelado",
}


def get_status_label(status: int) -> str:
    return ODOO_STATUS_MAP.get(status, f"Estado {status}")


@app.get("/odoo/review", name="odoo_review")
def odoo_review(
    request: Request,
    session: Session = Depends(get_session),
    search: str = "",
    filter_type: str = "all",  # all, orphan_tickets, orphan_tasks
):
    """Review page for Odoo tasks, tickets, and projects."""
    
    # Get tasks and tickets
    tasks = session.exec(select(OdooTask)).all()
    tickets = session.exec(select(OdooTicket)).all()
    projects = session.exec(select(OdooProject)).all()
    
    # Apply search filter
    if search:
        search_lower = search.lower()
        tasks = [t for t in tasks if search_lower in str(t.task_id).lower()]
        tickets = [t for t in tickets if search_lower in str(t.ticket_id).lower()]
        projects = [p for p in projects if search_lower in p.name.lower() or search_lower in str(p.project_id).lower()]
    
    # Find orphans
    orphan_tickets = [t for t in tickets if t.task_id is None]
    orphan_tasks = [t for t in tasks if t.ticket_id is None]
    
    # Apply filter
    if filter_type == "orphan_tickets":
        tickets = orphan_tickets
        tasks = []
        projects = []
    elif filter_type == "orphan_tasks":
        tasks = orphan_tasks
        tickets = []
        projects = []
    
    return templates.TemplateResponse(
        request,
        "odoo_review.html",
        {
            "tasks": tasks,
            "tickets": tickets,
            "projects": projects,
            "orphan_tickets_count": len(orphan_tickets),
            "orphan_tasks_count": len(orphan_tasks),
            "search": search,
            "filter_type": filter_type,
            "get_status_label": get_status_label,
        },
    )


@app.get("/odoo/tasks/{task_id}/edit", name="odoo_task_edit")
def odoo_task_edit_get(
    task_id: int,
    request: Request,
    session: Session = Depends(get_session),
):
    """Edit Odoo task page."""
    task = session.get(OdooTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    
    return templates.TemplateResponse(
        request,
        "odoo_task_edit.html",
        {
            "task": task,
            "get_status_label": get_status_label,
        },
    )


@app.post("/odoo/tasks/{task_id}/edit", name="odoo_task_edit_post")
def odoo_task_edit_post(
    task_id: int,
    request: Request,
    session: Session = Depends(get_session),
    odoo_task_id: int = Form(...),
    status: int = Form(...),
    ticket_id: Optional[int] = Form(None),
    feature_id: Optional[int] = Form(None),
    project_id: Optional[int] = Form(None),
):
    """Update Odoo task."""
    task = session.get(OdooTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    
    task.task_id = odoo_task_id
    task.status = status
    task.ticket_id = ticket_id or None
    task.feature_id = feature_id or None
    task.project_id = project_id or None
    task.updated_at = datetime.utcnow()
    
    session.add(task)
    session.commit()
    
    return RedirectResponse(url="/odoo/review", status_code=303)


@app.get("/odoo/tickets/{ticket_id}/edit", name="odoo_ticket_edit")
def odoo_ticket_edit_get(
    ticket_id: int,
    request: Request,
    session: Session = Depends(get_session),
):
    """Edit Odoo ticket page."""
    ticket = session.get(OdooTicket, ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket no encontrado")
    
    return templates.TemplateResponse(
        request,
        "odoo_ticket_edit.html",
        {
            "ticket": ticket,
            "get_status_label": get_status_label,
        },
    )


@app.post("/odoo/tickets/{ticket_id}/edit", name="odoo_ticket_edit_post")
def odoo_ticket_edit_post(
    ticket_id: int,
    request: Request,
    session: Session = Depends(get_session),
    odoo_ticket_id: int = Form(...),
    status: int = Form(...),
    task_id: Optional[int] = Form(None),
):
    """Update Odoo ticket."""
    ticket = session.get(OdooTicket, ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket no encontrado")
    
    ticket.ticket_id = odoo_ticket_id
    ticket.status = status
    ticket.task_id = task_id or None
    ticket.updated_at = datetime.utcnow()
    
    session.add(ticket)
    session.commit()
    
    return RedirectResponse(url="/odoo/review", status_code=303)


@app.get("/odoo/projects/{project_id}/edit", name="odoo_project_edit")
def odoo_project_edit_get(
    project_id: int,
    request: Request,
    session: Session = Depends(get_session),
):
    """Edit Odoo project page."""
    project = session.get(OdooProject, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    
    return templates.TemplateResponse(
        request,
        "odoo_project_edit.html",
        {
            "project": project,
        },
    )


@app.post("/odoo/projects/{project_id}/edit", name="odoo_project_edit_post")
def odoo_project_edit_post(
    project_id: int,
    request: Request,
    session: Session = Depends(get_session),
    odoo_project_id: int = Form(...),
    name: str = Form(...),
    keys: str = Form(""),
    tags: str = Form(""),
    tag_id: Optional[int] = Form(None),
):
    """Update Odoo project."""
    project = session.get(OdooProject, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    
    project.project_id = odoo_project_id
    project.name = name
    project.keys = keys
    project.tags = tags
    project.tag_id = tag_id or None
    
    session.add(project)
    session.commit()
    
    return RedirectResponse(url="/odoo/review", status_code=303)

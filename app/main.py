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

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from .db import engine, get_session, init_db
from .models import AnnualBudget, AuthSession, Client, Project, User

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


def _get_budget(session: Session, client_id: int, year: int) -> Optional[AnnualBudget]:
    statement = select(AnnualBudget).where(
        AnnualBudget.client_id == client_id,
        AnnualBudget.year == year,
    )
    return session.exec(statement).first()


def _budget_warning_message(
    session: Session, *, client_id: int, year: int
) -> Optional[str]:
    budget = _get_budget(session, client_id, year)
    if budget is None:
        return None

    projects = session.exec(
        select(Project).where(Project.client_id == client_id, Project.year == year)
    ).all()

    # Warning para tomar decisión: considera todos (aprobados + borradores).
    used_support = sum((p.estimated_support_cost for p in projects), start=Decimal("0"))
    used_improvement = sum(
        (p.estimated_improvement_cost for p in projects), start=Decimal("0")
    )

    remaining_support = budget.support_amount - used_support
    remaining_improvement = budget.improvement_amount - used_improvement

    parts: list[str] = []
    if remaining_support < 0:
        parts.append(
            f"Soporte excedido por {budget.currency} {_fmt_money(abs(remaining_support))}"
        )
    if remaining_improvement < 0:
        parts.append(
            f"Mejora excedida por {budget.currency} {_fmt_money(abs(remaining_improvement))}"
        )
    if not parts:
        return None
    return "⚠ Presupuesto excedido: " + " · ".join(parts)


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

    if message is None:
        message = _budget_warning_message(session, client_id=client_id, year=year)

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
        },
    )


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

    warning = _budget_warning_message(session, client_id=client_id, year=year)
    if warning:
        return RedirectResponse(
            url=f"/clients/{client_id}?year={year}&message={quote_plus(warning)}",
            status_code=303,
        )

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

    warning = _budget_warning_message(
        session, client_id=project.client_id, year=project.year
    )
    if warning:
        return RedirectResponse(
            url=f"/clients/{project.client_id}?year={project.year}&message={quote_plus(warning)}",
            status_code=303,
        )

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

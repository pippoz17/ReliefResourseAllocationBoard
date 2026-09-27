import os
import json
import base64
import hashlib
import hmac
import secrets
from datetime import date
from pathlib import Path

from dotenv import load_dotenv
import mysql.connector

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

ROOT = Path(__file__).parent

DB = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "database": os.getenv("DB_NAME", "relief_board"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
}

SECRET = os.getenv("SECRET_KEY", "local-demo-secret")

app = FastAPI(title="Relief Resource Allocation Board")

app.mount(
    "/static",
    StaticFiles(directory=str(ROOT / "static")),
    name="static",
)

templates = Jinja2Templates(directory=str(ROOT / "templates"))


# ============================================================
# DATABASE HELPERS
# ============================================================

def conn():
    return mysql.connector.connect(**DB)


def one(sql, params=()):
    connection = conn()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(sql, params)
        return cursor.fetchone()
    finally:
        cursor.close()
        connection.close()


def all_(sql, params=()):
    connection = conn()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(sql, params)
        return cursor.fetchall()
    finally:
        cursor.close()
        connection.close()


def run(sql, params=()):
    connection = conn()
    cursor = connection.cursor()

    try:
        cursor.execute(sql, params)
        record_id = cursor.lastrowid
        connection.commit()
        return record_id
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def log(
    entity,
    entity_id,
    action,
    actor,
    before=None,
    after=None,
    reason=None,
):
    run(
        """
        INSERT INTO audit_logs
        (
            entity_type,
            entity_id,
            action,
            actor_id,
            before_value,
            after_value,
            reason
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            entity,
            entity_id,
            action,
            actor,
            json.dumps(before) if before is not None else None,
            json.dumps(after) if after is not None else None,
            reason,
        ),
    )


# ============================================================
# PASSWORD / SESSION HELPERS
# ============================================================

def hpw(password):
    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        180000,
    )

    return (
        "pbkdf2$180000$"
        + base64.urlsafe_b64encode(salt).decode()
        + "$"
        + base64.urlsafe_b64encode(digest).decode()
    )


def vpw(password, stored):
    try:
        _, iterations, salt, digest = stored.split("$")

        salt = base64.urlsafe_b64decode(salt)
        expected = base64.urlsafe_b64decode(digest)

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            int(iterations),
        )

        return hmac.compare_digest(actual, expected)

    except Exception:
        return False


def token(user_id):
    encoded = base64.urlsafe_b64encode(
        str(user_id).encode()
    ).decode().rstrip("=")

    signature = hmac.new(
        SECRET.encode(),
        encoded.encode(),
        hashlib.sha256,
    ).hexdigest()

    return encoded + "." + signature


def user(request: Request):
    session = request.cookies.get("relief_session")

    if not session:
        return None

    try:
        encoded, signature = session.split(".", 1)

        expected_signature = hmac.new(
            SECRET.encode(),
            encoded.encode(),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(
            signature,
            expected_signature,
        ):
            return None

        padding = "=" * (-len(encoded) % 4)

        user_id = int(
            base64.urlsafe_b64decode(
                encoded + padding
            ).decode()
        )

        return one(
            """
            SELECT id, name, email, role
            FROM users
            WHERE id = %s
            """,
            (user_id,),
        )

    except Exception:
        return None


def page(request: Request, template_name, **context):
    context.update(
        request=request,
        user=user(request),
        today=date.today(),
    )

    return templates.TemplateResponse(
        template_name,
        context,
    )


def guard(request: Request, roles):
    current_user = user(request)

    if not current_user:
        return None, RedirectResponse("/login", status_code=303)

    if current_user["role"] not in roles:
        return (
            None,
            page(
                request,
                "message.html",
                title="ACCESS DENIED",
                message="Your role cannot perform this action.",
            ),
        )

    return current_user, None


# ============================================================
# MATCHING ENGINE
# ============================================================

ZONE = {
    ("A", "A"): 0,
    ("A", "B"): 5,
    ("A", "C"): 11,
    ("A", "D"): 18,
    ("B", "A"): 5,
    ("B", "B"): 0,
    ("B", "C"): 7,
    ("B", "D"): 14,
    ("C", "A"): 11,
    ("C", "B"): 7,
    ("C", "C"): 0,
    ("C", "D"): 8,
    ("D", "A"): 18,
    ("D", "B"): 14,
    ("D", "C"): 8,
    ("D", "D"): 0,
}

PRIORITY = {
    "CRITICAL": 1,
    "HIGH": 0.75,
    "MEDIUM": 0.5,
    "LOW": 0.25,
}


def match(request_data, resources):
    remaining = (
        float(request_data["required_qty"])
        - float(request_data["allocated_qty"])
    )

    proposals = []

    for resource in resources:

        if resource["status"] != "available":
            continue

        if float(resource["available_qty"]) <= 0:
            continue

        if (
            resource["capability"].lower()
            != request_data["required_capability"].lower()
        ):
            continue

        if (
            resource["expiry_date"]
            and resource["expiry_date"] < date.today()
        ):
            continue

        request_type = request_data["request_type"].lower()
        resource_type = resource["resource_type"]

        # Resource-type compatibility
        if (
            "shelter" in request_type
            and resource_type != "shelter"
        ):
            continue

        if (
            "ambulance" in request_type
            and resource_type != "vehicle"
        ):
            continue

        if (
            "transport" in request_type
            and resource_type != "vehicle"
        ):
            continue

        if (
            "first aid" in request_type
            and resource_type != "volunteer"
        ):
            continue

        supply_types = [
            "water",
            "medical oxygen",
            "medical kit",
            "food",
            "blanket",
        ]

        if (
            request_type in supply_types
            and resource_type != "supply"
        ):
            continue

        if remaining <= 0:
            break

        request_zone = request_data["location_zone"][-1]
        resource_zone = resource["location_zone"][-1]

        distance = ZONE.get(
            (resource_zone, request_zone),
            20,
        )

        priority_score = (
            PRIORITY[request_data["priority"]] * 35
        )

        proximity_score = (
            max(0, 1 - distance / 20) * 25
        )

        availability_score = (
            min(
                1,
                float(resource["available_qty"])
                / remaining,
            )
            * 15
        )

        expiry_score = 10

        if resource["expiry_date"]:
            days_until_expiry = (
                resource["expiry_date"] - date.today()
            ).days

            expiry_score = max(
                0,
                min(
                    1,
                    1 - days_until_expiry / 30,
                ),
            ) * 15

        capability_score = 10

        score = round(
            priority_score
            + proximity_score
            + availability_score
            + expiry_score
            + capability_score,
            2,
        )

        reasons = [
            (
                f"{request_data['priority']} priority "
                f"→ {priority_score:.1f}/35"
            ),
            (
                f"{distance:g} km from request "
                f"→ {proximity_score:.1f}/25"
            ),
            (
                f"{resource['available_qty']:g} available "
                f"→ {availability_score:.1f}/15"
            ),
        ]

        if resource["expiry_date"]:
            reasons.append(
                f"Expires in {days_until_expiry} day(s) "
                f"→ {expiry_score:.1f}/15"
            )
        else:
            reasons.append(
                "No expiry penalty → 10/15"
            )

        reasons.append(
            "Exact capability match → 10/10"
        )

        proposals.append(
            {
                "resource": resource,
                "qty": min(
                    float(resource["available_qty"]),
                    remaining,
                ),
                "score": score,
                "breakdown": {
                    "priority": round(priority_score, 2),
                    "distance": round(proximity_score, 2),
                    "availability": round(
                        availability_score,
                        2,
                    ),
                    "expiry": round(expiry_score, 2),
                    "capability": capability_score,
                    "distance_km": distance,
                    "reasons": reasons,
                },
            }
        )

    proposals.sort(
        key=lambda item: -item["score"]
    )

    selected = []

    for proposal in proposals:
        if remaining <= 0:
            break

        proposal["qty"] = min(
            proposal["qty"],
            remaining,
        )

        remaining -= proposal["qty"]
        selected.append(proposal)

    return selected, round(
        max(0, remaining),
        2,
    )


def conflicts():
    rows = all_(
        """
        SELECT
            a.resource_id,
            res.name AS resource_name,
            res.available_qty,
            SUM(a.proposed_qty) AS proposed_total,
            COUNT(*) AS competitors
        FROM allocations a
        JOIN resources res
            ON res.id = a.resource_id
        JOIN requests r
            ON r.id = a.request_id
        WHERE a.status IN
            ('PENDING_APPROVAL', 'PROPOSED', 'CONFLICT')
          AND r.status IN
            ('OPEN', 'PARTIALLY_FULFILLED')
        GROUP BY
            a.resource_id,
            res.name,
            res.available_qty
        HAVING
            SUM(a.proposed_qty) > res.available_qty
            OR COUNT(*) > 1
        """
    )

    for row in rows:
        row["over"] = max(
            0,
            float(row["proposed_total"])
            - float(row["available_qty"]),
        )

    return rows


# ============================================================
# BASIC ROUTES
# IMPORTANT:
# Every FastAPI route that receives the HTTP request MUST use
# request: Request. This prevents FastAPI from treating "req"
# as a required query parameter.
# ============================================================

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    if user(request):
        return RedirectResponse(
            "/dashboard",
            status_code=303,
        )

    return RedirectResponse(
        "/login",
        status_code=303,
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return page(
        request,
        "login.html",
        error=None,
    )


@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    current_user = one(
        """
        SELECT *
        FROM users
        WHERE email = %s
        """,
        (email.strip().lower(),),
    )

    if (
        not current_user
        or not vpw(
            password,
            current_user["password_hash"],
        )
    ):
        return page(
            request,
            "login.html",
            error="Invalid credentials.",
        )

    response = RedirectResponse(
        "/dashboard",
        status_code=303,
    )

    response.set_cookie(
        "relief_session",
        token(current_user["id"]),
        httponly=True,
        samesite="lax",
        max_age=28800,
    )

    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(
        "/login",
        status_code=303,
    )

    response.delete_cookie("relief_session")

    return response


# ============================================================
# DASHBOARD
# ============================================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    if not user(request):
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    summary = {
        "active": one(
            """
            SELECT COUNT(*) AS c
            FROM requests
            WHERE status IN
                ('OPEN', 'PARTIALLY_FULFILLED')
            """
        )["c"],

        "critical": one(
            """
            SELECT COUNT(*) AS c
            FROM requests
            WHERE status IN
                ('OPEN', 'PARTIALLY_FULFILLED')
              AND priority = 'CRITICAL'
            """
        )["c"],

        "resources": float(
            one(
                """
                SELECT COALESCE(
                    SUM(available_qty), 0
                ) AS c
                FROM resources
                WHERE status = 'available'
                """
            )["c"]
        ),

        "allocations": one(
            """
            SELECT COUNT(*) AS c
            FROM allocations
            WHERE status IN
                ('APPROVED', 'MODIFIED')
            """
        )["c"],

        "unmet": float(
            one(
                """
                SELECT COALESCE(
                    SUM(required_qty - allocated_qty),
                    0
                ) AS c
                FROM requests
                WHERE status IN
                    ('OPEN', 'PARTIALLY_FULFILLED')
                """
            )["c"]
        ),

        "transit": one(
            """
            SELECT COUNT(*) AS c
            FROM dispatches
            WHERE status IN
                ('DISPATCHED', 'IN_TRANSIT')
            """
        )["c"],

        "conflicts": len(conflicts()),
    }

    requests_list = all_(
        """
        SELECT
            r.*,
            required_qty - allocated_qty AS unmet
        FROM requests r
        WHERE status IN
            ('OPEN', 'PARTIALLY_FULFILLED')
        ORDER BY
            FIELD(
                priority,
                'CRITICAL',
                'HIGH',
                'MEDIUM',
                'LOW'
            ),
            created_at
        LIMIT 8
        """
    )

    allocations_list = all_(
        """
        SELECT
            a.*,
            r.request_type,
            r.priority,
            res.name AS resource_name
        FROM allocations a
        JOIN requests r
            ON r.id = a.request_id
        JOIN resources res
            ON res.id = a.resource_id
        ORDER BY a.id DESC
        LIMIT 8
        """
    )

    dispatches_list = all_(
        """
        SELECT
            d.*,
            a.request_id,
            a.approved_qty,
            r.request_type,
            res.name AS resource_name
        FROM dispatches d
        JOIN allocations a
            ON a.id = d.allocation_id
        JOIN requests r
            ON r.id = a.request_id
        JOIN resources res
            ON res.id = a.resource_id
        ORDER BY d.id DESC
        LIMIT 5
        """
    )

    return page(
        request,
        "dashboard.html",
        s=summary,
        reqs=requests_list,
        acts=allocations_list,
        ds=dispatches_list,
        conf=conflicts()[:5],
    )


# ============================================================
# REQUESTS
# ============================================================

@app.get("/requests", response_class=HTMLResponse)
def requests_page(request: Request):
    if not user(request):
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    rows = all_(
        """
        SELECT
            r.*,
            required_qty - allocated_qty AS unmet,
            u.name AS creator
        FROM requests r
        JOIN users u
            ON u.id = r.created_by
        ORDER BY
            FIELD(
                priority,
                'CRITICAL',
                'HIGH',
                'MEDIUM',
                'LOW'
            ),
            id DESC
        """
    )

    return page(
        request,
        "requests.html",
        rows=rows,
    )


def auto_match_request(request_id):
    request_data = one(
        "SELECT * FROM requests WHERE id = %s",
        (request_id,),
    )

    if (
        not request_data
        or request_data["status"]
        not in ("OPEN", "PARTIALLY_FULFILLED")
    ):
        return

    resources = all_(
        """
        SELECT *
        FROM resources
        WHERE status = 'available'
          AND available_qty > 0
        """
    )

    proposals, unmet = match(
        request_data,
        resources,
    )

    run(
        """
        DELETE FROM allocations
        WHERE request_id = %s
          AND status IN
              ('PROPOSED', 'PENDING_APPROVAL', 'CONFLICT')
        """,
        (request_id,),
    )

    for proposal in proposals:
        run(
            """
            INSERT INTO allocations
            (
                request_id,
                resource_id,
                proposed_qty,
                score,
                score_breakdown,
                status
            )
            VALUES
            (%s, %s, %s, %s, %s, %s)
            """,
            (
                request_id,
                proposal["resource"]["id"],
                proposal["qty"],
                proposal["score"],
                json.dumps(proposal["breakdown"]),
                "PENDING_APPROVAL",
            ),
        )


def auto_rematch_open_requests():
    active_requests = all_(
        """
        SELECT id
        FROM requests
        WHERE status IN
            ('OPEN', 'PARTIALLY_FULFILLED')
        ORDER BY
            FIELD(
                priority,
                'CRITICAL',
                'HIGH',
                'MEDIUM',
                'LOW'
            ),
            created_at
        """
    )

    for request_data in active_requests:
        auto_match_request(
            request_data["id"]
        )


@app.post("/requests/create")
def create_request(
    request: Request,
    request_type: str = Form(...),
    required_capability: str = Form(...),
    required_qty: float = Form(...),
    location_zone: str = Form(...),
    priority: str = Form(...),
    urgency: int = Form(70),
    deadline: str = Form(""),
    notes: str = Form(""),
):
    current_user, error = guard(
        request,
        {"coordinator", "admin"},
    )

    if error:
        return error

    if required_qty <= 0:
        return page(
            request,
            "message.html",
            title="INVALID REQUEST",
            message="Quantity must be positive.",
        )

    deadline_value = (
        deadline.replace("T", " ")
        if deadline
        else None
    )

    request_id = run(
        """
        INSERT INTO requests
        (
            request_type,
            required_capability,
            required_qty,
            location_zone,
            priority,
            urgency,
            deadline,
            notes,
            created_by
        )
        VALUES
        (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            request_type,
            required_capability,
            required_qty,
            location_zone,
            priority,
            urgency,
            deadline_value,
            notes,
            current_user["id"],
        ),
    )

    log(
        "request",
        request_id,
        "CREATED",
        current_user["id"],
        after={
            "required_qty": required_qty,
            "priority": priority,
        },
    )

    auto_match_request(request_id)

    return RedirectResponse(
        f"/matching?request_id={request_id}",
        status_code=303,
    )


# ============================================================
# RESOURCES
# ============================================================

@app.get("/resources", response_class=HTMLResponse)
def resources_page(request: Request):
    if not user(request):
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    return page(
        request,
        "resources.html",
        rows=all_(
            """
            SELECT *
            FROM resources
            ORDER BY
                status,
                resource_type,
                name
            """
        ),
    )


@app.post("/resources/create")
def create_resource(
    request: Request,
    resource_type: str = Form(...),
    name: str = Form(...),
    capability: str = Form(...),
    total_qty: float = Form(...),
    available_qty: float = Form(...),
    location_zone: str = Form(...),
    expiry_date: str = Form(""),
):
    current_user, error = guard(
        request,
        {
            "coordinator",
            "resource_manager",
            "admin",
        },
    )

    if error:
        return error

    if (
        total_qty <= 0
        or available_qty < 0
        or available_qty > total_qty
    ):
        return page(
            request,
            "message.html",
            title="INVALID RESOURCE",
            message=(
                "Available quantity must be "
                "between zero and total quantity."
            ),
        )

    resource_id = run(
        """
        INSERT INTO resources
        (
            resource_type,
            name,
            capability,
            total_qty,
            available_qty,
            location_zone,
            expiry_date,
            status
        )
        VALUES
        (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            resource_type,
            name,
            capability,
            total_qty,
            available_qty,
            location_zone,
            expiry_date or None,
            "available"
            if available_qty
            else "depleted",
        ),
    )

    log(
        "resource",
        resource_id,
        "CREATED",
        current_user["id"],
        after={
            "name": name,
            "available_qty": available_qty,
        },
    )

    auto_rematch_open_requests()

    return RedirectResponse(
        "/resources",
        status_code=303,
    )


@app.post("/resources/{resource_id}/toggle")
def toggle_resource(
    request: Request,
    resource_id: int,
):
    current_user, error = guard(
        request,
        {
            "coordinator",
            "resource_manager",
            "admin",
        },
    )

    if error:
        return error

    resource = one(
        "SELECT * FROM resources WHERE id = %s",
        (resource_id,),
    )

    if not resource:
        raise HTTPException(
            status_code=404,
            detail="Resource not found",
        )

    if resource["status"] == "available":
        new_status = "unavailable"
    elif resource["available_qty"] > 0:
        new_status = "available"
    else:
        new_status = "depleted"

    run(
        """
        UPDATE resources
        SET status = %s
        WHERE id = %s
        """,
        (new_status, resource_id),
    )

    log(
        "resource",
        resource_id,
        "STATUS_CHANGED",
        current_user["id"],
        before={"status": resource["status"]},
        after={"status": new_status},
    )

    return RedirectResponse(
        "/resources",
        status_code=303,
    )


# ============================================================
# MATCHING BOARD
# ============================================================

@app.get("/matching", response_class=HTMLResponse)
def matching_page(
    request: Request,
    request_id: int = 0,
):
    if not user(request):
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    queue = all_(
        """
        SELECT
            *,
            required_qty - allocated_qty AS unmet
        FROM requests
        WHERE status IN
            ('OPEN', 'PARTIALLY_FULFILLED')
        ORDER BY
            FIELD(
                priority,
                'CRITICAL',
                'HIGH',
                'MEDIUM',
                'LOW'
            ),
            created_at
        """
    )

    selected = None

    if request_id:
        selected = one(
            """
            SELECT
                *,
                required_qty - allocated_qty AS unmet
            FROM requests
            WHERE id = %s
            """,
            (request_id,),
        )

    proposals = []

    if selected:
        proposals = all_(
            """
            SELECT
                a.*,
                res.name AS resource_name,
                res.resource_type,
                res.capability,
                res.available_qty,
                res.location_zone,
                res.expiry_date
            FROM allocations a
            JOIN resources res
                ON res.id = a.resource_id
            WHERE a.request_id = %s
              AND a.status IN
                  ('PENDING_APPROVAL', 'PROPOSED', 'CONFLICT')
            ORDER BY score DESC
            """,
            (request_id,),
        )

        for proposal in proposals:
            if isinstance(
                proposal["score_breakdown"],
                str,
            ):
                proposal["score_breakdown"] = json.loads(
                    proposal["score_breakdown"]
                )

    return page(
        request,
        "matching.html",
        queue=queue,
        selected=selected,
        props=proposals,
        conf=conflicts(),
    )


@app.post("/requests/{request_id}/match")
def run_match(
    request: Request,
    request_id: int,
):
    current_user, error = guard(
        request,
        {"coordinator", "admin"},
    )

    if error:
        return error

    request_data = one(
        "SELECT * FROM requests WHERE id = %s",
        (request_id,),
    )

    if not request_data:
        raise HTTPException(
            status_code=404,
            detail="Request not found",
        )

    if request_data["status"] not in (
        "OPEN",
        "PARTIALLY_FULFILLED",
    ):
        return page(
            request,
            "message.html",
            title="MATCHING BLOCKED",
            message="This request is not open for matching.",
        )

    resources = all_(
        """
        SELECT *
        FROM resources
        WHERE status = 'available'
          AND available_qty > 0
        """
    )

    proposals, unmet = match(
        request_data,
        resources,
    )

    run(
        """
        DELETE FROM allocations
        WHERE request_id = %s
          AND status IN
              ('PROPOSED', 'PENDING_APPROVAL', 'CONFLICT')
        """,
        (request_id,),
    )

    for proposal in proposals:
        run(
            """
            INSERT INTO allocations
            (
                request_id,
                resource_id,
                proposed_qty,
                score,
                score_breakdown,
                status
            )
            VALUES
            (%s, %s, %s, %s, %s, 'PENDING_APPROVAL')
            """,
            (
                request_id,
                proposal["resource"]["id"],
                proposal["qty"],
                proposal["score"],
                json.dumps(proposal["breakdown"]),
            ),
        )

    return RedirectResponse(
        f"/matching?request_id={request_id}",
        status_code=303,
    )


# ============================================================
# APPROVAL / MODIFY / REJECT
# ============================================================

@app.post("/allocations/{allocation_id}/approve")
def approve(
    request: Request,
    allocation_id: int,
    approved_qty: float = Form(None),
):
    current_user, error = guard(
        request,
        {"coordinator", "admin"},
    )

    if error:
        return error

    connection = conn()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT
                a.*,
                r.required_qty,
                r.allocated_qty AS request_allocated
            FROM allocations a
            JOIN requests r
                ON r.id = a.request_id
            WHERE a.id = %s
            FOR UPDATE
            """,
            (allocation_id,),
        )

        allocation = cursor.fetchone()

        if not allocation:
            raise HTTPException(
                status_code=404,
                detail="Allocation not found",
            )

        cursor.execute(
            """
            SELECT *
            FROM resources
            WHERE id = %s
            FOR UPDATE
            """,
            (allocation["resource_id"],),
        )

        resource = cursor.fetchone()

        if not resource:
            raise HTTPException(
                status_code=404,
                detail="Resource not found",
            )

        qty = float(
            approved_qty
            if approved_qty is not None
            else allocation["proposed_qty"]
        )

        available = float(
            resource["available_qty"]
        )

        remaining = (
            float(allocation["required_qty"])
            - float(allocation["request_allocated"])
        )

        if (
            qty <= 0
            or qty > available
            or qty > remaining
        ):
            connection.rollback()

            return page(
                request,
                "message.html",
                title="ALLOCATION BLOCKED",
                message=(
                    f"Current stock: {available:g}. "
                    f"Request remaining: {remaining:g}. "
                    f"Requested approval: {qty:g}. "
                    "The database transaction was not committed."
                ),
            )

        cursor.execute(
            """
            UPDATE resources
            SET
                available_qty = available_qty - %s,
                status =
                    CASE
                        WHEN available_qty - %s <= 0
                        THEN 'depleted'
                        ELSE 'available'
                    END
            WHERE id = %s
            """,
            (
                qty,
                qty,
                resource["id"],
            ),
        )

        cursor.execute(
            """
            UPDATE allocations
            SET
                approved_qty = %s,
                status = 'APPROVED',
                decided_by = %s,
                decided_at = NOW()
            WHERE id = %s
            """,
            (
                qty,
                current_user["id"],
                allocation_id,
            ),
        )

        new_allocated = (
            float(allocation["request_allocated"])
            + qty
        )

        new_status = (
            "FULFILLED"
            if new_allocated
            >= float(allocation["required_qty"])
            else "PARTIALLY_FULFILLED"
        )

        cursor.execute(
            """
            UPDATE requests
            SET
                allocated_qty = %s,
                status = %s
            WHERE id = %s
            """,
            (
                new_allocated,
                new_status,
                allocation["request_id"],
            ),
        )

        cursor.execute(
            """
            INSERT INTO audit_logs
            (
                entity_type,
                entity_id,
                action,
                actor_id,
                before_value,
                after_value
            )
            VALUES
            ('allocation', %s, 'APPROVED', %s, %s, %s)
            """,
            (
                allocation_id,
                current_user["id"],
                json.dumps(
                    {
                        "status": allocation["status"],
                        "proposed_qty": float(
                            allocation["proposed_qty"]
                        ),
                    }
                ),
                json.dumps(
                    {
                        "approved_qty": qty,
                    }
                ),
            ),
        )

        connection.commit()

    except HTTPException:
        raise

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()

    return RedirectResponse(
        f"/matching?request_id={allocation['request_id']}",
        status_code=303,
    )


@app.post("/allocations/{allocation_id}/modify")
def modify(
    request: Request,
    allocation_id: int,
    new_qty: float = Form(...),
    override_reason: str = Form(...),
):
    current_user, error = guard(
        request,
        {"coordinator", "admin"},
    )

    if error:
        return error

    if not override_reason.strip():
        return page(
            request,
            "message.html",
            title="REASON REQUIRED",
            message="Manual override requires a reason.",
        )

    connection = conn()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT
                a.*,
                r.required_qty,
                r.allocated_qty AS request_allocated
            FROM allocations a
            JOIN requests r
                ON r.id = a.request_id
            WHERE a.id = %s
            FOR UPDATE
            """,
            (allocation_id,),
        )

        allocation = cursor.fetchone()

        if not allocation:
            raise HTTPException(
                status_code=404,
                detail="Allocation not found",
            )

        cursor.execute(
            """
            SELECT *
            FROM resources
            WHERE id = %s
            FOR UPDATE
            """,
            (allocation["resource_id"],),
        )

        resource = cursor.fetchone()

        if not resource:
            raise HTTPException(
                status_code=404,
                detail="Resource not found",
            )

        qty = float(new_qty)
        available = float(
            resource["available_qty"]
        )

        remaining = (
            float(allocation["required_qty"])
            - float(allocation["request_allocated"])
        )

        if (
            qty <= 0
            or qty > available
            or qty > remaining
        ):
            connection.rollback()

            return page(
                request,
                "message.html",
                title="OVERRIDE BLOCKED",
                message=(
                    f"Current stock: {available:g}; "
                    f"request remaining: {remaining:g}."
                ),
            )

        before = {
            "status": allocation["status"],
            "proposed_qty": float(
                allocation["proposed_qty"]
            ),
            "score": float(
                allocation["score"]
            ),
        }

        cursor.execute(
            """
            UPDATE resources
            SET
                available_qty = available_qty - %s,
                status =
                    CASE
                        WHEN available_qty - %s <= 0
                        THEN 'depleted'
                        ELSE 'available'
                    END
            WHERE id = %s
            """,
            (
                qty,
                qty,
                resource["id"],
            ),
        )

        cursor.execute(
            """
            UPDATE allocations
            SET
                approved_qty = %s,
                status = 'MODIFIED',
                is_manual_override = TRUE,
                override_reason = %s,
                decided_by = %s,
                decided_at = NOW()
            WHERE id = %s
            """,
            (
                qty,
                override_reason.strip(),
                current_user["id"],
                allocation_id,
            ),
        )

        new_allocated = (
            float(allocation["request_allocated"])
            + qty
        )

        new_status = (
            "FULFILLED"
            if new_allocated
            >= float(allocation["required_qty"])
            else "PARTIALLY_FULFILLED"
        )

        cursor.execute(
            """
            UPDATE requests
            SET
                allocated_qty = %s,
                status = %s
            WHERE id = %s
            """,
            (
                new_allocated,
                new_status,
                allocation["request_id"],
            ),
        )

        cursor.execute(
            """
            INSERT INTO audit_logs
            (
                entity_type,
                entity_id,
                action,
                actor_id,
                before_value,
                after_value,
                reason
            )
            VALUES
            (
                'allocation',
                %s,
                'MODIFIED',
                %s,
                %s,
                %s,
                %s
            )
            """,
            (
                allocation_id,
                current_user["id"],
                json.dumps(before),
                json.dumps(
                    {
                        "approved_qty": qty,
                    }
                ),
                override_reason.strip(),
            ),
        )

        connection.commit()

    except HTTPException:
        raise

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()

    return RedirectResponse(
        f"/matching?request_id={allocation['request_id']}",
        status_code=303,
    )


@app.post("/allocations/{allocation_id}/reject")
def reject(
    request: Request,
    allocation_id: int,
    reason: str = Form(""),
):
    current_user, error = guard(
        request,
        {"coordinator", "admin"},
    )

    if error:
        return error

    allocation = one(
        "SELECT * FROM allocations WHERE id = %s",
        (allocation_id,),
    )

    if not allocation:
        raise HTTPException(
            status_code=404,
            detail="Allocation not found",
        )

    run(
        """
        UPDATE allocations
        SET
            status = 'REJECTED',
            decided_by = %s,
            decided_at = NOW(),
            override_reason = %s
        WHERE id = %s
        """,
        (
            current_user["id"],
            reason,
            allocation_id,
        ),
    )

    log(
        "allocation",
        allocation_id,
        "REJECTED",
        current_user["id"],
        before={"status": allocation["status"]},
        after={"status": "REJECTED"},
        reason=reason,
    )

    return RedirectResponse(
        f"/matching?request_id={allocation['request_id']}",
        status_code=303,
    )


# ============================================================
# DISPATCH
# ============================================================

@app.get("/dispatch", response_class=HTMLResponse)
def dispatch_page(request: Request):
    if not user(request):
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    rows = all_(
        """
        SELECT
            d.*,
            a.request_id,
            a.approved_qty,
            r.request_type,
            r.priority,
            res.name AS resource_name
        FROM dispatches d
        JOIN allocations a
            ON a.id = d.allocation_id
        JOIN requests r
            ON r.id = a.request_id
        JOIN resources res
            ON res.id = a.resource_id
        ORDER BY d.id DESC
        """
    )

    ready = all_(
        """
        SELECT
            a.*,
            r.request_type,
            r.priority,
            res.name AS resource_name
        FROM allocations a
        JOIN requests r
            ON r.id = a.request_id
        JOIN resources res
            ON res.id = a.resource_id
        LEFT JOIN dispatches d
            ON d.allocation_id = a.id
        WHERE a.status IN
            ('APPROVED', 'MODIFIED')
          AND d.id IS NULL
        """
    )

    return page(
        request,
        "dispatch.html",
        rows=rows,
        ready=ready,
    )


@app.post("/allocations/{allocation_id}/dispatch")
def dispatch(
    request: Request,
    allocation_id: int,
    dispatched_qty: float = Form(...),
    owner: str = Form(...),
):
    current_user, error = guard(
        request,
        {
            "dispatcher",
            "coordinator",
            "admin",
        },
    )

    if error:
        return error

    allocation = one(
        "SELECT * FROM allocations WHERE id = %s",
        (allocation_id,),
    )

    if (
        not allocation
        or allocation["status"]
        not in ("APPROVED", "MODIFIED")
        or dispatched_qty <= 0
        or dispatched_qty
        > float(allocation["approved_qty"])
    ):
        return page(
            request,
            "message.html",
            title="DISPATCH BLOCKED",
            message=(
                "Dispatch quantity must be positive "
                "and no greater than approved quantity."
            ),
        )

    dispatch_id = run(
        """
        INSERT INTO dispatches
        (
            allocation_id,
            dispatched_qty,
            owner,
            status,
            dispatched_at
        )
        VALUES
        (%s, %s, %s, 'DISPATCHED', NOW())
        """,
        (
            allocation_id,
            dispatched_qty,
            owner,
        ),
    )

    log(
        "dispatch",
        dispatch_id,
        "DISPATCHED",
        current_user["id"],
        after={
            "allocation_id": allocation_id,
            "qty": dispatched_qty,
            "owner": owner,
        },
    )

    return RedirectResponse(
        "/dispatch",
        status_code=303,
    )


@app.post("/dispatches/{dispatch_id}/deliver")
def deliver(
    request: Request,
    dispatch_id: int,
    delivered_qty: float = Form(...),
):
    current_user, error = guard(
        request,
        {
            "dispatcher",
            "coordinator",
            "admin",
        },
    )

    if error:
        return error

    connection = conn()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT
                d.*,
                a.request_id
            FROM dispatches d
            JOIN allocations a
                ON a.id = d.allocation_id
            WHERE d.id = %s
            FOR UPDATE
            """,
            (dispatch_id,),
        )

        dispatch_data = cursor.fetchone()

        if not dispatch_data:
            raise HTTPException(
                status_code=404,
                detail="Dispatch not found",
            )

        new_total = (
            float(
                dispatch_data[
                    "total_delivered_qty"
                ]
            )
            + delivered_qty
        )

        if (
            delivered_qty <= 0
            or new_total
            > float(
                dispatch_data[
                    "dispatched_qty"
                ]
            )
        ):
            connection.rollback()

            return page(
                request,
                "message.html",
                title="DELIVERY BLOCKED",
                message=(
                    "Cumulative delivered quantity "
                    "cannot exceed dispatched quantity."
                ),
            )

        status = (
            "DELIVERED"
            if new_total
            >= float(
                dispatch_data[
                    "dispatched_qty"
                ]
            )
            else "IN_TRANSIT"
        )

        cursor.execute(
            """
            INSERT INTO deliveries
            (
                dispatch_id,
                delivered_qty,
                recorded_by
            )
            VALUES
            (%s, %s, %s)
            """,
            (
                dispatch_id,
                delivered_qty,
                current_user["id"],
            ),
        )

        cursor.execute(
            """
            UPDATE dispatches
            SET
                total_delivered_qty = %s,
                status = %s
            WHERE id = %s
            """,
            (
                new_total,
                status,
                dispatch_id,
            ),
        )

        cursor.execute(
            """
            INSERT INTO audit_logs
            (
                entity_type,
                entity_id,
                action,
                actor_id,
                after_value
            )
            VALUES
            (
                'delivery',
                %s,
                'DELIVERED',
                %s,
                %s
            )
            """,
            (
                dispatch_id,
                current_user["id"],
                json.dumps(
                    {
                        "event_qty": delivered_qty,
                        "total_delivered": new_total,
                    }
                ),
            ),
        )

        connection.commit()

    except HTTPException:
        raise

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()

    return RedirectResponse(
        "/dispatch",
        status_code=303,
    )


# ============================================================
# API / AUDIT / DETAILS
# ============================================================

@app.get("/api/dashboard/summary")
def api_dashboard_summary(request: Request):
    if not user(request):
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
        )

    return {
        "active": one(
            """
            SELECT COUNT(*) c
            FROM requests
            WHERE status IN
                ('OPEN', 'PARTIALLY_FULFILLED')
            """
        )["c"],

        "critical": one(
            """
            SELECT COUNT(*) c
            FROM requests
            WHERE status IN
                ('OPEN', 'PARTIALLY_FULFILLED')
              AND priority = 'CRITICAL'
            """
        )["c"],

        "resources": float(
            one(
                """
                SELECT COALESCE(
                    SUM(available_qty), 0
                ) c
                FROM resources
                WHERE status = 'available'
                """
            )["c"]
        ),

        "allocations": one(
            """
            SELECT COUNT(*) c
            FROM allocations
            WHERE status IN
                ('APPROVED', 'MODIFIED')
            """
        )["c"],

        "unmet": float(
            one(
                """
                SELECT COALESCE(
                    SUM(required_qty - allocated_qty),
                    0
                ) c
                FROM requests
                WHERE status IN
                    ('OPEN', 'PARTIALLY_FULFILLED')
                """
            )["c"]
        ),

        "transit": one(
            """
            SELECT COUNT(*) c
            FROM dispatches
            WHERE status IN
                ('DISPATCHED', 'IN_TRANSIT')
            """
        )["c"],

        "conflicts": len(conflicts()),
    }


@app.get("/audit", response_class=HTMLResponse)
def audit(request: Request):
    if not user(request):
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    rows = all_(
        """
        SELECT
            a.*,
            u.name AS actor_name
        FROM audit_logs a
        JOIN users u
            ON u.id = a.actor_id
        ORDER BY a.created_at DESC
        LIMIT 300
        """
    )

    return page(
        request,
        "audit.html",
        rows=rows,
    )


@app.get("/allocation/{allocation_id}", response_class=HTMLResponse)
def detail(
    request: Request,
    allocation_id: int,
):
    if not user(request):
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    allocation = one(
        """
        SELECT
            a.*,
            r.request_type,
            r.required_capability,
            r.required_qty,
            r.allocated_qty,
            r.priority,
            res.name AS resource_name
        FROM allocations a
        JOIN requests r
            ON r.id = a.request_id
        JOIN resources res
            ON res.id = a.resource_id
        WHERE a.id = %s
        """,
        (allocation_id,),
    )

    if not allocation:
        raise HTTPException(
            status_code=404,
            detail="Allocation not found",
        )

    logs = all_(
        """
        SELECT
            l.*,
            u.name AS actor_name
        FROM audit_logs l
        JOIN users u
            ON u.id = l.actor_id
        WHERE l.entity_type = 'allocation'
          AND l.entity_id = %s
        ORDER BY l.created_at
        """,
        (allocation_id,),
    )

    dispatch_data = one(
        """
        SELECT *
        FROM dispatches
        WHERE allocation_id = %s
        """,
        (allocation_id,),
    )

    return page(
        request,
        "detail.html",
        a=allocation,
        logs=logs,
        dispatch=dispatch_data,
    )
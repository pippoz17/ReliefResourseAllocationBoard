# Relief Resource Allocation Board — Python + MySQL Edition

This version deliberately removes React, Node, AWS and other frontend/backend stacks. The whole application is **Python (FastAPI + Jinja2) + MySQL**, with HTML/CSS served directly by FastAPI.

## Run

1. Install MySQL 8+ and create the database:
```sql
CREATE DATABASE relief_board CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```
2. Copy `.env.example` to `.env` and set `DB_PASSWORD`.
3. Install:
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```
4. Create tables:
```bash
python setup_db.py
```
5. Seed synthetic demo data:
```bash
python seed.py
```
6. Run:
```bash
uvicorn app:app --reload
```
7. Open `http://127.0.0.1:8000`

Demo login: `coordinator@relief.local` / `demo123`.

## What is implemented

- Automatic matching when a new request is created
- Automatic re-matching of active requests when a new resource is registered
- Live dashboard KPI refresh every 5 seconds on dashboard/matching/dispatch pages

- Request/resource registration
- Supplies, volunteers, vehicles, shelters
- Explainable weighted matching
- Priority/location/availability/expiry/capability scoring
- Conflict monitoring
- Unmet quantities
- Manual approval, override and rejection
- MySQL `SELECT ... FOR UPDATE` transaction for double-allocation protection
- Dispatch ownership and quantity tracking
- Partial delivery with cumulative delivery guard
- Audit history
- Responsive mission-control UI

## Important architecture choice

The frontend is server-rendered HTML/CSS. There is **no React and no Node.js**. Forms post directly to FastAPI routes, which read/write MySQL. This is the fastest way to satisfy the team's requirement to stay with Python + MySQL while still delivering a polished web dashboard.

## Judge demo

1. Dashboard → critical request
2. Matching Board → Run Matching
3. Show score + WHY explanation
4. Show unmet quantity
5. Modify with a reason
6. Approve
7. Dispatch
8. Record partial delivery
9. Audit History

The strongest technical claim is the approval transaction: resource stock is locked with `SELECT ... FOR UPDATE`, re-checked, decremented, request allocation updated and audit written before commit. A concurrent approval therefore cannot over-consume the same resource.

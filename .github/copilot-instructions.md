## Repo summary

This is the backend API for "Système de Gestion des Achats" — a Django REST Framework application (Django 5.x) with a React/Vite frontend located in `../front`. Key features: JWT auth stored in cookies, 3-step approval workflow for purchase requests, email notifications via `services/email_service.py`, optional Google Drive storage via `services/google_drive_service.py`.

## Quick orientation (what an AI agent needs first)

- Entry points: `manage.py` (dev server / migrations) and `simplonservice/settings.py` (environment-driven configuration). For production, the `Procfile` runs Gunicorn: `gunicorn simplonservice.wsgi:application --bind 0.0.0.0:$PORT`.
- Main app: `core/` (models, views, serializers, authentication middleware). Look at `core/models.py`, `core/serializers.py`, and `core/views.py` for primary data flows.
- Services: `services/email_service.py` (async threaded email helper) and `services/google_drive_service.py` (service-account Drive uploads). These encapsulate external integrations; prefer to unit-test by mocking these classes.

## Architecture notes (big picture)

- Auth: custom `CustomUser` (`core.models.CustomUser`) + JWT via `rest_framework_simplejwt`. The project uses a cookie-based JWT middleware and authentication class (see `core/authentication.py` and `simplonservice/settings.py` — `CookieJWTAuthentication`, `CookieJWTMiddleware`). Maintain cookie/security flags in `settings.py` and `.env`.
- Workflow: `PurchaseRequest` model contains `status` state (pending -> mg_approved -> accounting_reviewed -> director_approved). `RequestStep` records each approval/rejection step. Business logic lives in `core.views` and serializers.
- File storage: attachments stored either as Drive files (when `GOOGLE_DRIVE_ENABLED=True`) or as plain URLs/files under `media/attachments/`. `google_drive_service.py` reads credentials from `GOOGLE_SERVICE_ACCOUNT_INFO` (JSON string) or `GOOGLE_SERVICE_ACCOUNT_FILE` (path).

## Environment & important variables (from `README.md` and `settings.py`)

- Required (development): `SECRET_KEY`, `DEBUG`, optionally `DATABASE_URL`. For Google Drive: `GOOGLE_DRIVE_ENABLED`, `GOOGLE_SERVICE_ACCOUNT_FILE` or `GOOGLE_SERVICE_ACCOUNT_INFO`, and `GOOGLE_DRIVE_FOLDER_ID`.
- Email: `EMAIL_BACKEND`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD` (defaults to console backend in DEBUG).
- Frontend integration: `FRONTEND_URL` used to build links in emails; CORS/CSRF origins are configured from `CORS_ALLOWED_ORIGINS` / `CSRF_TRUSTED_ORIGINS` in settings.

## Dev workflows & commands (concrete)

- Install deps: `pip install -r requirements.txt` (backend) and `npm install` in `front/`.
- Run migrations and dev server:
  - `python manage.py migrate`
  - `python manage.py createsuperuser`
  - `python manage.py runserver`
- Run production-like server locally: `gunicorn simplonservice.wsgi:application --bind 0.0.0.0:8000` (Procfile uses $PORT).
- Frontend dev: in `front/` use `npm run dev` (Vite) — backend CORS settings include `http://localhost:3000` and `http://localhost:5173`.

## Patterns & conventions specific to this repo

- Serializers often contain business logic and side effects (e.g., `UserRegistrationSerializer.create()` sends welcome emails via `EmailService`). When changing behavior, update tests and be cautious about network side-effects — mock `EmailService`.
- The code prefers timezone-aware datetimes (`django.utils.timezone`). Use `timezone.now()` for new timestamps.
- Pagination: DRF PageNumberPagination with default page size 20 (`REST_FRAMEWORK.PAGE_SIZE`). Adjust API clients accordingly.
- Rate limiting: anon=100/day, user=1000/day configured in settings.

## Integration points to mock or stub in tests

- `services.email_service.EmailService` — used across user creation, password reset, and request notifications.
- `services.google_drive_service.GoogleDriveService` — raises `GoogleDriveServiceError` if not configured; tests should set `GOOGLE_DRIVE_ENABLED=False` or patch the class.

## Files to inspect when changing behavior

- Authentication: `core/authentication.py`, `core/middleware.py` (cookie-JWT behavior).
- Models & business rules: `core/models.py`, `core/serializers.py`, `core/views.py`.
- External services: `services/email_service.py`, `services/google_drive_service.py`.
- Settings & env: `simplonservice/settings.py`, root `.env` (not checked in). Also `Procfile` for production process.

## Helpful examples

- To create a user via API: POST `/auth/register/` handled in `core/views.register_user` which uses `UserRegistrationSerializer` (see `core/serializers.py:UserRegistrationSerializer`).
- Password reset flow: `core/views.password_reset_request` -> `PasswordResetCode` -> `password_reset_verify` -> `password_reset_confirm` (uses Django cache to store reset token).

## Quick tips for an AI agent

- Prefer small, focused edits. Follow project patterns: keep side-effecting code inside services and serializers as currently done.
- When adding features that send emails or upload files, add a corresponding toggle via `settings.py` env flags and write tests that patch external services.
- Reference exact file paths in PR descriptions (e.g., `core/views.py`, `services/email_service.py`) and include a short test plan.

If any section is unclear or you want more details (example requests, env examples, CI or deployment steps), tell me which area to expand and I will iterate.

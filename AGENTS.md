# Repository Guidelines

## Project Structure & Module Organization

Backend code lives in `app/`. API routers and schemas are under `app/api/`, persistence code under `app/models/` and `app/repositories/`, business logic under `app/services/`, and Celery workflows under `app/tasks/`. Database changes belong in sequentially numbered `alembic/versions/` migrations. The Vue 3/TypeScript client is in `frontend/src/`, organized into views, reusable components, stores, composables, and API clients. Python tests live in `tests/` (with integration tests in `tests/integration/`); frontend unit and end-to-end tests use `*.spec.ts` beside source files and in `frontend/e2e/`. Documentation and brand assets belong in `docs/`.

## Build, Test, and Development Commands

- `make build` builds all Docker images; `make up` starts the local stack.
- `make logs-api` or `make logs-worker` follows service logs; `make down` stops services.
- `make test` runs the Python suite in the worker container; `make test-cov` writes coverage to `htmlcov/`.
- `make db-migrate` applies Alembic migrations.
- `cd frontend && pnpm install && pnpm dev` runs the Vite development server.
- From `frontend/`, use `pnpm build`, `pnpm lint:ci`, `pnpm test`, and `pnpm test:e2e` for type/build, lint, Vitest, and Playwright checks.

## Coding Style & Naming Conventions

Use four spaces in Python and keep lines at 120 characters. Format with Black and isort; Ruff targets Python 3.10. Use `snake_case` for modules/functions, `PascalCase` for classes, and descriptive service/repository names. For Vue and TypeScript, follow the existing ESLint and Prettier configuration. Use PascalCase component files, `useX` names for composables, and camelCase for variables. Prefix intentionally unused TypeScript bindings with `_`.

## Testing Guidelines

Pytest discovers `test_*.py`, `Test*`, and `test_*`; mark specialized cases with `integration`, `security`, `performance`, `slow`, or `benchmark`. Add regression tests near the affected subsystem and avoid external-network assumptions in unit tests. Run focused tests with `pytest tests/test_pipeline.py -k case_name`. No fixed coverage threshold is configured, but new behavior should be covered.

## Commit & Pull Request Guidelines

Recent history follows Conventional Commit-style subjects such as `feat(dast): ...`, `fix(ui): ...`, and `docs(roadmap): ...`. Keep commits focused and use an imperative, scoped summary. Pull requests should explain the problem and solution, list verification commands, link relevant issues, call out migrations or configuration changes, and include screenshots for visible UI changes.

## Security & Configuration

Never commit `.env`, credentials, tenant data, scan output, or GeoIP databases. Generate secrets with `scripts/generate_secrets.py`, preserve tenant isolation in all queries, and treat `make db-reset` and `make clean` as destructive operations.

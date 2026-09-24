# Frontend

Browser console for SecAgent RiskOps. Planned in `v0.2.5 Web Console`; not yet
implemented — this directory currently holds no application code.

What runs in a browser today is the read-only web demo at `/demo`. It is plain
HTML, CSS and JavaScript with no build step, in `backend/app/webdemo/static/`,
and is served by the API. See [docs/web-demo.md](../docs/web-demo.md). The
console described below is a separate, later piece of work.

## Stack

- Vite + React + TypeScript
- React Router for routing, TanStack Query for server state
- Tailwind CSS for styling

## API contract

Types are generated from the backend's OpenAPI schema
(`http://localhost:8000/openapi.json`) rather than hand-written, so a backend
change that the frontend has not absorbed fails CI instead of failing at
runtime.

## Local development

The Vite dev server proxies `/api` to the backend on `:8000`, keeping both on a
single origin so session cookies work without CORS exceptions. `make dev` starts
both processes.

## Pages

Shipping in `v0.2.5`, matching backend capabilities that exist by then:

- Login
- SOC Inbox (incident list)
- Incident detail and agent timeline
- Approval queue and decision screens (self-approved decisions highlighted)
- Audit chain viewer with integrity status

Owned by later milestones, alongside the backends they depend on:

- GRC controls and evidence packages (`v0.3`)
- Risk register (`v0.3`)
- Knowledge base (`v0.5`)

## Out of scope for v0.2.5

Realtime push (the console polls), mobile layouts, and internationalization.

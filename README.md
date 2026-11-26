# Trust, but verify

Post-quantum, zero-trust protection for files and messages while keys, devices
and user permissions change — plus an explainable detector that shows an operator
when an identity gains unexpected privileges or moves between services.

Built for Yugaantar DevForge 2026, Track 4.

> Work in progress. Setup, architecture, evidence and limitations will be
> documented here as components land.

## Requirements
- Node.js **24.11.1 or newer** (the core uses only Node built-ins: no `npm install` needed)

## Layout
| Path | What |
|---|---|
| `track4_service.mjs` | Judging adapter (one JSON request on stdin → one JSON response on stdout) |
| `core/` | Key service, access control, audit log, messaging, detector (TypeScript, run directly by Node) |
| `tests/` | `npm test` — Node's built-in test runner |
| `dashboard/` | Operator console (Next.js) for the demo |

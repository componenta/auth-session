# Componenta Auth Session

Authentication-session contracts and lifecycle for Componenta Auth 3.

This package owns the logical authenticated session model. It does not depend
on `componenta/session`, HTTP, cookies, Cycle ORM or a database implementation.

Related packages:

- `componenta/auth-session-database` — persistent storage.
- `componenta/auth-session-http` — browser/HTTP transport, middleware and session-bound CSRF.
- `componenta/auth-session-app` — Componenta DI parameter integration.

## Session timestamps

`AuthSession::$authenticatedAt` is the initial successful login time and remains
unchanged during credential rotation or reauthentication. `reauthenticatedAt`
and `reauthenticationEvidence` describe the latest fresh proof; `evidence`
describes the cumulative authentication evidence.

The redundant `createdAt` constructor argument and property have been removed.
Update named calls by removing `createdAt:` and positional calls by removing the
timestamp immediately before `authenticatedAt`. Pre-authentication transactions
still have their own `createdAt`, because they exist before authentication.

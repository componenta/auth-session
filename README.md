# Componenta Auth Session

Authentication-session contracts and lifecycle for Componenta Auth 3.

This package owns the logical authenticated session model. It does not depend
on `componenta/session`, HTTP, cookies, Cycle ORM or a database implementation.

Related packages:

- `componenta/auth-session-database` — persistent storage.
- `componenta/auth-session-http` — browser/HTTP transport and middleware.
- `componenta/auth-session-app` — Componenta DI parameter integration.
- `componenta/auth-session-csrf` — authentication-session-bound CSRF.

# Componenta Auth Session

Authentication-session contracts and lifecycle for Componenta Auth 4.

Version 2 requires `componenta/auth ^4.0.0` and `componenta/identity ^1.1.1`.

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

Assurance requirements always check the current `evidence` first. When `maxAge`
is set, the initial login or latest reauthentication proof must also establish
freshness for those methods and capabilities. A privilege-change rotation can
replace current evidence while preserving the historical reauthentication
proof; that historical proof cannot restore a method or capability removed
from current evidence.

The session model has no `createdAt` property or constructor argument. When
migrating from a pre-1.0 development snapshot, remove `createdAt:` from named
calls and the timestamp immediately before `authenticatedAt` from positional
calls. Pre-authentication transactions still have their own `createdAt`, because
they exist before authentication.

## Session metadata

Metadata stores bounded scalar or null values under validated names. Numeric
names such as `'0'` and `'42'` follow PHP's integer array-key normalization;
their identity is preserved during persistence. Names with leading zeros such
as `'001'` remain distinct string keys.

# PEGASI IOB Shared

Versioned TypeScript helpers for PEGASI IOB microservices.

This package exists to remove duplicated low-level helpers without coupling service repositories to each other. Services must depend on released package versions, not sibling source paths.

## Scope

- Environment/config parsing primitives.
- Stable JSON serialization for fingerprints and deterministic hashes.
- Prefix-based ID generation.
- Generic HS256 JWT verification helpers for Sprint services.

## Non-goals

- No Fastify-specific decorators or request types.
- No database, AWS, queue, or service adapter code.
- No business rules owned by a specific PEGASI IOB service.
- No direct imports from `pegasi-iob-*` service repositories.

## Validation

```bash
npm ci
npm run validate
npm run build
```

## Versioning

Use SemVer. Microservices should pin exact versions or controlled ranges and upgrade deliberately through normal PR review.


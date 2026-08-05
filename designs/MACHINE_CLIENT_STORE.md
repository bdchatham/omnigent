# Machine Client Store (design)

**Status:** Draft, for maintainer input
**Relates to:** #3977 (the env-configured stop-gap this replaces)

## 0. Problem

Omnigent can mint a token for a machine principal, and it can only ever know
about one of them. #3977 added an OAuth 2.0 client-credentials grant whose
confidential client is three environment variables, `OMNIGENT_MACHINE_CLIENT_ID`,
`OMNIGENT_MACHINE_CLIENT_SECRET_HASH` and `OMNIGENT_MACHINE_SUB`. That was the
right size for the case that prompted it, one automation identity on one
deployment, and it is what I have been running on my hosted stack to cover
GitHub Actions and some on-call automation.

Two things about that shape do not survive contact with a second consumer.

A machine client is a principal, and every other principal in omnigent lives in
the database partitioned by workspace. `SqlUser`, `SqlAccountToken` and
`SqlDeviceGrant` all carry `workspace_id` in the primary key, defaulted from
`current_workspace_id`. A client read from the process environment is
deployment-global by construction, so it cannot express a machine identity that
belongs to one workspace rather than to the deployment.

Revocation does not exist. `designs/CLIENT_CREDENTIALS.md` accepts this
explicitly, and the 3600 second ceiling on `OMNIGENT_MACHINE_TOKEN_TTL` is there
because expiry is the only bound on a stolen token. With one shared credential,
revoking a single consumer is not expressible at all. Rotating the secret cuts
off every consumer at once, and the cut takes a redeploy.

## 1. Current Model

Worth stating precisely, because most of it is being kept.

`MachineClientConfig.from_env()` reads the three variables plus an optional TTL
and returns one config or `None`. All unset is the clean off, and leaves
`POST /oauth/token` unmounted. Any other combination raises at startup rather
than coming up with an endpoint that refuses every request.

The secret is stored only as its `hash_secret` digest, HMAC-SHA256 keyed by
`cookie_secret`, and compared with `hmac.compare_digest`. Both the id and the
secret comparison run without short-circuiting, so a failure does not disclose
through timing which half was wrong.

The machine `sub` is vetted by `_vet_machine_sub` at mount and again on every
mint, so promoting that principal to admin stops new tokens instead of waiting
for a restart. Reserved identities are refused outright.

The minted token reuses `mint_delegated_token` with no `grant_id`, which is what
tells the auth layer to skip the revocation denylist. Its `scope` claim confines
it to the same delegated path allowlist the device grant uses.

## 2. What Already Exists

The store this design proposes is the third instance of a settled pattern rather
than a new subsystem.

`DeviceGrantStore` is described in its own module docstring as a sibling to
`SqlAlchemyAccountStore`, same database, separate API surface. It already
implements the parts that are easy to get wrong. Secrets are never stored raw,
`device_code` and each refresh token being kept as `hash_secret` digests.
Single-use redemption is atomic, an `UPDATE ... WHERE ... ` plus a rowcount
check, so a code cannot be redeemed twice or a rotated refresh token replayed
under concurrent requests.

There is also a precedent for an environment-provided credential that does not
own the credential. `OMNIGENT_ACCOUNTS_INIT_ADMIN_PASSWORD` takes effect on the
first boot of a deployment's accounts database and is ignored with a warning once
an admin exists. Environment bootstraps, the database owns.

## 3. Shape of the Answer

A `machine_clients` table, a `MachineClientStore` beside `DeviceGrantStore`, and
a resolver seam between the store and the token endpoint so the grant handler
does not know where a client came from.

```
POST /oauth/token
  │
  ├─ _presented_client(request, form)        unchanged, RFC 6749 §2.3.1
  │
  ├─ MachineClientResolver.get(client_id)    NEW seam
  │     ├─ StoreResolver   → machine_clients (workspace-scoped)
  │     └─ EnvResolver     → the #3977 variables, first-boot bootstrap only
  │
  ├─ constant-time secret compare            unchanged, hash_secret
  ├─ _vet_machine_sub(matched.sub)           per matched client
  └─ mint_delegated_token(..., grant_id=?)   see D4
```

Everything outside the resolver stays as #3977 built it. The RFC parsing, the
digest comparison, the sub vetting, the per-IP sliding window on the
unauthenticated client check, the delegated token shape, and the standing-down
behaviour when the device grant owns `POST /oauth/token` are all unchanged.

## 4. Decisions

Proposals, not settled calls. Each is the version I would defend, and the ones I
am least sure of are D4 and D6.

### D1 Table Shape

`machine_clients`, partitioned like its siblings.

| Column | Notes |
|---|---|
| `workspace_id` | part of the PK, `default=current_workspace_id` |
| `client_id` | part of the PK, the identifier presented at the endpoint |
| `secret_hash` | `hash_secret` digest, never the raw secret |
| `sub` | the principal minted tokens act as |
| `token_ttl_seconds` | per client, same ceiling as today |
| `created_at`, `created_by` | who registered it, for audit |
| `disabled_at` | soft disable, so a revoked client id cannot be silently reused |

`client_id` is scoped by workspace rather than globally unique, which follows the
sibling tables and means two workspaces can both register `github-actions`.

### D2 Stored Secret Form

`hash_secret` keyed by `cookie_secret`, unchanged. It is already the repository's
one stored-secret convention and it already covers the machine client. The raw
secret is returned once at registration and never persisted.

This inherits the existing coupling, which is worth naming rather than
discovering later. One key underpins the secret check and token signing, so
rotating `cookie_secret` invalidates every stored machine secret at the same time
it invalidates sessions. `designs/CLIENT_CREDENTIALS.md` already logs that
coupling at startup.

### D3 Constant-Time Lookup

Today both comparisons run unconditionally. A store lookup reintroduces the leak
that avoids, because an unknown `client_id` returns before the HMAC and a known
one pays for it, making client ids enumerable by timing.

The digest is therefore computed and compared on every request, against a fixed
dummy digest when the id resolves to nothing. Cost per request is one HMAC either
way.

### D4 Revocation Scope

A store gives revocation somewhere to happen. Deleting or disabling a row stops
minting immediately. It does not touch tokens already minted, because a machine
token deliberately carries no `grant_id` and the auth layer therefore skips the
denylist for it.

Two options, and this is the one I would most like maintainer input on.

Keep tokens denylist-free and leave the TTL ceiling at 3600 seconds. Revocation
stops minting, and an already-minted token dies on expiry. Simple, and no change
to the auth layer.

Or give machine tokens a `grant_id` referencing the client row and let the
existing denylist apply. Revocation becomes immediate for issued tokens too, and
the 3600 second ceiling loses its reason to exist, at the cost of a denylist
lookup per request and a machine token that is no longer distinguishable from a
device token by the absence of that claim.

I lean towards the second, because the ceiling exists only as compensation for
missing revocation and the store removes that constraint. The reason to hesitate
is that the absent `grant_id` is currently load-bearing signal, and changing what
it means is a change to a security boundary rather than an addition beside it.

### D5 Env as Bootstrap

The #3977 variables keep working and stop being the source of truth. On first
boot, if they are set and the workspace has no machine clients, they seed one row
and log that they did. Once a row exists they are ignored with a warning, exactly
as `OMNIGENT_ACCOUNTS_INIT_ADMIN_PASSWORD` behaves.

This keeps a headless deploy working with no registration step, keeps my hosted
stack running across the change, and avoids a config surface that has to be
deprecated separately.

### D6 Registration Surface

A store needs a way to put rows in it, and the smallest thing that works is a
CLI command run by an operator with database access. An admin API is the larger
version and is what a workspace-facing feature would need.

Which one is right depends on a product question I should not answer alone. If a
machine client is deployment infrastructure, the CLI is enough and the API is
scope. If workspaces provision their own automation credentials, it is an API and
an admin UI from the start. The table shape above is the same either way, which
is why this decision can trail the others.

## 5. Delivery Slices

Each reviewable on its own, and each leaves the tree working.

1. The table, the model, and the migration. No behaviour change.
2. `MachineClientStore` with the atomic-update idiom, plus its tests.
3. The resolver seam, backed by the existing env config. Pure refactor of
   #3977, no new capability, and the point at which the endpoint stops caring
   where a client came from.
4. The store-backed resolver, with D3's constant-time lookup.
5. The first-boot bootstrap of D5.
6. Registration, per D6.
7. The revocation decision from D4, if it lands as `grant_id`.

Slice 3 is the one worth landing early even if the rest waits. It is a
behaviour-preserving refactor of code that is already reviewed, and it makes the
env-versus-store decision reversible.

## 6. Still Open

- D4, the `grant_id` question, and with it whether the 3600 second TTL ceiling
  can be relaxed.
- D6, CLI or API, which follows from whether a machine client is infrastructure
  or a workspace-facing feature.
- Whether two clients may share a `sub`. Allowing it is what makes zero-downtime
  secret rotation possible, registering a second credential for the same
  principal and retiring the first. Forbidding it makes per-consumer attribution
  a guarantee rather than a convention. My preference is to allow it and warn.
- Per-client scopes stay out. The `scope` claim resolves through the shared
  delegated allowlist that the device grant also reads, so narrowing it per client
  changes a contract both grants depend on. That is its own design.

## A. Rejected Alternatives

**A JSON list in an environment variable.** Multiple clients without a
migration, and it was my first instinct. It fails on the two things that motivate
the change. The clients stay deployment-global, so a workspace-scoped machine
identity is still not expressible, and revocation is still a redeploy. It also
sits against the repository's own convention, where environment variables bootstrap
principals and the database owns them.

**A mounted JSON or YAML credentials file.** Better than the environment variable
for structured multi-entry secrets, and it is what a service whose credentials are
purely operator-editable would use. Same two failures as above.

**Dynamic Client Registration, RFC 7591.** The standard answer for programmatic
client creation, and the right one for a deployment acting as a general-purpose
authorization server. Omnigent is an application with an automation identity, so
the endpoint, its access-token policy, and its client-metadata surface are all
scope that no request has asked for.

**Reusing `SqlDeviceGrant` for machine clients.** They share a store pattern, not
a lifecycle. A device grant is created by a human consenting in a browser and
carries a user, a status, and rotating refresh tokens. A machine client is
registered by an operator, has no consent step, and has no refresh token. Folding
them into one table would mean columns that are null for half the rows and a
status enum meaning two different things.

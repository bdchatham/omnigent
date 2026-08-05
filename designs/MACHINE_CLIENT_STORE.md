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

Proposals, not settled calls. Each is the version I would defend, and the one I am
least sure of is D4.

### D1 Table Shape

`machine_clients`, partitioned like its siblings.

| Column | Notes |
|---|---|
| `workspace_id` | part of the PK, `default=current_workspace_id` |
| `client_id` | part of the PK, the identifier presented at the endpoint |
| `sub` | the principal minted tokens act as |
| `token_ttl_seconds` | per client, same ceiling as today |
| `created_at`, `created_by` | who registered it |
| `disabled_at` | soft disable, so a revoked client id cannot be silently reused |

`workspace_id` earns the column by consistency rather than by immediate use.
Every sibling principal table partitions on it, and a machine client is a
principal, so a table that omitted it would be the one row in the schema that
cannot answer which workspace it belongs to. A deployment that never uses more
than workspace 0 pays a column for that.

`created_by` is bookkeeping, and it becomes load-bearing the moment more than one
person can register a client. Recording it from the start costs nothing and
avoids a backfill against rows whose provenance is already lost.

`client_id` is scoped by workspace rather than globally unique, which follows the
sibling tables and means two workspaces can both register `github-actions`.

Secrets live in a child table rather than a column on the row above.

| `machine_client_secrets` | Notes |
|---|---|
| `workspace_id`, `client_id` | FK to the client |
| `secret_hash` | `hash_secret` digest, never the raw secret |
| `created_at` | when this secret was added |
| `expires_at` | nullable, set when the secret is being retired |

A column would allow exactly one live secret, which makes rotation a cutover.
Rotating then means registering a second `client_id` and retiring the first, so
the client's identity changes underneath its consumers and the audit trail splits
across two ids for one automation. With a child table, a rotation is additive.
Register a second secret, both authenticate, migrate the consumer, set
`expires_at` on the old one. The identity is stable throughout and an operator
can see when each secret entered service.

Authentication accepts any unexpired secret for the client. D3's constant-time
requirement then applies across the set rather than to a single digest.

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

The presented secret is therefore hashed on every request, once, and compared
against a fixed dummy digest when the id resolves to nothing. Cost per request is
one HMAC either way.

With D1's secret set, the presented digest is compared against every live secret
using `hmac.compare_digest` and the results combined without short-circuiting, so
the answer does not depend on which secret matched or on the order they were
checked. The single HMAC dominates the cost, and the residual signal is how many
live secrets a client has, which is one or two during a rotation window and is
not sensitive.

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
the 3600 second ceiling loses its reason to exist.

The cost is more than a lookup. A machine token today is validatable offline,
signature plus expiry and nothing else, so the auth path for it has no store
dependency. Adding a `grant_id` puts a denylist read on every authenticated
request, which matters most for the consumers this grant exists to serve, a CI job
that mints once an hour and then makes many calls. It also raises a question this
design has to answer rather than inherit, which is what happens when that read
fails. Fail closed and a database blip takes down all machine auth. Fail open and
revocation is bypassable exactly when it is most wanted. The device grant already
lives with this, so there is a precedent to follow rather than a policy to invent,
but it should be a stated choice.

I lean towards the second, because the ceiling exists only as compensation for
missing revocation and the store removes that constraint. The reasons to hesitate
are that the absent `grant_id` is currently load-bearing signal, so changing what
it means edits a security boundary rather than adding beside it, and that offline
validation is a property worth naming before trading away.

### D5 Env as Bootstrap

The #3977 variables keep working and stop being the source of truth. On first
boot, if they are set and the workspace has no machine clients, they seed one row
and log that they did. Once a row exists they are ignored with a warning, exactly
as `OMNIGENT_ACCOUNTS_INIT_ADMIN_PASSWORD` behaves.

This keeps a headless deploy working with no registration step, keeps my hosted
stack running across the change, and avoids a config surface that has to be
deprecated separately.

### D6 Registration Surface

Registration is restricted to workspace and deployment operators, and the existing
`is_admin` boolean is the gate.

That is a smaller statement than it sounds, because there is no finer gate
available. Omnigent has no role primitive. What exists is `is_admin` on `SqlUser`,
set through `PermissionStore.set_admin` and promoted from the operator-editable
admin list, and a per-resource ladder in `session_permissions` with
`LEVEL_READ` through `LEVEL_OWNER` keyed by conversation. The ladder is session
sharing, not capabilities, so there is no "may manage machine clients" permission
to grant and no way to express one without either stretching a conversation-scoped
level onto a non-conversation resource or introducing the codebase's first roles
table. Either of those is a larger design than the registry it would serve, so the
registry should not be gated on it. Admin-or-not is the honest ceiling for now, and
it is sufficient, because registering a machine client is an operator action.

The surface is a CLI command first, and an admin HTTP route is a follow-on that
reuses the same check. The CLI needs no new HTTP surface and no new guard, so it is
the shorter path to a usable registry.

Two things a reviewer should hold this to. First, the admin check is currently
copy-pasted, defined privately as `_require_admin` in both `sharing.py` and
`default_policies.py` and inlined in three more spellings across `auth.py` and
`accounts_auth.py`. A registry route should extract a shared dependency rather than
add a sixth. Second, whatever path it lands on must sit outside
`delegated_path_allowed` (`auth.py`), or a machine token could register machine
clients. The primary guard against that is already in place, since the machine
`sub` is vetted non-admin at mount and on every mint and therefore fails an admin
check regardless, but path placement is the second layer and should be deliberate
rather than incidental.

### D7 Sub Sharing

Two clients may point at the same `sub`, and the store warns rather than refuses.

The apparent cost of allowing it is per-consumer attribution, and that cost is not
real. `mint_delegated_token` already sets an `act` claim, RFC 8693 provenance
carrying the `client_id`, so which client acted is recorded independently of which
principal it acted as. Attribution survives a shared `sub` provided the audit path
reads `act.client_id` rather than `sub`, which is an obligation on whoever consumes
the trail and is worth stating in this document because it is not obvious from the
schema.

What allowing it buys is a second rotation story alongside D1's. Overlapping
secrets on one client covers rotating a credential. A second client on the same
`sub` covers migrating a consumer, standing up a new automation against the same
principal and retiring the old one on its own schedule, without either of them
sharing a secret.

## 5. Delivery Slices

Each reviewable on its own, and each leaves the tree working.

1. Both tables from D1, their models, and the migration. No behaviour change.
2. `MachineClientStore` with the atomic-update idiom, plus its tests.
3. The resolver seam, backed by the existing env config. Pure refactor of
   #3977, no new capability, and the point at which the endpoint stops caring
   where a client came from.
4. The store-backed resolver, with D3's constant-time lookup.
5. The first-boot bootstrap of D5.
6. The registration CLI of D6, and with it the extraction of a shared admin-check
   dependency so this is not the sixth private copy.
7. The revocation decision from D4, if it lands as `grant_id`.

Slice 3 is the one worth landing early even if the rest waits. It is a
behaviour-preserving refactor of code that is already reviewed, and it makes the
env-versus-store decision reversible.

## 6. Still Open

- D4, the `grant_id` question, and with it both whether the 3600 second TTL ceiling
  can be relaxed and what the auth path does when the denylist read fails.
- Rotating `cookie_secret` gets harder as the registry grows, and this design does
  not solve it. D2 keeps the existing stored form, so one key underpins both the
  stored secret check and token signing. Today that means rotation invalidates one
  environment-configured secret, a coordinated config change on two sides. With N
  stored clients it invalidates all N at once with no partial path, so every
  consumer must re-register inside the same window. Whether stored secrets should
  be keyed by something rotatable independently of session signing is a real
  question, and it is the one place the sibling pattern does not already have an
  answer to copy.
- Which workspace the D5 bootstrap seeds. `current_workspace_id` defaults to 0, so
  a single-workspace deployment is unambiguous and a multi-workspace one is not.
  Seeding workspace 0 explicitly and documenting it is probably right, but it is
  currently unspecified rather than decided.
- Per-client scopes stay out. The `scope` claim resolves through the shared
  delegated allowlist that the device grant also reads, so narrowing it per client
  changes a contract both grants depend on. The cost of deferring is that every
  machine client gets the full allowlist, which reaches `/v1/sessions`,
  `/v1/agents`, `/v1/hosts` and `/v1/runners`, so a client that only creates
  sessions is broader than it needs to be. That is acceptable while clients are
  operator-registered, and it is its own design when they are not.

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

**`secret_hash` as a column on the client row.** One fewer table, and it is what
#3977 effectively has today. It allows exactly one live secret, which makes every
rotation a cutover with no window where both the old and new credential work. The
smaller variant of D1's child table is two columns, a current and a previous
digest, which does buy an overlap window but cannot express when the previous one
stops being accepted. Retiring a secret then means remembering to clear a column
rather than setting a date, so the child table is worth the migration.

**Extending `session_permissions` to gate registration.** The levels ladder
(`LEVEL_READ` through `LEVEL_OWNER`) is the only permission machinery finer than
`is_admin`, so reaching for it is tempting. It is keyed by conversation, and a
machine client is not one, so this would mean either a sentinel conversation id
standing in for the whole workspace or a second meaning for a column that already
has one. `is_admin` is coarser and honest.

**Reusing `SqlDeviceGrant` for machine clients.** They share a store pattern, not
a lifecycle. A device grant is created by a human consenting in a browser and
carries a user, a status, and rotating refresh tokens. A machine client is
registered by an operator, has no consent step, and has no refresh token. Folding
them into one table would mean columns that are null for half the rows and a
status enum meaning two different things.

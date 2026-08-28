# Loco model encryption — runnable example

A tiny Loco app whose `users` table stores an encrypted SSN (random IV) and
a deterministically-encrypted email (queryable by equality). It uses
sqlite-in-memory, so nothing is persisted between runs — the goal is to
demonstrate the full encryption flow end-to-end, not to be a real app.

## Run it

From this directory:

```sh
LOCO_ENCRYPTION_PRIMARY_KEY=$(openssl rand -hex 32) \
LOCO_ENCRYPTION_DETERMINISTIC_KEY=$(openssl rand -hex 32) \
LOCO_ENCRYPTION_SALT=$(openssl rand -hex 32) \
cargo run -- start
```

The app starts on `localhost:5150`.

## Try it

```sh
# Create a user — the SSN and email are encrypted before INSERT.
curl -s -X POST localhost:5150/users \
  -H 'content-type: application/json' \
  -d '{"name":"Alice","ssn":"123-45-6789","email":"alice@example.com"}'

# Find the user by encrypted email — uses encrypt_query_value() under the hood.
curl -s "localhost:5150/users/by_email?email=alice@example.com"

# What's actually in the database — encrypted JSON envelopes.
curl -s "localhost:5150/users/raw?id=1"
```

## What to look at

- `src/models.rs` — entity + `impl_encryptable_fields!` with the
  deterministic marker on `email`.
- `src/controllers.rs` — three handlers that show the three relevant
  call sites: `insert_encrypted` on save, `decrypt_fields_ctx` on
  read, and `encrypt_query_value` for equality queries.
- `src/app.rs` — `Hooks::boot` is the standard `create_app` call;
  the encryption provider auto-registers from `config.encryption`.
- `config/development.yaml` — wires the env vars into the encryption
  config block.

## What's deliberately not here

- No migration crate. The schema is created in `Hooks::after_context`
  via `Schema::create_table_from_entity` against an in-memory sqlite
  database. A real app would have a `migration/` crate.
- No auth, mailer, or background workers. Those are orthogonal to
  encryption and would obscure the flow.
- No persistence. Restart the app and your data is gone — that's by
  design here.

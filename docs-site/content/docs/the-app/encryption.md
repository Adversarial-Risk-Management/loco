+++
title = "Model Encryption"
description = ""
date = 2026-05-01T00:00:00+00:00
updated = 2026-05-01T00:00:00+00:00
draft = false
weight = 6
sort_by = "weight"
template = "docs/page.html"

[extra]
lead = ""
toc = true
top = false
flair =[]
+++

Loco ships with column-level encryption for your models. You declare which fields hold sensitive data, and Loco transparently encrypts them before they hit the database and decrypts them when you read them back. The design is modeled after Rails' Active Record Encryption, with one notable difference: Loco uses HKDF-SHA256 instead of PBKDF2 for per-field key derivation.

## What it protects against

Model encryption is a defense against data exposure at rest. If a database backup is stolen, a replication target is misconfigured, or an admin pastes a query result into the wrong window, encrypted columns remain ciphertext. Anyone reading the row sees a base64 envelope, not the underlying value.

It does **not** protect against a compromised application server. The app holds the keys; if an attacker gets code execution inside your process, they can decrypt anything the app can decrypt. Likewise, model encryption is not a substitute for transport security, access control, or careful logging — it's a layer underneath those, narrowly aimed at "the database was leaked."

Under the hood, Loco uses AES-256-GCM, an AEAD cipher. Each ciphertext carries an authentication tag, so any tampering with the stored bytes will fail decryption rather than silently return garbage.

## Configuration

Encryption is configured per environment in your `config/<env>.yaml`:

```yaml
encryption:
  primary_key: {{ get_env(name="LOCO_ENCRYPTION_PRIMARY_KEY") }}
  deterministic_key: {{ get_env(name="LOCO_ENCRYPTION_DETERMINISTIC_KEY", default="") }}
  previous_keys:
    - {{ get_env(name="LOCO_ENCRYPTION_KEY_2025_01", default="") }}
  key_derivation:
    enabled: true
    salt: {{ get_env(name="LOCO_ENCRYPTION_SALT") }}
```

Each key is a 32-byte value supplied as 64 hex characters. Generate one with:

```sh
openssl rand -hex 32
```

`primary_key` is required as soon as any model declares an encrypted field. It is the key Loco uses to encrypt new writes.

`deterministic_key` is required only if at least one field uses deterministic mode (see below). If none of your encrypted fields are deterministic, you can leave it empty.

`previous_keys` is a list of older keys that Loco will try when a row's ciphertext was written under a key that is no longer primary. Reads will transparently fall back through this list; writes always use the current primary. Leaving it empty is fine for greenfield apps.

`key_derivation` is recommended. When enabled, Loco does not encrypt with the raw configured key — it derives a per-field subkey via HKDF-SHA256 with the configured `salt` and the column name as the HKDF info string. A leaked subkey for column `ssn` cannot be reused to decrypt ciphertexts from a column with a different name. Note that derivation is keyed by *column name only*, not `(table, column)`: two tables with a column named `email` will derive the same subkey under the same master, so column names should be reasonably distinct across tables that share a key. The `salt` itself should be a stable, environment-scoped secret; if you change it, every existing ciphertext will need re-encryption.

## Generating an encrypted model

The `generate model` command understands two new field modifiers, `encrypted` and `encrypted:deterministic`:

```sh
cargo loco generate model user \
  ssn:string:encrypted \
  email:string:encrypted:deterministic \
  name:string
```

This produces a migration that stores the encrypted columns as text (the ciphertext envelope is JSON-encoded). After running migrations and regenerating entities:

```sh
cargo loco db migrate
cargo loco db entities
```

open `src/models/users.rs` and wire up the encryption macro:

```rust
use loco_rs::impl_encryptable_fields;

impl_encryptable_fields!(super::_entities::users::ActiveModel, [
    ssn,
    email(deterministic),
]);
```

The macro takes the `ActiveModel` type and a list of fields. A bare identifier marks a field as randomly-encrypted; wrapping it as `field(deterministic)` opts that field into deterministic mode. The macro generates the trait implementations Loco needs to find, encrypt, and decrypt those columns at runtime. Plain fields like `name` are untouched.

## Saving and reading encrypted models

Encryption is explicit at the call site. You build an `ActiveModel` as usual, then call `encrypt_fields_ctx` before saving:

```rust
use loco_rs::prelude::*;

// Save
let active = users::ActiveModel {
    ssn: Set(ssn),
    ..Default::default()
};
let user = active.encrypt_fields_ctx(&ctx)?.insert(&ctx.db).await?;
```

`encrypt_fields_ctx` walks the active model, encrypts every field that was registered through the macro, and returns the active model with those fields rewritten to ciphertext. Unset fields are left alone, so partial updates work the same as they always have in SeaORM.

Reading is the symmetric operation:

```rust
if let Some(mut user) = users::Entity::find_by_id(id).one(&ctx.db).await? {
    user.decrypt_fields_ctx::<users::Entity>(&ctx)?;
    println!("{}", user.ssn);
}
```

`decrypt_fields_ctx` mutates the model in place. After it returns, the encrypted columns hold the original plaintext. The turbofish (`::<users::Entity>`) tells the helper which entity's field set to operate on; this is needed because `decrypt_fields_ctx` works on the generated `Model`, which doesn't carry its `Entity` as a type parameter.

The choice to make encryption explicit, rather than transparent on `find` and `save`, is deliberate. It keeps the cost (a key derivation plus an AES round per field) at predictable points in the code, and it lets you write background jobs that re-encrypt rows without recursive work.

## Querying deterministic fields

Random-IV encryption produces a different ciphertext every time you encrypt the same plaintext, so you cannot use it in a `WHERE` clause. Deterministic mode solves this: the IV is derived from the plaintext and the key, so the same input always produces the same ciphertext. You can then equality-match against the stored bytes.

Loco exposes a helper for this:

```rust
use loco_rs::encryption::encrypt_query_value;

let needle = encrypt_query_value::<users::Entity>("email", "alice@example.com", &ctx)?;
let user = users::Entity::find()
    .filter(users::Column::Email.eq(needle))
    .one(&ctx.db)
    .await?;
```

`encrypt_query_value` takes the entity, the column name, and the plaintext, and returns the exact ciphertext envelope you'd find in the database. Pass it straight to `Column::Email.eq(...)` and SeaORM will issue a normal indexed equality query.

The trade-off is real. Deterministic ciphertexts leak which rows share the same plaintext: an attacker with read access to the table can group rows by encrypted email even if they cannot decrypt any of them. For low-cardinality fields (think `country_code`) this is close to giving up the plaintext entirely. Reserve deterministic mode for fields where you actually need equality lookups — typically uniqueness checks, login flows, or foreign-key-style joins on natural keys — and keep everything else random.

## Key rotation

Rotation works by stacking keys. To rotate:

1. Generate a new key with `openssl rand -hex 32`.
2. Set it as `primary_key`.
3. Move the old `primary_key` to the front of `previous_keys`.
4. Restart the app.

From that moment on, every new write uses the new key. Reads of older rows fail to decrypt under the new primary, fall through to `previous_keys`, find a match, and succeed. The envelope's `h.i` field records a label of the key used for the write, and decryption walks the configured key list in order — primary first, then each previous key — until GCM authentication succeeds. There's no separate index over key ids, so a row that lands on the last entry of `previous_keys` costs `len(previous_keys)` AES-GCM decryption attempts. In practice this is microseconds and not worth pre-routing on `h.i`, but it's why long `previous_keys` lists are worth pruning after re-encryption.

To actually finish the rotation — that is, to rewrite old rows under the new key — you need to read each row and save it again. A simple background task that pages through the table, calls `encrypt_fields_ctx`, and writes the row back is enough. Once every row has been re-encrypted, you can drop the old key from `previous_keys`.

Deterministic keys cannot be rotated. This matches Rails' behavior and follows from the design: deterministic ciphertexts are a function of `(plaintext, deterministic_key)`, and any equality query you run has to use the same key the data was written with. If you rotate the deterministic key, every existing query helper stops matching existing rows. If you absolutely have to rotate it, you must re-encrypt every deterministic column in lockstep with the configuration change, which usually means downtime or a careful dual-write migration.

## Threat model

Be honest with yourself about what this feature buys you.

It protects against **leaked database state**: stolen `pg_dump` output, a misconfigured replica, a snapshot copied to the wrong S3 bucket, an admin pasting query results into a chat. Anyone who only sees the database sees ciphertext.

It does not protect against a **compromised application server**. The app holds the keys, in memory, by design. Anyone who can run code in your process can decrypt anything you can decrypt. If your threat model includes app-server compromise, you need a different layer (KMS with audit logging, HSM-backed decryption, per-request user-bound keys, etc.).

By default, ciphertexts are *not* bound to their `(table, column)` location. If an attacker with row-level write access to the database moves a ciphertext from `users.ssn` into `audit_log.notes`, the value will decrypt successfully when `audit_log` is read. To close that gap, opt the model into Additional Authenticated Data binding via the macro's `aad_namespace`:

```rust
impl_encryptable_fields!(
    users::ActiveModel,
    [ssn, email(deterministic)],
    aad_namespace = "users",
);
```

This makes `Encryptable::field_aad("ssn")` return `b"users:ssn"`, which AES-GCM authenticates alongside the ciphertext. A relocated ciphertext authenticates against a different AAD and fails. You can also implement `field_aad` by hand for non-`(table, column)` schemes — anything goes as long as encrypt and decrypt agree. Turning AAD on for an existing field invalidates ciphertexts written without it; plan the rollout the same way you would a key rotation.

Finally, AES-GCM with random IVs has a birthday-bound limit. Roughly: after about 2^32 encryptions under a single key, the probability of an IV collision becomes non-negligible. If you are encrypting at that scale, rotate keys before you get there. For most applications this is far beyond anything you'll hit, but it is the reason to take key rotation seriously even when nothing has gone wrong.

## Ciphertext format

Each encrypted value is a JSON envelope stored as text:

```json
{"p": "<base64-ciphertext>", "h": {"v": 1, "iv": "<b64>", "at": "<b64>", "i": "primary", "d": true}}
```

The fields are:

- `p` — the base64-encoded ciphertext.
- `h.v` — envelope version. Current version is `1`. The version field exists so that future format changes can be deployed without breaking older ciphertexts.
- `h.iv` — base64-encoded IV (12 bytes, as required by GCM).
- `h.at` — base64-encoded authentication tag.
- `h.i` — key id; `"primary"` for the current primary key, or a label matching an entry in `previous_keys`. The field name `i` matches Rails' envelope for compatibility. The legacy alias `h.kid` is still accepted on read but is no longer emitted on write.
- `h.d` — `true` if the value was encrypted with the deterministic key, `false` or absent otherwise.

You shouldn't need to parse this yourself. It's documented because the format is part of the contract: if you back up encrypted columns, dump them, or replicate them to another store, you can be confident that any Loco app with the right keys can read them.

## Custom key providers

The `KeyProvider` trait is public. If you want keys to come from somewhere other than the YAML config — AWS KMS, HashiCorp Vault, an HSM, an internal secrets service — you can implement the trait and register your provider during application boot:

```rust
loco_rs::encryption::registry::set_global(my_provider);
```

The registration call belongs in your `Hooks::boot` implementation, before any model code runs. Once installed, a custom provider replaces the YAML-driven one wholesale; the rest of the encryption machinery (envelope format, deterministic mode, key derivation, rotation through `previous_keys`) is unchanged. This is the supported extension point for organizations that want centralized key management without giving up the rest of the feature.

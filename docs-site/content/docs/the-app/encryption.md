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

Loco ships with column-level encryption for your models. You declare which fields hold sensitive data, and Loco encrypts them before they hit the database. Encryption happens automatically when you save; decryption is **explicit** — you call `decrypt_fields_ctx` on a loaded model rather than having the getter decrypt for you. This is the one workflow difference from Rails' Active Record Encryption, whose attribute readers decrypt transparently. The cryptographic design otherwise follows Rails, with one notable difference: Loco uses HKDF-SHA256 instead of PBKDF2 for per-field key derivation.

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
  # Quote list entries: an unset env var would otherwise render an empty
  # (null) YAML item, which fails config parsing. Empty strings are skipped.
  previous_keys:
    - "{{ get_env(name='LOCO_ENCRYPTION_KEY_2025_01', default='') }}"
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

This produces a migration that stores the encrypted columns as `text`, whatever inner type you wrote (`string:encrypted` becomes `text`, not `varchar`). The stored value is a JSON envelope, not the plaintext, and it is longer than the plaintext: roughly 90 bytes of fixed overhead plus 4/3 of the ciphertext length. A `varchar(255)` column overflows on plaintexts of about 120 characters. Use `text` for any hand-written migration too, and call `loco_rs::encryption::estimate_encrypted_size(plaintext_len)` if you need a bound for a length-limited store. After running migrations and regenerating entities:

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

Both `String` (`ssn:string!:encrypted`) and nullable `Option<String>` (`ssn:string:encrypted`, the generator's default) columns work. A `None` in a nullable field is stored as SQL `NULL` — nothing is encrypted, and it decrypts back to `None`.

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

## Compression

Long, redundant payloads — JSON blobs, biographies, free-form journal entries — can take significant database space once encrypted. Loco zlib-`deflate`s the plaintext before encryption **by default**, matching Rails. You don't need to do anything to get it; bare fields are compressed:

```rust
impl_encryptable_fields!(profiles::ActiveModel, [
    bio,                  // compressed by default
    notes(no_compress),   // opted out
    email(deterministic), // deterministic fields are never compressed
]);
```

Compression only kicks in when the plaintext is at least 140 bytes (the same threshold Rails uses); shorter values are stored uncompressed because the zlib header overhead would outweigh any savings. The envelope's `h.c` flag records per-value whether a given ciphertext was compressed, so decryption transparently inflates when needed and moving a field on or off the opt-out list never strands existing rows — old ciphertexts decrypt regardless of the current setting.

Deterministic fields are never compressed: deflate output is not stable across zlib versions, so compressing first would break the equal-plaintext-equal-ciphertext property that deterministic mode exists to provide. You don't need to opt them out explicitly.

### When to opt out: CRIME/BREACH

Compressing plaintext before encrypting it leaks length-correlated information. AES-GCM ciphertext is the same length as its input, so the stored length reveals how *compressible* the value was — and encryption doesn't hide length. This becomes an attack (the CRIME / BREACH class) when a single field mixes **attacker-influenced** bytes with **secret** bytes and the attacker can observe the stored ciphertext length: they vary their input, watch which guesses make the value compress smaller, and recover the secret a piece at a time.

For database-at-rest storage this is usually a weak threat — an attacker rarely gets the tight adaptive guess-and-measure loop the network attacks rely on. But opt a field out with `(no_compress)` when it concatenates user-controlled input with a secret (for example a note that embeds an internal token) and that ciphertext's length is observable. Fields that are wholly secret or wholly non-secret are fine left on the default.

## Key rotation

Rotation works by stacking keys. To rotate:

1. Generate a new key with `openssl rand -hex 32`.
2. Set it as `primary_key`.
3. Move the old `primary_key` to the front of `previous_keys`.
4. Restart the app.

From that moment on, every new write uses the new key. Reads of older rows fail to decrypt under the new primary, fall through to `previous_keys`, find a match, and succeed. The envelope's `h.i` field records a label of the key used for the write, and decryption walks the configured key list in order — primary first, then each previous key — until GCM authentication succeeds. There's no separate index over key ids, so a row that lands on the last entry of `previous_keys` costs `len(previous_keys)` AES-GCM decryption attempts. In practice this is microseconds and not worth pre-routing on `h.i`, but it's why long `previous_keys` lists are worth pruning after re-encryption.

Rows also **migrate lazily on save**, matching Rails' previous-encryption-schemes behavior: when `encrypt_fields_ctx` sees a value that is already an envelope, it keeps it untouched if it is fully current, but transparently decrypts and re-encrypts it under the current primary when it was written under a `previous_keys` entry (or an older envelope version). Deterministic fields are exempt — their key does not rotate, so their envelopes are always current. An envelope that none of the configured keys can decrypt fails the save instead of being persisted unreadable; that surfaces a prematurely-pruned `previous_keys` entry (or, for AAD-bound fields, a relocated ciphertext) at write time.

To actively finish a rotation — rewrite every old row rather than waiting for organic saves — page through the table, call `encrypt_fields_ctx` on each row's `ActiveModel` with the stored (encrypted) values `Set`, and save it back. Once every row has been re-encrypted, drop the old key from `previous_keys`.

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

### Binding to row values (`aad_fields`)

`aad_namespace` stops a ciphertext moving between columns. It does not stop one moving between *rows* of the same column — in a multi-tenant table, from one organization's row to another's. Add `aad_fields` to authenticate sibling column values too:

```rust
impl_encryptable_fields!(
    integration_credentials::ActiveModel,
    [credentials(no_compress)],
    aad_namespace = "integration_credential",
    aad_fields = [org_id],
);
```

The AAD for `credentials` becomes `integration_credential:credentials` followed by `\0org_id=<json>` for each listed column, in declaration order, where `<json>` is the value's JSON text — strings quoted (`"6f96…"`), numbers and booleans bare. Values are rendered through `serde_json` on both the save path (from the `ActiveModel`) and the read path (from the `Model`), so they agree byte-for-byte: a `Uuid` is its quoted hyphenated lowercase string. Quoting makes the encoding injective — the string `"7"` and the number `7` bind differently, and a string cannot spell a second entry. Only scalar columns are accepted; `Option` columns must be `Some`.

The rules are strict on purpose. On save, a scope column that is `NotSet` while an encrypted field is `Set` is an error — a partial update that touches no encrypted column is fine. On read, a missing or `null` scope column is an error. Silently binding to an empty scope would write rows that later fail to decrypt.

Deterministic fields on a scoped model are bound to the scope as well, so the same plaintext under two tenants is two different ciphertexts. Build the query needle with the scoped helper; the unscoped `encrypt_query_value` returns an error for such models rather than a query that never matches:

```rust
let scope = RowScope::new().with("org_id", &org_id)?;
let needle = encrypt_query_value_scoped::<credentials::Entity>("external_id", &input, &scope, &ctx)?;
```

`encrypt_query_value_with` is the same without an `AppContext`, for an explicit provider. `Encryptable::row_scope` / `row_scope_from_json` are the generated hooks; implement them by hand if your scope is not a plain list of columns.

Finally, AES-GCM with random IVs has a birthday-bound limit. Roughly: after about 2^32 encryptions under a single key, the probability of an IV collision becomes non-negligible. If you are encrypting at that scale, rotate keys before you get there. For most applications this is far beyond anything you'll hit, but it is the reason to take key rotation seriously even when nothing has gone wrong.

## Ciphertext format

Each encrypted value is a JSON envelope stored as text:

```json
{"p": "<base64-ciphertext>", "h": {"v": 1, "iv": "<b64>", "at": "<b64>", "i": "primary", "d": true}}
```

The fields are:

- `p` — the base64-encoded ciphertext.
- `h.v` — envelope version, always `1`. The version and the `d`/`c` flags are folded into the AES-GCM authenticated data, so a storage-layer attacker cannot flip them to force a mis-decryption or to suppress decompression — tampering with any of them fails authentication. There is exactly one accepted version: an envelope with any other `v` is rejected as malformed rather than read under a fallback scheme. A future format change bumps the version together with an explicit migration.
- `h.iv` — base64-encoded IV (12 bytes, as required by GCM).
- `h.at` — base64-encoded authentication tag.
- `h.i` — key id; `"primary"` for the current primary key, a label matching an entry in `previous_keys`, or `"deterministic"` for values written under the deterministic key. The field name `i` matches Rails' envelope shape, though the value is a semantic label rather than Rails' key fingerprint, so envelopes are not wire-compatible across the two stacks.
- `h.d` — `true` if the value was encrypted with the deterministic key, `false` or absent otherwise.
- `h.c` — `true` if the plaintext was zlib-compressed before encryption, `false` or absent otherwise.

You shouldn't need to parse this yourself. It's documented because the format is part of the contract: if you back up encrypted columns, dump them, or replicate them to another store, you can be confident that any Loco app with the right keys can read them.

## Custom key providers

The `KeyProvider` trait is public. If you want keys to come from somewhere other than the YAML config — AWS KMS, HashiCorp Vault, an HSM, an internal secrets service — you can implement the trait and register your provider during application boot:

```rust
loco_rs::encryption::registry::set_global(my_provider);
```

The registration call belongs in your `Hooks::boot` implementation, before any model code runs. Once installed, a custom provider replaces the YAML-driven one wholesale; the rest of the encryption machinery (envelope format, deterministic mode, key derivation, rotation through `previous_keys`) is unchanged. This is the supported extension point for organizations that want centralized key management without giving up the rest of the feature.

### Per-row key providers

One process-wide provider is the wrong shape for a multi-tenant table where each organization has its own keys. `Encryptable::provider_for(scope, ctx)` selects a provider per row from its [`RowScope`](#binding-to-row-values-aad_fields); the `*_ctx` helpers and `encrypt_query_value_scoped` call it first and fall back to the registry only when it returns `Ok(None)`. Name the function through the macro:

```rust
impl_encryptable_fields!(
    integration_credentials::ActiveModel,
    [credentials(no_compress)],
    aad_namespace = "integration_credential",
    aad_fields = [org_id],
    provider_for = crate::encryption::org_provider,
);

pub fn org_provider(scope: &RowScope, ctx: &AppContext) -> EncryptionResult<Option<SharedKeyProvider>> {
    let org_id = scope.get("org_id").and_then(|v| v.as_str()).ok_or_else(|| {
        EncryptionError::Scope("org_id missing from scope".into())
    })?;
    let cache = ctx.shared_store.get_ref::<OrgProviders>().expect("installed at boot");
    Ok(cache.get(org_id))
}
```

The hook is synchronous. Building a tenant's provider usually needs I/O — reading and unsealing its keypair, calling a KMS — so do that at an async point you already have (a request extractor, the start of a job) and cache the resulting `SharedKeyProvider` in `ctx.shared_store`; `provider_for` only looks it up. The cache owner is responsible for eviction: when a tenant's keys rotate (retire the old key, install the new one), drop that tenant's cached provider in the same step, or its rows keep being written under the retired key until the process restarts.

A hook declared through the macro is fail-closed: `Ok(None)` becomes an error instead of falling back to the global provider, which would write the row under a key the tenant does not own and read it back successfully. Only the trait's default (no `provider_for` declared) means "use the registry".

The per-tenant provider still implements the whole `KeyProvider` trait, so retired tenant keys go in `get_decryption_keys()`, and rows written under them re-encrypt under the active key on their next save, as described under [Key rotation](#key-rotation). `h.i` records whatever `get_key_id()` returns — a tenant key's row id is a reasonable choice. The explicit-provider methods (`encrypt_fields(&p)`, `decrypt_fields::<E, _>(&p)`, `encrypt_query_value_with`) bypass `provider_for` entirely; use them when you already hold the tenant's provider.

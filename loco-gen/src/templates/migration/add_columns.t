{% set mig_ts = ts | date(format="%Y%m%d_%H%M%S") -%}
{% set mig_name = name | snake_case -%}
{% set plural_snake = table | plural | snake_case -%}
{% set module_name = "m" ~  mig_ts ~ "_" ~ mig_name -%}
to: "migration/src/{{module_name}}.rs"
skip_glob: "migration/src/m????????_??????_{{mig_name}}.rs"
{% if encrypted_fields and encrypted_fields | length > 0 -%}
message: |
  Migration `{{mig_name}}` added! Apply it with `$ cargo loco db migrate && cargo loco db entities`.

  Encryption was requested for: {% for f in encrypted_fields %}`{{f.name}}`{% if f.deterministic %} (deterministic){% endif %}{% if not loop.last %}, {% endif %}{% endfor %}
  Add the new fields to the `impl_encryptable_fields!` call in `src/models/{{plural_snake}}.rs`
  (or add one if the model has none):

      use loco_rs::impl_encryptable_fields;
      impl_encryptable_fields!(super::_entities::{{plural_snake}}::ActiveModel, [
      {%- for f in encrypted_fields %}
          {{f.name}}{% if f.deterministic %}(deterministic){% endif %}{% if not loop.last %},{% endif -%}
      {% endfor %}
      ], aad_namespace = "{{plural_snake}}");

  Enable the `encryption` feature on your `loco-rs` dependency in `Cargo.toml`.
  Set `encryption.primary_key`, `encryption.deterministic_key` and
  `encryption.key_derivation_salt` in your `config/*.yaml`.
{% else -%}
message: "Migration `{{mig_name}}` added! You can now apply it with `$ cargo loco db migrate && cargo loco db entities`."
{%- endif %}
injections:
- into: "migration/src/lib.rs"
  before: "inject-above"
  content: "            Box::new({{module_name}}::Migration),"
- into: "migration/src/lib.rs"
  before: "pub struct Migrator"
  content: "mod {{module_name}};"
---
use loco_rs::schema::*;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        {% for column in columns -%}
        add_column(m, "{{plural_snake}}", "{{column.0}}", ColType::{{column.1}}).await?;
        {% endfor -%}
        Ok(())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        {% for column in columns -%}
        remove_column(m, "{{plural_snake}}", "{{column.0}}").await?;
        {% endfor -%}
        Ok(())
    }
}

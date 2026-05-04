//! HTTP handlers for the encryption example.

use axum::{extract::Query, routing, Json};
use loco_rs::{encryption::encrypt_query_value, prelude::*};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, Statement};
use serde::{Deserialize, Serialize};

use crate::models::{ActiveModel, Column, Entity};

#[derive(Deserialize)]
pub struct CreateBody {
    pub name: String,
    pub ssn: String,
    pub email: String,
}

#[derive(Serialize)]
pub struct UserDto {
    pub id: i32,
    pub name: String,
    pub ssn: String,
    pub email: String,
}

/// `POST /users` — create a user, encrypting SSN and email before INSERT.
async fn create(State(ctx): State<AppContext>, Json(body): Json<CreateBody>) -> Result<Response> {
    let active = ActiveModel {
        name: Set(body.name),
        ssn: Set(body.ssn),
        email: Set(body.email),
        ..Default::default()
    };
    // The single line that drives encryption at write time:
    let mut user = active.encrypt_fields_ctx(&ctx)?.insert(&ctx.db).await?;
    // `insert` returns the row in its on-disk form (i.e. encrypted). Decrypt
    // before responding so this endpoint round-trips plaintext.
    user.decrypt_fields_ctx::<Entity>(&ctx)?;
    format::json(UserDto {
        id: user.id,
        name: user.name,
        ssn: user.ssn,
        email: user.email,
    })
}

#[derive(Deserialize)]
pub struct ByEmailQuery {
    pub email: String,
}

/// `GET /users/by_email?email=...` — find by email via deterministic
/// encryption, then decrypt the row.
async fn by_email(
    State(ctx): State<AppContext>,
    Query(q): Query<ByEmailQuery>,
) -> Result<Response> {
    // Build the deterministic ciphertext we want to match on.
    let needle = encrypt_query_value::<Entity>("email", &q.email, &ctx)?;
    let mut user = Entity::find()
        .filter(Column::Email.eq(needle))
        .one(&ctx.db)
        .await?
        .ok_or_else(|| Error::NotFound)?;

    user.decrypt_fields_ctx::<Entity>(&ctx)?;
    format::json(UserDto {
        id: user.id,
        name: user.name,
        ssn: user.ssn,
        email: user.email,
    })
}

#[derive(Deserialize)]
pub struct RawQuery {
    pub id: i32,
}

#[derive(Serialize)]
pub struct RawDto {
    pub id: i32,
    pub name: String,
    pub ssn: String,
    pub email: String,
}

/// `GET /users/raw?id=N` — return the row exactly as it sits in the
/// database, so you can see the encrypted JSON envelopes.
async fn raw(State(ctx): State<AppContext>, Query(q): Query<RawQuery>) -> Result<Response> {
    use sea_orm::ConnectionTrait;
    let stmt = Statement::from_sql_and_values(
        ctx.db.get_database_backend(),
        "SELECT id, name, ssn, email FROM users WHERE id = ?",
        [q.id.into()],
    );
    let row = ctx
        .db
        .query_one_raw(stmt)
        .await?
        .ok_or_else(|| Error::NotFound)?;
    let dto = RawDto {
        id: row.try_get::<i32>("", "id").unwrap_or_default(),
        name: row.try_get::<String>("", "name").unwrap_or_default(),
        ssn: row.try_get::<String>("", "ssn").unwrap_or_default(),
        email: row.try_get::<String>("", "email").unwrap_or_default(),
    };
    format::json(dto)
}

pub fn routes() -> Routes {
    Routes::new()
        .prefix("/users")
        .add("/", routing::post(create))
        .add("/by_email", routing::get(by_email))
        .add("/raw", routing::get(raw))
}

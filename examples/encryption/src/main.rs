//! Entry point for the loco-encryption-example binary.
//!
//! Delegates to Loco's standard CLI so the app supports `start`, `routes`,
//! `db`, etc. The interesting code lives in `app.rs`, `models.rs`, and
//! `controllers.rs`.

use loco_rs::cli;
use migration::Migrator;

mod app;
mod controllers;
mod migration;
mod models;

#[tokio::main]
async fn main() -> loco_rs::Result<()> {
    Box::pin(cli::main::<app::App, Migrator>()).await
}

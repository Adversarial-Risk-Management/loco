//! In-tree migration that creates the `users` table at boot. A real app
//! would split this into its own crate; we keep it inline here so the
//! example fits in one directory.

pub use sea_orm_migration::prelude::*;

use crate::models;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(CreateUsers)]
    }
}

#[derive(DeriveMigrationName)]
pub struct CreateUsers;

#[async_trait::async_trait]
impl MigrationTrait for CreateUsers {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(models::Entity)
                    .col(
                        ColumnDef::new(models::Column::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(models::Column::Name).string().not_null())
                    .col(ColumnDef::new(models::Column::Ssn).text().null())
                    .col(ColumnDef::new(models::Column::Email).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(models::Entity).to_owned())
            .await
    }
}

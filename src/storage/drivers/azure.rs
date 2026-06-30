use opendal::{services::Azblob, Operator};

use super::StoreDriver;
use crate::storage::{drivers::opendal_adapter::OpendalAdapter, StorageResult};

/// Create new Azure storage using authentication from the environment.
///
/// `OpenDAL` loads Azure credentials from `AZBLOB_ACCOUNT_KEY`, `AZURE_CLIENT_ID`,
/// `AZURE_CLIENT_SECRET`, and related Azure environment variables.
///
/// # Examples
/// ```
/// use loco_rs::storage::drivers::azure;
/// let azure_driver = azure::new("container_name", "account_name", "endpoint");
/// ```
///
/// # Errors
///
/// When could not initialize the client instance
pub fn new(
    container_name: &str,
    account_name: &str,
    endpoint: &str,
) -> StorageResult<Box<dyn StoreDriver>> {
    let azure = Azblob::default()
        .container(container_name)
        .account_name(account_name)
        .endpoint(endpoint);

    // opendal 0.58: Operator::new returns a finished Operator (no .finish()).
    Ok(Box::new(OpendalAdapter::new(Operator::new(azure)?)))
}

/// Create new Azure storage with an explicit account key.
///
/// # Examples
/// ```
/// use loco_rs::storage::drivers::azure;
/// let azure_driver = azure::with_credentials(
///     "container_name",
///     "account_name",
///     "endpoint",
///     "YWNjZXNzX2tleQ==",
/// );
/// ```
///
/// # Errors
///
/// When could not initialize the client instance
pub fn with_credentials(
    container_name: &str,
    account_name: &str,
    endpoint: &str,
    access_key: &str,
) -> StorageResult<Box<dyn StoreDriver>> {
    let azure = Azblob::default()
        .container(container_name)
        .account_name(account_name)
        .endpoint(endpoint)
        .account_key(access_key);

    Ok(Box::new(OpendalAdapter::new(Operator::new(azure)?)))
}

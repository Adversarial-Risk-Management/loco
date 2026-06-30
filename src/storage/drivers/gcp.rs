use opendal::{services::Gcs, Operator};

use super::StoreDriver;
use crate::storage::{drivers::opendal_adapter::OpendalAdapter, StorageResult};

/// Create new GCP storage using Application Default Credentials.
///
/// # Examples
/// ```
/// use loco_rs::storage::drivers::gcp;
/// let gcp_driver = gcp::new("bucket_name");
/// ```
///
/// # Errors
///
/// When could not initialize the client instance
pub fn new(bucket_name: &str) -> StorageResult<Box<dyn StoreDriver>> {
    let gcs = Gcs::default().bucket(bucket_name);

    Ok(Box::new(OpendalAdapter::new(Operator::new(gcs)?.finish())))
}

/// Create new GCP storage with an explicit service-account credential file.
///
/// # Examples
/// ```
/// use loco_rs::storage::drivers::gcp;
/// let gcp_driver = gcp::with_credentials("bucket_name", "credential_path");
/// ```
///
/// # Errors
///
/// When could not initialize the client instance
pub fn with_credentials(
    bucket_name: &str,
    credential_path: &str,
) -> StorageResult<Box<dyn StoreDriver>> {
    let gcs = Gcs::default()
        .bucket(bucket_name)
        .credential_path(credential_path);

    // opendal 0.58: Operator::new returns a finished Operator (no .finish()).
    Ok(Box::new(OpendalAdapter::new(Operator::new(gcs)?)))
}

use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
#[cfg(feature = "cli")]
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_variant::to_variant_name;
use ulid::Ulid;
#[cfg(feature = "bg_pg")]
pub mod pg;
#[cfg(feature = "bg_redis")]
pub mod redis;
#[cfg(feature = "bg_sqlt")]
pub mod sqlt;

use crate::{
    app::AppContext,
    config::{
        self, Config, PostgresQueueConfig, QueueConfig, RedisQueueConfig, SqliteQueueConfig,
        WorkerMode,
    },
    Error, Result,
};

/// A filter for querying jobs by values within `task_data`.
///
/// Paths use [RFC 6901](https://tools.ietf.org/html/rfc6901) JSON pointer
/// syntax (e.g. `"/user_id"`, `"/org/id"`). Only scalar filter values (string,
/// number, bool, null) are supported.
#[derive(Clone, Debug)]
pub struct JobDataFilter {
    /// RFC 6901 JSON pointer path, e.g. `"/user_id"` or `"/org/id"`
    pub path: String,
    /// Scalar value to match
    pub value: serde_json::Value,
}

/// A composable filter for querying jobs across all dimensions at once.
///
/// All fields are optional; only set fields are applied. Filters combine with
/// AND semantics.
#[derive(Clone, Debug, Default)]
pub struct JobFilter {
    pub status: Option<Vec<JobStatus>>,
    pub age_days: Option<i64>,
    pub name: Option<String>,
    pub data: Option<Vec<JobDataFilter>>,
}

/// Validates that a [`JobDataFilter`] has a well-formed RFC 6901 path and a
/// scalar value.
fn validate_filter(filter: &JobDataFilter) -> Result<()> {
    if !filter.path.starts_with('/') {
        return Err(Error::string(&format!(
            "JSON pointer path must start with '/': {}",
            filter.path
        )));
    }
    for segment in filter.path[1..].split('/') {
        if segment.is_empty() {
            return Err(Error::string(&format!(
                "JSON pointer path contains empty segment: {}",
                filter.path
            )));
        }
    }
    if filter.value.is_object() || filter.value.is_array() {
        return Err(Error::string(&format!(
            "filter value must be a scalar (string, number, bool, or null), got: {}",
            filter.value
        )));
    }
    Ok(())
}

/// Extracts a value from job data using a JSON pointer path.
///
/// This is a thin wrapper around [`serde_json::Value::pointer`].
///
/// # Examples
/// ```
/// use serde_json::json;
/// use loco_rs::bgworker::extract_job_data_value;
///
/// let data = json!({"org": {"id": "abc123"}});
/// assert_eq!(extract_job_data_value(&data, "/org/id"), Some(&json!("abc123")));
/// assert_eq!(extract_job_data_value(&data, "/missing"), None);
/// ```
#[must_use]
pub fn extract_job_data_value<'a>(
    data: &'a serde_json::Value,
    pointer: &str,
) -> Option<&'a serde_json::Value> {
    data.pointer(pointer)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(ValueEnum))]
pub enum JobStatus {
    #[serde(rename = "queued")]
    Queued,
    #[serde(rename = "processing")]
    Processing,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "cancelled")]
    Cancelled,
}

impl std::str::FromStr for JobStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "queued" => Ok(Self::Queued),
            "processing" => Ok(Self::Processing),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(format!("Invalid status: {s}")),
        }
    }
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        to_variant_name(self).expect("only enum supported").fmt(f)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Job {
    pub id: String,
    pub name: String,
    #[serde(rename = "task_data")]
    pub data: serde_json::Value,
    pub status: JobStatus,
    pub run_at: DateTime<Utc>,
    pub interval: Option<i64>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub tags: Option<Vec<String>>,
}

// Queue struct now holds both a QueueProvider and QueueRegistrar
pub enum Queue {
    #[cfg(feature = "bg_redis")]
    Redis(
        redis::RedisPool,
        Arc<tokio::sync::Mutex<redis::JobRegistry>>,
        redis::RunOpts,
        tokio_util::sync::CancellationToken,
    ),
    #[cfg(feature = "bg_pg")]
    Postgres(
        pg::PgPool,
        std::sync::Arc<tokio::sync::Mutex<pg::JobRegistry>>,
        pg::RunOpts,
        tokio_util::sync::CancellationToken,
    ),
    #[cfg(feature = "bg_sqlt")]
    Sqlite(
        sqlt::SqlitePool,
        std::sync::Arc<tokio::sync::Mutex<sqlt::JobRegistry>>,
        sqlt::RunOpts,
        tokio_util::sync::CancellationToken,
    ),
    None,
}

impl Queue {
    /// Add a job to the queue
    ///
    /// Returns the job ID if the queue provider supports it:
    /// - `Some(String)` - Job ID for Redis, `PostgreSQL`, and `SQLite` providers
    /// - `None` - When using `Queue::None` or if the provider doesn't support job IDs
    ///
    /// # Errors
    ///
    /// This function will return an error if the enqueue operation fails
    #[allow(unused_variables)]
    pub async fn enqueue<A: Serialize + Send + Sync>(
        &self,
        class: String,
        queue: Option<String>,
        args: A,
        tags: Option<Vec<String>>,
    ) -> Result<Option<String>> {
        tracing::debug!(worker = class, queue = ?queue, tags = ?tags, "Enqueuing background job");
        let job_id = match self {
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => {
                Some(redis::enqueue(pool, class, queue, args, tags).await?)
            }
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => Some(
                pg::enqueue(
                    pool,
                    &class,
                    serde_json::to_value(args)?,
                    chrono::Utc::now(),
                    None,
                    tags,
                )
                .await
                .map_err(Box::from)?,
            ),
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => Some(
                sqlt::enqueue(
                    pool,
                    &class,
                    serde_json::to_value(args)?,
                    chrono::Utc::now(),
                    None,
                    tags,
                )
                .await
                .map_err(Box::from)?,
            ),
            _ => None,
        };
        Ok(job_id)
    }

    /// Register a worker
    ///
    /// # Errors
    ///
    /// This function will return an error if fails
    #[allow(unused_variables)]
    pub async fn register<
        A: Serialize + Send + Sync + 'static + for<'de> serde::Deserialize<'de>,
        W: BackgroundWorker<A> + 'static,
    >(
        &self,
        worker: W,
    ) -> Result<()> {
        tracing::info!(worker = W::class_name(), "Registering background worker");
        match self {
            #[cfg(feature = "bg_redis")]
            Self::Redis(_, p, _, _) => {
                let mut p = p.lock().await;
                p.register_worker(W::class_name(), worker)?;
            }
            #[cfg(feature = "bg_pg")]
            Self::Postgres(_, registry, _, _) => {
                let mut r = registry.lock().await;
                r.register_worker(W::class_name(), worker)?;
            }
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(_, registry, _, _) => {
                let mut r = registry.lock().await;
                r.register_worker(W::class_name(), worker)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Runs the worker loop for this [`Queue`].
    ///
    /// # Errors
    ///
    /// This function will return an error if fails
    #[allow(unused_variables)]
    pub async fn run(&self, tags: Vec<String>) -> Result<()> {
        tracing::info!("Starting background job processing");
        match self {
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, registry, run_opts, token) => {
                let handles = registry
                    .lock()
                    .await
                    .run(pool, run_opts, &token.clone(), &tags);
                Self::process_worker_handles(handles).await?;
            }
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, registry, run_opts, token) => {
                let handles = registry
                    .lock()
                    .await
                    .run(pool, run_opts, &token.clone(), &tags);
                Self::process_worker_handles(handles).await?;
            }
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, registry, run_opts, token) => {
                let handles = registry
                    .lock()
                    .await
                    .run(pool, run_opts, &token.clone(), &tags);
                Self::process_worker_handles(handles).await?;
            }
            _ => {
                tracing::error!(
                    "No queue provider is configured: compile with at least one queue provider \
                     feature"
                );
            }
        }
        Ok(())
    }

    /// Process worker task handles and handle any errors
    ///
    /// # Errors
    /// This function will return an error if a worker task fails to join
    #[allow(dead_code)]
    async fn process_worker_handles(handles: Vec<tokio::task::JoinHandle<()>>) -> Result<()> {
        let handle_count = handles.len();
        tracing::debug!(worker_count = handle_count, "Processing worker handles");

        for (index, handle) in handles.into_iter().enumerate() {
            if let Err(e) = handle.await {
                if e.is_cancelled() {
                    tracing::debug!(
                        worker_index = index,
                        "Worker task cancelled during shutdown"
                    );
                } else if e.is_panic() {
                    tracing::error!(worker_index = index, "Worker task panicked");
                    std::panic::resume_unwind(e.into_panic());
                } else {
                    tracing::error!(worker_index = index, error = ?e, "Worker task failed to join");
                    return Err(crate::Error::Worker(format!("Worker join error: {e}")));
                }
            }
        }
        tracing::info!(
            worker_count = handle_count,
            "All worker tasks finished successfully"
        );
        Ok(())
    }

    /// Runs the setup of this [`Queue`].
    ///
    /// # Errors
    ///
    /// This function will return an error if fails
    pub async fn setup(&self) -> Result<()> {
        match self {
            #[cfg(feature = "bg_redis")]
            Self::Redis(_, _, _, _) => {}
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => {
                pg::initialize_database(pool).await.map_err(Box::from)?;
            }
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => {
                sqlt::initialize_database(pool).await.map_err(Box::from)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Performs clear on this [`Queue`].
    ///
    /// # Errors
    ///
    /// This function will return an error if fails
    pub async fn clear(&self) -> Result<()> {
        tracing::info!("Clearing all jobs from queue");
        match self {
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => {
                redis::clear(pool).await?;
            }
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => {
                pg::clear(pool).await.map_err(Box::from)?;
            }
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => {
                sqlt::clear(pool).await.map_err(Box::from)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns a ping of this [`Queue`].
    ///
    /// # Errors
    ///
    /// This function will return an error if fails
    pub async fn ping(&self) -> Result<()> {
        tracing::trace!("Pinging job queue");
        match self {
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => {
                redis::ping(pool).await?;
            }
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => {
                pg::ping(pool).await.map_err(Box::from)?;
            }
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => {
                sqlt::ping(pool).await.map_err(Box::from)?;
            }
            _ => {}
        }
        Ok(())
    }

    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            #[cfg(feature = "bg_redis")]
            Self::Redis(_, _, _, _) => "redis queue".to_string(),
            #[cfg(feature = "bg_pg")]
            Self::Postgres(_, _, _, _) => "postgres queue".to_string(),
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(_, _, _, _) => "sqlite queue".to_string(),
            _ => "no queue".to_string(),
        }
    }

    /// # Errors
    ///
    /// Does not currently return an error, but the postgres or other future
    /// queue implementations might, so using Result here as return type.
    pub fn shutdown(&self) -> Result<()> {
        tracing::info!("Shutting down background job processing");
        match self {
            #[cfg(feature = "bg_redis")]
            Self::Redis(_, _, _, cancellation_token) => cancellation_token.cancel(),
            #[cfg(feature = "bg_pg")]
            Self::Postgres(_, _, _, cancellation_token) => cancellation_token.cancel(),
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(_, _, _, cancellation_token) => cancellation_token.cancel(),
            _ => {}
        }

        Ok(())
    }

    /// Retrieves jobs with optional status and age filtering.
    ///
    /// # Errors
    ///
    /// Returns an error if no queue provider is configured or if the underlying
    /// provider's query fails.
    pub async fn get_jobs(
        &self,
        status: Option<&Vec<JobStatus>>,
        age_days: Option<i64>,
    ) -> Result<Vec<Job>> {
        tracing::info!(status = ?status, age_days = ?age_days, "Retrieving jobs");
        match self {
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => Ok(pg::get_jobs(pool, status, age_days)
                .await
                .map_err(Box::from)?),
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => Ok(sqlt::get_jobs(pool, status, age_days)
                .await
                .map_err(Box::from)?),
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => Ok(redis::get_jobs(pool, status, age_days).await?),
            Self::None => {
                tracing::error!(
                    "No queue provider is configured: compile with at least one queue provider \
                     feature"
                );
                Err(Error::string("provider not configured"))
            }
        }
    }

    /// Retrieves a single job by its ID.
    ///
    /// # Errors
    /// - If no queue provider is configured, it will return an error indicating the lack of configuration.
    /// - Any error in the underlying provider's query logic will propagate from the respective function.
    pub async fn get_job(&self, job_id: &str) -> Result<Option<Job>> {
        tracing::debug!(job_id = job_id, "Retrieving job by ID");
        match self {
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => {
                Ok(pg::get_job(pool, job_id).await.map_err(Box::from)?)
            }
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => Ok(sqlt::get_job(pool, job_id).await?),
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => Ok(redis::get_job(pool, job_id).await?),
            Self::None => {
                tracing::error!(
                    "No queue provider is configured: compile with at least one queue provider feature"
                );
                Err(Error::string("provider not configured"))
            }
        }
    }

    /// Retrieves jobs filtered by worker name with optional status and age filtering.
    ///
    /// # Errors
    /// - If no queue provider is configured, it will return an error indicating the lack of configuration.
    /// - Any error in the underlying provider's query logic will propagate from the respective function.
    pub async fn get_jobs_by_name(
        &self,
        worker_name: &str,
        status: Option<&Vec<JobStatus>>,
        age_days: Option<i64>,
    ) -> Result<Vec<Job>> {
        tracing::info!(
            worker_name = worker_name,
            status = ?status,
            age_days = ?age_days,
            "Retrieving jobs by worker name"
        );

        match self {
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => {
                Ok(pg::get_jobs_by_name(pool, worker_name, status, age_days)
                    .await
                    .map_err(Box::from)?)
            }
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => {
                Ok(sqlt::get_jobs_by_name(pool, worker_name, status, age_days).await?)
            }
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => {
                Ok(redis::get_jobs_by_name(pool, worker_name, status, age_days).await?)
            }
            Self::None => {
                tracing::error!(
                    "No queue provider is configured: compile with at least one queue provider feature"
                );
                Err(Error::string("provider not configured"))
            }
        }
    }

    /// Retrieves jobs filtered by matching scalar values at JSON pointer paths
    /// within `task_data`.
    ///
    /// Multiple filters combine with AND semantics. Use JSON pointer syntax for
    /// paths (e.g. `"/org/id"`).
    ///
    /// # Errors
    /// - If no queue provider is configured.
    /// - If any filter has an invalid path or non-scalar value.
    /// - If the underlying provider query fails.
    pub async fn get_jobs_by_data(
        &self,
        filters: &[JobDataFilter],
        status: Option<&Vec<JobStatus>>,
        age_days: Option<i64>,
    ) -> Result<Vec<Job>> {
        for filter in filters {
            validate_filter(filter)?;
        }

        match self {
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => {
                Ok(pg::get_jobs_by_data(pool, filters, status, age_days)
                    .await
                    .map_err(Box::from)?)
            }
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => {
                Ok(sqlt::get_jobs_by_data(pool, filters, status, age_days).await?)
            }
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => {
                Ok(redis::get_jobs_by_data(pool, filters, status, age_days).await?)
            }
            Self::None => {
                tracing::error!(
                    "No queue provider is configured: compile with at least one queue provider \
                     feature"
                );
                Err(Error::string("provider not configured"))
            }
        }
    }

    /// Retrieves jobs matching all dimensions of a [`JobFilter`] in a single
    /// query.
    ///
    /// Returns a flat JSON array (like `get_jobs`). No pagination.
    ///
    /// # Errors
    /// - If no queue provider is configured.
    /// - If any data filter has an invalid path or non-scalar value.
    /// - If the underlying provider query fails.
    pub async fn query_jobs(&self, filter: &JobFilter) -> Result<Vec<Job>> {
        if let Some(data_filters) = &filter.data {
            for f in data_filters {
                validate_filter(f)?;
            }
        }

        match self {
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => {
                Ok(pg::query_jobs(pool, filter).await.map_err(Box::from)?)
            }
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => Ok(sqlt::query_jobs(pool, filter).await?),
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => Ok(redis::query_jobs(pool, filter).await?),
            Self::None => {
                tracing::error!(
                    "No queue provider is configured: compile with at least one queue provider \
                     feature"
                );
                Err(Error::string("provider not configured"))
            }
        }
    }

    /// Cancels a specific job by its ID.
    ///
    /// Returns `true` if the job was cancelled, `false` if the job was not found
    /// or was not in a cancellable state (only jobs with status `queued` can be cancelled).
    ///
    /// # Errors
    /// - If no queue provider is configured, it will return an error indicating the lack of configuration.
    /// - Any error in the underlying provider's cancellation logic will propagate from the respective function.
    pub async fn cancel_job(&self, job_id: &str) -> Result<bool> {
        tracing::info!(job_id = job_id, "Cancelling job by ID");
        match self {
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => {
                Ok(pg::cancel_job(pool, job_id).await.map_err(Box::from)?)
            }
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => sqlt::cancel_job(pool, job_id).await,
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => redis::cancel_job(pool, job_id).await,
            Self::None => {
                tracing::error!(
                    "No queue provider is configured: compile with at least one queue provider feature"
                );
                Err(Error::string("provider not configured"))
            }
        }
    }

    /// Cancels jobs based on the given job name for the configured queue
    /// provider.
    ///
    /// # Errors
    /// - If no queue provider is configured, it will return an error indicating
    ///   the lack of configuration.
    /// - If the Redis provider is selected, it will return an error stating
    ///   that cancellation is not supported.
    /// - Any error in the underlying provider's cancellation logic will
    ///   propagate from the respective function.
    pub async fn cancel_jobs(&self, job_name: &str) -> Result<()> {
        tracing::info!(job_name = job_name, "Cancelling jobs by name");

        match self {
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => pg::cancel_jobs_by_name(pool, job_name).await,
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => sqlt::cancel_jobs_by_name(pool, job_name).await,
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => redis::cancel_jobs_by_name(pool, job_name).await,
            Self::None => {
                tracing::error!(
                    "No queue provider is configured: compile with at least one queue provider \
                     feature"
                );
                Err(Error::string("provider not configured"))
            }
        }
    }

    /// Clears jobs older than a specified number of days for the configured
    /// queue provider.
    ///
    /// # Errors
    /// - If no queue provider is configured, it will return an error indicating
    ///   the lack of configuration.
    /// - If the Redis provider is selected, it will return an error stating
    ///   that clearing jobs is not supported.
    /// - Any error in the underlying provider's job clearing logic will
    ///   propagate from the respective function.
    pub async fn clear_jobs_older_than(
        &self,
        age_days: i64,
        status: &Vec<JobStatus>,
    ) -> Result<()> {
        tracing::info!(age_days = age_days, status = ?status, "Clearing older jobs");

        match self {
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => {
                pg::clear_jobs_older_than(pool, age_days, Some(status)).await
            }
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => {
                sqlt::clear_jobs_older_than(pool, age_days, Some(status)).await
            }
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => {
                redis::clear_jobs_older_than(pool, age_days, Some(status)).await
            }
            Self::None => {
                tracing::error!(
                    "No queue provider is configured: compile with at least one queue provider \
                     feature"
                );
                Err(Error::string("provider not configured"))
            }
        }
    }

    /// Clears jobs based on their status for the configured queue provider.
    ///
    /// # Errors
    /// - If no queue provider is configured, it will return an error indicating
    ///   the lack of configuration.
    /// - If the Redis provider is selected, it will return an error stating
    ///   that clearing jobs is not supported.
    /// - Any error in the underlying provider's job clearing logic will
    ///   propagate from the respective function.
    pub async fn clear_by_status(&self, status: Vec<JobStatus>) -> Result<()> {
        tracing::info!(status = ?status, "Clearing jobs by status");
        match self {
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => pg::clear_by_status(pool, status).await,
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => sqlt::clear_by_status(pool, status).await,
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => redis::clear_by_status(pool, status).await,
            Self::None => {
                tracing::error!(
                    "No queue provider is configured: compile with at least one queue provider \
                     feature"
                );
                Err(Error::string("provider not configured"))
            }
        }
    }

    /// Requeued job with the given minutes ages.
    ///
    /// # Errors
    /// - If no queue provider is configured, it will return an error indicating
    ///   the lack of configuration.
    /// - If the Redis provider is selected, it will return an error stating
    ///   that clearing jobs is not supported.
    /// - Any error in the underlying provider's job clearing logic will
    ///   propagate from the respective function.
    pub async fn requeue(&self, age_minutes: &i64) -> Result<()> {
        tracing::info!(age_minutes = age_minutes, "Requeuing stale jobs");
        match self {
            #[cfg(feature = "bg_pg")]
            Self::Postgres(pool, _, _, _) => pg::requeue(pool, age_minutes).await,
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(pool, _, _, _) => sqlt::requeue(pool, age_minutes).await,
            #[cfg(feature = "bg_redis")]
            Self::Redis(pool, _, _, _) => redis::requeue(pool, age_minutes).await,
            Self::None => {
                tracing::error!(
                    "No queue provider is configured: compile with at least one queue provider \
                     feature"
                );
                Err(Error::string("provider not configured"))
            }
        }
    }

    /// Dumps the list of jobs to a YAML file at the specified path.
    ///
    /// This function retrieves jobs from the queue, optionally filtered by
    /// their status, and writes the job data to a YAML file.
    ///
    /// # Errors
    /// - If the specified path cannot be created, an error will be returned.
    /// - If the job retrieval or YAML serialization fails, an error will be
    ///   returned.
    /// - If there is an issue creating the dump file, an error will be returned
    pub async fn dump(
        &self,
        path: &Path,
        status: Option<&Vec<JobStatus>>,
        age_days: Option<i64>,
    ) -> Result<PathBuf> {
        tracing::info!(path = %path.display(), status = ?status, age_days = ?age_days, "Dumping jobs to file");

        if !path.exists() {
            tracing::debug!(path = %path.display(), "Directory does not exist, creating...");
            std::fs::create_dir_all(path)?;
        }

        let dump_file = path.join(format!(
            "loco-dump-jobs-{}.yaml",
            chrono::Utc::now().format("%Y-%m-%d-%H-%M-%S")
        ));

        let jobs = self.get_jobs(status, age_days).await?;

        let data = serde_yaml::to_string(&jobs)?;
        let mut file = File::create(&dump_file)?;
        file.write_all(data.as_bytes())?;

        tracing::info!(file = %dump_file.display(), "Jobs successfully dumped to file");
        Ok(dump_file)
    }

    /// Imports jobs from a YAML file into the configured queue provider.
    ///
    /// This function reads job data from a YAML file located at the specified
    /// `path` and imports the jobs into the queue.
    ///
    /// # Errors
    /// - If there is an issue opening or reading the YAML file, an error will
    ///   be returned.
    /// - If the queue provider is Redis or none, an error will be returned
    ///   indicating the lack of support.
    /// - If any issues occur while enqueuing the jobs, the function will return
    ///   an error.
    pub async fn import(&self, path: &Path) -> Result<()> {
        tracing::info!(path = %path.display(), "Importing jobs from file");

        match &self {
            #[cfg(feature = "bg_pg")]
            Self::Postgres(_, _, _, _) => {
                let jobs: Vec<Job> = serde_yaml::from_reader(File::open(path)?)?;
                for job in jobs {
                    self.enqueue(job.name.clone(), None, job.data, None).await?;
                }
                Ok(())
            }
            #[cfg(feature = "bg_sqlt")]
            Self::Sqlite(_, _, _, _) => {
                let jobs: Vec<Job> = serde_yaml::from_reader(File::open(path)?)?;
                for job in jobs {
                    self.enqueue(job.name.clone(), None, job.data, None).await?;
                }
                Ok(())
            }
            #[cfg(feature = "bg_redis")]
            Self::Redis(_, _, _, _) => {
                let jobs: Vec<Job> = serde_yaml::from_reader(File::open(path)?)?;
                for job in jobs {
                    self.enqueue(job.name.clone(), None, job.data, None).await?;
                }
                Ok(())
            }
            Self::None => {
                tracing::error!(
                    "No queue provider is configured: compile with at least one queue provider \
                     feature"
                );
                Err(Error::string("provider not configured"))
            }
        }
    }
}

#[async_trait]
pub trait BackgroundWorker<A: Send + Sync + serde::Serialize + 'static>: Send + Sync {
    /// If you have a specific queue
    /// in mind and the provider supports custom / priority queues, make your
    /// worker return it. Otherwise, return `None`.
    #[must_use]
    fn queue() -> Option<String> {
        None
    }

    /// Specifies tags associated with this worker. Workers might only process
    /// jobs matching specific tags during startup.
    #[must_use]
    fn tags() -> Vec<String> {
        Vec::new()
    }

    fn build(ctx: &AppContext) -> Self;
    #[must_use]
    fn class_name() -> String
    where
        Self: Sized,
    {
        use heck::ToUpperCamelCase;
        let type_name = std::any::type_name::<Self>();
        let name = type_name.split("::").last().unwrap_or(type_name);
        name.to_upper_camel_case()
    }
    async fn perform_later(ctx: &AppContext, args: A) -> crate::Result<String>
    where
        Self: Sized,
    {
        let job_id = match &ctx.config.workers.mode {
            WorkerMode::BackgroundQueue => {
                if let Some(p) = &ctx.queue_provider {
                    let tags = Self::tags();
                    let tags_option = if tags.is_empty() { None } else { Some(tags) };

                    p.enqueue(Self::class_name(), Self::queue(), args, tags_option)
                        .await?
                        .unwrap_or_else(|| Ulid::new().to_string())
                } else {
                    return Err(Error::string(
                        "perform_later: background queue is selected, but queue was not populated \
                         in context",
                    ));
                }
            }
            WorkerMode::ForegroundBlocking => {
                let job_id = Ulid::new().to_string();
                Self::build(ctx).perform(args).await?;
                job_id
            }
            WorkerMode::BackgroundAsync => {
                let dx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(err) = Self::build(&dx).perform(args).await {
                        tracing::error!(err = err.to_string(), "worker failed to perform job");
                    }
                })
                .id()
                .to_string()
            }
        };
        Ok(job_id)
    }

    async fn perform(&self, args: A) -> crate::Result<()>;
}

/// Initialize the system according to configuration
///
/// # Errors
///
/// This function will return an error if it fails
pub async fn converge(queue: &Queue, config: &QueueConfig) -> Result<()> {
    queue.setup().await?;
    match config {
        QueueConfig::Postgres(PostgresQueueConfig {
            dangerously_flush,
            uri: _,
            max_connections: _,
            enable_logging: _,
            connect_timeout: _,
            idle_timeout: _,
            poll_interval_sec: _,
            num_workers: _,
            min_connections: _,
        })
        | QueueConfig::Sqlite(SqliteQueueConfig {
            dangerously_flush,
            uri: _,
            max_connections: _,
            enable_logging: _,
            connect_timeout: _,
            idle_timeout: _,
            poll_interval_sec: _,
            num_workers: _,
            min_connections: _,
        })
        | QueueConfig::Redis(RedisQueueConfig {
            dangerously_flush,
            uri: _,
            queues: _,
            num_workers: _,
        }) => {
            if *dangerously_flush {
                tracing::warn!("Flush mode enabled - clearing all jobs from queue");
                queue.clear().await?;
            }
        }
    }
    Ok(())
}

/// Create a provider
///
/// # Errors
///
/// This function will return an error if fails to build
#[allow(clippy::missing_panics_doc)]
pub async fn create_queue_provider(config: &Config) -> Result<Option<Arc<Queue>>> {
    if config.workers.mode == config::WorkerMode::BackgroundQueue {
        if let Some(queue) = &config.queue {
            match queue {
                #[cfg(feature = "bg_redis")]
                config::QueueConfig::Redis(qcfg) => {
                    tracing::debug!("Creating Redis queue provider");
                    Ok(Some(Arc::new(redis::create_provider(qcfg).await?)))
                }
                #[cfg(feature = "bg_pg")]
                config::QueueConfig::Postgres(qcfg) => {
                    tracing::debug!("Creating Postgres queue provider");
                    Ok(Some(Arc::new(pg::create_provider(qcfg).await?)))
                }
                #[cfg(feature = "bg_sqlt")]
                config::QueueConfig::Sqlite(qcfg) => {
                    tracing::debug!("Creating SQLite queue provider");
                    Ok(Some(Arc::new(sqlt::create_provider(qcfg).await?)))
                }

                #[allow(unreachable_patterns)]
                _ => Err(Error::string(
                    "No queue provider feature was selected and compiled, but queue configuration \
                     is present",
                )),
            }
        } else {
            // tracing::warn!("Worker mode is BackgroundQueue but no queue configuration is
            // present");
            Ok(None)
        }
    } else {
        // tracing::debug!("Worker mode is not BackgroundQueue, skipping queue provider
        // creation");
        Ok(None)
    }
}

#[cfg(test)]
mod tests {

    use std::path::Path;

    use insta::assert_debug_snapshot;

    use super::*;
    use crate::tests_cfg;

    fn sqlite_config(db_path: &Path) -> SqliteQueueConfig {
        SqliteQueueConfig {
            uri: format!(
                "sqlite://{}?mode=rwc",
                db_path.join("sample.sqlite").display()
            ),
            dangerously_flush: false,
            enable_logging: false,
            max_connections: 1,
            min_connections: 1,
            connect_timeout: 500,
            idle_timeout: 500,
            poll_interval_sec: 1,
            num_workers: 1,
        }
    }

    #[tokio::test]
    async fn queue_enqueue_returns_job_id() {
        let tree_fs = tree_fs::TreeBuilder::default()
            .drop(true)
            .create()
            .expect("create temp folder");

        // Test with SQLite provider - should return Some(job_id)
        let qcfg = sqlite_config(tree_fs.root.as_path());
        let queue = sqlt::create_provider(&qcfg)
            .await
            .expect("create sqlite queue");

        queue.setup().await.expect("setup sqlite db");

        let job_id = queue
            .enqueue(
                "TestJob".to_string(),
                None,
                serde_json::json!({"test": "data"}),
                None,
            )
            .await
            .expect("enqueue job");

        assert!(job_id.is_some(), "SQLite provider should return job ID");
        let job_id = job_id.unwrap();
        assert!(!job_id.is_empty(), "Job ID should not be empty");
        assert!(
            ulid::Ulid::from_string(&job_id).is_ok(),
            "Job ID should be valid ULID"
        );

        // Test with None provider - should return None
        let none_queue = Queue::None;
        let job_id = none_queue
            .enqueue(
                "TestJob".to_string(),
                None,
                serde_json::json!({"test": "data"}),
                None,
            )
            .await
            .expect("enqueue to None provider");

        assert!(job_id.is_none(), "None provider should return None");
    }

    #[tokio::test]
    async fn can_dump_jobs() {
        let tree_fs = tree_fs::TreeBuilder::default()
            .drop(true)
            .create()
            .expect("create temp folder");
        let qcfg = sqlite_config(tree_fs.root.as_path());
        let queue = sqlt::create_provider(&qcfg)
            .await
            .expect("create sqlite queue");

        let pool = sqlx::SqlitePool::connect(&qcfg.uri)
            .await
            .expect("connect to sqlite db");

        queue.setup().await.expect("setup sqlite db");
        tests_cfg::queue::sqlite_seed_data(&pool).await;

        let dump_file = queue
            .dump(
                tree_fs.root.as_path(),
                Some(&vec![JobStatus::Failed, JobStatus::Cancelled]),
                None,
            )
            .await
            .expect("dump jobs");

        assert_debug_snapshot!(std::fs::read_to_string(dump_file).unwrap());
    }

    #[tokio::test]
    async fn cat_import_jobs_form_file() {
        let tree_fs = tree_fs::TreeBuilder::default()
            .drop(true)
            .create()
            .expect("create temp folder");
        let qcfg = sqlite_config(tree_fs.root.as_path());
        let queue = sqlt::create_provider(&qcfg)
            .await
            .expect("create sqlite queue");

        let pool = sqlx::SqlitePool::connect(&qcfg.uri)
            .await
            .expect("connect to sqlite db");

        queue.setup().await.expect("setup sqlite db");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlt_loco_queue")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(count, 0);

        queue
            .import(
                PathBuf::from("tests")
                    .join("fixtures")
                    .join("queue")
                    .join("jobs.yaml")
                    .as_path(),
            )
            .await
            .expect("dump import");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlt_loco_queue")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(count, 14);
    }

    #[tokio::test]
    async fn queue_get_job_returns_job() {
        let tree_fs = tree_fs::TreeBuilder::default()
            .drop(true)
            .create()
            .expect("create temp folder");
        let qcfg = sqlite_config(tree_fs.root.as_path());
        let queue = sqlt::create_provider(&qcfg)
            .await
            .expect("create sqlite queue");

        let pool = sqlx::SqlitePool::connect(&qcfg.uri)
            .await
            .expect("connect to sqlite db");

        queue.setup().await.expect("setup sqlite db");
        tests_cfg::queue::sqlite_seed_data(&pool).await;

        // Test getting an existing job
        let job = queue
            .get_job("01JDM0X8EVAM823JZBGKYNBA99")
            .await
            .expect("get job");
        assert!(job.is_some());
        let job = job.unwrap();
        assert_eq!(job.id, "01JDM0X8EVAM823JZBGKYNBA99");

        // Test getting a non-existent job
        let job = queue.get_job("nonexistent").await.expect("get job");
        assert!(job.is_none());
    }

    #[tokio::test]
    async fn queue_get_jobs_by_name() {
        let tree_fs = tree_fs::TreeBuilder::default()
            .drop(true)
            .create()
            .expect("create temp folder");
        let qcfg = sqlite_config(tree_fs.root.as_path());
        let queue = sqlt::create_provider(&qcfg)
            .await
            .expect("create sqlite queue");

        let pool = sqlx::SqlitePool::connect(&qcfg.uri)
            .await
            .expect("connect to sqlite db");

        queue.setup().await.expect("setup sqlite db");
        tests_cfg::queue::sqlite_seed_data(&pool).await;

        // Test getting jobs by name (UserAccountActivation has 2 jobs in fixture)
        let jobs = queue
            .get_jobs_by_name("UserAccountActivation", None, None)
            .await
            .expect("get jobs by name");
        assert_eq!(jobs.len(), 2);

        // Test getting jobs by name with status filter
        let jobs = queue
            .get_jobs_by_name(
                "UserAccountActivation",
                Some(&vec![JobStatus::Queued]),
                None,
            )
            .await
            .expect("get jobs by name with status");
        assert_eq!(jobs.len(), 1);
    }

    #[tokio::test]
    async fn queue_cancel_job_by_id() {
        let tree_fs = tree_fs::TreeBuilder::default()
            .drop(true)
            .create()
            .expect("create temp folder");
        let qcfg = sqlite_config(tree_fs.root.as_path());
        let queue = sqlt::create_provider(&qcfg)
            .await
            .expect("create sqlite queue");

        let pool = sqlx::SqlitePool::connect(&qcfg.uri)
            .await
            .expect("connect to sqlite db");

        queue.setup().await.expect("setup sqlite db");
        tests_cfg::queue::sqlite_seed_data(&pool).await;

        // Cancel a queued job
        let cancelled = queue
            .cancel_job("01JDM0X8EVAM823JZBGKYNBA99")
            .await
            .expect("cancel job");
        assert!(cancelled);

        // Verify job is cancelled
        let job = queue
            .get_job("01JDM0X8EVAM823JZBGKYNBA99")
            .await
            .expect("get job")
            .unwrap();
        assert_eq!(job.status, JobStatus::Cancelled);

        // Try to cancel again - should return false
        let cancelled_again = queue
            .cancel_job("01JDM0X8EVAM823JZBGKYNBA99")
            .await
            .expect("cancel job");
        assert!(!cancelled_again);
    }

    #[test]
    fn extract_job_data_value_nested() {
        let data = serde_json::json!({"org": {"id": "abc123", "nested": {"deep": 42}}});
        assert_eq!(
            extract_job_data_value(&data, "/org/id"),
            Some(&serde_json::json!("abc123"))
        );
        assert_eq!(
            extract_job_data_value(&data, "/org/nested/deep"),
            Some(&serde_json::json!(42))
        );
        assert_eq!(extract_job_data_value(&data, "/missing"), None);
    }

    #[test]
    fn validate_filter_rejects_bad_paths() {
        // Path not starting with /
        let f = JobDataFilter {
            path: "org/id".to_string(),
            value: serde_json::json!("x"),
        };
        assert!(validate_filter(&f).is_err());

        // Empty segment
        let f = JobDataFilter {
            path: "/a//b".to_string(),
            value: serde_json::json!("x"),
        };
        assert!(validate_filter(&f).is_err());

        // Object value
        let f = JobDataFilter {
            path: "/a".to_string(),
            value: serde_json::json!({"nested": true}),
        };
        assert!(validate_filter(&f).is_err());

        // Array value
        let f = JobDataFilter {
            path: "/a".to_string(),
            value: serde_json::json!([1, 2]),
        };
        assert!(validate_filter(&f).is_err());
    }

    #[test]
    fn validate_filter_accepts_scalars() {
        for val in [
            serde_json::json!("hello"),
            serde_json::json!(42),
            serde_json::json!(true),
            serde_json::Value::Null,
        ] {
            let f = JobDataFilter {
                path: "/a/b".to_string(),
                value: val,
            };
            assert!(validate_filter(&f).is_ok());
        }
    }

    #[tokio::test]
    async fn queue_get_jobs_by_data() {
        let tree_fs = tree_fs::TreeBuilder::default()
            .drop(true)
            .create()
            .expect("create temp folder");
        let qcfg = sqlite_config(tree_fs.root.as_path());
        let queue = sqlt::create_provider(&qcfg)
            .await
            .expect("create sqlite queue");

        let pool = sqlx::SqlitePool::connect(&qcfg.uri)
            .await
            .expect("connect to sqlite db");

        queue.setup().await.expect("setup sqlite db");
        tests_cfg::queue::sqlite_seed_data(&pool).await;

        // Filter by user_id = 133 (should match job 01JDM0X8EVAM823JZBGKYNBA99)
        let filters = vec![JobDataFilter {
            path: "/user_id".to_string(),
            value: serde_json::json!(133),
        }];
        let jobs = queue
            .get_jobs_by_data(&filters, None, None)
            .await
            .expect("get jobs by data");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, "01JDM0X8EVAM823JZBGKYNBA99");

        // Filter by email = "user24@example.com" (should match job 01JDM0X8EVAM823JZBGKYNBA87)
        let filters = vec![JobDataFilter {
            path: "/email".to_string(),
            value: serde_json::json!("user24@example.com"),
        }];
        let jobs = queue
            .get_jobs_by_data(&filters, None, None)
            .await
            .expect("get jobs by data");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, "01JDM0X8EVAM823JZBGKYNBA87");

        // Filter with status constraint
        let filters = vec![JobDataFilter {
            path: "/email".to_string(),
            value: serde_json::json!("user11@example.com"),
        }];
        let jobs = queue
            .get_jobs_by_data(&filters, Some(&vec![JobStatus::Completed]), None)
            .await
            .expect("get jobs by data");
        assert_eq!(jobs.len(), 0); // user11 is queued, not completed

        // Multiple filters (AND): user_id=133 AND email=user11@example.com
        let filters = vec![
            JobDataFilter {
                path: "/user_id".to_string(),
                value: serde_json::json!(133),
            },
            JobDataFilter {
                path: "/email".to_string(),
                value: serde_json::json!("user11@example.com"),
            },
        ];
        let jobs = queue
            .get_jobs_by_data(&filters, None, None)
            .await
            .expect("get jobs by data");
        assert_eq!(jobs.len(), 1);

        // Multiple filters (AND) that don't both match same job
        let filters = vec![
            JobDataFilter {
                path: "/user_id".to_string(),
                value: serde_json::json!(133),
            },
            JobDataFilter {
                path: "/email".to_string(),
                value: serde_json::json!("user24@example.com"),
            },
        ];
        let jobs = queue
            .get_jobs_by_data(&filters, None, None)
            .await
            .expect("get jobs by data");
        assert_eq!(jobs.len(), 0);

        // Path doesn't exist in any job → returns empty
        let filters = vec![JobDataFilter {
            path: "/nonexistent/path".to_string(),
            value: serde_json::json!("anything"),
        }];
        let jobs = queue
            .get_jobs_by_data(&filters, None, None)
            .await
            .expect("get jobs by data");
        assert_eq!(jobs.len(), 0);
    }

    #[tokio::test]
    async fn queue_query_jobs_combined() {
        let tree_fs = tree_fs::TreeBuilder::default()
            .drop(true)
            .create()
            .expect("create temp folder");
        let qcfg = sqlite_config(tree_fs.root.as_path());
        let queue = sqlt::create_provider(&qcfg)
            .await
            .expect("create sqlite queue");

        let pool = sqlx::SqlitePool::connect(&qcfg.uri)
            .await
            .expect("connect to sqlite db");

        queue.setup().await.expect("setup sqlite db");
        tests_cfg::queue::sqlite_seed_data(&pool).await;

        // Combine name + data + status filters
        let filter = JobFilter {
            name: Some("UserAccountActivation".to_string()),
            data: Some(vec![JobDataFilter {
                path: "/user_id".to_string(),
                value: serde_json::json!(133),
            }]),
            status: Some(vec![JobStatus::Queued]),
            ..Default::default()
        };
        let jobs = queue.query_jobs(&filter).await.expect("query_jobs");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, "01JDM0X8EVAM823JZBGKYNBA99");

        // Same name + data but wrong status → empty
        let filter = JobFilter {
            name: Some("UserAccountActivation".to_string()),
            data: Some(vec![JobDataFilter {
                path: "/user_id".to_string(),
                value: serde_json::json!(133),
            }]),
            status: Some(vec![JobStatus::Completed]),
            ..Default::default()
        };
        let jobs = queue.query_jobs(&filter).await.expect("query_jobs");
        assert_eq!(jobs.len(), 0);

        // Empty filter → all jobs
        let filter = JobFilter::default();
        let jobs = queue.query_jobs(&filter).await.expect("query_jobs");
        assert_eq!(jobs.len(), 14);
    }
}

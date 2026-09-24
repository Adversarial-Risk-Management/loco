//! # Application Bootstrapping and Logic
//! This module contains functions and structures for bootstrapping and running
//! your application.
use std::{
    env,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::Router;
#[cfg(feature = "with-db")]
use sea_orm_migration::MigratorTrait;
use tokio::{signal, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

#[cfg(feature = "with-db")]
use crate::db;
use crate::{
    app::{AppContext, Hooks, Initializer},
    banner::print_banner,
    bgworker, cache,
    config::{self, Config, WorkerMode},
    controller::ListRoutes,
    env_vars,
    environment::Environment,
    errors::Error,
    mailer::{EmailSender, MailerWorker},
    prelude::BackgroundWorker,
    scheduler::{self, Scheduler},
    storage::{self, Storage},
    task::{self, Tasks},
    Result,
};

/// Represents the application startup mode.
#[derive(Debug, PartialEq, Eq)]
pub enum StartMode {
    /// Run the application as a server only. when running web server only,
    /// workers job will not handle.
    ServerOnly,
    /// Run the application web server and the worker in the same process.
    ServerAndWorker,
    /// Run the server and scheduler without workers.
    ServerAndScheduler,
    /// Pulling job worker and execute them
    WorkerOnly {
        /// Specifies that the worker should only handle jobs associated with one of these tags.
        /// If empty, the worker handles all jobs.
        tags: Vec<String>,
    },
    /// Run workers and scheduler without the HTTP server.
    WorkerAndScheduler {
        /// Specifies that the worker should only handle jobs associated with one of these tags.
        /// If empty, the worker handles all jobs.
        tags: Vec<String>,
    },
    /// Run the app with all available components in the same process.
    All,
}

pub struct BootResult {
    /// Application Context
    pub app_context: AppContext,
    /// Web server routes
    pub router: Option<Router>,
    /// worker processor
    pub worker: Option<Vec<String>>,
    /// scheduler processor
    pub run_scheduler: bool,
}

/// Configuration structure for serving an application.
#[derive(Debug)]
pub struct ServeParams {
    /// The port number on which the server will listen for incoming
    /// connections.
    pub port: i32,
    /// The network address to which the server will bind. It specifies the
    /// interface to listen on.
    pub binding: String,
}

/// Runs the application based on the provided `BootResult`.
///
/// This function is responsible for starting the application, including the
/// server and/or workers.
///
/// # Errors
///
/// When could not initialize the application.
pub async fn start<H: Hooks>(
    boot: BootResult,
    server_config: ServeParams,
    no_banner: bool,
) -> Result<()> {
    start_until::<H>(boot, server_config, no_banner, shutdown_signal()).await
}

async fn start_until<H: Hooks>(
    boot: BootResult,
    server_config: ServeParams,
    no_banner: bool,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let scheduler = if boot.run_scheduler {
        Some(scheduler::<H>(&boot.app_context, None, None, None)?)
    } else {
        None
    };

    if !no_banner {
        print_banner(&boot, &server_config);
    }

    let BootResult {
        router,
        worker,
        run_scheduler: _,
        app_context,
    } = boot;

    let worker_handle = if app_context.config.workers.mode == WorkerMode::BackgroundQueue {
        worker
            .map(|tags| start_queue_worker(&app_context, tags))
            .transpose()?
    } else {
        None
    };

    let scheduler_handle = scheduler.map(|scheduler| {
        let app_context = app_context.clone();
        tokio::spawn(async move {
            let shutdown = app_context.shutdown.clone();
            if let Err(err) = scheduler.run_until(&app_context, shutdown).await {
                error!(err = err.to_string(), "error while running scheduler");
            }
        })
    });

    let mut server = router.map(|router| H::serve(router, &app_context, &server_config));
    let shutdown_token = app_context.shutdown.clone();
    tokio::pin!(shutdown);

    let mut server_result = if let Some(server) = server.as_mut() {
        tokio::select! {
            result = &mut *server => Some(result),
            () = shutdown.as_mut() => None,
            () = shutdown_token.cancelled() => None,
        }
    } else {
        tokio::select! {
            () = shutdown.as_mut() => {},
            () = shutdown_token.cancelled() => {},
        }
        None
    };

    info!("shutting down...");
    app_context.shutdown.cancel();

    let queue_shutdown_result = if worker_handle.is_some() {
        app_context
            .queue_provider
            .as_ref()
            .ok_or(Error::QueueProviderMissing)
            .and_then(|queue| queue.shutdown())
    } else {
        Ok(())
    };

    let drained = drain_or_force_quit(async move {
        if server_result.is_none()
            && let Some(server) = server.as_mut()
        {
            server_result = Some(server.await);
        }

        if let Some(handle) = worker_handle
            && let Err(err) = handle.await
        {
            error!(err = err.to_string(), "failed to join queue worker task");
        }

        if let Some(handle) = scheduler_handle
            && let Err(err) = handle.await
        {
            error!(err = err.to_string(), "failed to join scheduler task");
        }

        server_result
    })
    .await;

    H::on_shutdown(&app_context).await;

    drained.flatten().unwrap_or(Ok(()))?;
    queue_shutdown_result?;

    Ok(())
}

/// Awaits `drain` until it completes or a second shutdown signal arrives.
///
/// Returns `None` when the operator forces the exit before `drain` completes.
/// The pending `drain` future is dropped in that case, so a stuck job cannot
/// block process exit.
pub(crate) async fn drain_or_force_quit<T>(
    drain: impl std::future::Future<Output = T>,
) -> Option<T> {
    info!("press ctrl-c again to force quit");
    tokio::select! {
        result = drain => Some(result),
        () = shutdown_signal() => {
            warn!("forced shutdown: running tasks did not finish");
            None
        }
    }
}

fn start_queue_worker(app_context: &AppContext, tags: Vec<String>) -> Result<JoinHandle<()>> {
    debug!("note: worker is run in-process (tokio spawn)");

    if let Some(queue) = &app_context.queue_provider {
        let cloned_queue = queue.clone();
        let handle = tokio::spawn(async move {
            if let Err(err) = cloned_queue.run(tags).await {
                error!(err = err.to_string(), "error while running worker");
            }
        });
        return Ok(handle);
    }

    Err(Error::QueueProviderMissing)
}

/// Run task
///
/// # Errors
///
/// When running could not run the task.
pub async fn run_task<H: Hooks>(
    app_context: &AppContext,
    task: Option<&String>,
    vars: &task::Vars,
) -> Result<()> {
    let mut tasks = Tasks::default();
    H::register_tasks(&mut tasks);

    if let Some(task) = task {
        let task_span = tracing::span!(tracing::Level::DEBUG, "task", task,);
        let _guard = task_span.enter();
        tasks.run(app_context, task, vars).await?;
    } else {
        let list = tasks.list();
        for item in &list {
            println!("{:<30}[{}]", item.name, item.detail);
        }
    }
    Ok(())
}

/// Initializes a new scheduler instance based on the provided configuration and context.
fn scheduler<H: Hooks>(
    app_context: &AppContext,
    config: Option<&PathBuf>,
    name: Option<String>,
    tag: Option<String>,
) -> Result<Scheduler> {
    let env_config_path = env::var(env_vars::SCHEDULER_CONFIG).ok();

    let config_path: Option<&Path> = config.map_or_else(
        || env_config_path.as_deref().map(Path::new),
        |path| Some(path.as_path()),
    );

    let scheduler = match config_path {
        Some(path) => Scheduler::from_config::<H>(path, &app_context.environment)?,
        None => {
            if let Some(config) = &app_context.config.scheduler {
                Scheduler::new::<H>(config, &app_context.environment)?
            } else {
                return Err(Error::Scheduler(scheduler::Error::Empty));
            }
        }
    };

    Ok(scheduler.by_spec(&scheduler::Spec { name, tag }))
}

/// Runs the scheduler with the given configuration and context. in case if list
/// args is true prints scheduler job configuration
///
/// This function initializes the scheduler, registers tasks through the
/// provided [`Hooks`], and executes the scheduler based on the specified
/// configuration or context. The scheduler continuously runs, managing and
/// executing scheduled tasks until a signal is received to shut down.
/// Upon receiving this signal, the function gracefully shuts down all running
/// tasks and exits safely.
///
/// # Errors
///
/// When running could not run the scheduler.
pub async fn run_scheduler<H: Hooks>(
    app_context: &AppContext,
    config: Option<&PathBuf>,
    name: Option<String>,
    tag: Option<String>,
    list: bool,
) -> Result<()> {
    let task_span = tracing::span!(tracing::Level::DEBUG, "scheduler_jobs");
    let _guard = task_span.enter();

    let scheduler = scheduler::<H>(app_context, config, name, tag)?;
    if list {
        println!("{scheduler}");
        Ok(())
    } else {
        let result = scheduler.run(app_context).await;
        H::on_shutdown(app_context).await;
        Ok(result?)
    }
}

/// Represents commands for handling database-related operations.
#[derive(Debug)]
pub enum RunDbCommand {
    /// Apply pending migrations.
    Migrate,
    /// Run one or more down migrations.
    Down(u32),
    /// Drop all tables, then reapply all migrations.
    Reset,
    /// Check the status of all migrations.
    Status,
    /// Generate entity.
    Entities,
    /// Truncate tables, by executing the implementation in [`Hooks::seed`]
    /// (without dropping).
    Truncate,
    /// Seed database.
    Seed {
        reset: bool,
        from: PathBuf,
        dump: bool,
        dump_tables: Option<Vec<String>>,
    },
    /// Dump database schema
    Schema,
}

#[cfg(feature = "with-db")]
/// Handles database commands.
///
/// # Errors
///
/// Return an error when the given command fails. mostly return
/// [`sea_orm::DbErr`]
#[allow(clippy::cognitive_complexity)]
pub async fn run_db<H: Hooks, M: MigratorTrait>(
    app_context: &AppContext,
    cmd: RunDbCommand,
) -> Result<()> {
    match cmd {
        RunDbCommand::Migrate => {
            tracing::warn!("migrate:");
            db::migrate::<M>(&app_context.db).await?;
        }
        RunDbCommand::Down(steps) => {
            tracing::warn!("down:");
            db::down::<M>(&app_context.db, steps).await?;
        }
        RunDbCommand::Reset => {
            tracing::warn!("reset:");
            db::reset::<M>(&app_context.db).await?;
        }
        RunDbCommand::Status => {
            tracing::warn!("status:");
            db::status::<M>(&app_context.db).await?;
        }
        RunDbCommand::Entities => {
            tracing::warn!("entities:");

            tracing::warn!("{}", db::entities::<M>(app_context).await?);
        }
        RunDbCommand::Truncate => {
            tracing::warn!("truncate:");
            H::truncate(app_context).await?;
        }
        RunDbCommand::Seed {
            reset,
            from,
            dump,
            dump_tables,
        } => {
            tracing::warn!(reset = reset, from = %from.display(), "seed:");

            if let Some(tables) = dump_tables {
                // Explicit table list: schema-introspection dump of just those tables.
                db::dump_tables(&app_context.db, from.as_path(), Some(tables)).await?;
            } else if dump {
                // Plain `--dump`: route through Hooks::dump so apps can override
                // it with typed, streaming db::dump per entity.
                db::run_app_dump::<H>(app_context, &from).await?;
            } else {
                if reset {
                    db::reset::<M>(&app_context.db).await?;
                }
                db::run_app_seed::<H>(app_context, &from).await?;
            }
        }
        RunDbCommand::Schema => {
            db::dump_schema(app_context, "schema_dump.json").await?;
            println!("Database schema dumped to 'schema_dump.json'");
        }
    }
    Ok(())
}

/// Initializes the application context by loading configuration and
/// establishing connections.
///
/// # Errors
/// When has an error to create DB connection.
pub async fn create_context<H: Hooks>(
    environment: &Environment,
    config: Config,
) -> Result<AppContext> {
    if config.logger.pretty_backtrace {
        // SAFETY: `create_context` runs during boot, before the server or any
        // background-worker threads are spawned, so no other thread is reading
        // or writing the environment concurrently.
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
        warn!(
            "pretty backtraces are enabled (this is great for development but has a runtime cost \
             for production. disable with `logger.pretty_backtrace` in your config yaml)"
        );
    }
    #[cfg(feature = "with-db")]
    let db = db::connect(&config.database).await?;

    let mailer = if let Some(cfg) = config.mailer.as_ref() {
        create_mailer(cfg)?
    } else {
        None
    };

    let queue_provider = bgworker::create_queue_provider(&config).await?;
    let ctx = AppContext {
        environment: environment.clone(),
        #[cfg(feature = "with-db")]
        db,
        queue_provider,
        storage: Storage::single(storage::drivers::null::new()).into(),
        cache: cache::create_cache_provider(&config).await?,
        config,
        mailer,
        shared_store: Arc::new(crate::app::SharedStore::default()),
        shutdown: CancellationToken::new(),
    };

    H::after_context(ctx).await
}

#[cfg(feature = "with-db")]
/// Creates an application based on the specified mode and environment.
///
/// # Errors
///
/// When could not create the application
pub async fn create_app<H: Hooks, M: MigratorTrait>(
    mode: StartMode,
    environment: &Environment,
    config: Config,
) -> Result<BootResult> {
    let app_context = create_context::<H>(environment, config).await?;
    db::converge::<H, M>(&app_context, &app_context.config.database).await?;

    if let (Some(queue), Some(config)) = (&app_context.queue_provider, &app_context.config.queue) {
        bgworker::converge(queue, config).await?;
    }

    run_app::<H>(&mode, app_context).await
}

#[cfg(not(feature = "with-db"))]
pub async fn create_app<H: Hooks>(
    mode: StartMode,
    environment: &Environment,
    config: Config,
) -> Result<BootResult> {
    let app_context = create_context::<H>(environment, config).await?;

    if let (Some(queue), Some(config)) = (&app_context.queue_provider, &app_context.config.queue) {
        bgworker::converge(queue, config).await?;
    }

    run_app::<H>(&mode, app_context).await
}

/// Run the application with the  given mode
/// # Errors
///
/// When could not create the application
pub async fn run_app<H: Hooks>(mode: &StartMode, app_context: AppContext) -> Result<BootResult> {
    H::before_run(&app_context).await?;
    let initializers = H::initializers(&app_context).await?;

    info!(
        initializers = ?initializers.iter().map(|init| init.name()).collect::<Vec<_>>().join(","),
        "initializers loaded"
    );

    for initializer in &initializers {
        initializer.before_run(&app_context).await?;
    }

    match mode {
        StartMode::ServerOnly => {
            let router = setup_routes::<H>(&app_context, &initializers).await?;
            Ok(BootResult {
                app_context,
                router: Some(router),
                worker: None,
                run_scheduler: false,
            })
        }
        StartMode::ServerAndWorker => {
            register_workers::<H>(&app_context).await?;
            let router = setup_routes::<H>(&app_context, &initializers).await?;
            Ok(BootResult {
                app_context,
                router: Some(router),
                worker: Some(vec![]),
                run_scheduler: false,
            })
        }
        StartMode::ServerAndScheduler => {
            let router = setup_routes::<H>(&app_context, &initializers).await?;
            Ok(BootResult {
                app_context,
                router: Some(router),
                worker: None,
                run_scheduler: true,
            })
        }
        StartMode::All => {
            register_workers::<H>(&app_context).await?;
            let router = setup_routes::<H>(&app_context, &initializers).await?;
            Ok(BootResult {
                app_context,
                router: Some(router),
                worker: Some(vec![]),
                run_scheduler: true,
            })
        }
        StartMode::WorkerOnly { tags } => {
            register_workers::<H>(&app_context).await?;
            Ok(BootResult {
                app_context,
                router: None,
                worker: Some(tags.clone()),
                run_scheduler: false,
            })
        }
        StartMode::WorkerAndScheduler { tags } => {
            register_workers::<H>(&app_context).await?;
            Ok(BootResult {
                app_context,
                router: None,
                worker: Some(tags.clone()),
                run_scheduler: true,
            })
        }
    }
}

/// Sets up the application's routes based on the provided initializers and hooks.
async fn setup_routes<H: Hooks>(
    app_context: &AppContext,
    initializers: &[Box<dyn Initializer>],
) -> Result<Router> {
    let app = H::before_routes(app_context).await?;
    let app = H::routes(app_context).to_router::<H>(app_context.clone(), app)?;
    let mut router = H::after_routes(app, app_context).await?;

    for initializer in initializers {
        router = initializer.after_routes(router, app_context).await?;
    }

    Ok(router)
}

async fn register_workers<H: Hooks>(app_context: &AppContext) -> Result<()> {
    if app_context.config.workers.mode == WorkerMode::BackgroundQueue {
        if let Some(queue) = &app_context.queue_provider {
            queue.register(MailerWorker::build(app_context)).await?;
            H::connect_workers(app_context, queue).await?;
        } else {
            return Err(Error::QueueProviderMissing);
        }

        debug!("done registering workers and queues");
    }
    Ok(())
}

#[must_use]
pub fn list_endpoints<H: Hooks>(ctx: &AppContext) -> Vec<ListRoutes> {
    H::routes(ctx).collect()
}

/// Waits for a shutdown signal, either via Ctrl+C or termination signal.
///
/// # Panics
///
/// This function will panic if it fails to install the signal handlers for
/// Ctrl+C or the terminate signal on Unix-based systems.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

pub struct MiddlewareInfo {
    pub id: String,
    pub enabled: bool,
    pub detail: String,
}

#[must_use]
pub fn list_middlewares<H: Hooks>(ctx: &AppContext) -> Vec<MiddlewareInfo> {
    H::middlewares(ctx)
        .iter()
        .map(|m| MiddlewareInfo {
            id: m.name().to_string(),
            enabled: m.is_enabled(),
            detail: m.config().unwrap_or_default().to_string(),
        })
        .collect::<Vec<_>>()
}

/// Initializes an [`EmailSender`] based on the mailer configuration settings
/// ([`config::Mailer`]).
fn create_mailer(config: &config::Mailer) -> Result<Option<EmailSender>> {
    if config.stub {
        return Ok(Some(EmailSender::stub()));
    }
    if let Some(smtp) = config.smtp.as_ref()
        && smtp.enable
    {
        return Ok(Some(EmailSender::smtp(smtp)?));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::{bgworker::Queue, controller::AppRoutes, tests_cfg::app::get_app_context};

    struct LifecycleHooks;

    #[async_trait]
    impl Hooks for LifecycleHooks {
        fn app_name() -> &'static str {
            "lifecycle_hooks_test"
        }

        async fn boot(
            _mode: StartMode,
            _environment: &Environment,
            _config: Config,
        ) -> Result<BootResult> {
            unreachable!("not exercised by this test")
        }

        async fn connect_workers(_ctx: &AppContext, _queue: &Queue) -> Result<()> {
            unreachable!("not exercised by this test")
        }

        fn register_tasks(_tasks: &mut task::Tasks) {
            unreachable!("not exercised by this test")
        }

        async fn truncate(_ctx: &AppContext) -> Result<()> {
            unreachable!("not exercised by this test")
        }

        async fn seed(_ctx: &AppContext, _path: &Path) -> Result<()> {
            unreachable!("not exercised by this test")
        }

        fn routes(_ctx: &AppContext) -> AppRoutes {
            unreachable!("not exercised by this test")
        }

        async fn serve(
            _app: axum::Router,
            ctx: &AppContext,
            _serve_params: &ServeParams,
        ) -> Result<()> {
            ctx.shutdown.cancelled().await;
            ctx.shared_store
                .get::<Arc<Mutex<Vec<&'static str>>>>()
                .unwrap()
                .lock()
                .unwrap()
                .push("server stopped");
            Ok(())
        }

        async fn on_shutdown(ctx: &AppContext) {
            ctx.shared_store
                .get::<Arc<Mutex<Vec<&'static str>>>>()
                .unwrap()
                .lock()
                .unwrap()
                .push("hook");
        }
    }

    #[tokio::test]
    async fn shutdown_drains_components_before_running_hook() {
        let app_context = get_app_context().await;
        let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        app_context.shared_store.insert(Arc::clone(&events));
        let shutdown = app_context.shutdown.clone();

        start_until::<LifecycleHooks>(
            BootResult {
                app_context,
                router: Some(axum::Router::new()),
                worker: None,
                run_scheduler: false,
            },
            ServeParams {
                port: 0,
                binding: "127.0.0.1".to_string(),
            },
            true,
            std::future::ready(()),
        )
        .await
        .unwrap();

        assert!(shutdown.is_cancelled());
        assert_eq!(*events.lock().unwrap(), ["server stopped", "hook"]);
    }
}

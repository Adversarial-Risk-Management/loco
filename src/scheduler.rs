//! # Scheduler Module
//! TBD

use std::{
    collections::HashMap,
    fmt, io,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Instant,
};

use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::Instrument;
use uuid::Uuid;

use crate::{
    app::{AppContext, Hooks},
    environment::Environment,
    task::{Tasks, Vars},
};

mod cron;

static RE_IS_CRON_SYNTAX: OnceLock<Regex> = OnceLock::new();

fn get_re_is_cron_syntax() -> &'static Regex {
    RE_IS_CRON_SYNTAX.get_or_init(|| Regex::new(r"^[\*\d]").unwrap())
}

/// Errors that may occur while operating the scheduler.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("schedulers not configured")]
    Empty,

    #[error("task `{0}` not found")]
    TaskNotFound(String),

    #[error("Scheduler config file not found in path: '{}'", path.display())]
    ConfigNotFound { path: PathBuf, error: io::Error },

    #[error("Invalid scheduler config schema. err: '{}'", error.as_display())]
    InvalidConfigSchema { error: serde_yaml::Error },

    #[error("Invalid cron {cron}. err: '{}'", error.as_display())]
    InvalidCronSyntax { cron: String, error: String },

    #[error(transparent)]
    IO(#[from] std::io::Error),
}

/// Result type used in the module, with a custom error type.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Configuration structure for the scheduler.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// A list of jobs to be scheduled.
    pub jobs: HashMap<String, Job>,
    /// The default output setting for the jobs.
    #[serde(default)]
    pub output: Output,
}

/// Representing a single job in the scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    /// The command to run.
    /// In case of task: it should be a task name and also task arguments
    pub run: String,
    #[serde(default)]
    pub shell: bool,
    #[serde(default)]
    pub run_on_start: bool,
    #[serde(rename = "schedule")]
    /// The cron expression defining the job's schedule.
    ///
    /// The format is as follows:
    /// sec   min   hour   day of month   month   day of week   year
    /// * *     *      *              *       *             *
    pub cron: String,
    /// Tags for tagging the job.
    pub tags: Option<Vec<String>>,
    /// Output settings for the job.
    pub output: Option<Output>,
}

impl fmt::Display for Scheduler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "#      job_name       run_on_start      schedule               tags               run"
        )?;

        let mut job_names: Vec<&String> = self.jobs.keys().collect();
        job_names.sort();

        for (index, &job_name) in job_names.iter().enumerate() {
            if let Some(job) = self.jobs.get(job_name) {
                writeln!(
                    f,
                    "{:<6} {:<15} {:<12} {:<22} {:<18} {:?}",
                    index + 1,
                    job_name,
                    job.run_on_start,
                    job.cron,
                    job.tags
                        .as_ref()
                        .map_or_else(|| "-".to_string(), |tags| tags.join(", ")),
                    job.run,
                )?;
            }
        }

        Ok(())
    }
}

/// Representing the scheduler itself.
#[derive(Clone)]
pub struct Scheduler {
    pub jobs: HashMap<String, Job>,
    default_output: Output,
    app_context: Arc<AppContext>,
    tasks: Arc<Tasks>,
}

/// Specification used to filter all scheduler job with the given Spec.
#[derive(Debug)]
pub struct Spec {
    pub name: Option<String>,
    pub tag: Option<String>,
}

/// Enum representing the scheduler job output.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub enum Output {
    /// Silent output, the STDOUT or STDERR of the job will not view out.
    #[serde(rename = "silent")]
    Silent,
    /// The STDOUT or STDERR of the job will view propagated
    #[default]
    #[serde(rename = "stdout")]
    STDOUT,
}

/// Structure representing the job command.
#[derive(Clone, Debug)]
pub struct JobDescription {
    /// The command to execute.
    pub command: String,
    /// The output setting for the job.
    pub output: Output,
    /// The environment in which the job will run.
    pub environment: Environment,
}

/// What a scheduled job runs on each firing.
#[derive(Clone)]
enum JobExecution {
    /// A registered task, run in the scheduler process.
    Task {
        name: String,
        args: Vec<String>,
        tasks: Arc<Tasks>,
        app_context: Arc<AppContext>,
    },
    /// A shell command, run in a subprocess.
    Shell(JobDescription),
}

impl Job {
    /// Prepares the shell command for a job configured with `shell: true`.
    ///
    /// [`JobDescription::run`] executes the description through a shell. The
    /// scheduler runs native tasks in process instead.
    #[must_use]
    pub fn prepare_command(
        &self,
        default_output: &Output,
        environment: &Environment,
    ) -> JobDescription {
        JobDescription {
            command: self.run.clone(),
            output: self
                .output
                .clone()
                .unwrap_or_else(|| default_output.clone()),
            environment: environment.clone(),
        }
    }

    fn task_arguments(&self) -> io::Result<Vec<String>> {
        shlex::split(&self.run).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid quoting in scheduler task",
            )
        })
    }
}

impl JobDescription {
    /// Executes this command string through the platform shell.
    ///
    /// # Errors
    ///
    /// In addition to all the IO errors possible
    pub fn run(&self) -> io::Result<std::process::Output> {
        tracing::info!(command = &self.command, "execute job command");
        self.run_process(&shell_process(&self.command))
    }

    fn run_process(&self, process: &duct::Expression) -> io::Result<std::process::Output> {
        let mut exec_job = process.env("LOCO_ENV", self.environment.to_string());
        exec_job = match self.output {
            Output::Silent => exec_job.stdout_null().stderr_null(),
            Output::STDOUT => exec_job,
        };

        exec_job.run()
    }
}

fn shell_process(command: &str) -> duct::Expression {
    // Run the command through the platform shell (previously `duct_sh`).
    if cfg!(windows) {
        duct::cmd!("cmd.exe", "/C", command)
    } else {
        duct::cmd!("/bin/sh", "-c", command)
    }
}

impl Scheduler {
    /// Creates a new scheduler instance from the given configuration file.
    ///
    /// # Errors
    ///
    /// When could not parse the given file content into a [`Config`] struct.
    pub fn from_config<H: Hooks>(config: &Path, app_context: &AppContext) -> Result<Self> {
        let config_str =
            std::fs::read_to_string(config).map_err(|error| Error::ConfigNotFound {
                path: config.to_path_buf(),
                error,
            })?;

        let config: Config = serde_yaml::from_str(&config_str)
            .map_err(|error| Error::InvalidConfigSchema { error })?;

        Self::new::<H>(&config, app_context)
    }

    /// Creates a new scheduler instance from the provided configuration data.
    ///
    /// When creating a new scheduler instance all register task should be
    /// loaded for validate the given configuration.
    ///
    /// # Errors
    ///
    /// When there is not job in the given config
    pub fn new<H: Hooks>(data: &Config, app_context: &AppContext) -> Result<Self> {
        let mut tasks = Tasks::default();
        H::register_tasks(&mut tasks);

        let mut jobs = HashMap::new();
        for (job_name, job) in &data.jobs {
            if job.shell {
                jobs.insert(job_name.clone(), job.clone());
            } else {
                let arguments = job.task_arguments()?;
                let task_name = arguments.first().map_or("", String::as_str);
                if tasks.names().iter().any(|name| name.as_str() == task_name) {
                    jobs.insert(job_name.clone(), job.clone());
                } else {
                    return Err(Error::TaskNotFound(task_name.to_string()));
                }
            }
        }

        if jobs.is_empty() {
            return Err(Error::Empty);
        }

        Ok(Self {
            jobs,
            default_output: data.output.clone(),
            app_context: Arc::new(app_context.clone()),
            tasks: Arc::new(tasks),
        })
    }

    /// Filters the scheduler's jobs based on the provided specification.
    #[must_use]
    pub fn by_spec(self, include_jobs: &Spec) -> Self {
        let jobs = self
            .jobs
            .into_iter()
            .filter(|(job_name, job)| {
                if let Some(name) = &include_jobs.name {
                    return name == job_name;
                }

                if let Some(tag) = &include_jobs.tag
                    && let Some(job_tags) = &job.tags
                {
                    return job_tags.contains(tag);
                }

                true
            })
            .collect::<HashMap<String, Job>>();

        Self { jobs, ..self }
    }

    /// Runs the scheduled jobs according to their cron expressions.
    ///
    /// # Errors
    ///
    /// When could not add job to the scheduler
    pub async fn run(self) -> Result<()> {
        let mut tasks = tokio::task::JoinSet::new();

        for (job_name, job) in self.jobs {
            let execution = if job.shell {
                JobExecution::Shell(
                    job.prepare_command(&self.default_output, &self.app_context.environment),
                )
            } else {
                let mut args = job.task_arguments()?.into_iter();
                JobExecution::Task {
                    name: args.next().unwrap_or_default(),
                    args: args.collect(),
                    tasks: Arc::clone(&self.tasks),
                    app_context: Arc::clone(&self.app_context),
                }
            };

            let cron_syntax = if get_re_is_cron_syntax().is_match(&job.cron) {
                job.cron.clone()
            } else {
                english_to_cron::str_cron_syntax(&job.cron).map_err(|err| {
                    Error::InvalidCronSyntax {
                        cron: job.cron.clone(),
                        error: err.to_string(),
                    }
                })?
            };
            let cron =
                cron::Cron::parse(&cron_syntax).map_err(|error| Error::InvalidCronSyntax {
                    cron: cron_syntax.clone(),
                    error,
                })?;

            tasks.spawn(async move {
                // Runs of this job. Dropping the set on shutdown cancels task
                // runs; shell runs already in a subprocess run to completion.
                let mut runs = tokio::task::JoinSet::new();
                if job.run_on_start {
                    runs.spawn(execute_job(job_name.clone(), execution.clone()));
                }
                while let Some(next) = cron.next_after(chrono::Utc::now()) {
                    let wait = (next - chrono::Utc::now()).to_std().unwrap_or_default();
                    tokio::time::sleep(wait).await;
                    while runs.try_join_next().is_some() {}
                    // A run does not wait for the previous one, so a slow run
                    // never delays the next tick.
                    runs.spawn(execute_job(job_name.clone(), execution.clone()));
                }
                tracing::warn!(job_name, "cron has no further occurrences; job stopped");
                while runs.join_next().await.is_some() {}
            });
        }

        crate::boot::shutdown_signal().await;
        tasks.shutdown().await;

        Ok(())
    }
}

async fn execute_job(job_name: String, execution: JobExecution) {
    let task_span = tracing::span!(
        tracing::Level::DEBUG,
        "run_job",
        job_name,
        job_id = ?Uuid::new_v4(),
    );

    async move {
        let start = Instant::now();
        match execution {
            JobExecution::Task {
                name,
                args,
                tasks,
                app_context,
            } => {
                // Only the task name: its arguments may carry secrets.
                tracing::info!(task = name, "execute scheduler task");
                match tasks.run(&app_context, &name, &Vars::from_args(args)).await {
                    Ok(()) => tracing::debug!(
                        duration = ?start.elapsed(),
                        "execute scheduler job finished"
                    ),
                    Err(err) => tracing::error!(
                        duration = ?start.elapsed(),
                        error = %err,
                        "failed to execute scheduler task"
                    ),
                }
            }
            JobExecution::Shell(job_description) => {
                tracing::info!(command = job_description.command, "execute job command");
                // `run_process` blocks for the whole child-process lifetime,
                // so it runs off the async runtime's worker threads. The
                // process is unchecked to report its exit status below.
                let result = tokio::task::spawn_blocking(move || {
                    job_description
                        .run_process(&shell_process(&job_description.command).unchecked())
                })
                .await;
                match result {
                    Ok(Ok(output)) if !output.status.success() => tracing::error!(
                        duration = ?start.elapsed(),
                        status_code = output.status.code(),
                        "failed to execute scheduler job in sub process"
                    ),
                    Ok(Ok(output)) => tracing::debug!(
                        duration = ?start.elapsed(),
                        status_code = output.status.code(),
                        "execute scheduler job finished"
                    ),
                    Ok(Err(err)) => tracing::error!(
                        duration = ?start.elapsed(),
                        error = %err,
                        "failed to execute scheduler job in sub process"
                    ),
                    Err(err) => tracing::error!(
                        duration = ?start.elapsed(),
                        error = %err,
                        "scheduler job panicked"
                    ),
                }
            }
        }
    }
    .instrument(task_span)
    .await;
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use insta::assert_debug_snapshot;
    use tests_cfg::db::AppHook;
    use tokio::time::{self, Duration};
    use tree_fs::TreeBuilder;

    use super::*;
    use crate::{task::TaskInfo, tests_cfg, Result as LocoResult};

    /// Arguments each run of [`RecordTask`] received.
    type Runs = Arc<Mutex<Vec<Vec<String>>>>;

    /// Records its arguments in the [`Runs`] in the app's shared store.
    struct RecordTask;

    #[async_trait::async_trait]
    impl crate::task::Task for RecordTask {
        fn task(&self) -> TaskInfo {
            TaskInfo {
                name: "record".to_string(),
                detail: "record native task execution".to_string(),
            }
        }

        async fn run(&self, app_context: &AppContext, vars: &Vars) -> LocoResult<()> {
            app_context
                .shared_store
                .get::<Runs>()
                .expect("test recorder should be registered")
                .lock()
                .unwrap()
                .push(vars.args().to_vec());
            Ok(())
        }
    }

    async fn setup_scheduler_config() -> (Scheduler, tree_fs::Tree) {
        let tree = TreeBuilder::default()
            .add_file(
                "scheduler.yaml",
                r#"
jobs:
  print_task:
    run: foo
    schedule: "*/5 * * * * *"
    tags:
      - base
      - echo

  write_to_file:
    run: "echo loco >> ./scheduler.txt"
    shell: true
    schedule: "*/5 * * * * *"
    tags:
      - base
      - write

  run_on_start_task:
    run: "echo \"Does this run on start?\" >> ./run_on_start.txt "
    shell: true
    schedule: "every 24 hours"
    run_on_start: true
    tags:
      - start
"#,
            )
            .create()
            .expect("Failed to create test directory structure");

        let scheduler = Scheduler::from_config::<AppHook>(
            &tree.root.join("scheduler.yaml"),
            &tests_cfg::app::get_app_context().await,
        )
        .expect("Failed to create scheduler from config");

        (scheduler, tree)
    }

    #[tokio::test]
    pub async fn can_display_scheduler() {
        let (scheduler, _tree) = setup_scheduler_config().await;
        assert_debug_snapshot!(format!("{scheduler}"));
    }

    #[tokio::test]
    pub async fn can_load_from_config_local_config() {
        // Succeeds as long as loading the config doesn't panic or error.
        let (_, _tree) = setup_scheduler_config().await;
    }

    #[tokio::test]
    pub async fn can_load_from_env_config() {
        let app_context = tests_cfg::app::get_app_context().await;
        let scheduler =
            Scheduler::new::<AppHook>(&app_context.config.scheduler.clone().unwrap(), &app_context);

        assert!(scheduler.is_ok());
    }

    #[tokio::test]
    pub async fn can_load_jobs_by_spec_tag_multiple_jobs() {
        let (scheduler, _tree) = setup_scheduler_config().await;
        let scheduler = scheduler.by_spec(&Spec {
            name: None,
            tag: Some("base".to_string()),
        });

        assert_eq!(scheduler.jobs.len(), 2);
    }

    #[tokio::test]
    pub async fn can_load_jobs_by_spec_tag_single_jobs() {
        let (scheduler, _tree) = setup_scheduler_config().await;
        let scheduler = scheduler.by_spec(&Spec {
            name: None,
            tag: Some("echo".to_string()),
        });

        assert_eq!(scheduler.jobs.len(), 1);
        assert!(scheduler.jobs.contains_key("print_task"));
    }

    #[tokio::test]
    pub async fn can_load_jobs_by_spec_with_job_name() {
        let (scheduler, _tree) = setup_scheduler_config().await;
        let scheduler = scheduler.by_spec(&Spec {
            name: Some("write_to_file".to_string()),
            tag: None,
        });

        assert_eq!(scheduler.jobs.len(), 1);
        assert!(scheduler.jobs.contains_key("write_to_file"));
    }

    #[test]
    pub fn can_prepare_command() {
        let job = Job {
            run: "echo loco".to_string(),
            shell: true,
            run_on_start: false,
            cron: "*/5 * * * * *".to_string(),
            tags: None,
            output: None,
        };

        let prepare_command = job.prepare_command(&Output::STDOUT, &Environment::Test);
        assert_debug_snapshot!("can_prepare_command_[shell]", prepare_command);
    }

    #[tokio::test]
    async fn native_task_runs_in_process_with_arguments_on_start_and_later_ticks() {
        let tree = TreeBuilder::default().drop(true).create().unwrap();
        let sentinel = tree.root.join("shell-sentinel");
        let (mut scheduler, _config_tree) = setup_scheduler_config().await;
        let runs = Runs::default();
        scheduler.app_context.shared_store.insert(Arc::clone(&runs));
        let mut tasks = Tasks::default();
        tasks.register(RecordTask);
        scheduler.tasks = Arc::new(tasks);
        scheduler.jobs = HashMap::from([(
            "record".to_string(),
            Job {
                run: format!(
                    "record 'two words' '' '$LOCO_ENV' flag:on ; touch '{}'",
                    sentinel.display()
                ),
                shell: false,
                run_on_start: true,
                cron: "* * * * * *".to_string(),
                tags: None,
                output: None,
            },
        )]);

        let handle = tokio::spawn(async move { scheduler.run().await });
        let completed = time::timeout(Duration::from_secs(5), async {
            while runs.lock().unwrap().len() < 2 {
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        handle.abort();
        let _ = handle.await;
        assert!(
            completed.is_ok(),
            "native scheduler did not run its task on startup and a later tick"
        );
        let expected = [
            "two words",
            "",
            "$LOCO_ENV",
            "flag:on",
            ";",
            "touch",
            sentinel.to_str().unwrap(),
        ];
        let runs = runs.lock().unwrap();
        assert!(runs.iter().all(|args| args == &expected), "{runs:?}");
        assert!(
            !sentinel.exists(),
            "native arguments must not execute shell syntax"
        );
    }

    #[tokio::test]
    async fn native_job_validation_uses_quoted_arguments() {
        let (scheduler, _tree) = setup_scheduler_config().await;
        let app_context = tests_cfg::app::get_app_context().await;
        let mut config = Config {
            jobs: scheduler.jobs,
            output: Output::STDOUT,
        };
        config.jobs.retain(|name, _| name == "print_task");
        config.jobs.get_mut("print_task").unwrap().run = "'foo' 'value:two words'".to_string();
        assert!(Scheduler::new::<AppHook>(&config, &app_context).is_ok());
        config.jobs.get_mut("print_task").unwrap().run = "foo 'unclosed".to_string();
        assert!(matches!(
            Scheduler::new::<AppHook>(&config, &app_context),
            Err(Error::IO(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[cfg(unix)]
    #[test]
    fn shell_jobs_retain_output_modes_and_unsuccessful_status() {
        for output in [Output::STDOUT, Output::Silent] {
            let job = Job {
                run: "printf stdout; printf stderr >&2; exit 37".to_string(),
                shell: true,
                run_on_start: false,
                cron: "* * * * * *".to_string(),
                tags: None,
                output: Some(output.clone()),
            };
            let description = job.prepare_command(&output, &Environment::Test);
            let process = shell_process(&job.run).unchecked();
            let process = if matches!(output, Output::STDOUT) {
                process.stdout_capture().stderr_capture()
            } else {
                process
            };
            let result = description.run_process(&process).unwrap();
            assert_eq!(result.status.code(), Some(37));
            if matches!(output, Output::Silent) {
                assert!(result.stdout.is_empty());
                assert!(result.stderr.is_empty());
            } else {
                assert_eq!(result.stdout, b"stdout");
                assert_eq!(result.stderr, b"stderr");
            }
        }
    }

    #[tokio::test]
    pub async fn can_run() {
        let (mut scheduler, _config_tree) = setup_scheduler_config().await;

        let tree_fs = tree_fs::TreeBuilder::default()
            .drop(true)
            .add("scheduler.txt", "")
            .add("scheduler2.txt", "")
            .add("scheduler3.txt", "")
            .create()
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(tree_fs.root.join("scheduler.txt"))
                .unwrap()
                .lines()
                .count(),
            0
        );
        assert_eq!(
            std::fs::read_to_string(tree_fs.root.join("scheduler2.txt"))
                .unwrap()
                .lines()
                .count(),
            0
        );
        assert_eq!(
            std::fs::read_to_string(tree_fs.root.join("scheduler3.txt"))
                .unwrap()
                .lines()
                .count(),
            0
        );

        scheduler.jobs = HashMap::from([
            (
                "test".to_string(),
                Job {
                    run: format!(
                        "echo loco >> {}",
                        tree_fs.root.join("scheduler.txt").display()
                    ),
                    shell: true,
                    run_on_start: false,
                    cron: "run every 1 second".to_string(),
                    tags: None,
                    output: None,
                },
            ),
            (
                "test_2".to_string(),
                Job {
                    run: format!(
                        "echo loco >> {}",
                        tree_fs.root.join("scheduler2.txt").display()
                    ),
                    shell: true,
                    run_on_start: false,
                    cron: "* * * * * ? *".to_string(),
                    tags: None,
                    output: None,
                },
            ),
            (
                "test_3".to_string(),
                Job {
                    run: format!(
                        "echo loco >> {}",
                        tree_fs.root.join("scheduler3.txt").display()
                    ),
                    shell: true,
                    run_on_start: true,
                    cron: "0 0 * * * * *".to_string(),
                    tags: None,
                    output: None,
                },
            ),
        ]);

        let handle = tokio::spawn(async move {
            scheduler.run().await.unwrap();
        });

        time::sleep(Duration::from_secs(5)).await;
        handle.abort();

        assert!(
            std::fs::read_to_string(tree_fs.root.join("scheduler.txt"))
                .unwrap()
                .lines()
                .count()
                >= 4
        );
        assert!(
            std::fs::read_to_string(tree_fs.root.join("scheduler2.txt"))
                .unwrap()
                .lines()
                .count()
                >= 4
        );
        assert_eq!(
            std::fs::read_to_string(tree_fs.root.join("scheduler3.txt"))
                .unwrap()
                .lines()
                .count(),
            1
        );
    }
}

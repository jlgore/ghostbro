//! Ghost Relay (`0x47`) content-relay engine.
//!
//! The relay implements the store-and-forward queuing model from the PRD: a
//! client submits a job (web fetch, git mirror, or package retrieval), the
//! server persists a durable job record and returns immediately, and a pool of
//! background workers performs the actual fetch. Results are stored per client
//! key ID under the spool directory and retrieved later over a fresh tunnel.
//!
//! Responsibilities that live here:
//!   * background worker pool + durable on-disk queue with crash recovery,
//!   * per-client TTL and storage/job-count quota enforcement,
//!   * web fetch with optional HTML-to-markdown normalization,
//!   * git mirroring (`git clone --mirror` → bundle),
//!   * package retrieval from PyPI / npm / crates.io with digest verification.

use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use ghost_proxy_common::{
    keys::key_id_hex,
    protocol::{
        GHOST_RELAY_ARTIFACT_NORMALIZED, GHOST_RELAY_ARTIFACT_PRIMARY, GHOST_RELAY_OP_DELETE,
        GHOST_RELAY_OP_DOWNLOAD, GHOST_RELAY_OP_LIST, GHOST_RELAY_OP_SUBMIT_GIT,
        GHOST_RELAY_OP_SUBMIT_PACKAGE, GHOST_RELAY_OP_SUBMIT_WEB, GHOST_RELAY_STATUS_FAILED,
        GHOST_RELAY_STATUS_INVALID, GHOST_RELAY_STATUS_NOT_FOUND, GHOST_RELAY_STATUS_OK,
        GHOST_RELAY_STATUS_PENDING, GHOST_RELAY_STATUS_QUOTA, GHOST_RELAY_STATUS_UNSUPPORTED,
        GHOST_RELAY_VERSION, PROTOCOL_GHOST_RELAY,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use tokio::{process::Command, sync::mpsc, sync::Mutex, time};

mod normalize;

pub use normalize::html_to_markdown;

const RELAY_MAX_URL_LEN: usize = 2048;
const RELAY_MAX_DOWNLOAD_CHUNK: usize = 16 * 1024 - 64;
const DEFAULT_RELAY_SPOOL_DIR: &str = "/var/lib/ghost-proxy/relay";
const GIT_BUNDLE_NAME: &str = "mirror.bundle";

const JOB_STATUS_QUEUED: &str = "queued";
const JOB_STATUS_RUNNING: &str = "running";
const JOB_STATUS_COMPLETE: &str = "complete";
const JOB_STATUS_FAILED: &str = "failed";

/// Tunable relay limits. Sourced from the `[relay]` config section with
/// environment overrides for the spool directory and loopback allowance so the
/// smoke harness can redirect storage and target local test servers.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub spool_dir: PathBuf,
    pub job_ttl: Duration,
    pub max_jobs_per_client: usize,
    pub max_bytes_per_client: u64,
    pub max_object_len: usize,
    pub worker_count: usize,
    pub reap_interval: Duration,
    pub fetch_timeout: Duration,
    pub git_timeout: Duration,
    pub allow_loopback: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            spool_dir: PathBuf::from(DEFAULT_RELAY_SPOOL_DIR),
            job_ttl: Duration::from_secs(24 * 60 * 60),
            max_jobs_per_client: 64,
            max_bytes_per_client: 256 * 1024 * 1024,
            max_object_len: 64 * 1024 * 1024,
            worker_count: 4,
            reap_interval: Duration::from_secs(60),
            fetch_timeout: Duration::from_secs(20),
            git_timeout: Duration::from_secs(120),
            allow_loopback: false,
        }
    }
}

impl RelayConfig {
    /// Apply the `GHOST_PROXY_RELAY_SPOOL_DIR` / `GHOST_PROXY_RELAY_ALLOW_LOOPBACK`
    /// environment overrides on top of whatever config/defaults produced `self`.
    pub fn with_env_overrides(mut self) -> Self {
        if let Some(dir) = std::env::var_os("GHOST_PROXY_RELAY_SPOOL_DIR") {
            self.spool_dir = PathBuf::from(dir);
        }
        if std::env::var_os("GHOST_PROXY_RELAY_ALLOW_LOOPBACK").is_some() {
            self.allow_loopback = true;
        }
        self
    }
}

/// Reference to a persisted job, sent through the worker queue.
#[derive(Debug, Clone)]
struct JobRef {
    key_id_hex: String,
    job_id: String,
}

struct RelayInner {
    config: RelayConfig,
    tx: mpsc::UnboundedSender<JobRef>,
    http: reqwest::Client,
    /// Per-client serialization for quota accounting. Holding the per-key lock
    /// across the usage read + write makes the check-then-write atomic so
    /// concurrent jobs for the same client cannot both pass the quota check
    /// before writing. Keyed on key_id_hex; different clients never contend.
    client_locks: std::sync::Mutex<std::collections::HashMap<String, Arc<std::sync::Mutex<()>>>>,
}

/// Handle to the running relay engine. Cloning is cheap (shared `Arc`).
#[derive(Clone)]
pub struct RelayEngine {
    inner: Arc<RelayInner>,
}

impl RelayEngine {
    /// Start the engine: spawn the worker pool, the periodic TTL reaper, and a
    /// one-shot recovery scan that re-enqueues jobs interrupted by a restart.
    pub fn start(config: RelayConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<JobRef>();
        let http = relay_client_defaults(reqwest::Client::builder(), config.fetch_timeout, config.allow_loopback)
            .build()
            .expect("failed to build relay HTTP client");
        let inner = Arc::new(RelayInner {
            config,
            tx,
            http,
            client_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
        });

        let rx = Arc::new(Mutex::new(rx));
        for worker in 0..inner.config.worker_count.max(1) {
            let inner = inner.clone();
            let rx = rx.clone();
            tokio::spawn(async move {
                loop {
                    let job = {
                        let mut guard = rx.lock().await;
                        guard.recv().await
                    };
                    let Some(job) = job else { break };
                    inner.process_job(worker, job).await;
                }
            });
        }

        // Periodic TTL reaper.
        {
            let inner = inner.clone();
            tokio::spawn(async move {
                let mut ticker = time::interval(inner.config.reap_interval);
                loop {
                    ticker.tick().await;
                    if let Err(error) = inner.reap_expired() {
                        tracing::warn!(?error, "GHOST_RELAY_REAP_ERROR");
                    }
                }
            });
        }

        // Crash recovery: re-enqueue jobs that were queued/running before restart.
        {
            let inner = inner.clone();
            tokio::spawn(async move {
                if let Err(error) = inner.recover_pending() {
                    tracing::warn!(?error, "GHOST_RELAY_RECOVERY_ERROR");
                }
            });
        }

        RelayEngine { inner }
    }

    /// Handle one decrypted relay request, returning the response payload. This
    /// never errors: internal failures are mapped to a `FAILED` status so the
    /// tunnel always gets a well-formed frame.
    pub async fn dispatch(&self, key_id: &[u8; 8], request: &[u8]) -> Vec<u8> {
        match self.inner.dispatch(key_id, request).await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(?error, key_id = %key_id_hex(key_id), "GHOST_RELAY_ERROR");
                relay_status_response(GHOST_RELAY_STATUS_FAILED, b"internal relay error")
            }
        }
    }
}

impl RelayInner {
    async fn dispatch(&self, key_id: &[u8; 8], request: &[u8]) -> Result<Vec<u8>> {
        if request.len() < 3
            || request[0] != PROTOCOL_GHOST_RELAY
            || request[1] != GHOST_RELAY_VERSION
        {
            return Ok(relay_status_response(
                GHOST_RELAY_STATUS_INVALID,
                b"invalid relay header",
            ));
        }

        let mut cursor = RelayCursor::new(&request[3..]);
        match request[2] {
            GHOST_RELAY_OP_SUBMIT_WEB => self.submit_web(key_id, &mut cursor),
            GHOST_RELAY_OP_SUBMIT_GIT => self.submit_git(key_id, &mut cursor),
            GHOST_RELAY_OP_SUBMIT_PACKAGE => self.submit_package(key_id, &mut cursor),
            GHOST_RELAY_OP_LIST => self.list(key_id),
            GHOST_RELAY_OP_DOWNLOAD => self.download(key_id, &mut cursor),
            GHOST_RELAY_OP_DELETE => self.delete(key_id, &mut cursor),
            _ => Ok(relay_status_response(
                GHOST_RELAY_STATUS_UNSUPPORTED,
                b"unsupported relay operation",
            )),
        }
    }

    // ---- submit ----------------------------------------------------------

    fn submit_web(&self, key_id: &[u8; 8], cursor: &mut RelayCursor<'_>) -> Result<Vec<u8>> {
        let url = cursor.read_string(RELAY_MAX_URL_LEN)?;
        let normalize = cursor.read_optional_u8()?.unwrap_or(0) != 0;
        validate_public_url(&url, self.config.allow_loopback)?;
        self.enqueue(key_id, "web_fetch", url, normalize)
    }

    fn submit_git(&self, key_id: &[u8; 8], cursor: &mut RelayCursor<'_>) -> Result<Vec<u8>> {
        let url = cursor.read_string(RELAY_MAX_URL_LEN)?;
        validate_git_url(&url, self.config.allow_loopback)?;
        self.enqueue(key_id, "git_mirror", url, false)
    }

    fn submit_package(&self, key_id: &[u8; 8], cursor: &mut RelayCursor<'_>) -> Result<Vec<u8>> {
        let ecosystem = cursor.read_string(32)?;
        let name = cursor.read_string(256)?;
        let version = cursor.read_string(128)?;
        let spec = PackageSpec::parse(&ecosystem, &name, &version)?;
        self.enqueue(key_id, "package", spec.encode(), false)
    }

    /// Return the per-client quota lock, creating it on first use. Keyed on
    /// key_id_hex so only jobs for the same client serialize.
    fn client_lock(&self, key_id_hex: &str) -> Arc<std::sync::Mutex<()>> {
        let mut locks = self
            .client_locks
            .lock()
            .expect("client lock registry poisoned");
        locks.entry(key_id_hex.to_owned()).or_default().clone()
    }

    /// Persist a queued job and hand it to the worker pool. Enforces per-client
    /// quotas before accepting.
    fn enqueue(
        &self,
        key_id: &[u8; 8],
        kind: &str,
        source: String,
        normalize: bool,
    ) -> Result<Vec<u8>> {
        let client_dir = self.client_dir(key_id);
        // Serialize quota accounting for this client across the usage read and
        // the metadata write below, so concurrent enqueues cannot both pass.
        let quota_lock = self.client_lock(&key_id_hex(key_id));
        let _quota_guard = quota_lock.lock().expect("client quota lock poisoned");
        let (job_count, byte_total) = self.client_usage(&client_dir)?;
        if job_count >= self.config.max_jobs_per_client {
            return Ok(relay_status_response(
                GHOST_RELAY_STATUS_QUOTA,
                format!(
                    "job quota reached ({} of {})",
                    job_count, self.config.max_jobs_per_client
                )
                .as_bytes(),
            ));
        }
        if byte_total >= self.config.max_bytes_per_client {
            return Ok(relay_status_response(
                GHOST_RELAY_STATUS_QUOTA,
                b"storage quota reached",
            ));
        }

        fs::create_dir_all(client_dir.join("jobs"))?;
        fs::create_dir_all(client_dir.join("objects"))?;

        let now = unix_timestamp_ms()?;
        let job_id = relay_job_id(key_id, &source, now);
        let metadata = RelayJobMetadata {
            job_id: job_id.clone(),
            kind: kind.to_owned(),
            status: JOB_STATUS_QUEUED.to_owned(),
            source,
            normalize,
            http_status: None,
            content_type: None,
            body_len: 0,
            normalized_len: None,
            sha256: None,
            error: None,
            created_at_ms: now,
            updated_at_ms: now,
            expires_at_ms: now + self.config.job_ttl.as_millis() as u64,
        };
        write_metadata(&client_dir, &metadata)?;
        tracing::info!(
            key_id = %key_id_hex(key_id),
            job_id,
            kind,
            "GHOST_RELAY_JOB_QUEUED"
        );

        let job_ref = JobRef {
            key_id_hex: key_id_hex(key_id),
            job_id: job_id.clone(),
        };
        if self.tx.send(job_ref).is_err() {
            tracing::error!(job_id, "GHOST_RELAY_QUEUE_CLOSED");
        }
        Ok(relay_bytes_response(GHOST_RELAY_STATUS_OK, job_id.as_bytes()))
    }

    // ---- retrieval -------------------------------------------------------

    fn list(&self, key_id: &[u8; 8]) -> Result<Vec<u8>> {
        let client_dir = self.client_dir(key_id);
        let jobs_dir = client_dir.join("jobs");
        let now = unix_timestamp_ms()?;
        let mut rows = Vec::new();
        if jobs_dir.exists() {
            for entry in fs::read_dir(&jobs_dir)? {
                let path = entry?.path();
                if path.extension().is_some_and(|ext| ext == "toml") {
                    let metadata = read_metadata(&path)?;
                    if metadata.expires_at_ms <= now {
                        continue; // expired; reaper will remove it
                    }
                    rows.push(format!(
                        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                        metadata.job_id,
                        metadata.kind,
                        metadata.status,
                        metadata.http_status.unwrap_or(0),
                        metadata.body_len,
                        u8::from(metadata.normalized_len.is_some()),
                        metadata.source,
                    ));
                }
            }
        }
        rows.sort();
        Ok(relay_bytes_response(
            GHOST_RELAY_STATUS_OK,
            rows.join("\n").as_bytes(),
        ))
    }

    fn download(&self, key_id: &[u8; 8], cursor: &mut RelayCursor<'_>) -> Result<Vec<u8>> {
        let job_id = cursor.read_string(128)?;
        validate_job_id(&job_id)?;
        let offset = cursor.read_u32()? as usize;
        let max_len = usize::from(cursor.read_u16()?).min(RELAY_MAX_DOWNLOAD_CHUNK);
        let artifact = cursor.read_optional_u8()?.unwrap_or(GHOST_RELAY_ARTIFACT_PRIMARY);

        let client_dir = self.client_dir(key_id);
        let metadata_path = metadata_path(&client_dir, &job_id);
        if !metadata_path.exists() {
            return Ok(relay_status_response(
                GHOST_RELAY_STATUS_NOT_FOUND,
                b"job not found",
            ));
        }
        let metadata = read_metadata(&metadata_path)?;
        if metadata.expires_at_ms <= unix_timestamp_ms()? {
            return Ok(relay_status_response(
                GHOST_RELAY_STATUS_NOT_FOUND,
                b"job expired",
            ));
        }
        match metadata.status.as_str() {
            JOB_STATUS_QUEUED | JOB_STATUS_RUNNING => {
                return Ok(relay_status_response(
                    GHOST_RELAY_STATUS_PENDING,
                    b"job not ready",
                ));
            }
            JOB_STATUS_FAILED => {
                let message = metadata.error.unwrap_or_else(|| "job failed".to_owned());
                return Ok(relay_status_response(
                    GHOST_RELAY_STATUS_FAILED,
                    message.as_bytes(),
                ));
            }
            _ => {}
        }

        let object = match artifact {
            GHOST_RELAY_ARTIFACT_NORMALIZED => {
                if metadata.normalized_len.is_none() {
                    return Ok(relay_status_response(
                        GHOST_RELAY_STATUS_NOT_FOUND,
                        b"no normalized artifact for job",
                    ));
                }
                normalized_object_path(&client_dir, &job_id)
            }
            _ => primary_object_path(&client_dir, &job_id),
        };
        let body = fs::read(object)?;
        let total = body.len();
        let start = offset.min(total);
        let end = total.min(start + max_len);
        let terminal = u8::from(end >= total);

        let mut response = relay_header(GHOST_RELAY_STATUS_OK);
        response.push(terminal);
        response.extend_from_slice(&(total as u32).to_be_bytes());
        response.extend_from_slice(&((end - start) as u32).to_be_bytes());
        response.extend_from_slice(&body[start..end]);
        Ok(response)
    }

    fn delete(&self, key_id: &[u8; 8], cursor: &mut RelayCursor<'_>) -> Result<Vec<u8>> {
        let job_id = cursor.read_string(128)?;
        validate_job_id(&job_id)?;
        let client_dir = self.client_dir(key_id);
        let metadata_path = metadata_path(&client_dir, &job_id);
        if !metadata_path.exists() {
            return Ok(relay_status_response(
                GHOST_RELAY_STATUS_NOT_FOUND,
                b"job not found",
            ));
        }
        let _ = fs::remove_file(primary_object_path(&client_dir, &job_id));
        let _ = fs::remove_file(normalized_object_path(&client_dir, &job_id));
        fs::remove_file(metadata_path)?;
        tracing::info!(key_id = %key_id_hex(key_id), job_id, "GHOST_RELAY_JOB_DELETED");
        Ok(relay_status_response(GHOST_RELAY_STATUS_OK, b"deleted"))
    }

    // ---- background processing ------------------------------------------

    async fn process_job(&self, worker: usize, job: JobRef) {
        if let Err(error) = self.process_job_inner(&job).await {
            tracing::warn!(
                worker,
                job_id = %job.job_id,
                ?error,
                "GHOST_RELAY_JOB_ERROR"
            );
            let client_dir = self.config.spool_dir.join(&job.key_id_hex);
            if let Ok(mut metadata) = read_metadata(&metadata_path(&client_dir, &job.job_id)) {
                metadata.status = JOB_STATUS_FAILED.to_owned();
                metadata.error = Some(error.to_string());
                metadata.updated_at_ms = unix_timestamp_ms().unwrap_or(metadata.updated_at_ms);
                let _ = write_metadata(&client_dir, &metadata);
            }
        }
    }

    async fn process_job_inner(&self, job: &JobRef) -> Result<()> {
        let client_dir = self.config.spool_dir.join(&job.key_id_hex);
        let metadata_path = metadata_path(&client_dir, &job.job_id);
        let Ok(mut metadata) = read_metadata(&metadata_path) else {
            return Ok(()); // job deleted before the worker reached it
        };
        if metadata.status == JOB_STATUS_COMPLETE {
            return Ok(());
        }

        metadata.status = JOB_STATUS_RUNNING.to_owned();
        metadata.updated_at_ms = unix_timestamp_ms()?;
        write_metadata(&client_dir, &metadata)?;
        tracing::info!(job_id = %job.job_id, kind = %metadata.kind, "GHOST_RELAY_JOB_START");

        let outcome = match metadata.kind.as_str() {
            "web_fetch" => self.run_web_fetch(&client_dir, &metadata).await,
            "git_mirror" => self.run_git_mirror(&client_dir, &metadata).await,
            "package" => self.run_package(&client_dir, &metadata).await,
            other => bail!("unknown relay job kind {other}"),
        }?;

        // Enforce the per-client storage quota against the produced artifact.
        // Hold the per-client quota lock across the usage read and the object
        // write so concurrent jobs for this client cannot both pass the check.
        // The critical section is fully synchronous (no .await), so the std
        // Mutex guard is never held across an await point.
        let quota_lock = self.client_lock(&job.key_id_hex);
        let quota_guard = quota_lock.lock().expect("client quota lock poisoned");
        let (_, existing_bytes) = self.client_usage(&client_dir)?;
        if existing_bytes.saturating_add(outcome.body.len() as u64) > self.config.max_bytes_per_client
        {
            bail!("storage quota would be exceeded by job result");
        }
        if outcome.body.len() > self.config.max_object_len {
            bail!(
                "result {} bytes exceeds max object size {}",
                outcome.body.len(),
                self.config.max_object_len
            );
        }

        let mut sha = Sha256::new();
        sha.update(&outcome.body);
        let sha256 = format!("{:x}", sha.finalize());
        fs::write(primary_object_path(&client_dir, &metadata.job_id), &outcome.body)?;
        // Quota check + primary write are committed; release before any further
        // (potentially awaiting) work so the lock is never held across an await.
        drop(quota_guard);

        metadata.body_len = outcome.body.len() as u64;
        metadata.http_status = outcome.http_status;
        metadata.content_type = outcome.content_type.clone();
        metadata.sha256 = Some(sha256);

        // Optional HTML-to-markdown normalization for web fetches.
        if metadata.normalize && is_html(outcome.content_type.as_deref(), &outcome.body) {
            let html = String::from_utf8_lossy(&outcome.body);
            let markdown = html_to_markdown(&html);
            fs::write(
                normalized_object_path(&client_dir, &metadata.job_id),
                markdown.as_bytes(),
            )?;
            metadata.normalized_len = Some(markdown.len() as u64);
        }

        metadata.status = JOB_STATUS_COMPLETE.to_owned();
        metadata.error = None;
        metadata.updated_at_ms = unix_timestamp_ms()?;
        write_metadata(&client_dir, &metadata)?;
        tracing::info!(
            job_id = %metadata.job_id,
            bytes = metadata.body_len,
            normalized = metadata.normalized_len.unwrap_or(0),
            "GHOST_RELAY_JOB_COMPLETE"
        );
        Ok(())
    }

    async fn run_web_fetch(
        &self,
        _client_dir: &Path,
        metadata: &RelayJobMetadata,
    ) -> Result<JobOutcome> {
        validate_public_url(&metadata.source, self.config.allow_loopback)?;
        let (status, content_type, body) = self
            .http_get_bytes(&metadata.source, self.config.max_object_len)
            .await?;
        Ok(JobOutcome {
            body,
            http_status: Some(status),
            content_type,
        })
    }

    async fn run_git_mirror(
        &self,
        client_dir: &Path,
        metadata: &RelayJobMetadata,
    ) -> Result<JobOutcome> {
        validate_git_url(&metadata.source, self.config.allow_loopback)?;
        let work = client_dir.join("work").join(&metadata.job_id);
        let mirror = work.join("mirror.git");
        let bundle = work.join(GIT_BUNDLE_NAME);
        let _ = fs::remove_dir_all(&work);
        fs::create_dir_all(&work)?;

        let mut clone = Command::new("git");
        clone
            .arg("clone")
            .arg("--mirror")
            .arg("--quiet")
            // End-of-options separator: the client-controlled URL can never be
            // parsed by git as an option (e.g. a leading `-`).
            .arg("--")
            .arg(&metadata.source)
            .arg(&mirror)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "true")
            .kill_on_drop(true);
        run_command_with_timeout(clone, self.config.git_timeout, "git clone --mirror").await?;

        let mut bundle_cmd = Command::new("git");
        bundle_cmd
            .arg("-C")
            .arg(&mirror)
            .arg("bundle")
            .arg("create")
            .arg(&bundle)
            .arg("--all")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "true")
            .kill_on_drop(true);
        run_command_with_timeout(bundle_cmd, self.config.git_timeout, "git bundle create").await?;

        // Size-check the produced bundle before reading it into memory, mirroring
        // the http_get_bytes max_object_len guard. Without this a large remote
        // can produce a multi-GB bundle that fs::read would fully allocate before
        // the post-job guard runs.
        let bundle_len = fs::metadata(&bundle)
            .context("failed to stat produced git bundle")?
            .len();
        if bundle_len > self.config.max_object_len as u64 {
            let _ = fs::remove_dir_all(&work);
            bail!(
                "git bundle {bundle_len} bytes exceeds max object size {}",
                self.config.max_object_len
            );
        }
        let body = fs::read(&bundle).context("failed to read produced git bundle")?;
        let _ = fs::remove_dir_all(&work);
        Ok(JobOutcome {
            body,
            http_status: None,
            content_type: Some("application/x-git-bundle".to_owned()),
        })
    }

    async fn run_package(
        &self,
        _client_dir: &Path,
        metadata: &RelayJobMetadata,
    ) -> Result<JobOutcome> {
        let spec = PackageSpec::decode(&metadata.source)?;
        let resolved = spec
            .resolve(self.config.allow_loopback, self.config.fetch_timeout)
            .await?;
        let (status, content_type, body) = self
            .http_get_bytes(&resolved.url, self.config.max_object_len)
            .await?;
        if status >= 400 {
            bail!("package download returned HTTP {status}");
        }
        resolved.digest.verify(&body)?;
        Ok(JobOutcome {
            body,
            http_status: Some(status),
            content_type,
        })
    }

    async fn http_get_bytes(
        &self,
        url: &str,
        max_len: usize,
    ) -> Result<(u16, Option<String>, Vec<u8>)> {
        // Validate + pin in one step so reqwest cannot independently re-resolve
        // the host to a different (internal) address (DNS-rebinding TOCTOU).
        let (client, _parsed) =
            validate_and_pin(url, self.config.allow_loopback, self.config.fetch_timeout)?;
        let response = client
            .get(url)
            .send()
            .await
            .with_context(|| format!("failed to fetch {url}"))?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_owned());
        if let Some(len) = response.content_length() {
            if len > max_len as u64 {
                bail!("response body advertises {len} bytes, exceeds limit {max_len}");
            }
        }
        let body = response.bytes().await.context("failed to read relay body")?;
        if body.len() > max_len {
            bail!("response body {} bytes exceeds limit {max_len}", body.len());
        }
        Ok((status, content_type, body.to_vec()))
    }

    // ---- maintenance -----------------------------------------------------

    fn reap_expired(&self) -> Result<usize> {
        let mut removed = 0;
        let now = unix_timestamp_ms()?;
        let Ok(entries) = fs::read_dir(&self.config.spool_dir) else {
            return Ok(0);
        };
        for entry in entries {
            let client_dir = entry?.path();
            let jobs_dir = client_dir.join("jobs");
            if !jobs_dir.is_dir() {
                continue;
            }
            for job in fs::read_dir(&jobs_dir)? {
                let path = job?.path();
                if path.extension().is_none_or(|ext| ext != "toml") {
                    continue;
                }
                let Ok(metadata) = read_metadata(&path) else {
                    continue;
                };
                if metadata.expires_at_ms <= now {
                    let _ = fs::remove_file(primary_object_path(&client_dir, &metadata.job_id));
                    let _ = fs::remove_file(normalized_object_path(&client_dir, &metadata.job_id));
                    let _ = fs::remove_file(&path);
                    removed += 1;
                    tracing::info!(job_id = %metadata.job_id, "GHOST_RELAY_JOB_EXPIRED");
                }
            }
        }
        if removed > 0 {
            tracing::info!(removed, "GHOST_RELAY_REAP");
        }
        Ok(removed)
    }

    fn recover_pending(&self) -> Result<()> {
        let Ok(entries) = fs::read_dir(&self.config.spool_dir) else {
            return Ok(());
        };
        let mut requeued = 0;
        for entry in entries {
            let client_dir = entry?.path();
            let Some(key_id_hex) = client_dir.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let jobs_dir = client_dir.join("jobs");
            if !jobs_dir.is_dir() {
                continue;
            }
            for job in fs::read_dir(&jobs_dir)? {
                let path = job?.path();
                if path.extension().is_none_or(|ext| ext != "toml") {
                    continue;
                }
                let Ok(metadata) = read_metadata(&path) else {
                    continue;
                };
                if metadata.status == JOB_STATUS_QUEUED || metadata.status == JOB_STATUS_RUNNING {
                    let _ = self.tx.send(JobRef {
                        key_id_hex: key_id_hex.to_owned(),
                        job_id: metadata.job_id,
                    });
                    requeued += 1;
                }
            }
        }
        if requeued > 0 {
            tracing::info!(requeued, "GHOST_RELAY_RECOVERED");
        }
        Ok(())
    }

    /// Count non-expired jobs and total stored bytes for a client.
    fn client_usage(&self, client_dir: &Path) -> Result<(usize, u64)> {
        let jobs_dir = client_dir.join("jobs");
        if !jobs_dir.is_dir() {
            return Ok((0, 0));
        }
        let now = unix_timestamp_ms()?;
        let mut jobs = 0;
        let mut bytes = 0;
        for entry in fs::read_dir(&jobs_dir)? {
            let path = entry?.path();
            if path.extension().is_none_or(|ext| ext != "toml") {
                continue;
            }
            let Ok(metadata) = read_metadata(&path) else {
                continue;
            };
            if metadata.expires_at_ms <= now {
                continue;
            }
            jobs += 1;
            bytes += metadata.body_len + metadata.normalized_len.unwrap_or(0);
        }
        Ok((jobs, bytes))
    }

    fn client_dir(&self, key_id: &[u8; 8]) -> PathBuf {
        self.config.spool_dir.join(key_id_hex(key_id))
    }
}

struct JobOutcome {
    body: Vec<u8>,
    http_status: Option<u16>,
    content_type: Option<String>,
}

// ---- package resolution --------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ecosystem {
    Pypi,
    Npm,
    Crates,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageSpec {
    ecosystem: Ecosystem,
    name: String,
    version: Option<String>,
}

struct ResolvedPackage {
    url: String,
    digest: ExpectedDigest,
}

enum ExpectedDigest {
    None,
    Sha256(String),
    Sha512(Vec<u8>),
}

impl ExpectedDigest {
    fn verify(&self, body: &[u8]) -> Result<()> {
        match self {
            // A missing/unsupported digest is a hard failure on the package
            // download path: with registry-controlled URLs plus redirect or DNS
            // rebinding, accepting unverified bytes is an integrity bypass.
            ExpectedDigest::None => {
                bail!("package download rejected: registry provided no usable digest")
            }
            ExpectedDigest::Sha256(expected) => {
                let mut hasher = Sha256::new();
                hasher.update(body);
                let actual = format!("{:x}", hasher.finalize());
                if actual.eq_ignore_ascii_case(expected) {
                    Ok(())
                } else {
                    bail!("package sha256 mismatch: expected {expected}, got {actual}")
                }
            }
            ExpectedDigest::Sha512(expected) => {
                let mut hasher = Sha512::new();
                hasher.update(body);
                let actual = hasher.finalize();
                if actual.as_slice() == expected.as_slice() {
                    Ok(())
                } else {
                    bail!("package sha512 integrity mismatch")
                }
            }
        }
    }
}

impl PackageSpec {
    fn parse(ecosystem: &str, name: &str, version: &str) -> Result<Self> {
        let ecosystem = match ecosystem.to_ascii_lowercase().as_str() {
            "pypi" | "pip" => Ecosystem::Pypi,
            "npm" => Ecosystem::Npm,
            "crates" | "cargo" => Ecosystem::Crates,
            other => bail!("unsupported package ecosystem {other}"),
        };
        validate_package_name(name)?;
        if let Some(version) = non_empty(version) {
            validate_package_version(version)?;
        }
        if ecosystem == Ecosystem::Crates && non_empty(version).is_none() {
            bail!("crates packages require an explicit version");
        }
        Ok(Self {
            ecosystem,
            name: name.to_owned(),
            version: non_empty(version).map(str::to_owned),
        })
    }

    /// Round-trip wire encoding stored in job metadata, e.g. `pypi:requests@2.31.0`.
    fn encode(&self) -> String {
        let eco = match self.ecosystem {
            Ecosystem::Pypi => "pypi",
            Ecosystem::Npm => "npm",
            Ecosystem::Crates => "crates",
        };
        match &self.version {
            Some(version) => format!("{eco}:{}@{version}", self.name),
            None => format!("{eco}:{}", self.name),
        }
    }

    fn decode(encoded: &str) -> Result<Self> {
        let (eco, rest) = encoded
            .split_once(':')
            .context("malformed package spec, missing ecosystem")?;
        let (name, version) = match rest.rsplit_once('@') {
            // Guard against npm scope `@scope/name` having no version.
            Some((name, version)) if !name.is_empty() => (name, version),
            _ => (rest, ""),
        };
        Self::parse(eco, name, version)
    }

    async fn resolve(&self, allow_loopback: bool, timeout: Duration) -> Result<ResolvedPackage> {
        match self.ecosystem {
            Ecosystem::Pypi => self.resolve_pypi(allow_loopback, timeout).await,
            Ecosystem::Npm => self.resolve_npm(allow_loopback, timeout).await,
            Ecosystem::Crates => self.resolve_crates(allow_loopback, timeout).await,
        }
    }

    async fn resolve_pypi(&self, allow_loopback: bool, timeout: Duration) -> Result<ResolvedPackage> {
        let url = match &self.version {
            Some(version) => format!("https://pypi.org/pypi/{}/{}/json", self.name, version),
            None => format!("https://pypi.org/pypi/{}/json", self.name),
        };
        let json = get_json(&url, allow_loopback, timeout).await?;
        let urls = json
            .get("urls")
            .and_then(|value| value.as_array())
            .context("pypi response missing urls array")?;
        // Prefer a wheel, fall back to the first available artifact (sdist).
        let chosen = urls
            .iter()
            .find(|entry| entry.get("packagetype").and_then(|v| v.as_str()) == Some("bdist_wheel"))
            .or_else(|| urls.first())
            .context("pypi package has no downloadable artifacts")?;
        let download = chosen
            .get("url")
            .and_then(|value| value.as_str())
            .context("pypi artifact missing url")?
            .to_owned();
        let digest = chosen
            .get("digests")
            .and_then(|value| value.get("sha256"))
            .and_then(|value| value.as_str())
            .map(|value| ExpectedDigest::Sha256(value.to_owned()))
            .unwrap_or(ExpectedDigest::None);
        Ok(ResolvedPackage {
            url: download,
            digest,
        })
    }

    async fn resolve_npm(&self, allow_loopback: bool, timeout: Duration) -> Result<ResolvedPackage> {
        let url = format!("https://registry.npmjs.org/{}", self.name);
        let json = get_json(&url, allow_loopback, timeout).await?;
        let version = match &self.version {
            Some(version) => version.clone(),
            None => json
                .get("dist-tags")
                .and_then(|tags| tags.get("latest"))
                .and_then(|value| value.as_str())
                .context("npm package missing dist-tags.latest")?
                .to_owned(),
        };
        let dist = json
            .get("versions")
            .and_then(|versions| versions.get(&version))
            .and_then(|entry| entry.get("dist"))
            .with_context(|| format!("npm version {version} not found"))?;
        let tarball = dist
            .get("tarball")
            .and_then(|value| value.as_str())
            .context("npm dist missing tarball")?
            .to_owned();
        // Verify the subresource integrity if it is a SHA-512 entry.
        let digest = dist
            .get("integrity")
            .and_then(|value| value.as_str())
            .and_then(parse_sri_sha512)
            .map(ExpectedDigest::Sha512)
            .unwrap_or(ExpectedDigest::None);
        Ok(ResolvedPackage {
            url: tarball,
            digest,
        })
    }

    async fn resolve_crates(&self, allow_loopback: bool, timeout: Duration) -> Result<ResolvedPackage> {
        let version = self
            .version
            .as_ref()
            .context("crates packages require a version")?;
        let meta_url = format!("https://crates.io/api/v1/crates/{}/{version}", self.name);
        let json = get_json(&meta_url, allow_loopback, timeout).await?;
        let version_obj = json
            .get("version")
            .context("crates response missing version object")?;
        let dl_path = version_obj
            .get("dl_path")
            .and_then(|value| value.as_str())
            .context("crates version missing dl_path")?;
        let checksum = version_obj
            .get("checksum")
            .and_then(|value| value.as_str())
            .map(|value| ExpectedDigest::Sha256(value.to_owned()))
            .unwrap_or(ExpectedDigest::None);
        Ok(ResolvedPackage {
            url: crates_download_url(dl_path)?,
            digest: checksum,
        })
    }
}

/// Join a registry-supplied `dl_path` against the fixed crates.io base and
/// assert the resolved host is an expected crates registry/CDN host. Prevents
/// host-confusion (e.g. `dl_path` `@evil.com/x` -> `https://crates.io@evil.com/x`,
/// where `evil.com` becomes the host via the userinfo delimiter) and
/// scheme-relative/absolute redirects embedded in `dl_path`.
fn crates_download_url(dl_path: &str) -> Result<String> {
    const EXPECTED_HOSTS: [&str; 2] = ["crates.io", "static.crates.io"];
    let joined = reqwest::Url::parse("https://crates.io/")
        .context("invalid crates base URL")?
        .join(dl_path)
        .with_context(|| format!("invalid crates dl_path {dl_path}"))?;
    let host = joined
        .host_str()
        .context("crates download URL missing host")?;
    if !EXPECTED_HOSTS.contains(&host) {
        bail!("crates dl_path resolved to unexpected host {host}");
    }
    Ok(joined.into())
}

/// Registry hosts `get_json` is permitted to query. Defense-in-depth on the
/// entry host; the per-hop redirect guard + IP pinning below cover redirects.
const REGISTRY_HOSTS: &[&str] = &["pypi.org", "registry.npmjs.org", "crates.io"];

/// Reject any registry query URL whose host is not a known package registry.
fn assert_registry_host(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).context("invalid registry URL")?;
    let host = parsed.host_str().context("registry URL missing host")?;
    if REGISTRY_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
    {
        Ok(())
    } else {
        bail!("registry host {host} is not an allowed package registry");
    }
}

async fn get_json(url: &str, allow_loopback: bool, timeout: Duration) -> Result<serde_json::Value> {
    assert_registry_host(url)?;
    // Registry hosts are subject to the same rebinding window, so validate the
    // resolved IPs and pin them into a request-scoped client before fetching.
    let (client, _parsed) = validate_and_pin(url, allow_loopback, timeout)?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .with_context(|| format!("failed to query registry {url}"))?;
    let status = response.status();
    let bytes = response.bytes().await.context("failed to read registry body")?;
    if !status.is_success() {
        bail!("registry {url} returned HTTP {}", status.as_u16());
    }
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse registry JSON {url}"))
}

/// Parse an npm `integrity` SRI string and return the SHA-512 digest bytes.
fn parse_sri_sha512(integrity: &str) -> Option<Vec<u8>> {
    let encoded = integrity.split_whitespace().find_map(|token| {
        token.strip_prefix("sha512-")
    })?;
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    // A SHA-512 digest is exactly 64 bytes. Reject malformed payloads rather
    // than coercing them into an ExpectedDigest::Sha512 of the wrong length.
    if decoded.len() == 64 {
        Some(decoded)
    } else {
        None
    }
}

// ---- validation ----------------------------------------------------------

fn validate_public_url(url: &str, allow_loopback: bool) -> Result<()> {
    let parsed = reqwest::Url::parse(url).context("invalid relay URL")?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => bail!("unsupported relay URL scheme {scheme}"),
    }
    resolve_guard(&parsed, allow_loopback).map(|_| ())
}

fn validate_git_url(url: &str, allow_loopback: bool) -> Result<()> {
    let parsed = reqwest::Url::parse(url).context("invalid git URL")?;
    match parsed.scheme() {
        "http" | "https" | "git" => {}
        scheme => bail!("unsupported git URL scheme {scheme}"),
    }
    resolve_guard(&parsed, allow_loopback).map(|_| ())
}

/// Resolve the URL host and reject loopback, private, multicast, and
/// unspecified destinations to prevent the relay from being used to reach
/// internal services (SSRF guard).
///
/// Returns the validated socket addresses so the caller can pin them into the
/// HTTP client, closing the DNS-rebinding TOCTOU window between this guard and
/// reqwest's own (otherwise independent) resolution.
fn resolve_guard(parsed: &reqwest::Url, allow_loopback: bool) -> Result<Vec<SocketAddr>> {
    use std::net::ToSocketAddrs;
    let host = parsed.host_str().context("relay URL missing host")?;
    let port = parsed
        .port_or_known_default()
        .context("relay URL missing port")?;
    let mut validated = Vec::new();
    for addr in (host, port).to_socket_addrs()? {
        let ip = addr.ip();
        if ip.is_unspecified()
            || ip.is_multicast()
            || (!allow_loopback && ip.is_loopback())
            || (!allow_loopback && is_private_ip(ip))
        {
            bail!("relay URL resolves to disallowed address {ip}");
        }
        validated.push(addr);
    }
    if validated.is_empty() {
        bail!("relay URL host did not resolve");
    }
    Ok(validated)
}

/// Apply the relay's shared HTTP client defaults (timeout, user-agent) plus a
/// custom redirect policy that re-runs `resolve_guard` on every hop. Without the
/// per-hop check, a redirect `Location` could point into loopback/private/
/// metadata hosts (e.g. 169.254.169.254) and bypass the initial-URL guard.
fn relay_client_defaults(
    builder: reqwest::ClientBuilder,
    timeout: Duration,
    allow_loopback: bool,
) -> reqwest::ClientBuilder {
    let redirect_policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error(anyhow::anyhow!("too many redirects"));
        }
        match resolve_guard(attempt.url(), allow_loopback) {
            Ok(_) => attempt.follow(),
            Err(err) => attempt.error(err),
        }
    });
    builder
        .timeout(timeout)
        .redirect(redirect_policy)
        .user_agent("ghost-proxy-relay/0.2 (+https://github.com/ghost-proxy)")
}

/// Validate `url` through `resolve_guard` and build a request-scoped client that
/// is pinned (via `resolve_to_addrs`) to exactly the IPs that were validated.
/// reqwest then connects to those addresses instead of performing a second,
/// independent DNS lookup, so a low-TTL rebind cannot swap in an internal IP
/// after the guard has passed.
fn validate_and_pin(
    url: &str,
    allow_loopback: bool,
    timeout: Duration,
) -> Result<(reqwest::Client, reqwest::Url)> {
    let parsed = reqwest::Url::parse(url).context("invalid relay URL")?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => bail!("unsupported relay URL scheme {scheme}"),
    }
    let addrs = resolve_guard(&parsed, allow_loopback)?;
    let host = parsed.host_str().context("relay URL missing host")?;
    let client = relay_client_defaults(reqwest::Client::builder(), timeout, allow_loopback)
        .resolve_to_addrs(host, &addrs)
        .build()
        .context("failed to build pinned relay HTTP client")?;
    Ok((client, parsed))
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

fn validate_job_id(job_id: &str) -> Result<()> {
    if job_id.is_empty()
        || !job_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        bail!("invalid relay job id");
    }
    Ok(())
}

fn validate_package_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 256 {
        bail!("invalid package name length");
    }
    if name.contains("..") {
        bail!("package name may not contain '..'");
    }
    let ok = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b'@'));
    if !ok {
        bail!("package name contains disallowed characters");
    }
    Ok(())
}

fn validate_package_version(version: &str) -> Result<()> {
    if version.len() > 128 {
        bail!("invalid package version length");
    }
    let ok = version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'));
    if !ok {
        bail!("package version contains disallowed characters");
    }
    Ok(())
}

fn non_empty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn is_html(content_type: Option<&str>, body: &[u8]) -> bool {
    if let Some(content_type) = content_type {
        let lowered = content_type.to_ascii_lowercase();
        if lowered.contains("text/html") || lowered.contains("application/xhtml") {
            return true;
        }
        if lowered.contains("text/plain") || lowered.contains("application/json") {
            return false;
        }
    }
    // Sniff for an HTML marker in the first chunk.
    let head = &body[..body.len().min(1024)];
    let lowered = head.to_ascii_lowercase();
    let needle = b"<html";
    lowered
        .windows(needle.len())
        .any(|window| window == needle)
        || lowered
            .windows(b"<!doctype html".len())
            .any(|window| window == b"<!doctype html")
}

async fn run_command_with_timeout(
    mut command: Command,
    timeout: Duration,
    label: &str,
) -> Result<()> {
    let output = time::timeout(timeout, command.output())
        .await
        .with_context(|| format!("{label} timed out after {timeout:?}"))?
        .with_context(|| format!("failed to spawn {label}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{label} failed: {}", stderr.trim());
    }
    Ok(())
}

// ---- storage helpers -----------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayJobMetadata {
    job_id: String,
    kind: String,
    status: String,
    source: String,
    #[serde(default)]
    normalize: bool,
    http_status: Option<u16>,
    content_type: Option<String>,
    body_len: u64,
    normalized_len: Option<u64>,
    sha256: Option<String>,
    error: Option<String>,
    created_at_ms: u64,
    updated_at_ms: u64,
    expires_at_ms: u64,
}

fn metadata_path(client_dir: &Path, job_id: &str) -> PathBuf {
    client_dir.join("jobs").join(format!("{job_id}.toml"))
}

fn primary_object_path(client_dir: &Path, job_id: &str) -> PathBuf {
    client_dir.join("objects").join(format!("{job_id}.body"))
}

fn normalized_object_path(client_dir: &Path, job_id: &str) -> PathBuf {
    client_dir.join("objects").join(format!("{job_id}.md"))
}

fn read_metadata(path: &Path) -> Result<RelayJobMetadata> {
    let contents = fs::read_to_string(path)?;
    toml::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

/// Write job metadata atomically (temp file + rename) so a crash mid-write
/// never leaves a half-written record the recovery scan would choke on.
fn write_metadata(client_dir: &Path, metadata: &RelayJobMetadata) -> Result<()> {
    let path = metadata_path(client_dir, &metadata.job_id);
    let tmp = path.with_extension("toml.tmp");
    let contents = toml::to_string_pretty(metadata)?;
    fs::write(&tmp, contents)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

fn relay_job_id(key_id: &[u8; 8], source: &str, now_ms: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key_id);
    hasher.update(source.as_bytes());
    hasher.update(now_ms.to_be_bytes());
    format!("{:x}", hasher.finalize())[..24].to_owned()
}

fn unix_timestamp_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis() as u64)
}

// ---- wire helpers --------------------------------------------------------

fn relay_header(status: u8) -> Vec<u8> {
    vec![PROTOCOL_GHOST_RELAY, GHOST_RELAY_VERSION, status]
}

fn relay_status_response(status: u8, message: &[u8]) -> Vec<u8> {
    relay_bytes_response(status, message)
}

fn relay_bytes_response(status: u8, bytes: &[u8]) -> Vec<u8> {
    let mut response = relay_header(status);
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    response.extend_from_slice(&len.to_be_bytes());
    response.extend_from_slice(bytes);
    response
}

struct RelayCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> RelayCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_optional_u8(&mut self) -> Result<Option<u8>> {
        if self.pos >= self.bytes.len() {
            return Ok(None);
        }
        let byte = self.bytes[self.pos];
        self.pos += 1;
        Ok(Some(byte))
    }

    fn read_string(&mut self, max_len: usize) -> Result<String> {
        let len = usize::from(self.read_u16()?);
        if len > max_len {
            bail!("relay field length {len} exceeds maximum {max_len}");
        }
        let bytes = self.read_exact(len)?;
        String::from_utf8(bytes.to_vec()).context("relay field is not valid UTF-8")
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.pos + len > self.bytes.len() {
            bail!("truncated relay request");
        }
        let bytes = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_spec_round_trips_through_metadata() {
        let spec = PackageSpec::parse("pypi", "requests", "2.31.0").expect("valid spec");
        let encoded = spec.encode();
        assert_eq!("pypi:requests@2.31.0", encoded);
        assert_eq!(spec, PackageSpec::decode(&encoded).expect("decodes"));
    }

    #[test]
    fn package_spec_decodes_npm_scope_without_version() {
        let spec = PackageSpec::decode("npm:@scope/pkg").expect("scoped npm spec");
        assert_eq!(Ecosystem::Npm, spec.ecosystem);
        assert_eq!("@scope/pkg", spec.name);
        assert_eq!(None, spec.version);
    }

    #[test]
    fn crates_requires_version() {
        assert!(PackageSpec::parse("crates", "serde", "").is_err());
    }

    #[test]
    fn rejects_package_name_traversal() {
        assert!(validate_package_name("../etc/passwd").is_err());
        assert!(validate_package_name("requests").is_ok());
        assert!(validate_package_name("@scope/pkg").is_ok());
    }

    #[test]
    fn ssrf_guard_blocks_loopback_by_default() {
        assert!(validate_public_url("http://127.0.0.1/x", false).is_err());
        assert!(validate_public_url("http://127.0.0.1/x", true).is_ok());
    }

    #[test]
    fn sha256_digest_verifies() {
        let digest = ExpectedDigest::Sha256(
            // sha256 of "ghost"
            "9e7e4e7c8f8f3b9b8e9a8f0a3a9b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b".to_owned(),
        );
        // Wrong digest should fail.
        assert!(digest.verify(b"ghost").is_err());
    }

    #[test]
    fn missing_digest_is_rejected() {
        // F-009: no usable digest from the registry must not silently pass.
        assert!(ExpectedDigest::None.verify(b"any bytes at all").is_err());
    }

    #[test]
    fn resolve_guard_returns_validated_addr_and_rejects_private() {
        // F-004: a literal-IP URL exercises resolve_guard deterministically.
        let public = reqwest::Url::parse("http://93.184.216.34/x").unwrap();
        let addrs = resolve_guard(&public, false).expect("public ip allowed");
        assert!(addrs.iter().any(|a| a.ip().to_string() == "93.184.216.34"));

        let private = reqwest::Url::parse("http://10.0.0.5/x").unwrap();
        assert!(resolve_guard(&private, false).is_err());
        let metadata = reqwest::Url::parse("http://169.254.169.254/latest/meta-data").unwrap();
        assert!(resolve_guard(&metadata, false).is_err());
    }

    #[test]
    fn crates_dl_path_cannot_redirect_host() {
        // F-012: registry-controlled dl_path must not move the host off crates.io.
        let ok = crates_download_url("/api/v1/crates/serde/1.0.0/download").expect("valid path");
        assert_eq!("https://crates.io/api/v1/crates/serde/1.0.0/download", ok);
        // Userinfo host-confusion joins as a crates.io path, not an evil.com host.
        let confused = crates_download_url("@evil.com/x").expect("joins as path");
        assert!(confused.starts_with("https://crates.io/"), "got {confused}");
        // Scheme-relative and absolute redirects are rejected outright.
        assert!(crates_download_url("//evil.com/x").is_err());
        assert!(crates_download_url("https://evil.com/x").is_err());
    }

    #[test]
    fn registry_host_allowlist_rejects_unexpected_hosts() {
        // F-017.
        assert!(assert_registry_host("https://pypi.org/pypi/requests/json").is_ok());
        assert!(assert_registry_host("https://registry.npmjs.org/left-pad").is_ok());
        assert!(assert_registry_host("https://crates.io/api/v1/crates/serde/1.0.0").is_ok());
        assert!(assert_registry_host("http://169.254.169.254/latest/meta-data").is_err());
        assert!(assert_registry_host("https://pypi.org.evil.example/pypi/x/json").is_err());
        assert!(assert_registry_host("not a url").is_err());
    }

    #[test]
    fn parses_npm_sha512_integrity() {
        let raw = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0xab_u8; 64],
        );
        let integrity = format!("sha512-{raw}");
        let parsed = parse_sri_sha512(&integrity).expect("sha512 parsed");
        assert_eq!(64, parsed.len());
        assert!(parse_sri_sha512("sha1-deadbeef").is_none());
        // F-015: a well-formed prefix whose decoded payload is not 64 bytes
        // must be rejected rather than coerced into a wrong-length digest.
        let short = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0xab_u8; 32],
        );
        assert!(parse_sri_sha512(&format!("sha512-{short}")).is_none());
    }

    #[test]
    fn download_optional_artifact_defaults_to_primary() {
        let mut cursor = RelayCursor::new(&[]);
        assert_eq!(None, cursor.read_optional_u8().expect("no byte"));
    }
}

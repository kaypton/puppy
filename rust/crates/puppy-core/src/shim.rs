//! Bidirectional byte-stream copy between a frontend and a backend connection.
//!
//! The shim spawns two copy tasks; when either direction ends, the other side
//! is closed so its copy task can exit. `run` returns the byte counts copied
//! in each direction.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Default copy buffer size.
pub const DEFAULT_BUFFER_SIZE: usize = 32 * 1024;

/// Errors returned by [`ShimServer::new`].
#[derive(thiserror::Error, Debug)]
pub enum ShimError {
	#[error("shim: frontend is nil")]
	FrontendNil,
	#[error("shim: backend is nil")]
	BackendNil,
}

/// Runtime configuration for [`ShimServer`].
pub struct ShimServerConfiguration<S> {
	pub frontend: Option<S>,
	pub backend: Option<S>,
	pub buffer_size: usize,
}

/// Bidirectional copy between a frontend and a backend stream.
///
/// Both streams must implement `AsyncRead + AsyncWrite + Unpin + Send + 'static`.
/// Each stream is split into independent read and write halves via
/// `tokio::io::split` so the two copy directions never contend on the same
/// lock.
pub struct ShimServer<S> {
	frontend: S,
	backend: S,
	pub buf_size: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> ShimServer<S> {
	/// Constructs a `ShimServer` from the given configuration. Returns an
	/// error if either stream is missing. A non-positive `buffer_size` falls
	/// back to [`DEFAULT_BUFFER_SIZE`].
	pub fn new(config: ShimServerConfiguration<S>) -> Result<Self, ShimError> {
		let frontend = config.frontend.ok_or(ShimError::FrontendNil)?;
		let backend = config.backend.ok_or(ShimError::BackendNil)?;
		let buf_size = if config.buffer_size == 0 {
			DEFAULT_BUFFER_SIZE
		} else {
			config.buffer_size
		};
		Ok(Self {
			frontend,
			backend,
			buf_size,
		})
	}

	/// Copies bytes between the frontend and backend until both directions
	/// complete. Returns `(client_to_backend, backend_to_client)` byte counts.
	///
	/// Either direction closing closes the opposite stream so the other copy
	/// task can exit.
	pub async fn run(self) -> (u64, u64) {
		self.run_until(std::future::pending()).await
	}

	/// Like [`run`](Self::run) but aborts the copy when `shutdown` resolves.
	/// Both streams are closed when `shutdown` fires.
	pub async fn run_until<F: std::future::Future<Output = ()> + Send + 'static>(
		self,
		shutdown: F,
	) -> (u64, u64) {
		let Self {
			frontend,
			backend,
			buf_size,
		} = self;

		// Split each stream into read and write halves so the two copy
		// directions can proceed concurrently without contending on a single
		// lock. `tokio::io::split` returns `ReadHalf`/`WriteHalf` backed by an
		// internal `BiLock` that never deadlocks because each direction only
		// needs one half at a time.
		let (fe_read, fe_write) = tokio::io::split(frontend);
		let (be_read, be_write) = tokio::io::split(backend);

		// frontend -> backend
		let fe_to_be = async move {
			let mut total: u64 = 0;
			let mut reader = fe_read;
			let mut writer = be_write;
			let mut buf = vec![0u8; buf_size];
			loop {
				match reader.read(&mut buf).await {
					Ok(0) | Err(_) => break,
					Ok(n) => {
						if writer.write_all(&buf[..n]).await.is_err() {
							break;
						}
						total += n as u64;
					}
				}
			}
			// Close the backend write half so the other direction can exit.
			let _ = writer.shutdown().await;
			total
		};

		// backend -> frontend
		let be_to_fe = async move {
			let mut total: u64 = 0;
			let mut reader = be_read;
			let mut writer = fe_write;
			let mut buf = vec![0u8; buf_size];
			loop {
				match reader.read(&mut buf).await {
					Ok(0) | Err(_) => break,
					Ok(n) => {
						if writer.write_all(&buf[..n]).await.is_err() {
							break;
						}
						total += n as u64;
					}
				}
			}
			// Close the frontend write half so the other direction can exit.
			let _ = writer.shutdown().await;
			total
		};

		let copy = async move {
			let (fe_to_be, be_to_fe) = tokio::join!(fe_to_be, be_to_fe);
			(fe_to_be, be_to_fe)
		};

		tokio::pin!(shutdown);
		tokio::select! {
			result = copy => result,
			_ = shutdown => (0, 0),
		}
	}
}

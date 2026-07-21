use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use puppy_rpc::v1::{LogEntry, LogFilter};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
	pub cursor: String,
	pub server_instance_id: String,
	pub time_ms: i64,
	pub level: String,
	pub target: String,
	pub message: String,
	pub fields: HashMap<String, String>,
}

impl LogRecord {
	pub fn into_proto(self) -> LogEntry {
		LogEntry {
			cursor: self.cursor,
			server_instance_id: self.server_instance_id,
			time: Some(prost_types::Timestamp {
				seconds: self.time_ms.div_euclid(1000),
				nanos: (self.time_ms.rem_euclid(1000) * 1_000_000) as i32,
			}),
			level: self.level,
			target: self.target,
			message: self.message,
			fields: self.fields,
		}
	}
}

struct LogHubInner {
	instance_id: String,
	directory: PathBuf,
	sequence: AtomicU64,
	live: broadcast::Sender<LogRecord>,
	writer: std::sync::mpsc::Sender<LogRecord>,
}

#[derive(Clone)]
pub struct LogHub {
	inner: Arc<LogHubInner>,
}

impl LogHub {
	pub fn new(directory: &Path, instance_id: impl Into<String>) -> std::io::Result<Self> {
		std::fs::create_dir_all(directory)?;
		let instance_id = instance_id.into();
		let (live, _) = broadcast::channel(2_048);
		let (writer, receiver) = std::sync::mpsc::channel();
		let directory_buf = directory.to_path_buf();
		let writer_directory = directory_buf.clone();
		let writer_instance = instance_id.clone();
		std::thread::Builder::new()
			.name("puppy-log-writer".to_string())
			.spawn(move || writer_loop(&writer_directory, &writer_instance, receiver))?;
		Ok(Self {
			inner: Arc::new(LogHubInner {
				instance_id,
				directory: directory_buf,
				sequence: AtomicU64::new(0),
				live,
				writer,
			}),
		})
	}

	pub fn layer(&self) -> PuppyLogLayer {
		PuppyLogLayer { hub: self.clone() }
	}

	pub fn subscribe(&self) -> broadcast::Receiver<LogRecord> {
		self.inner.live.subscribe()
	}

	fn publish(&self, metadata: &tracing::Metadata<'_>, mut fields: HashMap<String, String>) {
		let sequence = self.inner.sequence.fetch_add(1, Ordering::Relaxed) + 1;
		let message = fields.remove("message").unwrap_or_default();
		let record = LogRecord {
			cursor: format!("{}:{sequence}", self.inner.instance_id),
			server_instance_id: self.inner.instance_id.clone(),
			time_ms: now_ms(),
			level: metadata.level().as_str().to_string(),
			target: metadata.target().to_string(),
			message,
			fields,
		};
		let _ = self.inner.writer.send(record.clone());
		let _ = self.inner.live.send(record);
	}

	pub fn list(
		&self,
		filter: Option<&LogFilter>,
		limit: usize,
		before_cursor: &str,
	) -> std::io::Result<(Vec<LogEntry>, String)> {
		let mut records = self.read_all()?;
		records.retain(|record| matches_filter(record, filter));
		if !before_cursor.is_empty() {
			if let Some(index) = records.iter().position(|r| r.cursor == before_cursor) {
				records.truncate(index);
			}
		}
		let take = limit.clamp(1, 2_000);
		let start = records.len().saturating_sub(take);
		let page = records.split_off(start);
		let next = page.first().map(|r| r.cursor.clone()).unwrap_or_default();
		Ok((page.into_iter().map(LogRecord::into_proto).collect(), next))
	}

	pub fn after(
		&self,
		cursor: &str,
		filter: Option<&LogFilter>,
	) -> std::io::Result<Vec<LogRecord>> {
		let mut records = self.read_all()?;
		if let Some(index) = records.iter().position(|r| r.cursor == cursor) {
			records.drain(..=index);
		}
		records.retain(|record| matches_filter(record, filter));
		Ok(records)
	}

	fn read_all(&self) -> std::io::Result<Vec<LogRecord>> {
		let mut paths = log_paths(&self.inner.directory)?;
		paths.sort();
		let mut result = Vec::new();
		for path in paths {
			let file = File::open(path)?;
			for line in BufReader::new(file).lines() {
				if let Ok(record) = serde_json::from_str::<LogRecord>(&line?) {
					result.push(record);
				}
			}
		}
		Ok(result)
	}

	pub fn apply_retention(&self, days: u64, max_bytes: u64) -> std::io::Result<()> {
		let mut paths = log_paths(&self.inner.directory)?;
		paths.sort_by_key(|path| path.metadata().and_then(|m| m.modified()).ok());
		if days > 0 {
			let cutoff = std::time::SystemTime::now()
				.checked_sub(std::time::Duration::from_secs(days * 86_400))
				.unwrap_or(std::time::UNIX_EPOCH);
			for path in &paths {
				if path
					.metadata()
					.and_then(|m| m.modified())
					.is_ok_and(|time| time < cutoff)
				{
					let _ = std::fs::remove_file(path);
				}
			}
		}
		if max_bytes > 0 {
			paths = log_paths(&self.inner.directory)?;
			paths.sort_by_key(|path| path.metadata().and_then(|m| m.modified()).ok());
			let mut total: u64 = paths
				.iter()
				.filter_map(|p| p.metadata().ok())
				.map(|m| m.len())
				.sum();
			let path_count = paths.len();
			for (index, path) in paths.into_iter().enumerate() {
				if total <= max_bytes {
					break;
				}
				// Keep the newest file open for the current writer even if it alone
				// exceeds the configured total.
				if index + 1 == path_count {
					break;
				}
				if let Ok(metadata) = path.metadata() {
					if std::fs::remove_file(&path).is_ok() {
						total = total.saturating_sub(metadata.len());
					}
				}
			}
		}
		Ok(())
	}
}

pub struct PuppyLogLayer {
	hub: LogHub,
}

impl<S> Layer<S> for PuppyLogLayer
where
	S: Subscriber,
{
	fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
		let mut visitor = FieldVisitor::default();
		event.record(&mut visitor);
		self.hub.publish(event.metadata(), visitor.fields);
	}
}

#[derive(Default)]
struct FieldVisitor {
	fields: HashMap<String, String>,
}

impl tracing::field::Visit for FieldVisitor {
	fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
		self.fields
			.insert(field.name().to_string(), format!("{value:?}"));
	}

	fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
		self.fields
			.insert(field.name().to_string(), value.to_string());
	}
}

fn writer_loop(
	directory: &Path,
	instance_id: &str,
	receiver: std::sync::mpsc::Receiver<LogRecord>,
) {
	let mut current_day = i64::MIN;
	let mut file: Option<File> = None;
	for record in receiver {
		let day = record.time_ms / 86_400_000;
		if day != current_day {
			let path = directory.join(format!("puppy-{instance_id}-{day}.jsonl"));
			file = OpenOptions::new().create(true).append(true).open(path).ok();
			current_day = day;
		}
		if let (Some(file), Ok(line)) = (file.as_mut(), serde_json::to_string(&record)) {
			let _ = writeln!(file, "{line}");
		}
	}
}

fn log_paths(directory: &Path) -> std::io::Result<Vec<PathBuf>> {
	Ok(std::fs::read_dir(directory)?
		.filter_map(Result::ok)
		.map(|entry| entry.path())
		.filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
		.collect())
}

pub fn matches_filter(record: &LogRecord, filter: Option<&LogFilter>) -> bool {
	let Some(filter) = filter else {
		return true;
	};
	if !filter.min_level.is_empty() && level_rank(&record.level) < level_rank(&filter.min_level) {
		return false;
	}
	if !filter.target.is_empty() && !record.target.contains(&filter.target) {
		return false;
	}
	if !filter.query.is_empty() {
		let query = filter.query.to_lowercase();
		if !record.message.to_lowercase().contains(&query)
			&& !record
				.fields
				.values()
				.any(|v| v.to_lowercase().contains(&query))
		{
			return false;
		}
	}
	true
}

fn level_rank(level: &str) -> u8 {
	match level.to_ascii_uppercase().as_str() {
		"TRACE" => 0,
		"DEBUG" => 1,
		"INFO" => 2,
		"WARN" => 3,
		"ERROR" => 4,
		_ => 0,
	}
}

fn now_ms() -> i64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis() as i64
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn filters_by_level_target_and_text() {
		let record = LogRecord {
			cursor: "instance:1".to_string(),
			server_instance_id: "instance".to_string(),
			time_ms: 1,
			level: "WARN".to_string(),
			target: "tunproxy".to_string(),
			message: "backend dial failed".to_string(),
			fields: HashMap::new(),
		};
		assert!(matches_filter(
			&record,
			Some(&LogFilter {
				min_level: "INFO".to_string(),
				target: "tun".to_string(),
				query: "dial".to_string()
			})
		));
		assert!(!matches_filter(
			&record,
			Some(&LogFilter {
				min_level: "ERROR".to_string(),
				target: String::new(),
				query: String::new()
			})
		));
	}

	#[test]
	fn reads_jsonl_history() {
		let directory = tempfile::tempdir().unwrap();
		let hub = LogHub::new(directory.path(), "instance").unwrap();
		let record = LogRecord {
			cursor: "instance:7".to_string(),
			server_instance_id: "instance".to_string(),
			time_ms: 7,
			level: "INFO".to_string(),
			target: "server".to_string(),
			message: "ready".to_string(),
			fields: HashMap::new(),
		};
		std::fs::write(
			directory.path().join("puppy-old-0.jsonl"),
			format!("{}\n", serde_json::to_string(&record).unwrap()),
		)
		.unwrap();
		let (entries, _) = hub.list(None, 10, "").unwrap();
		assert_eq!(entries.len(), 1);
		assert_eq!(entries[0].message, "ready");
	}
}

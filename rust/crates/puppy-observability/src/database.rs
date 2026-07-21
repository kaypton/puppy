use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use puppy_core::stats::{ConnectionInfo, ConnectionRegistry};
use puppy_rpc::v1::{Connection, ConnectionStatus, ListConnectionsRequest};
use rusqlite::{params, params_from_iter, types::Value, Connection as SqliteConnection};
use tokio_util::sync::CancellationToken;

#[derive(thiserror::Error, Debug)]
pub enum DatabaseError {
	#[error("open observability database: {0}")]
	Open(#[source] rusqlite::Error),
	#[error("query observability database: {0}")]
	Query(#[from] rusqlite::Error),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Totals {
	pub connections: u64,
	pub bytes_in: u64,
	pub bytes_out: u64,
}

#[derive(Clone)]
pub struct Database {
	inner: Arc<Mutex<SqliteConnection>>,
}

impl Database {
	pub fn open(path: &Path) -> Result<Self, DatabaseError> {
		if let Some(parent) = path.parent() {
			std::fs::create_dir_all(parent).map_err(|_| {
				DatabaseError::Open(rusqlite::Error::InvalidPath(parent.to_path_buf()))
			})?;
		}
		let conn = SqliteConnection::open(path).map_err(DatabaseError::Open)?;
		conn.pragma_update(None, "journal_mode", "WAL")?;
		conn.pragma_update(None, "busy_timeout", 5_000)?;
		conn.execute_batch(
			r#"
			CREATE TABLE IF NOT EXISTS connections (
			  id TEXT PRIMARY KEY,
			  server_instance_id TEXT NOT NULL,
			  status INTEGER NOT NULL,
			  frontend TEXT NOT NULL,
			  backend TEXT NOT NULL,
			  remote_addr TEXT NOT NULL,
			  target_host TEXT NOT NULL,
			  target_port INTEGER NOT NULL,
			  network TEXT NOT NULL,
			  protocol TEXT NOT NULL,
			  started_at_ms INTEGER NOT NULL,
			  closed_at_ms INTEGER,
			  bytes_in INTEGER NOT NULL,
			  bytes_out INTEGER NOT NULL,
			  close_reason TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_connections_started ON connections(started_at_ms DESC);
			CREATE INDEX IF NOT EXISTS idx_connections_status ON connections(status, started_at_ms DESC);
			CREATE INDEX IF NOT EXISTS idx_connections_frontend ON connections(frontend, started_at_ms DESC);
			"#,
		)?;
		conn.execute(
			"UPDATE connections SET status = ?1, closed_at_ms = CAST(strftime('%s','now') AS INTEGER) * 1000, close_reason = 'interrupted' WHERE status = ?2",
			params![ConnectionStatus::Interrupted as i32, ConnectionStatus::Active as i32],
		)?;
		Ok(Self {
			inner: Arc::new(Mutex::new(conn)),
		})
	}

	pub fn upsert(&self, instance_id: &str, info: &ConnectionInfo) -> Result<(), DatabaseError> {
		let closed_at = *info.closed_unix_ms.read();
		let reason = info.close_reason.read().clone();
		let status = if closed_at.is_none() {
			ConnectionStatus::Active
		} else if reason == "interrupted" {
			ConnectionStatus::Interrupted
		} else {
			ConnectionStatus::Closed
		};
		self.inner.lock().execute(
			r#"INSERT INTO connections (
			id, server_instance_id, status, frontend, backend, remote_addr,
			target_host, target_port, network, protocol, started_at_ms,
			closed_at_ms, bytes_in, bytes_out, close_reason
			) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
			ON CONFLICT(id) DO UPDATE SET status=excluded.status,
			closed_at_ms=excluded.closed_at_ms, bytes_in=excluded.bytes_in,
			bytes_out=excluded.bytes_out, close_reason=excluded.close_reason"#,
			params![
				info.id,
				instance_id,
				status as i32,
				info.frontend,
				info.backend,
				info.remote_addr,
				info.target.host,
				info.target.port,
				info.network,
				info.protocol.as_str(),
				info.started_unix_ms,
				closed_at,
				info.bytes_in(),
				info.bytes_out(),
				reason,
			],
		)?;
		Ok(())
	}

	pub fn get(&self, id: &str) -> Result<Option<Connection>, DatabaseError> {
		let conn = self.inner.lock();
		let mut stmt = conn.prepare(&format!("{} WHERE id = ?1", SELECT_CONNECTION))?;
		let mut rows = stmt.query(params![id])?;
		Ok(rows.next()?.map(row_to_connection).transpose()?)
	}

	pub fn list(
		&self,
		req: &ListConnectionsRequest,
	) -> Result<(Vec<Connection>, u64, String), DatabaseError> {
		let page_size = if req.page_size == 0 {
			100
		} else {
			req.page_size.clamp(1, 500)
		} as usize;
		let offset = req.page_token.parse::<usize>().unwrap_or(0);
		let mut clauses = Vec::new();
		let mut values: Vec<Value> = Vec::new();
		if req.status != ConnectionStatus::Unspecified as i32 {
			clauses.push("status = ?".to_string());
			values.push(Value::Integer(req.status as i64));
		}
		for (column, value) in [
			("frontend", &req.frontend),
			("network", &req.network),
			("protocol", &req.protocol),
		] {
			if !value.is_empty() {
				clauses.push(format!("{column} = ?"));
				values.push(Value::Text(value.clone()));
			}
		}
		if !req.query.is_empty() {
			clauses.push("(id LIKE ? OR remote_addr LIKE ? OR target_host LIKE ?)".to_string());
			let pattern = format!("%{}%", req.query);
			values.extend([
				Value::Text(pattern.clone()),
				Value::Text(pattern.clone()),
				Value::Text(pattern),
			]);
		}
		let where_sql = if clauses.is_empty() {
			String::new()
		} else {
			format!(" WHERE {}", clauses.join(" AND "))
		};
		let sort = match req.sort_by.as_str() {
			"closed_at" => "closed_at_ms",
			"bytes_in" => "bytes_in",
			"bytes_out" => "bytes_out",
			_ => "started_at_ms",
		};
		let direction = if req.descending { "DESC" } else { "ASC" };
		let conn = self.inner.lock();
		let total: u64 = conn.query_row(
			&format!("SELECT COUNT(*) FROM connections{where_sql}"),
			params_from_iter(values.iter()),
			|row| row.get(0),
		)?;
		let sql = format!("{SELECT_CONNECTION}{where_sql} ORDER BY {sort} {direction}, id {direction} LIMIT {} OFFSET {}", page_size + 1, offset);
		let mut stmt = conn.prepare(&sql)?;
		let mapped = stmt.query_map(params_from_iter(values.iter()), row_to_connection)?;
		let mut items = mapped.collect::<Result<Vec<_>, _>>()?;
		let has_more = items.len() > page_size;
		items.truncate(page_size);
		let next = if has_more {
			(offset + page_size).to_string()
		} else {
			String::new()
		};
		Ok((items, total, next))
	}

	pub fn totals(&self) -> Result<Totals, DatabaseError> {
		self.inner.lock().query_row(
			"SELECT COUNT(*), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0) FROM connections",
			[],
			|row| Ok(Totals { connections: row.get(0)?, bytes_in: row.get(1)?, bytes_out: row.get(2)? }),
		).map_err(DatabaseError::from)
	}

	pub fn apply_retention(&self, days: u64, max_rows: u64) -> Result<(), DatabaseError> {
		let conn = self.inner.lock();
		if days > 0 {
			let cutoff = now_ms() - (days as i64 * 86_400_000);
			conn.execute(
				"DELETE FROM connections WHERE status != ?1 AND closed_at_ms < ?2",
				params![ConnectionStatus::Active as i32, cutoff],
			)?;
		}
		if max_rows > 0 {
			conn.execute(
				"DELETE FROM connections WHERE id IN (SELECT id FROM connections WHERE status != ?1 ORDER BY started_at_ms DESC LIMIT -1 OFFSET ?2)",
				params![ConnectionStatus::Active as i32, max_rows],
			)?;
		}
		Ok(())
	}
}

const SELECT_CONNECTION: &str = "SELECT id,server_instance_id,status,frontend,backend,remote_addr,target_host,target_port,network,protocol,started_at_ms,closed_at_ms,bytes_in,bytes_out,close_reason FROM connections";

fn row_to_connection(row: &rusqlite::Row<'_>) -> rusqlite::Result<Connection> {
	let started: i64 = row.get(10)?;
	let closed: Option<i64> = row.get(11)?;
	Ok(Connection {
		id: row.get(0)?,
		server_instance_id: row.get(1)?,
		status: row.get(2)?,
		frontend: row.get(3)?,
		backend: row.get(4)?,
		remote_addr: row.get(5)?,
		target_host: row.get(6)?,
		target_port: row.get::<_, u32>(7)?,
		network: row.get(8)?,
		protocol: row.get(9)?,
		started_at: Some(timestamp(started)),
		closed_at: closed.map(timestamp),
		duration_ms: closed.unwrap_or_else(now_ms).saturating_sub(started) as u64,
		bytes_in: row.get(12)?,
		bytes_out: row.get(13)?,
		close_reason: row.get(14)?,
	})
}

pub fn connection_from_info(instance_id: &str, info: &ConnectionInfo) -> Connection {
	let closed = *info.closed_unix_ms.read();
	let reason = info.close_reason.read().clone();
	Connection {
		id: info.id.clone(),
		server_instance_id: instance_id.to_string(),
		status: if closed.is_none() {
			ConnectionStatus::Active as i32
		} else {
			ConnectionStatus::Closed as i32
		},
		frontend: info.frontend.clone(),
		backend: info.backend.clone(),
		remote_addr: info.remote_addr.clone(),
		target_host: info.target.host.clone(),
		target_port: info.target.port as u32,
		network: info.network.clone(),
		protocol: info.protocol.as_str().to_string(),
		started_at: Some(timestamp(info.started_unix_ms)),
		closed_at: closed.map(timestamp),
		duration_ms: closed
			.unwrap_or_else(now_ms)
			.saturating_sub(info.started_unix_ms) as u64,
		bytes_in: info.bytes_in(),
		bytes_out: info.bytes_out(),
		close_reason: reason,
	}
}

pub async fn run_checkpoint(
	db: Database,
	registry: ConnectionRegistry,
	instance_id: String,
	interval: Duration,
	retention_days: u64,
	max_rows: u64,
	cancel: CancellationToken,
) {
	let mut ticker = tokio::time::interval(interval);
	loop {
		tokio::select! {
			_ = cancel.cancelled() => {
				checkpoint(&db, &registry, &instance_id);
				break;
			}
			_ = ticker.tick() => checkpoint(&db, &registry, &instance_id),
		}
	}
	let _ = db.apply_retention(retention_days, max_rows);
}

fn checkpoint(db: &Database, registry: &ConnectionRegistry, instance_id: &str) {
	for info in registry.active().into_iter().chain(registry.drain_closed()) {
		if let Err(error) = db.upsert(instance_id, &info) {
			tracing::error!(%error, "persist connection snapshot failed");
		}
	}
}

fn timestamp(ms: i64) -> prost_types::Timestamp {
	prost_types::Timestamp {
		seconds: ms.div_euclid(1000),
		nanos: (ms.rem_euclid(1000) * 1_000_000) as i32,
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
	use std::sync::Arc;

	use puppy_core::backend::{Protocol, Target};
	use puppy_core::stats::{ConnectionInfo, ConnectionRegistry};

	use super::*;

	#[test]
	fn persists_active_and_closed_connection() {
		let directory = tempfile::tempdir().unwrap();
		let database = Database::open(&directory.path().join("history.sqlite3")).unwrap();
		let registry = ConnectionRegistry::new();
		let info = Arc::new(ConnectionInfo::with_backend(
			"c1",
			"http",
			"127.0.0.1:1234",
			Target {
				network: "tcp".to_string(),
				protocol: Protocol::Tls,
				host: "example.com".to_string(),
				port: 443,
			},
			Protocol::Tls,
			"tcp",
			"direct",
		));
		info.add_bytes_in(12);
		info.add_bytes_out(34);
		registry.register(info.clone());
		database.upsert("instance", &info).unwrap();
		let active = database.get("c1").unwrap().unwrap();
		assert_eq!(active.status, ConnectionStatus::Active as i32);
		assert_eq!((active.bytes_in, active.bytes_out), (12, 34));
		assert_eq!(active.target_host, "example.com");
		registry.remove("c1");
		let closed = registry.drain_closed().pop().unwrap();
		database.upsert("instance", &closed).unwrap();
		let stored = database.get("c1").unwrap().unwrap();
		assert_eq!(stored.status, ConnectionStatus::Closed as i32);
		assert!(stored.closed_at.is_some());
	}

	#[test]
	fn marks_stale_active_rows_interrupted_on_reopen() {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("history.sqlite3");
		let database = Database::open(&path).unwrap();
		let info = ConnectionInfo::new("c1", "http", "remote");
		database.upsert("old", &info).unwrap();
		drop(database);
		let reopened = Database::open(&path).unwrap();
		let stored = reopened.get("c1").unwrap().unwrap();
		assert_eq!(stored.status, ConnectionStatus::Interrupted as i32);
		assert_eq!(stored.close_reason, "interrupted");
	}
}

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Real SQL database storage backend (Postgres, MySQL, Oracle, or any other
SQLAlchemy-supported engine) — the storage counterpart to
:class:`~jscoup.storage.sqlite.SQLiteStorage`, for when many processes need
to share one observability store instead of each keeping its own local
SQLite file.

Optional: this module lazy-imports ``sqlalchemy`` at call time, never at
import time, so JSCoup stays fully usable with zero third-party
dependencies when this backend isn't used. Install with
``pip install jscoup[sql]``.

Mirrors :mod:`jscoup.storage.sqlite`'s schema and semantics exactly via
``sqlalchemy.Table``/``MetaData`` + ``metadata.create_all(engine,
checkfirst=True)``, so JSCoup creates the tables it needs on whichever
engine ``database_url`` points at, with no migration step.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from ..models import EventRecord
from .base import BaseStorage


class SqlStorage(BaseStorage):
    """Thread-safe storage backed by a real SQL database via SQLAlchemy."""

    def __init__(
        self,
        url: Optional[str] = None,
        max_events: Optional[int] = None,
        retention_days: Optional[int] = 14,
        schema: Optional[str] = None,
        *,
        drivername: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        database: Optional[str] = None,
        query: Optional[Dict[str, str]] = None,
        ssh_tunnel: Optional[Dict[str, Any]] = None,
        connect_args: Optional[Dict[str, Any]] = None,
        **engine_kwargs: Any,
    ):
        try:
            import sqlalchemy as sa
        except ImportError as exc:  # pragma: no cover - exercised via test skip
            raise ImportError(
                "SqlStorage needs SQLAlchemy — install it with `pip install "
                "jscoup[sql]` (or `pip install SQLAlchemy`)."
            ) from exc

        from .connections import apply_ssh_tunnel, build_sql_url

        # Accepts a plain URL, or the same connection built from discrete
        # parts (host/port/username/password/...).
        url = build_sql_url(
            url=url, drivername=drivername, username=username, password=password,
            host=host, port=port, database=database, query=query,
        )

        self._tunnel = None
        if ssh_tunnel:
            # The database is reachable only through an SSH bastion/jump
            # host, so open a local forwarded port first and connect to that.
            made_url = sa.engine.make_url(url)
            self._tunnel, local_host, local_port = apply_ssh_tunnel(
                ssh_tunnel, target_host=made_url.host, target_port=made_url.port or {"postgresql":5432,"mysql":3306,"mariadb":3306,"oracle":1521,"mssql":1433}.get(made_url.get_backend_name(),0)
            )
            url = made_url.set(host=local_host, port=local_port).render_as_string(hide_password=False)

        try:
            self._sa = sa
            self.max_events = max_events
            self.retention_days = retention_days
            self.engine = sa.create_engine(
                url, pool_pre_ping=True, connect_args=connect_args or {}, **engine_kwargs
            )

            # An isolated schema is real on Postgres/MySQL; SQLite has no
            # such concept, so `schema` is accepted there and ignored.
            self.schema = schema if schema and self.engine.dialect.name != "sqlite" else None
            if self.schema:
                try:
                    with self.engine.begin() as conn:
                        conn.execute(sa.schema.CreateSchema(self.schema, if_not_exists=True))
                except Exception:
                    # Two processes issuing CREATE SCHEMA IF NOT EXISTS at
                    # once can still race to a duplicate-object error on some
                    # database/driver versions. Only swallow it if the schema
                    # is actually there now.
                    inspector = sa.inspect(self.engine)
                    if self.schema not in inspector.get_schema_names():
                        raise

            self.metadata = sa.MetaData(schema=self.schema)

            self.events = sa.Table(
                "jscoup_events",
                self.metadata,
                sa.Column("id", sa.String(64), primary_key=True),
                sa.Column("ts", sa.Float, nullable=False, index=True),
                sa.Column("kind", sa.String(32)),
                sa.Column("name", sa.String(255)),
                sa.Column("status", sa.String(16), index=True),
                sa.Column("severity", sa.String(16)),
                sa.Column("category", sa.String(64), index=True),
                sa.Column("method", sa.String(16)),
                sa.Column("path", sa.String(500)),
                sa.Column("route", sa.String(500)),
                sa.Column("status_code", sa.Integer),
                sa.Column("duration_ms", sa.Float),
                sa.Column("error_type", sa.String(255)),
                sa.Column("error_message", sa.Text),
                sa.Column("fingerprint", sa.String(32), index=True),
                sa.Column("culprit", sa.String(255)),
                sa.Column("actor_subject", sa.String(255), index=True),
                sa.Column("actor_label", sa.String(255)),
                sa.Column("token_fingerprint", sa.String(32)),
                sa.Column("service", sa.String(255)),
                sa.Column("environment", sa.String(64)),
                sa.Column("trace_id", sa.String(255)),
                sa.Column("simulation_id", sa.String(64), index=True),
                sa.Column("parent_id", sa.String(64)),
                sa.Column("query_count", sa.Integer, default=0),
                sa.Column("db_time_ms", sa.Float, default=0),
                sa.Column("resolved", sa.Integer, default=0),
                sa.Column("payload", sa.Text, nullable=False),
            )
            self.queries = sa.Table(
                "jscoup_queries",
                self.metadata,
                sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
                sa.Column("event_id", sa.String(64), nullable=False, index=True),
                sa.Column("seq", sa.Integer),
                sa.Column("sql", sa.Text),
                sa.Column("params", sa.Text),
                sa.Column("duration_ms", sa.Float),
                sa.Column("rowcount", sa.Integer),
                sa.Column("error", sa.Text),
                sa.Column("backend", sa.String(64)),
                sa.Column("caller", sa.String(255)),
            )
            try:
                self.metadata.create_all(self.engine, checkfirst=True)
            except Exception:
                # checkfirst=True is check-then-create, not atomic: two
                # processes booting against a fresh database at once can both
                # pass the existence check before either's CREATE TABLE
                # commits, so the loser gets a duplicate-object error even
                # though the tables now exist — or are about to: the winner
                # creates them one after another, so the loser can see only
                # some of them yet. Retry (each attempt is idempotent) until
                # every table exists, and only re-raise if they never do.
                wanted = {table.name for table in self.metadata.tables.values()}
                for attempt in range(8):
                    existing = set(sa.inspect(self.engine).get_table_names(schema=self.schema))
                    if not wanted - existing:
                        break
                    time.sleep(0.05 * (attempt + 1))
                    try:
                        self.metadata.create_all(self.engine, checkfirst=True)
                    except Exception:
                        continue
                else:
                    existing = set(sa.inspect(self.engine).get_table_names(schema=self.schema))
                    if wanted - existing:
                        raise
            self._writes_since_trim = 0

        except BaseException:
            resource = getattr(self, "engine", None)
            if resource is None:resource = getattr(self, "client", None)
            if resource is not None:
                if hasattr(resource, "dispose"):resource.dispose()
                else:resource.close()
            if self._tunnel:self._tunnel.stop()
            raise

    @classmethod
    def from_file(cls, path: str, **overrides: Any) -> "SqlStorage":
        """Build a :class:`SqlStorage` from a connection file (``.json``,
        ``.yaml``/``.yml`` or ``.ini`` — see
        :func:`jscoup.storage.connections.load_connection_file`) instead of
        passing connection parts as keyword arguments directly. Anything in
        ``**overrides`` wins over the file's own values::

            storage = SqlStorage.from_file("/etc/jscoup/database.yaml")
        """
        from .connections import load_connection_file

        data = load_connection_file(path)
        data.update(overrides)
        return cls(**data)

    def close(self) -> None:
        self.engine.dispose()
        if self._tunnel is not None:
            self._tunnel.stop()

    # -- writes ------------------------------------------------------------ #

    def save(self, event: EventRecord) -> None:
        sa = self._sa
        payload = json.dumps(event.to_dict(), default=str, ensure_ascii=False)
        actor = event.actor
        row = dict(
            id=event.id, ts=event.ts, kind=event.kind, name=event.name, status=event.status,
            severity=event.severity, category=event.category, method=event.method,
            path=event.path, route=event.route, status_code=event.status_code,
            duration_ms=event.duration_ms, error_type=event.error_type,
            error_message=event.error_message, fingerprint=event.fingerprint,
            culprit=event.culprit,
            actor_subject=actor.subject if actor else None,
            actor_label=actor.label if actor else None,
            token_fingerprint=actor.token_fingerprint if actor else None,
            service=event.service, environment=event.environment, trace_id=event.trace_id,
            simulation_id=event.simulation_id, parent_id=event.parent_id,
            query_count=event.query_count, db_time_ms=event.db_time_ms,
            resolved=1 if event.resolved else 0, payload=payload,
        )
        with self.engine.begin() as conn:
            conn.execute(sa.delete(self.events).where(self.events.c.id == event.id))
            conn.execute(sa.insert(self.events), row)
            # The events row is fully replaced above, but its old query rows
            # aren't cascaded automatically, so clear them first.
            conn.execute(sa.delete(self.queries).where(self.queries.c.event_id == event.id))
            if event.queries:
                conn.execute(
                    sa.insert(self.queries),
                    [
                        dict(event_id=event.id, seq=i, sql=q.sql, params=q.params_preview,
                             duration_ms=q.duration_ms, rowcount=q.rowcount, error=q.error,
                             backend=q.backend, caller=q.caller)
                        for i, q in enumerate(event.queries)
                    ],
                )
        self._writes_since_trim += 1
        if self._writes_since_trim >= 50:
            self._writes_since_trim = 0
            self._trim()

    def _trim(self) -> None:
        sa = self._sa
        with self.engine.begin() as conn:
            if self.retention_days:
                cutoff = time.time() - self.retention_days * 86400
                stale_ids = sa.select(self.events.c.id).where(self.events.c.ts < cutoff)
                conn.execute(sa.delete(self.queries).where(self.queries.c.event_id.in_(stale_ids)))
                conn.execute(sa.delete(self.events).where(self.events.c.ts < cutoff))
            if self.max_events:
                keep_ids = sa.select(self.events.c.id).order_by(
                    self.events.c.ts.desc(), self.events.c.id.desc()
                ).limit(self.max_events)
                overflow_ids = sa.select(self.events.c.id).where(
                    self.events.c.id.not_in(keep_ids)
                )
                conn.execute(sa.delete(self.queries).where(self.queries.c.event_id.in_(overflow_ids)))
                conn.execute(sa.delete(self.events).where(self.events.c.id.not_in(keep_ids)))

    def mark_resolved(self, event_id: str, resolved: bool = True) -> bool:
        sa = self._sa
        with self.engine.begin() as conn:
            result = conn.execute(
                sa.update(self.events)
                .where(self.events.c.id == event_id)
                .values(resolved=1 if resolved else 0)
            )
        return result.rowcount > 0

    def purge(self, before: Optional[float] = None) -> int:
        sa = self._sa
        with self.engine.begin() as conn:
            where = self.events.c.ts < before if before is not None else sa.true()
            count = conn.execute(sa.select(sa.func.count()).select_from(self.events).where(where)).scalar_one()
            matching_ids = sa.select(self.events.c.id).where(where)
            conn.execute(sa.delete(self.queries).where(self.queries.c.event_id.in_(matching_ids)))
            conn.execute(sa.delete(self.events).where(where))
        return int(count or 0)

    # -- reads --------------------------------------------------------------- #

    def _clauses(self, filters: Dict[str, Any]) -> list:
        sa = self._sa
        c = self.events.c
        clauses = []
        for key, column in (
            ("status", c.status), ("category", c.category), ("kind", c.kind),
            ("severity", c.severity), ("fingerprint", c.fingerprint),
            ("simulation_id", c.simulation_id),
        ):
            if filters.get(key):
                clauses.append(column == filters[key])
        if filters.get("actor"):
            actor = filters["actor"]
            clauses.append(sa.or_(c.actor_subject == actor, c.actor_label == actor,
                                    c.token_fingerprint == actor))
        if filters.get("since"):
            clauses.append(c.ts >= filters["since"])
        if filters.get("search"):
            needle = f"%{filters['search']}%"
            clauses.append(sa.or_(c.name.like(needle), c.path.like(needle),
                                    c.error_message.like(needle), c.error_type.like(needle),
                                    c.actor_label.like(needle)))
        return clauses

    def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[EventRecord]:
        sa = self._sa
        stmt = sa.select(self.events.c.payload, self.events.c.resolved)
        for clause in self._clauses(filters):
            stmt = stmt.where(clause)
        stmt = stmt.order_by(self.events.c.ts.desc(), self.events.c.id.desc()).limit(limit).offset(offset)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        return [_hydrate(row.payload, row.resolved) for row in rows]

    def count(self, **filters: Any) -> int:
        sa = self._sa
        stmt = sa.select(sa.func.count()).select_from(self.events)
        for clause in self._clauses(filters):
            stmt = stmt.where(clause)
        with self.engine.connect() as conn:
            return int(conn.execute(stmt).scalar_one())

    def get(self, event_id: str) -> Optional[EventRecord]:
        sa = self._sa
        stmt = sa.select(self.events.c.payload, self.events.c.resolved).where(
            self.events.c.id == event_id
        )
        with self.engine.connect() as conn:
            row = conn.execute(stmt).first()
        return _hydrate(row.payload, row.resolved) if row else None

    def issues(self, limit: int = 50, since: Optional[float] = None) -> List[Dict[str, Any]]:
        """Events grouped by fingerprint alone, matching
        MemoryStorage/SQLiteStorage exactly. Descriptive text comes from a
        second query, picking each group's most recent event as the
        representative (same tie-break as ``list()``: newest timestamp,
        then id)."""
        sa = self._sa
        c = self.events.c
        group_stmt = sa.select(
            c.fingerprint, sa.func.count().label("count"), sa.func.max(c.ts).label("last_seen"),
            sa.func.min(c.ts).label("first_seen"),
            sa.func.count(sa.func.distinct(sa.func.coalesce(c.actor_subject, c.token_fingerprint))).label("actors"),
            sa.func.sum(c.resolved).label("resolved_count"),
        ).where(c.status == "error")
        for clause in self._clauses({"since": since}):
            group_stmt = group_stmt.where(clause)
        group_stmt = group_stmt.group_by(c.fingerprint).order_by(sa.func.max(c.ts).desc()).limit(limit)

        with self.engine.connect() as conn:
            groups = [dict(row) for row in conn.execute(group_stmt).mappings().all()]
            if groups:
                ranked = sa.select(
                    c.fingerprint, c.error_type, c.error_message, c.category, c.severity,
                    c.name, c.path, c.method,
                    sa.func.row_number().over(partition_by=c.fingerprint, order_by=(c.ts.desc(),c.id.desc())).label("rn")
                ).where(c.status == "error", c.fingerprint.in_([g["fingerprint"] for g in groups])).subquery()
                representatives = {r["fingerprint"]:dict(r) for r in conn.execute(sa.select(ranked).where(ranked.c.rn == 1)).mappings()}
                for group in groups:
                    rep = representatives.get(group["fingerprint"], {})
                    rep.pop("rn", None)
                    group.update(rep)
        return groups

    def summary(self, since: Optional[float] = None) -> Dict[str, Any]:
        sa = self._sa
        c = self.events.c
        base_clauses = self._clauses({"since": since})

        def _where(stmt):
            for clause in base_clauses:
                stmt = stmt.where(clause)
            return stmt

        totals_stmt = _where(sa.select(
            sa.func.count().label("events"),
            sa.func.sum(sa.case((c.status == "error", 1), else_=0)).label("errors"),
            sa.func.sum(sa.case((c.status == "slow", 1), else_=0)).label("slow"),
            sa.func.sum(sa.case((c.status == "ok", 1), else_=0)).label("ok"),
            sa.func.count(sa.func.distinct(c.fingerprint)).label("issues"),
            sa.func.count(sa.func.distinct(sa.func.coalesce(c.actor_subject, c.token_fingerprint))).label("actors"),
            sa.func.avg(c.duration_ms).label("avg_ms"),
            sa.func.max(c.duration_ms).label("max_ms"),
            sa.func.sum(c.query_count).label("queries"),
        ))
        by_category_stmt = _where(
            sa.select(c.category, sa.func.count().label("count")).where(c.status != "ok")
        ).group_by(c.category).order_by(sa.func.count().desc())
        by_endpoint_stmt = _where(
            sa.select(c.name, sa.func.count().label("count")).where(c.status == "error")
        ).group_by(c.name).order_by(sa.func.count().desc()).limit(8)
        # One expression object, no bind parameter: Postgres refuses a GROUP BY
        # expression whose bound literal ($2) differs from the SELECT's ($1).
        actor_expr = sa.func.coalesce(c.actor_label, sa.literal_column("'anonymous'"))
        by_actor_stmt = _where(
            sa.select(actor_expr.label("actor"),
                      sa.func.count().label("count")).where(c.status == "error")
        ).group_by(actor_expr).order_by(sa.func.count().desc()).limit(8)

        with self.engine.connect() as conn:
            totals = dict(conn.execute(totals_stmt).mappings().one())
            by_category = [dict(r) for r in conn.execute(by_category_stmt).mappings().all()]
            by_endpoint = [dict(r) for r in conn.execute(by_endpoint_stmt).mappings().all()]
            by_actor = [dict(r) for r in conn.execute(by_actor_stmt).mappings().all()]

        data = {k: (v or 0) for k, v in totals.items()}
        data["avg_ms"] = round(float(data.get("avg_ms") or 0), 2)
        data["max_ms"] = round(float(data.get("max_ms") or 0), 2)
        data["by_category"] = by_category
        data["by_endpoint"] = by_endpoint
        data["by_actor"] = by_actor
        return data

    def timeline(self, buckets: int = 60, window_seconds: int = 3600) -> List[Dict[str, Any]]:
        sa = self._sa
        now = time.time()
        start = now - window_seconds
        width = window_seconds / buckets
        stmt = sa.select(self.events.c.ts, self.events.c.status).where(
            self.events.c.ts >= start
        ).order_by(self.events.c.ts)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        series = [
            {"bucket": i, "start": start + i * width, "errors": 0, "slow": 0, "ok": 0}
            for i in range(buckets)
        ]
        for row in rows:
            index = min(int((row.ts - start) / width), buckets - 1)
            key = {"error": "errors", "slow": "slow"}.get(row.status, "ok")
            series[index][key] += 1
        return series


def _hydrate(payload: str, resolved: Any) -> EventRecord:
    event = EventRecord.from_dict(json.loads(payload))
    event.resolved = bool(resolved)
    return event

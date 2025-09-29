"""
PostgreSQL Database Manager for RedStorm using Neon
Handles all database operations including assessments, logs, and metrics
"""
import asyncio
import json
import asyncpg
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
import logging
from contextlib import asynccontextmanager
import os

logger = logging.getLogger("redstorm.database")

class DatabaseManager:
    """Async PostgreSQL database manager for RedStorm using Neon"""

    # ------------------------------------------------------------------
    # Life-cycle
    # ------------------------------------------------------------------
    def __init__(self, connection_string: str = None):
        if connection_string is None:
            connection_string = os.getenv(
                "DATABASE_URL",
                "postgresql://neondb_owner:npg_MmVRBU27isvj@ep-plain-frost-advtapzc-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require"
            )
        self.connection_string = connection_string
        self.pool: Optional[asyncpg.Pool] = None
        self._initialized = False

    async def connect(self):
        """Create connection pool and initialise schema."""
        try:
            self.pool = await asyncpg.create_pool(
                self.connection_string,
                min_size=5,
                max_size=20,
                command_timeout=60,
                server_settings={"application_name": "redstorm_app", "jit": "off"}
            )
            async with self.pool.acquire() as conn:
                await conn.execute("SELECT 1")
            await self._initialize_schema()
            self._initialized = True
            logger.info("Connected to Neon PostgreSQL database")
        except Exception as e:
            logger.error(f"Database connection error: {str(e)}")
            raise

    async def disconnect(self):
        """Close connection pool."""
        if self.pool:
            await self.pool.close()
            logger.info("Disconnected from PostgreSQL database")

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    async def _initialize_schema(self):
        """Idempotent schema creation."""
        try:
            async with self.pool.acquire() as conn:
                # Extensions
                await conn.execute("""
                    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
                    CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
                """)

                # assessments
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS assessments (
                        id SERIAL PRIMARY KEY,
                        assessment_id UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
                        client_id VARCHAR(255) NOT NULL,
                        target VARCHAR(255) NOT NULL,
                        status VARCHAR(50) NOT NULL,
                        current_phase VARCHAR(100),
                        start_time TIMESTAMP NOT NULL,
                        end_time TIMESTAMP,
                        results JSONB,
                        config JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_assessments_client_id ON assessments(client_id);
                    CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);
                    CREATE INDEX IF NOT EXISTS idx_assessments_target ON assessments(target);
                    CREATE INDEX IF NOT EXISTS idx_assessments_created_at ON assessments(created_at);
                """)

                # assessment_phases
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS assessment_phases (
                        id SERIAL PRIMARY KEY,
                        assessment_id UUID NOT NULL,
                        phase_name VARCHAR(100) NOT NULL,
                        status VARCHAR(50) NOT NULL,
                        start_time TIMESTAMP,
                        end_time TIMESTAMP,
                        results JSONB,
                        error_message TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_phases_assessment_id ON assessment_phases(assessment_id);
                    CREATE INDEX IF NOT EXISTS idx_phases_status ON assessment_phases(status);
                """)

                # scan_results
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id SERIAL PRIMARY KEY,
                        scan_id UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
                        scan_type VARCHAR(100) NOT NULL,
                        target VARCHAR(255) NOT NULL,
                        status VARCHAR(50) NOT NULL,
                        results JSONB,
                        start_time TIMESTAMP NOT NULL,
                        end_time TIMESTAMP,
                        error_message TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_scan_results_target ON scan_results(target);
                    CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status);
                    CREATE INDEX IF NOT EXISTS idx_scan_results_scan_type ON scan_results(scan_type);
                """)

                # vulnerability_findings  (reference_links instead of references)
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS vulnerability_findings (
                        id SERIAL PRIMARY KEY,
                        assessment_id UUID NOT NULL,
                        target VARCHAR(255) NOT NULL,
                        vulnerability_name VARCHAR(500) NOT NULL,
                        severity VARCHAR(50) NOT NULL,
                        cvss_score NUMERIC(3,1),
                        description TEXT,
                        remediation TEXT,
                        cve_ids JSONB,
                        reference_links JSONB,
                        false_positive BOOLEAN DEFAULT FALSE,
                        verified BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_vuln_findings_target ON vulnerability_findings(target);
                    CREATE INDEX IF NOT EXISTS idx_vuln_findings_severity ON vulnerability_findings(severity);
                    CREATE INDEX IF NOT EXISTS idx_vuln_findings_assessment ON vulnerability_findings(assessment_id);
                    CREATE INDEX IF NOT EXISTS idx_vuln_findings_false_positive ON vulnerability_findings(false_positive);
                """)

                # system_metrics
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS system_metrics (
                        id SERIAL PRIMARY KEY,
                        metric_name VARCHAR(200) NOT NULL,
                        metric_value NUMERIC NOT NULL,
                        metric_type VARCHAR(100) NOT NULL,
                        tags JSONB,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_metrics_name ON system_metrics(metric_name);
                    CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON system_metrics(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_metrics_type ON system_metrics(metric_type);
                """)

                # audit_logs
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id SERIAL PRIMARY KEY,
                        event_type VARCHAR(200) NOT NULL,
                        user_id VARCHAR(255),
                        target VARCHAR(255),
                        action VARCHAR(500) NOT NULL,
                        details JSONB,
                        ip_address INET,
                        user_agent TEXT,
                        success BOOLEAN,
                        error_message TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
                    CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
                """)

                # consent_validations
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS consent_validations (
                        id SERIAL PRIMARY KEY,
                        target VARCHAR(255) NOT NULL,
                        validation_result JSONB NOT NULL,
                        consent_details JSONB,
                        validated_by VARCHAR(255),
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_consent_target ON consent_validations(target);
                    CREATE INDEX IF NOT EXISTS idx_consent_timestamp ON consent_validations(timestamp);
                """)

                # Trigger function + trigger (idempotent)
                await conn.execute("""
                    CREATE OR REPLACE FUNCTION update_updated_at_column()
                    RETURNS TRIGGER AS $$
                    BEGIN
                        NEW.updated_at = CURRENT_TIMESTAMP;
                        RETURN NEW;
                    END;
                    $$ LANGUAGE plpgsql;

                    DROP TRIGGER IF EXISTS update_assessments_updated_at ON assessments;

                    CREATE TRIGGER update_assessments_updated_at
                        BEFORE UPDATE ON assessments
                        FOR EACH ROW
                        EXECUTE FUNCTION update_updated_at_column();
                """)
                logger.info("PostgreSQL schema initialized")
        except Exception as e:
            logger.error(f"Schema initialization error: {str(e)}")
            raise

    # ------------------------------------------------------------------
    # Connection helper
    # ------------------------------------------------------------------
    @asynccontextmanager
    async def get_connection(self):
        if not self.pool:
            raise RuntimeError("Database not connected")
        async with self.pool.acquire() as conn:
            yield conn

    # ------------------------------------------------------------------
    # Assessment CRUD
    # ------------------------------------------------------------------
    async def create_assessment(self, assessment_data: Dict[str, Any]) -> str:
        try:
            aid = assessment_data.get("assessment_id")
            cid = assessment_data.get("client_id")
            tgt = assessment_data.get("target")
            st  = assessment_data.get("status", "created")
            cfg = assessment_data.get("config", {})

            async with self.get_connection() as conn:
                row = await conn.fetchrow("""
                    INSERT INTO assessments (assessment_id, client_id, target, status, start_time, config)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    RETURNING assessment_id
                """, aid, cid, tgt, st, datetime.now(), json.dumps(cfg))
                logger.info(f"Created assessment: {row['assessment_id']}")
                return row["assessment_id"]
        except Exception as e:
            logger.error(f"Create assessment error: {str(e)}")
            raise

    async def update_assessment_status(
        self,
        assessment_id: str,
        status: str,
        current_phase: Optional[str] = None,
        results: Optional[Dict] = None
    ):
        try:
            parts = ["status = $2", "updated_at = $3"]
            params: List[Any] = [assessment_id, status, datetime.now()]

            if current_phase:
                parts.append(f"current_phase = ${len(parts)+2}")
                params.insert(-1, current_phase)
            if results:
                parts.append(f"results = ${len(parts)+2}")
                params.insert(-1, json.dumps(results))

            sql = f"UPDATE assessments SET {', '.join(parts)} WHERE assessment_id = $1"
            async with self.get_connection() as conn:
                await conn.execute(sql, *params)
                logger.debug(f"Updated assessment {assessment_id} status to {status}")
        except Exception as e:
            logger.error(f"Update assessment status error: {str(e)}")
            raise

    async def get_assessment(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        try:
            async with self.get_connection() as conn:
                row = await conn.fetchrow("SELECT * FROM assessments WHERE assessment_id = $1", assessment_id)
                if not row:
                    return None
                rec = dict(row)
                for col in ("results", "config"):
                    if rec.get(col):
                        rec[col] = json.loads(rec[col])
                return rec
        except Exception as e:
            logger.error(f"Get assessment error: {str(e)}")
            raise

    async def get_active_assessments(self, client_id: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            async with self.get_connection() as conn:
                if client_id:
                    rows = await conn.fetch(
                        "SELECT * FROM assessments WHERE status IN ('running','paused') AND client_id = $1",
                        client_id
                    )
                else:
                    rows = await conn.fetch("SELECT * FROM assessments WHERE status IN ('running','paused')")
                out = []
                for r in rows:
                    rec = dict(r)
                    for col in ("results", "config"):
                        if rec.get(col):
                            rec[col] = json.loads(rec[col])
                    out.append(rec)
                return out
        except Exception as e:
            logger.error(f"Get active assessments error: {str(e)}")
            raise

    # ------------------------------------------------------------------
    # Scan results
    # ------------------------------------------------------------------
    async def save_scan_results(self, scan_data: Dict[str, Any]) -> str:
        try:
            sid  = scan_data.get("scan_id")
            styp = scan_data.get("scan_type")
            tgt  = scan_data.get("target")
            st   = scan_data.get("status", "completed")
            res  = scan_data.get("results", {})
            err  = scan_data.get("error_message")

            async with self.get_connection() as conn:
                row = await conn.fetchrow("""
                    INSERT INTO scan_results (scan_id, scan_type, target, status, results, start_time, error_message)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    RETURNING scan_id
                """, sid, styp, tgt, st, json.dumps(res), datetime.now(), err)
                logger.info(f"Saved scan results: {row['scan_id']}")
                return row["scan_id"]
        except Exception as e:
            logger.error(f"Save scan results error: {str(e)}")
            raise

    async def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        try:
            async with self.get_connection() as conn:
                row = await conn.fetchrow("SELECT * FROM scan_results WHERE scan_id = $1", scan_id)
                if not row:
                    return None
                rec = dict(row)
                if rec.get("results"):
                    rec["results"] = json.loads(rec["results"])
                return rec
        except Exception as e:
            logger.error(f"Get scan results error: {str(e)}")
            raise

    # ------------------------------------------------------------------
    # Vulnerability findings
    # ------------------------------------------------------------------
    async def save_vulnerability_finding(self, finding_data: Dict[str, Any]) -> int:
        try:
            async with self.get_connection() as conn:
                row = await conn.fetchrow("""
                    INSERT INTO vulnerability_findings (
                        assessment_id, target, vulnerability_name, severity, cvss_score,
                        description, remediation, cve_ids, reference_links
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    RETURNING id
                """,
                    finding_data.get("assessment_id"),
                    finding_data.get("target"),
                    finding_data.get("vulnerability_name"),
                    finding_data.get("severity"),
                    finding_data.get("cvss_score"),
                    finding_data.get("description"),
                    finding_data.get("remediation"),
                    json.dumps(finding_data.get("cve_ids", [])),
                    json.dumps(finding_data.get("reference_links", []))
                )
                logger.info(f"Saved vulnerability finding: {row['id']}")
                return row["id"]
        except Exception as e:
            logger.error(f"Save vulnerability finding error: {str(e)}")
            raise

    async def get_vulnerability_findings(
        self,
        assessment_id: Optional[str] = None,
        target: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        try:
            async with self.get_connection() as conn:
                sql = "SELECT * FROM vulnerability_findings WHERE 1=1"
                params: List[Any] = []
                if assessment_id:
                    params.append(assessment_id)
                    sql += f" AND assessment_id = ${len(params)}"
                if target:
                    params.append(target)
                    sql += f" AND target = ${len(params)}"
                if severity:
                    params.append(severity)
                    sql += f" AND severity = ${len(params)}"
                sql += " ORDER BY created_at DESC"

                rows = await conn.fetch(sql, *params)
                out = []
                for r in rows:
                    rec = dict(r)
                    for col in ("cve_ids", "reference_links"):
                        if rec.get(col):
                            rec[col] = json.loads(rec[col])
                    out.append(rec)
                return out
        except Exception as e:
            logger.error(f"Get vulnerability findings error: {str(e)}")
            raise

    # ------------------------------------------------------------------
    # System metrics
    # ------------------------------------------------------------------
    async def save_metric(
        self,
        metric_name: str,
        metric_value: float,
        metric_type: str,
        tags: Optional[Dict[str, Any]] = None
    ):
        try:
            async with self.get_connection() as conn:
                await conn.execute("""
                    INSERT INTO system_metrics (metric_name, metric_value, metric_type, tags)
                    VALUES ($1, $2, $3, $4)
                """, metric_name, metric_value, metric_type, json.dumps(tags or {}))
        except Exception as e:
            logger.error(f"Save metric error: {str(e)}")
            raise

    async def get_system_metrics(
        self,
        metric_name: Optional[str] = None,
        time_range: str = "1h"
    ) -> List[Dict[str, Any]]:
        try:
            async with self.get_connection() as conn:
                sql = "SELECT * FROM system_metrics WHERE 1=1"
                params: List[Any] = []
                if metric_name:
                    params.append(metric_name)
                    sql += f" AND metric_name = ${len(params)}"

                if time_range.endswith("h"):
                    delta = timedelta(hours=int(time_range[:-1]))
                elif time_range.endswith("d"):
                    delta = timedelta(days=int(time_range[:-1]))
                else:
                    delta = timedelta(hours=1)
                cutoff = datetime.now() - delta
                params.append(cutoff)
                sql += f" AND timestamp >= ${len(params)}"
                sql += " ORDER BY timestamp DESC"

                rows = await conn.fetch(sql, *params)
                out = []
                for r in rows:
                    rec = dict(r)
                    if rec.get("tags"):
                        rec["tags"] = json.loads(rec["tags"])
                    out.append(rec)
                return out
        except Exception as e:
            logger.error(f"Get system metrics error: {str(e)}")
            raise

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------
    async def log_audit_event(self, event_data: Dict[str, Any]):
        try:
            async with self.get_connection() as conn:
                await conn.execute("""
                    INSERT INTO audit_logs (
                        event_type, user_id, target, action, details, ip_address,
                        user_agent, success, error_message
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """,
                    event_data.get("event_type"),
                    event_data.get("user_id"),
                    event_data.get("target"),
                    event_data.get("action"),
                    json.dumps(event_data.get("details", {})),
                    event_data.get("ip_address"),
                    event_data.get("user_agent"),
                    event_data.get("success", True),
                    event_data.get("error_message")
                )
        except Exception as e:
            logger.error(f"Log audit event error: {str(e)}")
            raise

    # ------------------------------------------------------------------
    # Consent validation
    # ------------------------------------------------------------------
    async def log_consent_validation(
        self,
        target: str,
        validation_result: Dict[str, Any]
    ):
        try:
            async with self.get_connection() as conn:
                await conn.execute("""
                    INSERT INTO consent_validations (target, validation_result, consent_details)
                    VALUES ($1, $2, $3)
                """,
                    target,
                    json.dumps(validation_result),
                    json.dumps(validation_result.get("details", {}))
                )
        except Exception as e:
            logger.error(f"Log consent validation error: {str(e)}")
            raise

    # ------------------------------------------------------------------
    # Health & statistics
    # ------------------------------------------------------------------
    async def health_check(self) -> Dict[str, Any]:
        try:
            async with self.get_connection() as conn:
                row = await conn.fetchrow("SELECT COUNT(*) AS count FROM assessments")
                return {
                    "status": "healthy",
                    "connection": "active",
                    "assessments_count": row["count"],
                    "database_type": "postgresql",
                    "pool_size": self.pool.get_size() if self.pool else 0
                }
        except Exception as e:
            logger.error(f"Database health check error: {str(e)}")
            return {"status": "unhealthy", "error": str(e), "connection": "failed"}

    async def get_system_statistics(self) -> Dict[str, Any]:
        try:
            async with self.get_connection() as conn:
                astats = await conn.fetchrow("""
                    SELECT
                        COUNT(*) AS total,
                        COUNT(CASE WHEN status='completed' THEN 1 END) AS completed,
                        COUNT(CASE WHEN status='running'   THEN 1 END) AS running,
                        COUNT(CASE WHEN status='error'     THEN 1 END) AS failed,
                        AVG(EXTRACT(EPOCH FROM (end_time - start_time))) AS avg_duration
                    FROM assessments
                """)
                vstats = await conn.fetchrow("""
                    SELECT
                        COUNT(*) AS total,
                        COUNT(CASE WHEN severity='critical' THEN 1 END) AS critical,
                        COUNT(CASE WHEN severity='high'     THEN 1 END) AS high,
                        COUNT(CASE WHEN severity='medium'   THEN 1 END) AS medium,
                        COUNT(CASE WHEN severity='low'      THEN 1 END) AS low
                    FROM vulnerability_findings
                    WHERE false_positive = FALSE
                """)
                recent = await conn.fetchrow("""
                    SELECT
                        COUNT(*) AS assessments_24h,
                        COUNT(DISTINCT target) AS unique_targets_24h
                    FROM assessments
                    WHERE created_at >= NOW() - INTERVAL '24 hours'
                """)
                return {"assessments": dict(astats),
                        "vulnerabilities": dict(vstats),
                        "recent_activity": dict(recent)}
        except Exception as e:
            logger.error(f"Get system statistics error: {str(e)}")
            return {}

# Global singleton
database_manager = DatabaseManager()
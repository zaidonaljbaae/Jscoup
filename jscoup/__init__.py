# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""JSCoup — API bug capture, database-aware analysis and a live tester UI.

Quick start::

    from jscoup import JSCoup

    bl = JSCoup(service_name="my-api", db_path=".jscoup/my-api.db")
    bl.watch_sqlite()          # trace every sqlite3 statement
    bl.install(app)            # Flask, FastAPI or Django

    # open http://localhost:8000/__jscoup

Everything is replaceable: ``storage=``, ``analyzers=``, ``config=`` and the
identity resolver all accept custom objects, and class/function names can be
aliased freely because the public surface is this module.
"""

from .analyzers import (
    AccessAnalyzer,
    AnalysisInput,
    AnalyzerEngine,
    AuthAnalyzer,
    BaseAnalyzer,
    CATEGORY_ACCESS,
    ConfigAnalyzer,
    DatabaseAnalyzer,
    DataShapeAnalyzer,
    GenericAnalyzer,
    HttpAnalyzer,
    NetworkAnalyzer,
    PerformanceAnalyzer,
    ValidationAnalyzer,
)
from .audit import AuditFinding, audit_code
from .config import JSCoupConfig
from .context import add_breadcrumb, all_contexts, current_context
from .core import JSCoup, LambdaContext
from .crypto import EncryptingStorage, generate_key as generate_encryption_key
from .dashboard.auth import hash_password
from .dbwatch import (
    connect,
    emit_query,
    instrument_django,
    instrument_sqlalchemy,
    instrument_sqlite3,
    uninstrument_sqlalchemy,
    uninstrument_sqlite3,
)
from .gateway import ALL_TARGETS, GatewayStore, GatewayUser
from .healthcheck import ApiCheckResult, check_apis
from .identity import IdentityResolver, decode_jwt_payload, fingerprint_token
from .loadtest import format_report as format_loadtest_report, run_load_test
from .models import (
    Actor,
    Breadcrumb,
    Diagnosis,
    EventRecord,
    QueryRecord,
    build_fingerprint,
)
from .redaction import Redactor
from .registry import ParamSpec, Registry, Target
from .simulator import Simulator
from .storage import BaseStorage, MemoryStorage, SQLiteStorage

__version__ = "1.0.0"
__author__ = "Zaidon Aljbaae"
__copyright__ = "Copyright (c) 2026 Zaidon Aljbaae"
__license__ = "MIT"
__author__ = "Zaidon Aljbaae"

__all__ = [
    "JSCoup",
    "JSCoupConfig",
    "LambdaContext",
    # models
    "EventRecord",
    "QueryRecord",
    "Breadcrumb",
    "Diagnosis",
    "Actor",
    "build_fingerprint",
    # storage
    "BaseStorage",
    "SQLiteStorage",
    "MemoryStorage",
    # analysis
    "AnalyzerEngine",
    "BaseAnalyzer",
    "AnalysisInput",
    "DatabaseAnalyzer",
    "DataShapeAnalyzer",
    "ValidationAnalyzer",
    "AuthAnalyzer",
    "AccessAnalyzer",
    "CATEGORY_ACCESS",
    "NetworkAnalyzer",
    "ConfigAnalyzer",
    "HttpAnalyzer",
    "PerformanceAnalyzer",
    "GenericAnalyzer",
    # instrumentation
    "connect",
    "emit_query",
    "instrument_sqlite3",
    "uninstrument_sqlite3",
    "instrument_sqlalchemy",
    "uninstrument_sqlalchemy",
    "instrument_django",
    # identity & privacy
    "IdentityResolver",
    "fingerprint_token",
    "decode_jwt_payload",
    "Redactor",
    "hash_password",
    # registry & simulation
    "Registry",
    "Target",
    "ParamSpec",
    "Simulator",
    # static audit
    "AuditFinding",
    "audit_code",
    "ApiCheckResult",
    "check_apis",
    # API Gateway
    "GatewayStore",
    "GatewayUser",
    "ALL_TARGETS",
    # encryption at rest (optional — pip install jscoup[crypto])
    "EncryptingStorage",
    "generate_encryption_key",
    # multi-service traffic testing
    "run_load_test",
    "format_loadtest_report",
    # context helpers
    "current_context",
    "all_contexts",
    "add_breadcrumb",
    "__version__",
    "__author__",
]

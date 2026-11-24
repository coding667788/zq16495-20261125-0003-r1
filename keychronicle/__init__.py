"""keychronicle: offline temporal trust audit for archived approvals."""

from .engine import AuditEngine, audit_bundle
from .loader import load_bundle
from .diff import diff_bundle_snapshots, diff_knowledge_cuts

__all__ = [
    "AuditEngine",
    "audit_bundle",
    "audit",
    "load_bundle",
    "diff_knowledge_cuts",
    "diff_bundle_snapshots",
]

audit = audit_bundle

__version__ = "1.0.0"

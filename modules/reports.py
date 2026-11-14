"""Compatibility facade exposing AdvancedReportEngine as ReportManager."""

from __future__ import annotations

from reports.engine import AdvancedReportEngine


class ReportManager(AdvancedReportEngine):
    """Preserves backward compatibility for all existing BLACKVEIL modules."""

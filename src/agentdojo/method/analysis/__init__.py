"""
Auditing Layer pipeline.
Implements the 4-Ring defense mechanism.
"""
from .pipeline import process_before_execution, process_after_execution

__all__ = ["process_before_execution", "process_after_execution"]

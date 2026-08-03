"""
Capture Layer module for AgentDojo Data Flow Tracking.
Provides AOP interceptors to capture reasoning contexts, inputs, and outputs.
"""
from .interceptor import enable_tracking

__all__ = ["enable_tracking"]

"""
Agentic Data Flow Tracking and Visualization Platform
Implements Capture (AOP), Modeling (FSM+PROV), lightweight policy analysis,
and Visualization layers.
"""

from .capture.interceptor import enable_tracking
from .visualization.dashboard import print_risk_card, start_dashboard


def activate_platform():
    """
    Activates the defensive monitoring.
    Can be called dynamically during startup.
    """
    enable_tracking()
    print("Agentic Data Flow Tracking Platform successfully hooked into AgentDojo.")


__all__ = ["activate_platform", "print_risk_card", "start_dashboard"]

"""
Agentic Data Flow Tracking and Visualization Platform
Implements Capture (AOP), Modeling (FSM+PROV), Analysis (4-Ring Auditing), and Visualization layers.
"""
from .capture.interceptor import enable_tracking
from .visualization.dashboard import start_dashboard, print_risk_card

import networkx as nx

def activate_platform():
    """
    Activates the defensive monitoring. 
    Can be called dynamically during startup.
    """
    enable_tracking()
    print("Agentic Data Flow Tracking Platform successfully hooked into AgentDojo.")

__all__ = ["activate_platform", "start_dashboard", "print_risk_card"]

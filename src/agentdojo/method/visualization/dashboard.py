"""
Provides simple Dashboard output, representing InconPreter and DataShield visualization.
In a real environment, this connects to a D3 frontend or Gradio/Streamlit UI.
"""
import json

def print_risk_card(event_details: dict):
    """
    InconPreter: Generates Natural Language Risk Card from Pipeline metrics.
    """
    print("\n" + "="*50)
    print("🚨 [InconPreter] SECURITY RISK CARD 🚨")
    print(f"Agent ID: {event_details.get('agent_id', 'Unknown')}")
    print(f"Target APP: {event_details.get('target_app', 'Unknown')}")
    print(f"Attempted Action: {event_details.get('tool_intent', 'Unknown')}")
    print(f"\nReason for Flagging:\n > {event_details.get('block_reason', 'Data Over-exposure Detected')}")
    print("\nRecommended Action: [BLOCK] | [WHITELIST]")
    print("="*50 + "\n")

def start_dashboard():
    """
    Dumps current Graph DB Provenance metrics for UI rendering.
    """
    from ..modeling.graph_db import get_graph_data
    data = get_graph_data()
    print("🌐 [Visualization Layer] Exporting Flowcept ProvenanceLens Graph:")
    print(json.dumps(data, indent=2))


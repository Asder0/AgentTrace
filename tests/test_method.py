import time
from agentdojo.method import activate_platform, start_dashboard, print_risk_card
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.method.modeling.graph_db import get_graph_data

def dummy_tool(text: str) -> str:
    """
    A simple dummy tool for testing.

    :param text: Some input text string.
    """
    return f"Processed: {text}"

def test_integration():
    """
    Tests if the interceptors successfully track function calls.
    """
    activate_platform()
    
    runtime = FunctionsRuntime()
    runtime.register_function(dummy_tool)
    
    kwargs = {"text": "password123 and test"}
    # Call the mocked pipeline (it will pass through capture -> analysis -> graph -> execution)
    result, error = runtime.run_function(None, "dummy_tool", kwargs)
    print("Function Result:", result)
    # Ring 1 detects injection in output "Processed: password123 and test" and blocks it
    # Ring 3 DOE still runs before Ring 1, so the output is redacted
    assert "[REDACTED]" in result or "BLOCKED" in result, "Data Over-exposure mitigation or injection detection failed"

    
    # Verify graph data
    graph_data = get_graph_data()
    # At least the default agent node and the newly generated activity/entity
    assert len(graph_data['nodes']) > 1, "Graph nodes were not populated"
    
    print_risk_card({
        "agent_id": "test",
        "target_app": "dummy",
        "tool_intent": "dummy_tool",
        "block_reason": "Testing the risk card generation"
    })
    start_dashboard()

if __name__ == "__main__":
    test_integration()

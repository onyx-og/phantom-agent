import pytest
import threading
from src.phantom_agent import PhantomAgent

@pytest.fixture
def agent(tmp_path):
    """Fixture that returns a running PhantomAgent instance with a test socket."""
    cfg = {
        "tokens": ["devtoken123"],
        "log_file": str(tmp_path / "agent.log"),
        "audit_log": str(tmp_path / "audit.jsonl"),
        "environment": {
            "linux": {"commands": {"echo": ["echo", "{0}"]}}
        },
    }
    agent = PhantomAgent(cfg)
    agent.sock_name = str(tmp_path / "test.sock")

    # Start the socket server in a background thread
    t = threading.Thread(target=agent.run_uds_server, args=(agent.sock_name,), daemon=True)
    t.start()

    return agent
import json
import socket
import pytest
import platform

def test_agent_initialization(agent):
    assert agent.config["tokens"] == ["devtoken123"]

@pytest.mark.skipif(platform.system() != "Linux", reason="Linux-only test")
def test_basic_command(agent):
    # Connect and send a request
    req = {
        "token": "devtoken123",
        "command": "echo",
        "args": ["hello"],
        "request_id": "1"
    }
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(agent.sock_name)
    body = json.dumps(req).encode()
    s.send(len(body).to_bytes(4, "big") + body)

    # Read reply
    hdr = s.recv(4)
    resp_len = int.from_bytes(hdr, "big")
    resp = json.loads(s.recv(resp_len).decode())

    assert resp["returncode"] == 0
    assert "hello" in resp["stdout"]

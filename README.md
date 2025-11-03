
# Phantom Agent

Phantom Agent is a local privileged task runner designed for Linux and Windows.

## Features
- Listens on a Unix Domain Socket (Linux) or Named Pipe (Windows).
- Executes whitelisted commands defined in `config.json`.
- Logs all executions in JSON format.
- Requires token authentication.

## Config
Commands are grouped by environment (Linux/Windows) and stored as arrays. Example:

```json
"commands": {
  "restart_nginx": ["systemctl", "restart", "nginx"]
}
```

## Linux Setup
1. Copy source files to `/opt/phantom-agent`
2. Install systemd unit:
   ```bash
   sudo cp phantom-agent.service /etc/systemd/system/
   sudo systemctl enable phantom-agent
   sudo systemctl start phantom-agent
   ```

## Windows Setup
- Register as a Windows service using `nssm` or `sc create`.
- Ensure Python and dependencies are installed.

## Invocation
Send JSON requests through the socket/pipe:
```json
{
  "token": "your-secure-token-here",
  "command": "restart_nginx",
  "args": []
}
```

## Security Notes
- Always restrict commands to safe whitelisted entries in `config.json`.
- Protect the socket/pipe permissions.
- Rotate tokens periodically.

## Development Setup for `phantom-agent`

### Clone the repository

```bash
git clone https://github.com/onyx-og/phantom-agent.git
cd phantom-agent
```

### Create and activate a virtual environment

#### Linux / macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Windows (PowerShell):

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

### Install dependencies

The script uses only the standard library *except* for Windows named pipe support, which requires `pywin32`.

```bash
pip install -r requirements-dev.txt
```


### (Optional) Create or edit a simple `config.json`

Example `config.json` for testing:

```json
{
  "tokens": ["devtoken123"],
  "log_file": "phantom-agent.log",
  "commands": {
    "echo": ["echo", "{0}"],
    "ls": ["ls", "-l", "{0}"]
  },
  "environment": {
    "windows": {
      "commands": {
        "list": ["cmd.exe", "/c", "dir", "{0}"]
      }
    },
    "linux": {
      "commands": {
        "list": ["ls", "-l", "{0}"]
      }
    }
  }
}
```

Keep it in the same directory as `phantom_agent.py`.

### Run the agent in development mode

#### Linux/macOS:

```bash
python phantom_agent.py
```

You should see logs like:

```
INFO phantom-agent: phantom-agent starting (uid=1000 user=myuser platform=linux)
INFO phantom-agent: Starting UDS server at /tmp/phantom_agent.sock
```

#### Windows:

Run PowerShell as administrator:

```powershell
python .\phantom_agent.py
```

Logs should show:

```
INFO phantom-agent: phantom-agent starting (uid=N/A user=YourName platform=windows)
INFO phantom-agent: Starting Named Pipe server at \\.\pipe\phantom_agent
```

### Test the agent

You can connect manually using `socat` (on Linux/macOS) or a small Python client.

Example client (Unix):

```bash
python - <<'EOF'
import socket, json, struct
req = json.dumps({"token":"devtoken123", "command":"echo", "args":["Hello World"], "request_id":"1"}).encode()
hdr = struct.pack(">I", len(req))
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.connect("/tmp/phantom_agent.sock")
    s.sendall(hdr + req)
    resp_len = struct.unpack(">I", s.recv(4))[0]
    resp = json.loads(s.recv(resp_len).decode())
    print(resp)
EOF
```

You should see:

```json
{"returncode":0,"stdout":"Hello World\n","stderr":""}
```

### Check logs

Log file (`phantom-agent.log` or `/var/log/phantom-agent.jsonl`) will contain audit entries like:

```
2025-11-03 19:10:22 INFO: Running command echo (request_id=1)
```

### Stop the agent

Press `Ctrl+C` in the terminal running `phantom-agent.py`.


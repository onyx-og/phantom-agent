
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

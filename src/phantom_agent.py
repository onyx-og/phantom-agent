
import os
import json
import socket
import time
import struct
import shlex
import getpass
import subprocess
import platform
import logging
from typing import List
import threading
from pathlib import Path
from logging.handlers import RotatingFileHandler

# [TODO] Integrate into config.json?
# CONFIG_PATH = os.environ.get("PHANTOM_AGENT_CONFIG", "/etc/phantom-agent/config.json")
# UNIX_SOCKET = os.environ.get("PHANTOM_AGENT_SOCKET", "/run/phantom-agent/phantom-agent.sock")

# Named Pipe support via pywin32 on Windows
try:
    if platform.system() == "Windows":
        import win32pipe, win32file, pywintypes  # type: ignore
        HAVE_PIPES = True
    else:
        HAVE_PIPES = False
except Exception:
    HAVE_PIPES = False

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

def load_config():
    env_path = os.environ.get("PHANTOM_AGENT_CONFIG")
    if env_path and Path(env_path).exists():
        with open(env_path, "r", encoding="utf-8") as f:
            return json.load(f)
        
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def setup_logger(log_file):
    logger = logging.getLogger("phantom-agent")
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=2)
    formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def safe_quote_windows(arg):
    if not arg:
        return '""'
    if any(c in arg for c in ' 	"'):
        arg = '"' + arg.replace('"', '\"') + '"'
    return arg

def build_command(cmd_spec, args: List[str]):
    """
    cmd_spec: must be a list of tokens, possibly with placeholders {0}, {1}, ...
    args: list of args strings provided by caller
    returns: list of tokens ready for subprocess.run
    """
    if not isinstance(cmd_spec, list):
        raise ValueError("command spec must be a list of tokens")
    # Platform-specific quoting
    tokens = []
    if platform.system() == "Windows":
        for tok in cmd_spec:
            try:
                tokf = tok.format(*[safe_quote_windows(a) for a in args])
            except Exception:
                tokf = tok
            tokens.append(tokf)
    else:
        for tok in cmd_spec:
            try:
                tokf = tok.format(*[shlex.quote(a) for a in args])
            except Exception:
                tokf = tok
            tokens.append(tokf)
    return tokens

# JSON length-prefixed framing helpers
def recv_msg(conn):
    # read 4 bytes length, then read that many bytes
    hdr = recvall(conn, 4)
    if not hdr:
        return None
    (n,) = struct.unpack(">I", hdr)
    body = recvall(conn, n)
    return body

def send_msg(conn, data_bytes: bytes):
    n = len(data_bytes)
    conn.sendall(struct.pack(">I", n) + data_bytes)

def recvall(conn, n):
    # receive exactly n bytes or None on EOF
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


class PhantomAgent:
    def __init__(self, config):
        
        self.config = config
        self.logger = setup_logger(config.get("log_file", "phantom-agent.log"))
        audit_path = config.get("audit_log", "phantom-agent.jsonl")
        self.audit_file = open(audit_path, "a", encoding="utf-8", buffering=1)
        self.os_name = platform.system().lower()
        env = self.config.get("environment", {}).get(self.os_name, {})
        self.commands = env.get("commands", {})

        try:
            uid = os.geteuid()
        except Exception:
            uid = "N/A"
        self.logger.info(
            "phantom-agent starting (uid=%s user=%s platform=%s)", 
            uid, getpass.getuser(), self.os_name
        )

        self.commands = config.get("environment", {}).get(self.os_name, {}).get("commands", {})
        if not self.commands:
            self.logger.error(f"No commands defined for environment {self.os_name}")
        # socket/pipe name
        if self.os_name == "windows":
            self.sock_name = r"\\.\pipe\phantom_agent"
        else:
            self.sock_name = "/tmp/phantom_agent.sock"
            if os.path.exists(self.sock_name):
                os.remove(self.sock_name)
        self.tokens = set(config.get("tokens", []))

    def audit(self, obj: dict):
        """Write a single JSON object line to audit file and flush."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        obj_out = {"ts": ts, **obj}
        try:
            self.audit_file.write(json.dumps(obj_out, ensure_ascii=False) + "\n")
        except Exception:
            # fallback to internal log
            self.logger.exception("Failed to write audit log")

    def run(self):
        if self.os_name == "windows":
            self.run_named_pipe_server(self.sock_name)
        else:
            self.run_uds_server(self.sock_name)

    # ---- Linux/Unix UDS ----
    def run_uds_server(self, sock_path):
        self.logger.info(f"Starting UDS server at {sock_path}")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(sock_path)
            server.listen(5)
            while True:
                conn, _ = server.accept()
                t = threading.Thread(target=self.uds_client_thread, args=(conn,))
                t.daemon = True
                t.start()

    def uds_client_thread(self, conn):
        with conn:
            try:
                body = recv_msg(conn)
                if body is None:
                    return
                req = json.loads(body.decode("utf-8"))
                # remote_identity could be the uid of the peer
                #  if desired (requires getsockopt SO_PEERCRED)
                remote = "local"
                resp_obj, status = self.handle_request(req, remote)
                send_msg(conn, json.dumps(resp_obj).encode("utf-8"))
            except Exception as e:
                self.logger.exception("UDS client handler error")
                try:
                    send_msg(conn, json.dumps({"error": "internal"}).encode("utf-8"))
                except Exception:
                    pass


    # ---- Windows Named Pipe ----
    def run_named_pipe_server(self, pipe_name: str):
        self.logger.info(f"Starting Named Pipe server at {pipe_name}")
        while True:
            try:
                pipe = win32pipe.CreateNamedPipe(
                    pipe_name,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    1, 65536, 65536,
                    0, None
                )
                win32pipe.ConnectNamedPipe(pipe, None)
                t = threading.Thread(target=self.handle_windows_pipe_client, args=(pipe,))
                t.daemon = True
                t.start()
            except Exception as e:
                self.logger.error(f"Named pipe server error: {e}")

    def handle_windows_pipe_client(self, pipe):
        try:
            hr, data = win32file.ReadFile(pipe, 65536)
            if hr == 0:
                # request = data.decode("utf-8")
                request = json.loads(data.decode("utf-8"))
                response = self.handle_request(request, "namedpipe")
                win32file.WriteFile(pipe, response.encode("utf-8"))
        except Exception as e:
            self.logger.error(f"Pipe client error: {e}")
        finally:
            try:
                win32file.CloseHandle(pipe)
            except Exception:
                pass

    # ---- Request Handler ----
    def handle_request(self, req, remote_identity: str = None):
         # expected fields: { "token": "xxx", "command": "name", "args": [...], "request_id": "..." }
        token = req.get("token")
        command = req.get("command")
        args = req.get("args", [])
        request_id = req.get("request_id")

        self.audit({
            "event": "execute.request", "request_id": request_id, 
            "caller": remote_identity, "command": command, "args": args
        })

        # auth
        if token not in self.config["tokens"]:
            self.audit({
                "event": "execute.auth_failed", "request_id": request_id, 
                "caller": remote_identity, "reason": "bad_token"
            })
            return {"error": "unauthorized"}, 403

        # whitelist
        if command not in self.commands:
            self.audit({
                "event": "execute.reject",
                "request_id": request_id,
                "caller": remote_identity,
                "command": command,
                "reason": f"unknown_command (env={self.os_name})"
            })
            return {"error": "unknown_command"}, 400

        cmd_spec = self.commands[command]

        try:
            cmd_list = build_command(cmd_spec, args)
        except Exception as e:
            self.audit({
                "event": "execute.bad_spec", "request_id": request_id, 
                "caller": remote_identity, "command": command, "error": str(e)
            })
            return {"error": "bad_command_spec", "why": str(e)}, 500

        # Execute safely (no shell=True)
        try:
            self.logger.info("Running command %s (request_id=%s)", command, request_id)
            proc = subprocess.run(
                cmd_list, capture_output=True, text=True,
                timeout=self.config.get("timeout_secs", 120
            ))
            resp = {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
            self.audit({
                "event": "execute.result", "request_id": request_id, 
                "caller": remote_identity,"command": command, "returncode": proc.returncode,
                "stdout_len": len(proc.stdout), "stderr_len": len(proc.stderr)
            })
            return resp, (200 if proc.returncode == 0 else 500)
        except subprocess.TimeoutExpired as te:
            self.audit({
                "event": "execute.timeout", "request_id": request_id,
                "caller": remote_identity, "command": command
            })
            return {"error": "timeout"}, 504
        except Exception as e:
            self.audit({
                "event": "execute.error", "request_id": request_id, 
                "caller": remote_identity, "command": command, "error": str(e)
            })
            return {"error": "exec_failed", "why": str(e)}, 500

if __name__ == "__main__":
    config = load_config()
    agent = PhantomAgent(config)
    agent.run()

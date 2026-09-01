"""Dev-server discovery, lifecycle, and injection-proxy primitives.

``server`` is the Design Tweak composition root and security-policy owner.
Every mutable collaborator is resolved through ``runtime`` at call time.  This
module never spawns a process or invokes ``lsof`` itself: those audited process
sinks remain in ``server._start_dev_proc`` and ``server._lsof_fields``.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler
from typing import Any, ClassVar, cast

NODE_BIN_DIRS = (
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/opt/local/bin",
    "/usr/bin",
    "~/.volta/bin",
    "~/.bun/bin",
    "~/.asdf/shims",
    "~/.local/share/fnm/aliases/default/bin",
    "~/Library/pnpm",
)
NVM_GLOB = "~/.nvm/versions/node/*/bin"

CHILD_ENV_STRIP = (
    "KIROCREW_PROXY_SECRET",
    "PORT",
    "NODE_OPTIONS",
    "SSH_AUTH_SOCK",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
)
CHILD_ENV_STRIP_PREFIXES = ("KIROCREW_", "KIRO_CREW_")

LOCKFILES = (
    ("pnpm-lock.yaml", "pnpm"),
    ("bun.lockb", "bun"),
    ("yarn.lock", "yarn"),
    ("package-lock.json", "npm"),
)
DEV_SCRIPTS = ("dev", "start:dev", "dev:web", "serve", "start")
PROC_TREE_MAX_DEPTH = 16


def node_bin_dirs(runtime: Any) -> list[Any]:
    """Return existing Node toolchain directories in lookup order."""

    dirs = [runtime.Path(directory).expanduser() for directory in runtime._NODE_BIN_DIRS]
    try:
        nvm = sorted(
            runtime.glob.glob(runtime.os.path.expanduser(runtime._NVM_GLOB)),
            reverse=True,
        )
        dirs = [runtime.Path(path) for path in nvm] + dirs
    except OSError:
        pass
    return [directory for directory in dirs if directory.is_dir()]


def resolve_bin(runtime: Any, name: str) -> Any | None:
    """Return the absolute package-manager path, if one can be resolved."""

    found = runtime.shutil.which(name)
    if found:
        return runtime.Path(found)
    for directory in runtime._node_bin_dirs():
        candidate = directory / name
        if candidate.is_file() and runtime.os.access(candidate, runtime.os.X_OK):
            return candidate
    return None


def child_env(runtime: Any, bin_dir: Any) -> dict[str, str]:
    """Build the untrusted dev child's credential-stripped environment."""

    env = {
        key: value
        for key, value in runtime.os.environ.items()
        if key not in runtime._CHILD_ENV_STRIP
        and not key.startswith(runtime._CHILD_ENV_STRIP_PREFIXES)
    }
    extra = [str(bin_dir)] + [str(directory) for directory in runtime._node_bin_dirs()]
    seen: set[str] = set()
    parts: list[str] = []
    for path in extra + runtime.os.environ.get("PATH", "").split(runtime.os.pathsep):
        if path and path not in seen:
            seen.add(path)
            parts.append(path)
    env["PATH"] = runtime.os.pathsep.join(parts)
    return env


def pkg_scripts(runtime: Any, root: Any) -> dict[str, Any]:
    """Load a project's package scripts without letting bad JSON escape."""

    try:
        raw = runtime.safe_read_file_bytes_nolink(
            str(root / "package.json"),
            within_root=str(root),
            max_bytes=runtime.MAX_BODY_BYTES,
        )
        if raw is None:
            return {}
        data = runtime.json.loads(raw.decode("utf-8"))
        scripts = data.get("scripts")
        return scripts if isinstance(scripts, dict) else {}
    except (OSError, ValueError, runtime.FileTooLargeError):
        return {}


def dev_command(runtime: Any, root: Any) -> list[str]:
    """Return the project's preferred package-manager dev command."""

    scripts = runtime._pkg_scripts(root)
    script = next((name for name in runtime._DEV_SCRIPTS if name in scripts), "")
    if not script:
        return []
    manager = next(
        (manager for lockfile, manager in runtime._LOCKFILES if (root / lockfile).is_file()),
        "npm",
    )
    return [manager, "run", script]


def classify_project(runtime: Any, root: Any) -> dict[str, Any]:
    """Classify a project as static-previewable or dev-server-backed."""

    entry = runtime._find_entry(root)
    unbundled = ""
    if entry is not None:
        try:
            raw = runtime.safe_read_file_bytes_nolink(
                str(entry),
                within_root=str(root),
                max_bytes=runtime.MAX_STATIC_BYTES,
            )
            if raw is not None:
                unbundled = runtime._unbundled_entry(raw)
        except (OSError, ValueError, runtime.FileTooLargeError):
            unbundled = ""
    command = runtime._dev_command(root)
    needs_dev_server = bool(unbundled) or (entry is None and bool(command))
    return {
        "needsDevServer": needs_dev_server,
        "devCommand": " ".join(command),
        "unbundledEntry": unbundled,
        "hasEntry": entry is not None,
    }


def loopback_listeners(runtime: Any) -> dict[int, int]:
    """Return ``{port: pid}`` for listeners reachable from loopback."""

    found: dict[int, int] = {}
    for record in runtime._lsof_fields(["-nP", "-iTCP", "-sTCP:LISTEN", "-Fpn"]):
        name = record["name"]
        if ":" not in name:
            continue
        host, _, port_text = name.rpartition(":")
        host = host.strip("[]")
        if host not in ("127.0.0.1", "localhost", "::1", "*", ""):
            continue
        try:
            found[int(port_text)] = int(record["pid"])
        except ValueError:
            continue
    return found


def cwd_for_pids(runtime: Any, pids: list[int]) -> dict[int, str]:
    """Resolve process working directories with one late-bound ``lsof`` call."""

    if not pids:
        return {}
    joined = ",".join(str(pid) for pid in dict.fromkeys(pids))
    out: dict[int, str] = {}
    for record in runtime._lsof_fields(["-a", "-p", joined, "-d", "cwd", "-Fn"]):
        try:
            out[int(record["pid"])] = record["name"]
        except ValueError:
            continue
    return out


def serves_html(runtime: Any, port: int) -> bool:
    """Return whether a loopback port answers with an HTML content type."""

    url = f"http://127.0.0.1:{port}/"
    try:
        request = runtime.urllib.request.Request(
            url,
            headers={"User-Agent": "DesignTweak-Detect"},
        )
        # The URL has a literal scheme and host, and ``port`` was parsed as an int.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with runtime.urllib.request.urlopen(  # noqa: S310
            request,
            timeout=runtime._PROBE_TIMEOUT,
        ) as response:
            return "text/html" in (response.headers.get("Content-Type") or "").lower()
    except runtime.urllib.error.HTTPError as exc:
        return "text/html" in (exc.headers.get("Content-Type") or "").lower()
    except (runtime.urllib.error.URLError, OSError, ValueError):
        return False


def detect_dev_servers(runtime: Any, root: Any, probe: bool = True) -> list[dict[str, Any]]:
    """Return dev servers plausibly serving ``root``, best match first."""

    listeners = runtime._loopback_listeners()
    working_dirs = runtime._cwd_for_pids(list(listeners.values()))

    out: list[dict[str, Any]] = []
    for port, pid in listeners.items():
        cwd = working_dirs.get(pid, "")
        if not cwd:
            continue
        try:
            depth = len(runtime.Path(cwd).resolve().relative_to(root).parts)
        except ValueError:
            continue
        out.append(
            {
                "port": port,
                "pid": pid,
                "cwd": cwd,
                "depth": depth,
                "url": f"http://localhost:{port}",
                "servesHtml": runtime._serves_html(port) if probe else None,
            }
        )
    out.sort(
        key=lambda candidate: (
            candidate["servesHtml"] is False,
            candidate["depth"],
            candidate["port"],
        )
    )
    return out


def auto_dev_server(runtime: Any, root: Any) -> str:
    """Return the only unambiguous HTML-serving dev URL, or an empty string."""

    html = [candidate for candidate in runtime._detect_dev_servers(root) if candidate["servesHtml"]]
    return html[0]["url"] if len(html) == 1 else ""


def stop_dev_proc(runtime: Any, project_id: str) -> bool:
    """Stop an owned process tree, or only the proxy for an adopted server."""

    record = runtime._DEV_PROCS.pop(project_id, None)
    if not record:
        return False
    runtime._stop_inject_proxy(record)
    process = record.get("proc")
    if process is None:
        return True
    try:
        runtime.kill_process_tree(process.pid, runtime.SIGTERM)
        try:
            process.wait(timeout=runtime._STOP_GRACE)
        except Exception:  # noqa: BLE001
            runtime.kill_process_tree(process.pid, runtime.SIGKILL)
    except (ProcessLookupError, PermissionError, ValueError, OSError):
        pass
    return True


def stop_all_dev_procs(runtime: Any) -> None:
    """Stop every tracked owned process and adopted proxy."""

    for project_id in list(runtime._DEV_PROCS):
        runtime._stop_dev_proc(project_id)


def dev_proc_alive(runtime: Any, project_id: str) -> bool:
    """Return whether an owned process or adopted proxy remains live."""

    record = runtime._DEV_PROCS.get(project_id)
    if not record:
        return False
    process = record.get("proc")
    if process is None:
        return bool(record.get("proxy"))
    return process.poll() is None


def in_proc_tree(runtime: Any, pid: int, root_pid: int, pgid: int | None) -> bool:
    """Return whether a listener belongs to the process tree ``server`` spawned."""

    if pgid is not None:
        try:
            return runtime.os.getpgid(pid) == pgid
        except OSError:
            return False
    seen: set[int] = set()
    current = pid
    for _ in range(runtime._PROC_TREE_MAX_DEPTH):
        if current == root_pid:
            return True
        if current <= 0 or current in seen:
            return False
        seen.add(current)
        current = runtime.get_ppid(current)
    return False


class DevProxyHandlerBase(BaseHTTPRequestHandler):
    """Byte-transparent reverse proxy, except HTML gains the overlay script.

    ``server`` binds a subclass whose ``runtime`` class attribute refers to its
    module object.  Late binding keeps the server namespace authoritative
    without importing the composition root back into this boundary.
    """

    runtime: ClassVar[Any] = None
    protocol_version = "HTTP/1.1"
    timeout = 30
    upstream_host = "127.0.0.1"
    upstream_port = 0
    proxy_port = 0

    def log_message(self, *args: Any) -> None:
        pass

    def _upstream(self) -> str:
        return f"{self.upstream_host}:{self.upstream_port}"

    def _dispatch(self) -> None:
        runtime = self.runtime
        if self.path.split("?", 1)[0] == runtime._OVERLAY_PATH:
            return self._serve_overlay()
        if "websocket" in self.headers.get("Upgrade", "").lower():
            return self._relay_ws()
        return self._relay_http()

    do_GET = _dispatch
    do_POST = _dispatch
    do_HEAD = _dispatch
    do_PUT = _dispatch
    do_PATCH = _dispatch
    do_DELETE = _dispatch
    do_OPTIONS = _dispatch

    def _serve_overlay(self) -> None:
        runtime = self.runtime
        try:
            javascript = runtime.INJECT_FILE.read_bytes()
        except OSError:
            javascript = b"// overlay not found"
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(javascript)))
        self.end_headers()
        self.wfile.write(javascript)

    def _relay_http(self) -> None:
        runtime = self.runtime
        body = b""
        length = self.headers.get("Content-Length")
        if length:
            try:
                size = int(length)
            except ValueError:
                size = -1
            if size > runtime.MAX_BODY_BYTES:
                self.close_connection = True
                self.send_error(
                    413,
                    f"request body over the {runtime.MAX_BODY_BYTES}-byte proxy limit",
                )
                return
            if size > 0:
                try:
                    body = self.rfile.read(size)
                except OSError:
                    self.close_connection = True
                    self.send_error(408, "request body timed out")
                    return
                if len(body) != size:
                    self.close_connection = True
                    self.send_error(400, "request body shorter than Content-Length")
                    return

        headers: dict[str, str] = {}
        for key, value in self.headers.items():
            low = key.lower()
            if low in runtime._HOP_BY_HOP or low in ("accept-encoding", "host"):
                continue
            if low in runtime._CREDENTIAL_REQUEST_HEADERS:
                continue
            headers[key] = value
        headers["Host"] = self._upstream()

        try:
            connection = runtime.http.client.HTTPConnection(
                self.upstream_host,
                self.upstream_port,
                timeout=runtime._RELAY_TIMEOUT,
            )
            connection.request(
                self.command,
                self.path,
                body=body or None,
                headers=headers,
            )
            response = connection.getresponse()
            payload = response.read(runtime.MAX_STATIC_BYTES + 1)
        except (OSError, runtime.http.client.HTTPException) as exc:
            self.send_error(502, f"dev server unreachable: {exc}")
            return

        if len(payload) > runtime.MAX_STATIC_BYTES:
            connection.close()
            self.send_error(
                502,
                f"dev server response over the {runtime.MAX_STATIC_BYTES}-byte preview limit",
            )
            return

        if "text/html" in (response.getheader("Content-Type") or "").lower():
            payload = runtime._rewrite_html(
                payload,
                base=None,
                script=runtime._OVERLAY_PATH,
            )

        self.send_response(response.status)
        for key, value in response.getheaders():
            low = key.lower()
            if low in runtime._HOP_BY_HOP or low == "content-length":
                continue
            if low in runtime._CREDENTIAL_RESPONSE_HEADERS:
                continue
            if not runtime._HEADER_NAME_RE.match(key):
                continue
            if low == "content-type":
                value = runtime._safe_upstream_ctype(value, self.path)
            if low == "location":
                value = self._keep_redirect_local(value)
            self.send_header(key, runtime._header_value(value))
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)
        connection.close()

    def _keep_redirect_local(self, location: str) -> str:
        """Re-point a redirect naming the upstream at this proxy's origin."""

        runtime = self.runtime
        try:
            parts = runtime.urlparse(location)
            if not parts.scheme and not parts.netloc:
                return location
            if parts.scheme.lower() not in ("http", "https"):
                return location
            if (parts.hostname or "").lower() not in runtime._LOOPBACK_HOSTS:
                return location
            port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        except ValueError:
            return location
        if port != self.upstream_port:
            return location
        rest = parts.path or "/"
        if parts.query:
            rest += "?" + parts.query
        if parts.fragment:
            rest += "#" + parts.fragment
        return f"http://127.0.0.1:{self.proxy_port}{rest}"

    def _relay_ws(self) -> None:
        runtime = self.runtime
        try:
            upstream = runtime.socket.create_connection(
                (self.upstream_host, self.upstream_port),
                timeout=10,
            )
        except OSError:
            self.send_error(502, "dev server unreachable")
            return

        lines = [f"{self.command} {self.path} HTTP/1.1"]
        for key, value in self.headers.items():
            if key.lower() in runtime._CREDENTIAL_REQUEST_HEADERS:
                continue
            lines.append(f"{key}: {self._upstream() if key.lower() == 'host' else value}")
        try:
            upstream.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace"))
        except OSError:
            upstream.close()
            return

        self.close_connection = True
        downstream = self.connection

        head = b""
        upstream.settimeout(runtime._RELAY_TIMEOUT)
        try:
            while b"\r\n\r\n" not in head and len(head) < 65536:
                part = upstream.recv(4096)
                if not part:
                    break
                head += part
        except OSError:
            upstream.close()
            return
        raw_head, separator, rest = head.partition(b"\r\n\r\n")
        if not separator:
            upstream.close()
            self.send_error(502, "malformed upstream handshake")
            return
        head_lines = raw_head.split(b"\r\n")
        sanitized = [head_lines[0]]
        for header_line in head_lines[1:]:
            name, _, _value = header_line.partition(b":")
            if (
                name.strip().lower().decode("latin-1", "replace")
                in runtime._CREDENTIAL_RESPONSE_HEADERS
            ):
                continue
            sanitized.append(header_line)
        try:
            downstream.sendall(b"\r\n".join(sanitized) + b"\r\n\r\n")
            if rest:
                downstream.sendall(rest)
        except OSError:
            upstream.close()
            return

        upstream.settimeout(None)
        downstream.settimeout(None)
        selector = runtime.selectors.DefaultSelector()
        selector.register(upstream, runtime.selectors.EVENT_READ, downstream)
        selector.register(downstream, runtime.selectors.EVENT_READ, upstream)
        try:
            while True:
                events = selector.select(timeout=runtime._WS_IDLE)
                if not events:
                    return
                for selector_key, _mask in events:
                    src_sock = cast(Any, selector_key.fileobj)
                    dst_sock = cast(Any, selector_key.data)
                    try:
                        chunk = src_sock.recv(65536)
                    except OSError:
                        return
                    if not chunk:
                        return
                    try:
                        dst_sock.sendall(chunk)
                    except OSError:
                        return
        finally:
            selector.close()
            try:
                upstream.close()
            except OSError:
                pass


def start_inject_proxy(runtime: Any, dev_url: str) -> tuple[object | None, str]:
    """Front ``dev_url`` with an overlay-injecting loopback proxy."""

    parsed = runtime.urlparse(dev_url)
    host = parsed.hostname or "127.0.0.1"
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None, ""
    bound = cast(
        type[DevProxyHandlerBase],
        type(
            "_BoundDevProxy",
            (runtime._DevProxyHandler,),
            {"upstream_host": host, "upstream_port": port},
        ),
    )
    try:
        server = runtime.ThreadingHTTPServer(("127.0.0.1", 0), bound)
    except OSError:
        return None, ""
    server.daemon_threads = True
    bound.proxy_port = server.server_address[1]
    runtime.threading.Thread(
        target=server.serve_forever,
        daemon=True,
        name="kiro-dev-proxy",
    ).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/"


def stop_inject_proxy(runtime: Any, record: dict[str, Any]) -> None:
    """Close a project's injection proxy and invalidate its cached URL."""

    server = record.get("proxy")
    if server is None:
        return
    try:
        server.shutdown()
        server.server_close()
    except Exception:  # noqa: BLE001
        pass
    record["proxy"] = None
    record["proxyUrl"] = ""
    record["proxyFor"] = ""


def front_with_proxy(runtime: Any, project_id: str, dev_url: str) -> str:
    """Reuse or create the credential-stripping proxy for a dev server."""

    record = runtime._DEV_PROCS.get(project_id)
    if record is not None and record.get("proxy") is not None and record.get("proxyFor") == dev_url:
        cached = str(record.get("proxyUrl") or "")
        if cached:
            return cached
    server, url = runtime._start_inject_proxy(dev_url)
    if not url:
        return ""
    if record is not None:
        runtime._stop_inject_proxy(record)
        record["proxy"] = server
        record["proxyUrl"] = url
        record["proxyFor"] = dev_url
    else:
        runtime._DEV_PROCS[project_id] = {
            "proc": None,
            "pgid": None,
            "url": dev_url,
            "proxy": server,
            "proxyUrl": url,
            "proxyFor": dev_url,
            "adopted": True,
        }
    return url


__all__ = [
    "CHILD_ENV_STRIP",
    "CHILD_ENV_STRIP_PREFIXES",
    "DEV_SCRIPTS",
    "LOCKFILES",
    "NODE_BIN_DIRS",
    "NVM_GLOB",
    "PROC_TREE_MAX_DEPTH",
    "DevProxyHandlerBase",
    "auto_dev_server",
    "child_env",
    "classify_project",
    "cwd_for_pids",
    "detect_dev_servers",
    "dev_command",
    "dev_proc_alive",
    "front_with_proxy",
    "in_proc_tree",
    "loopback_listeners",
    "node_bin_dirs",
    "pkg_scripts",
    "resolve_bin",
    "serves_html",
    "start_inject_proxy",
    "stop_all_dev_procs",
    "stop_dev_proc",
    "stop_inject_proxy",
]

"""A tiny forward proxy that the sandboxed browser is forced through.

Why: the browser must be able to reach the public internet (that is the point) but never loopback, the
LAN, the Docker host or cloud metadata. The proxy resolves every name itself, refuses anything that is
not a public address, and connects to the address it checked. Chromium never resolves names on its own
(it is started with host-resolver rules that fail every lookup), so there is no second, unchecked path.

Handles CONNECT (https, wss) and absolute-form HTTP requests. Nothing is cached or modified except
hop-by-hop headers; TLS is end-to-end between the browser and the site, so certificate errors still show."""
from __future__ import annotations

import asyncio
import threading
from typing import Callable
from urllib.parse import urlsplit

from .policy import Blocked, resolve_public

Resolver = Callable[[str, int], "list[str]"]
MAX_HEAD = 32 * 1024
HEAD_END = b"\r\n\r\n"
CONNECT_TIMEOUT = 12
IDLE_TIMEOUT = 25


class FilteringProxy:
    def __init__(self, resolver: Resolver = resolve_public, max_bytes: int = 48 << 20, max_conns: int = 64):
        self.resolver = resolver
        self.max_bytes = max_bytes
        self.max_conns = max_conns
        self.blocked: list[str] = []          # "host: reason" - shown in the report
        self.internal_attempts = 0            # requests aimed at private/internal destinations
        self.hosts: list[str] = []            # every destination host the page contacted (public ones)
        self.requests = 0
        self.bytes = 0
        self.port = 0
        self._active = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.AbstractServer | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> int:
        self._thread = threading.Thread(target=self._run, name="pg-proxy", daemon=True)
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("proxy did not start")
        return self.port

    def stop(self) -> None:
        loop = self._loop
        if loop and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        server = loop.run_until_complete(asyncio.start_server(self._handle, "127.0.0.1", 0, limit=MAX_HEAD))
        self._server = server
        self.port = server.sockets[0].getsockname()[1]
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            server.close()
            for t in asyncio.all_tasks(loop):
                t.cancel()
            try:
                loop.run_until_complete(asyncio.sleep(0))
            except Exception:
                pass
            loop.close()

    # ---------------------------------------------------------------- bookkeeping
    def _note_block(self, host: str, why: str) -> None:
        entry = f"{host[:80]}: {why}"
        if "private" in why or "internal" in why:
            self.internal_attempts += 1
        if entry not in self.blocked and len(self.blocked) < 40:
            self.blocked.append(entry)

    def _note_host(self, host: str) -> None:
        h = host.lower()
        if h not in self.hosts and len(self.hosts) < 80:
            self.hosts.append(h)

    # ---------------------------------------------------------------- connections
    async def _open_upstream(self, host: str, port: int):
        loop = asyncio.get_running_loop()
        addrs = await loop.run_in_executor(None, self.resolver, host, port)
        last: Exception | None = None
        for a in addrs[:4]:
            try:
                return await asyncio.wait_for(asyncio.open_connection(a, port), CONNECT_TIMEOUT)
            except Exception as e:  # try the next address
                last = e
        raise Blocked(f"could not connect ({type(last).__name__ if last else 'no address'})")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._active >= self.max_conns:
            writer.close()
            return
        self._active += 1
        try:
            await self._serve(reader, writer)
        except (asyncio.CancelledError, ConnectionError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError):
            pass
        except Exception:
            pass
        finally:
            self._active -= 1
            try:
                writer.close()
            except Exception:
                pass

    async def _reply(self, writer: asyncio.StreamWriter, code: int, reason: str) -> None:
        body = reason.encode()
        writer.write(f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        try:
            await writer.drain()
        except Exception:
            pass

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IDLE_TIMEOUT)
        if len(head) > MAX_HEAD:
            return
        first, _, rest = head.partition(b"\r\n")
        try:
            method, target, version = first.decode("latin-1").split(" ", 2)
        except ValueError:
            await self._reply(writer, 400, "Bad Request")
            return
        self.requests += 1
        if method.upper() == "CONNECT":
            host, _, port_s = target.rpartition(":")
            host = host.strip("[]")
            try:
                port = int(port_s)
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                await self._reply(writer, 400, "Bad Request")
                return
            try:
                up_r, up_w = await self._open_upstream(host, port)
            except Blocked as e:
                self._note_block(host, e.reason)
                await self._reply(writer, 403, "Blocked by sandbox policy")
                return
            self._note_host(host)
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            await self._pipe(reader, writer, up_r, up_w)
            return
        # plain HTTP, absolute-form: GET http://host/path HTTP/1.1
        try:
            u = urlsplit(target)
            if u.scheme.lower() != "http" or not u.hostname:
                raise ValueError
            host, port = u.hostname, u.port or 80
            path = (u.path or "/") + (("?" + u.query) if u.query else "")
        except ValueError:
            await self._reply(writer, 400, "Only http and https are supported")
            return
        try:
            up_r, up_w = await self._open_upstream(host, port)
        except Blocked as e:
            self._note_block(host, e.reason)
            await self._reply(writer, 403, "Blocked by sandbox policy")
            return
        self._note_host(host)
        lines = [f"{method} {path} {version}"]
        for line in rest.decode("latin-1").split("\r\n"):
            if not line:
                continue
            name = line.split(":", 1)[0].strip().lower()
            if name in ("proxy-connection", "connection", "keep-alive", "proxy-authorization", "te", "upgrade"):
                continue
            lines.append(line)
        lines.append("Connection: close")
        up_w.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        await up_w.drain()
        await self._pipe(reader, writer, up_r, up_w, rewrite_response_head=True)

    async def _pipe(self, c_r, c_w, u_r, u_w, rewrite_response_head: bool = False) -> None:
        async def pump(src, dst, rewrite_head: bool = False) -> None:
            pending = b""          # only used while waiting for a complete response head
            waiting = rewrite_head
            try:
                while True:
                    data = await asyncio.wait_for(src.read(65536), IDLE_TIMEOUT)
                    if not data:
                        break
                    if waiting:
                        pending += data
                        if HEAD_END not in pending and len(pending) < MAX_HEAD:
                            continue
                        data, pending, waiting = _force_close_header(pending), b"", False
                    self.bytes += len(data)
                    if self.bytes > self.max_bytes:
                        break
                    dst.write(data)
                    await dst.drain()
                if pending:
                    dst.write(pending)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(pump(c_r, u_w), pump(u_r, c_w, rewrite_response_head), return_exceptions=True)


def _force_close_header(chunk: bytes) -> bytes:
    """Tell the browser this connection ends after the response (we asked the origin for Connection: close)."""
    end = chunk.find(b"\r\n\r\n")
    if end < 0 or not chunk.startswith(b"HTTP/"):
        return chunk
    head, body = chunk[:end], chunk[end:]
    kept = [l for l in head.split(b"\r\n") if l.split(b":", 1)[0].strip().lower() not in (b"connection", b"keep-alive", b"proxy-connection")]
    return b"\r\n".join(kept + [b"Connection: close"]) + body

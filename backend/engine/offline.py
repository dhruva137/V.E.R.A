"""VERA_OFFLINE=1: outbound connections go only to this machine and to named scan targets.

An assessment of critical infrastructure runs on a laptop inside the
customer's network. Anything the tool sends out is a disclosure, so the
default is that it sends nothing: no cloud model, no update check, no schema
download, no remote git clone. `install()` enforces that in-process by wrapping
the socket calls every Python network client ends up in:

* `socket.socket.connect` / `connect_ex`: the blocking clients (the TLS and SSH
  probes, httpx's sync transport);
* `socket.getaddrinfo`: name resolution, which every hostname connection needs,
  including asyncio's;
* `asyncio` event-loop `create_connection`: the async clients (the LLM bridge),
  whose Windows proactor path connects without calling `socket.connect`.

Allowed: loopback addresses, `localhost`, and hosts registered with `allow()`.
The TLS and SSH collectors register the one host they were asked to probe
immediately before probing it, so an operator-named target is reachable and
nothing else is. A refused connection raises `OfflineBlocked`, a
`ConnectionRefusedError`, so every client reports it through its own error
path with the reason in the message.

Subprocesses are outside the wrapper. The only one that can reach the network
is `git clone` of a repository URL an operator gave as a scan target, which is
the exception the flag allows; the agent cannot name one (engine.agent.run_scan
refuses URLs).
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import threading

_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", ""}

_lock = threading.Lock()
_allowed: set[str] = set()
_blocked: list[str] = []
_installed = False
_originals: dict[str, object] = {}


class OfflineBlocked(ConnectionRefusedError):
    """A connection VERA_OFFLINE=1 refused."""


def requested() -> bool:
    return os.environ.get("VERA_OFFLINE", "") == "1"


def enforced() -> bool:
    return _installed


def _host_of(address) -> str:
    if isinstance(address, (tuple, list)) and address:
        return str(address[0])
    return str(address or "")


def is_local(host: str) -> bool:
    host = host.strip("[]").lower()
    if host in _LOCAL_NAMES:
        return True
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    # 0.0.0.0 / :: are what a server binds to; connecting to them reaches this machine.
    return address.is_loopback or address.is_unspecified


def permitted(host: str) -> bool:
    host = str(host or "").strip("[]").lower()
    with _lock:
        return is_local(host) or host in _allowed


def allow(host: str) -> None:
    """Register an operator-named scan target (and the addresses it resolves to)."""
    host = str(host or "").strip("[]").lower()
    if not host:
        return
    with _lock:
        _allowed.add(host)
    if not _installed or is_local(host):
        return
    try:
        infos = _originals["getaddrinfo"](host, None)  # type: ignore[operator]
    except OSError:
        return
    with _lock:
        _allowed.update(str(info[4][0]).lower() for info in infos)


def _refuse(host: str, what: str):
    with _lock:
        _blocked.append(host)
        del _blocked[:-50]
    raise OfflineBlocked(
        f"VERA_OFFLINE=1 blocked {what} to {host!r}: only this machine and operator-named scan "
        "targets are reachable. Unset VERA_OFFLINE to allow outbound connections."
    )


def install() -> bool:
    """Wrap the socket layer if VERA_OFFLINE=1. Idempotent. Returns whether the guard is on."""
    global _installed
    if _installed or not requested():
        return _installed
    with _lock:
        if _installed:
            return True
        _originals.update({
            "connect": socket.socket.connect, "connect_ex": socket.socket.connect_ex,
            "getaddrinfo": socket.getaddrinfo, "create_connection": asyncio.BaseEventLoop.create_connection,
        })
        original_connect, original_connect_ex = _originals["connect"], _originals["connect_ex"]
        original_getaddrinfo, original_loop_connect = _originals["getaddrinfo"], _originals["create_connection"]

        def connect(sock, address):
            if sock.family in (socket.AF_INET, socket.AF_INET6) and not permitted(_host_of(address)):
                _refuse(_host_of(address), "a connection")
            return original_connect(sock, address)

        def connect_ex(sock, address):
            if sock.family in (socket.AF_INET, socket.AF_INET6) and not permitted(_host_of(address)):
                _refuse(_host_of(address), "a connection")
            return original_connect_ex(sock, address)

        def getaddrinfo(host, *args, **kwargs):
            name = host.decode() if isinstance(host, bytes) else str(host or "")
            if host is not None and not permitted(name):
                _refuse(name, "a name lookup")
            return original_getaddrinfo(host, *args, **kwargs)

        async def create_connection(loop, protocol_factory, host=None, port=None, *args, **kwargs):
            if host is not None and not permitted(str(host)):
                _refuse(str(host), "a connection")
            return await original_loop_connect(loop, protocol_factory, host, port, *args, **kwargs)

        socket.socket.connect = connect
        socket.socket.connect_ex = connect_ex
        socket.getaddrinfo = getaddrinfo
        asyncio.BaseEventLoop.create_connection = create_connection
        _installed = True
    return True


def uninstall() -> None:
    """Restore the socket layer. Used by tests."""
    global _installed
    with _lock:
        if not _installed:
            return
        socket.socket.connect = _originals["connect"]
        socket.socket.connect_ex = _originals["connect_ex"]
        socket.getaddrinfo = _originals["getaddrinfo"]
        asyncio.BaseEventLoop.create_connection = _originals["create_connection"]
        _allowed.clear()
        _installed = False


def self_test() -> list[dict]:
    """Prove the guard in this process: egress blocked, loopback and named targets allowed.

    The outbound probes use 203.0.113.0/24 (RFC 5737, documentation only), so a
    guard that failed to block would still send nothing anywhere real.
    """
    os.environ["VERA_OFFLINE"] = "1"
    install()
    results = []

    def check(name: str, probe) -> None:
        try:
            ok, detail = probe()
        except Exception as exc:  # a probe that raises unexpectedly is a failed check, reported
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        results.append({"check": name, "ok": ok, "detail": detail})

    def blocked(fn) -> tuple[bool, str]:
        try:
            fn()
        except OfflineBlocked as exc:
            return True, str(exc)
        except OSError as exc:
            return False, f"not stopped by the guard: {exc}"
        return False, "the connection was allowed"

    check("outbound TCP is blocked", lambda: blocked(
        lambda: socket.create_connection(("203.0.113.1", 443), timeout=2).close()))
    def raw_connect():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(2)
            sock.connect(("203.0.113.1", 443))
        finally:
            sock.close()

    check("a raw socket connect to an IP is blocked", lambda: blocked(raw_connect))
    check("DNS lookups of outside names are blocked", lambda: blocked(
        lambda: socket.getaddrinfo("example.com", 443)))

    async def dial():
        await asyncio.open_connection("203.0.113.1", 443)

    check("async (LLM client) connections are blocked", lambda: blocked(lambda: asyncio.run(dial())))

    def loopback() -> tuple[bool, str]:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        try:
            socket.create_connection(server.getsockname(), timeout=2).close()
            return True, f"connected to {server.getsockname()}"
        finally:
            server.close()

    check("loopback is allowed (local model, dashboard)", loopback)

    def named_target() -> tuple[bool, str]:
        allow("203.0.113.9")
        return permitted("203.0.113.9") and not permitted("203.0.113.10"), \
            "an operator-named target is reachable; its neighbour is not"

    check("operator-named scan targets are allowed", named_target)
    return results


def main() -> int:
    """`python -m engine.offline`: print the self-test; exit 1 if any check fails."""
    results = self_test()
    for r in results:
        print(f"  {'PASS' if r['ok'] else 'FAIL'}  {r['check']}  ({r['detail'][:110]})")
    return 0 if all(r["ok"] for r in results) else 1


def status() -> dict:
    with _lock:
        allowed, blocked = sorted(_allowed), list(_blocked)
    if _installed:
        detail = "Outbound connections are limited to this machine and operator-named scan targets."
    elif requested():
        detail = "VERA_OFFLINE=1 is set but the guard is not installed in this process."
    else:
        detail = "VERA_OFFLINE is not set: outbound connections are not restricted."
    return {"requested": requested(), "enforced": _installed, "allowed_targets": allowed,
            "recently_blocked": blocked[-10:], "detail": detail}


if __name__ == "__main__":
    raise SystemExit(main())

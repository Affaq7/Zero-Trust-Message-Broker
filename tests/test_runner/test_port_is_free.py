"""port_is_free(): a closed server's port counts as free, a listening one does not (any OS)."""

import os
import socket

from runner.processes import port_is_free


def test_listening_port_is_busy():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        assert not port_is_free(srv.getsockname()[1])


def test_port_left_in_time_wait_counts_as_free():
    # The server side closes first, so its port is left in TIME_WAIT (as after a
    # uvicorn agent answered a request and was stopped). On Linux a plain bind()
    # would fail here for up to a minute. Like uvicorn (asyncio on POSIX), the
    # listener sets SO_REUSEADDR; Linux reuses a TIME_WAIT port only if it did.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name != "nt":
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    cli = socket.create_connection(("127.0.0.1", port))
    conn, _ = srv.accept()
    conn.close()
    srv.close()
    cli.recv(1)
    cli.close()
    assert port_is_free(port)

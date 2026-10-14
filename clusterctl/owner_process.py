"""Kernel process observations reused from the reviewed existing-owner runtime."""
from __future__ import annotations

import os
import socket
import struct
from contextlib import ExitStack, contextmanager
from pathlib import Path
import select
from typing import Any
import uuid

PROCESS_FIELDS = {"uid", "pid", "start_ticks", "boot_id"}


class PresenceError(ValueError):
    """Generic refusal without disclosing process or private path details."""


def validate_process(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != PROCESS_FIELDS:
        raise PresenceError("owner_process_rejected")
    for field, minimum, maximum in (
        ("uid", 0, 2**32), ("pid", 1, 2**31), ("start_ticks", 1, 2**64),
    ):
        item = value[field]
        if isinstance(item, bool) or not isinstance(item, int) or not minimum <= item < maximum:
            raise PresenceError("owner_process_rejected")
    try:
        if not isinstance(value["boot_id"], str) or str(uuid.UUID(value["boot_id"])) != value["boot_id"]:
            raise ValueError("invalid boot identifier")
    except (ValueError, AttributeError) as error:
        raise PresenceError("owner_process_rejected") from error
    return dict(value)


class ProcessPresence:
    """Pin one kernel process; no signals, polling loop, runtime RPC or key I/O."""

    def __init__(self, process: dict[str, Any]):
        self.process = validate_process(process)
        self.descriptor = -1
        try:
            self.descriptor = os.pidfd_open(self.process["pid"], 0)
            os.set_inheritable(self.descriptor, False)
            self.verify()
        except Exception as error:
            self.close()
            raise PresenceError("owner_process_unavailable") from error

    def verify(self) -> None:
        try:
            if self.descriptor < 0:
                raise ValueError("closed process observer")
            poller = select.poll()
            poller.register(self.descriptor, select.POLLIN | select.POLLERR | select.POLLHUP)
            if poller.poll(0):
                raise ValueError("process has exited")
            if Path("/proc/sys/kernel/random/boot_id").read_text().strip() != self.process["boot_id"]:
                raise ValueError("different host boot")
            root = Path("/proc") / str(self.process["pid"])
            uid_lines = [line.split()[1:] for line in (root / "status").read_text().splitlines() if line.startswith("Uid:")]
            if len(uid_lines) != 1 or [int(item) for item in uid_lines[0]] != [self.process["uid"]] * 4:
                raise ValueError("different process owner")
            fields = (root / "stat").read_text().rpartition(")")[2].split()
            if fields[0] in {"Z", "X", "x"} or int(fields[19]) != self.process["start_ticks"]:
                raise ValueError("different process start")
            if poller.poll(0):
                raise ValueError("process exited during observation")
        except Exception as error:
            raise PresenceError("owner_process_unavailable") from error

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def __enter__(self) -> ProcessPresence:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()


class ConnectedProcessObserver:
    """Pin the actual RPC peer through authentication and the complete observation.

    Use as LocalClient's owner-only connection observer within one foreground
    scope. Multiple RPCs must reach the same kernel process; this is transport
    association, not SDK/application/admission qualification or remote liveness.
    """

    def __init__(self) -> None:
        self._process: dict[str, Any] | None = None
        self._stack = ExitStack()
        self._presence: ProcessPresence | None = None
        self._active = False

    def __enter__(self) -> ConnectedProcessObserver:
        if self._active or self._process is not None:
            raise PresenceError("owner_process_observation_rejected")
        self._active = True
        return self

    @property
    def process(self) -> dict[str, Any] | None:
        return None if self._process is None else dict(self._process)

    @contextmanager
    def __call__(self, connection: socket.socket):
        if not self._active or not hasattr(socket, "SO_PEERCRED"):
            raise PresenceError("owner_process_observation_rejected")
        try:
            pid, uid, _gid = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.geteuid():
                raise ValueError("different process owner")
            process = dict(uid=uid, pid=pid,
                start_ticks=int((Path("/proc") / str(pid) / "stat").read_text().rpartition(")")[2].split()[19]),
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip())
            if self._process is not None and process != self._process:
                raise ValueError("different process on later connection")
            if self._presence is None:
                self._presence = self._stack.enter_context(ProcessPresence(process))
                self._process = process
            self._presence.verify()
        except Exception as error:
            raise PresenceError("owner_process_observation_rejected") from error
        yield
        self.verify()

    def verify(self) -> None:
        if not self._active or self._presence is None:
            raise PresenceError("owner_process_observation_rejected")
        self._presence.verify()

    def __exit__(self, *_args: Any) -> None:
        self._active = False
        self._stack.close()


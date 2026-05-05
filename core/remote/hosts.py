"""Remote host registry — discover and reach lab systems.

Reads ~/.config/raptor/hosts.json to know what machines are available,
what OS they run, and how to reach them. NEVER stores credentials —
authentication is handled by SSH config, key auth, or agent forwarding.

Usage:
    from core.remote.hosts import HostRegistry

    reg = HostRegistry()
    host = reg.get("rengy")           # specific host
    host = reg.by_os("windows")       # first Windows host
    host = reg.by_capability("fuzz")  # first host with fuzzing tools
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from core.logging import get_logger

logger = get_logger()

HOSTS_CONFIG = Path.home() / ".config" / "raptor" / "hosts.json"


@dataclass(frozen=True)
class RemoteHost:
    """A remote host RAPTOR can reach via SSH."""
    name: str
    os: str
    host: str
    user: str
    port: int = 22
    capabilities: tuple = ()
    screen_support: bool = True
    notes: str = ""

    @property
    def ssh_target(self) -> str:
        """SSH connection string (user@host)."""
        return f"{self.user}@{self.host}"

    @property
    def ssh_cmd_prefix(self) -> List[str]:
        """Base SSH command as a list (no credentials)."""
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
        if self.port != 22:
            cmd.extend(["-p", str(self.port)])
        cmd.append(self.ssh_target)
        return cmd

    def has_capability(self, cap: str) -> bool:
        return cap.lower() in (c.lower() for c in self.capabilities)


@dataclass
class StorageMount:
    """A shared storage location (NAS, NFS, etc.)."""
    name: str
    mount_type: str
    path: str
    purpose: str = ""
    host: str = ""


class HostRegistry:
    """Manages the host inventory from ~/.config/raptor/hosts.json."""

    def __init__(self, config_path: Path = None):
        self._path = config_path or HOSTS_CONFIG
        self._hosts: Dict[str, RemoteHost] = {}
        self._storage: Dict[str, StorageMount] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load hosts config: {e}")
            return

        for name, h in data.get("hosts", {}).items():
            self._hosts[name] = RemoteHost(
                name=name,
                os=h.get("os", "linux"),
                host=h.get("host", name),
                user=h.get("user", "root"),
                port=h.get("port", 22),
                capabilities=tuple(h.get("capabilities", ())),
                screen_support=h.get("screen_support", h.get("os", "linux") != "windows"),
                notes=h.get("notes", ""),
            )

        for name, s in data.get("storage", {}).items():
            self._storage[name] = StorageMount(
                name=name,
                mount_type=s.get("type", "local"),
                path=s.get("path", ""),
                purpose=s.get("purpose", ""),
                host=s.get("host", ""),
            )

    def get(self, name: str) -> Optional[RemoteHost]:
        return self._hosts.get(name)

    def by_os(self, os_name: str) -> Optional[RemoteHost]:
        """First host matching the given OS."""
        os_lower = os_name.lower()
        for h in self._hosts.values():
            if h.os.lower() == os_lower:
                return h
        return None

    def by_capability(self, cap: str) -> Optional[RemoteHost]:
        """First host with the given capability."""
        for h in self._hosts.values():
            if h.has_capability(cap):
                return h
        return None

    def all_hosts(self) -> List[RemoteHost]:
        return list(self._hosts.values())

    def get_storage(self, name: str) -> Optional[StorageMount]:
        return self._storage.get(name)

    def all_storage(self) -> List[StorageMount]:
        return list(self._storage.values())

    def is_configured(self) -> bool:
        return bool(self._hosts)

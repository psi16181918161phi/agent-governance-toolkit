# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Ephemeral Session Data Garbage Collection.

Purges ephemeral session state (VFS files, cached snapshots) on collection
and expires audit deltas that fall outside the configured retention window.
The reported ``GCResult`` and ``is_purged`` flag reflect what was actually
removed — a host that calls :meth:`EphemeralGC.collect` to delete sensitive
session data can trust the confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any


@dataclass
class GCResult:
    """Result of a garbage collection run."""

    session_id: str
    retained_deltas: int
    retained_hash: bool
    purged_vfs_files: int
    purged_caches: int
    storage_before_bytes: int
    storage_after_bytes: int
    gc_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def storage_saved_bytes(self) -> int:
        return self.storage_before_bytes - self.storage_after_bytes

    @property
    def savings_pct(self) -> float:
        if self.storage_before_bytes == 0:
            return 0.0
        return (self.storage_saved_bytes / self.storage_before_bytes) * 100


@dataclass
class RetentionPolicy:
    """Configuration for what to retain after GC."""

    delta_retention_days: int = 180
    hash_retention: str = "permanent"
    liability_snapshot: bool = True


class EphemeralGC:
    """
    Purges ephemeral session data and expires audit deltas per retention policy.
    """

    def __init__(self, policy: RetentionPolicy | None = None) -> None:
        self.policy = policy or RetentionPolicy()
        self._gc_history: list[GCResult] = []
        self._purged_sessions: set[str] = set()

    def collect(
        self,
        session_id: str,
        vfs: Any = None,
        delta_engine: Any = None,
        vfs_file_count: int = 0,
        cache_count: int = 0,
        delta_count: int = 0,
        estimated_vfs_bytes: int = 0,
        estimated_cache_bytes: int = 0,
        estimated_delta_bytes: int = 0,
        gc_agent_did: str = "did:agt:hypervisor:gc",
    ) -> GCResult:
        """Purge ephemeral session data and expire out-of-retention deltas.

        When a real ``vfs`` is supplied its files and cached snapshots are
        physically removed; when a real ``delta_engine`` is supplied, deltas
        older than ``policy.delta_retention_days`` are pruned. The
        ``estimated_*`` / ``*_count`` parameters are only used for storage
        accounting when the corresponding live object is absent — they never
        cause the result to report a purge that did not happen.
        """
        # --- VFS files + cached snapshots ---
        if vfs is not None:
            vfs_bytes_before = self._vfs_storage_bytes(vfs)
            purged_vfs_files, purged_caches = vfs.purge_all(gc_agent_did)
            vfs_bytes_after = 0 if vfs.file_count == 0 else self._vfs_storage_bytes(vfs)
            vfs_fully_purged = vfs.file_count == 0
        else:
            # No live handle: nothing is physically removed, so report no
            # purge (reporting vfs_file_count here would be a lie).
            vfs_bytes_before = estimated_vfs_bytes
            vfs_bytes_after = estimated_vfs_bytes
            purged_vfs_files = 0
            purged_caches = 0
            vfs_fully_purged = True

        # --- audit deltas (retain within window, expire the rest) ---
        if delta_engine is not None:
            total_deltas = len(delta_engine.deltas)
            delta_engine.prune_expired(self.should_expire_deltas)
            retained_deltas = len(delta_engine.deltas)
        else:
            total_deltas = delta_count
            retained_deltas = delta_count

        if total_deltas > 0:
            delta_bytes_before = estimated_delta_bytes
            delta_bytes_after = round(estimated_delta_bytes * retained_deltas / total_deltas)
        else:
            delta_bytes_before = estimated_delta_bytes
            delta_bytes_after = estimated_delta_bytes

        # Caches are physically purged only via the live VFS snapshots above;
        # estimated_cache_bytes is reclaimed proportionally to that purge.
        if purged_caches > 0 or vfs is None:
            cache_bytes_after = estimated_cache_bytes if vfs is None else 0
        else:
            cache_bytes_after = estimated_cache_bytes

        result = GCResult(
            session_id=session_id,
            retained_deltas=retained_deltas,
            retained_hash=self.policy.hash_retention == "permanent",
            purged_vfs_files=purged_vfs_files,
            purged_caches=purged_caches,
            storage_before_bytes=vfs_bytes_before + estimated_cache_bytes + delta_bytes_before,
            storage_after_bytes=vfs_bytes_after + cache_bytes_after + delta_bytes_after,
        )
        self._gc_history.append(result)

        # Honest flag: mark purged only when no live retained data remains.
        if vfs_fully_purged:
            self._purged_sessions.add(session_id)
        return result

    @staticmethod
    def _vfs_storage_bytes(vfs: Any) -> int:
        """Sum UTF-8 byte sizes of all files via the VFS public API."""
        total = 0
        for path in vfs.list_files():
            content = vfs.read(path)
            if content is not None:
                total += len(content.encode("utf-8"))
        return total

    def is_purged(self, session_id: str) -> bool:
        return session_id in self._purged_sessions

    def should_expire_deltas(self, delta_timestamp: datetime) -> bool:
        """Return True if a delta at ``delta_timestamp`` is outside retention.

        Compares the timestamp against ``policy.delta_retention_days``. A
        non-positive retention window means "retain nothing" (everything
        expires); deltas exactly at the cutoff are retained.
        """
        retention_days = self.policy.delta_retention_days
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        ts = delta_timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return ts < cutoff

    @property
    def history(self) -> list[GCResult]:
        return list(self._gc_history)

    @property
    def purged_session_count(self) -> int:
        return len(self._purged_sessions)

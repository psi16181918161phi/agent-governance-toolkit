# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governed agent-to-agent transport over the Mesh component.

This wires the Mesh standalone into the AGT host. Messages are sealed with the
sender's Identity key and routed through the mesh registry by did:mesh address.
Payloads can be sealed with end-to-end encryption to a recipient public key.
Transport is orthogonal to the decision pipeline; a host typically governs an
action first, then sends the result over mesh.
"""

from __future__ import annotations

from typing import Any, Optional

from mesh_engine import MeshManager


class MeshTransport:
    """A thin host facade over the Mesh component."""

    def __init__(self, mesh: Optional[MeshManager] = None) -> None:
        self._mesh = mesh or MeshManager()

    def register(self, did: str, endpoint: str, public_key_hex: str) -> dict[str, Any]:
        """Register an agent's endpoint and public key by its DID."""
        return self._mesh.register(did, endpoint, public_key_hex)

    def lookup(self, did: str) -> Optional[dict[str, Any]]:
        """Resolve a DID to its registered endpoint and public key."""
        return self._mesh.lookup(did)

    def send(
        self,
        *,
        from_did: str,
        from_private_key_hex: str,
        to_did: str,
        kind: str,
        payload: Any,
    ) -> dict[str, Any]:
        """Seal a message with the sender key and route it to the recipient."""
        message = self._mesh.seal_message(
            from_did=from_did,
            to_did=to_did,
            kind=kind,
            payload=payload,
            private_key_hex=from_private_key_hex,
        )
        routing = self._mesh.route(message)
        return {"message": message, "routing": routing}

    def verify(self, message: dict[str, Any], sender_public_key_hex: str) -> bool:
        """Verify a sealed message against the sender public key."""
        return self._mesh.verify_message(message, sender_public_key_hex)

    def seal_encrypted(
        self,
        *,
        recipient_public_key_hex: str,
        sender_private_key_hex: str,
        plaintext: str,
    ) -> dict[str, str]:
        """End-to-end encrypt a payload to a recipient public key."""
        return self._mesh.encrypt(recipient_public_key_hex, sender_private_key_hex, plaintext)

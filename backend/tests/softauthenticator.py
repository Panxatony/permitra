"""A software authenticator, so the passkey flow can be tested at all.

WebAuthn cannot be exercised with fixtures: every response is signed over a
challenge the server just generated, so a recorded credential is valid exactly
once and never again. Testing the flow therefore means having something that can
actually sign - which is what this is.

Deliberately built here rather than pulled in as a dependency. It is about
eighty lines of well-specified structure (W3C WebAuthn §6.5, §6.1), it needs
only `cryptography` and `cbor2` which are already present, and having it in the
repository means the failure cases can be produced on purpose: a wrong
challenge, a foreign origin, a replayed signature counter. Those are the cases
worth testing, and a black-box helper would not let us build them.

Attestation is "none": Permitra does not verify attestation statements, so
producing a real one would test nothing and cost a lot.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from webauthn.helpers import bytes_to_base64url

AAGUID = b"\x00" * 16          # "no particular authenticator model"
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_ATTESTED_DATA = 0x40


class SoftAuthenticator:
    """One authenticator holding one key pair, as a real security key would."""

    def __init__(self, credential_id: bytes | None = None):
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = credential_id or os.urandom(32)
        self.sign_count = 0

    # ---------- the pieces both ceremonies share ----------

    @staticmethod
    def _client_data(kind: str, challenge: bytes, origin: str) -> bytes:
        return json.dumps({
            "type": kind,
            "challenge": bytes_to_base64url(challenge),
            "origin": origin,
            "crossOrigin": False,
        }, separators=(",", ":")).encode()

    def _authenticator_data(self, rp_id: str, *, attested: bool) -> bytes:
        flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED
        if attested:
            flags |= FLAG_ATTESTED_DATA
        data = hashlib.sha256(rp_id.encode()).digest()
        data += struct.pack(">BI", flags, self.sign_count)
        if attested:
            data += (AAGUID
                     + struct.pack(">H", len(self.credential_id))
                     + self.credential_id
                     + self._cose_public_key())
        return data

    def _cose_public_key(self) -> bytes:
        """The public key in COSE_Key form (RFC 8152) - what the server stores."""
        numbers = self._key.public_key().public_numbers()
        return cbor2.dumps({
            1: 2,    # kty: EC2
            3: -7,   # alg: ES256
            -1: 1,   # crv: P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        })

    # ---------- registration ----------

    def register(self, rp_id: str, challenge: bytes, origin: str) -> dict:
        client_data = self._client_data("webauthn.create", challenge, origin)
        auth_data = self._authenticator_data(rp_id, attested=True)
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(attestation),
            },
            "clientExtensionResults": {},
        }

    # ---------- authentication ----------

    def authenticate(self, rp_id: str, challenge: bytes, origin: str,
                     *, advance_counter: bool = True) -> dict:
        """Signs an assertion.

        `advance_counter=False` reproduces a cloned or replayed authenticator:
        the signature is valid but the counter did not move, which is the one
        signal WebAuthn offers that a credential has been copied.
        """
        if advance_counter:
            self.sign_count += 1
        client_data = self._client_data("webauthn.get", challenge, origin)
        auth_data = self._authenticator_data(rp_id, attested=False)
        signature = self._sign(auth_data + hashlib.sha256(client_data).digest())
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(signature),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }

    def _sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload, ec.ECDSA(hashes.SHA256()))

    def sign_garbage(self, payload: bytes) -> bytes:
        """A syntactically valid signature over the wrong thing.

        Flipping bytes of a real signature usually yields something the parser
        rejects before the cryptography is even checked; signing different data
        exercises the verification itself.
        """
        signature = self._key.sign(b"not the payload", ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(signature)
        return encode_dss_signature(r, s)

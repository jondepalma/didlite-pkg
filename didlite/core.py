# Copyright 2025 Jon DePalma
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder
import multibase
import base64
from typing import Optional, TYPE_CHECKING
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend

if TYPE_CHECKING:
    from didlite.keystore import KeyStore

# W3C Multicodec prefix for Ed25519 public keys (0xed01)
# See: https://github.com/multiformats/multicodec/blob/master/table.csv
ED25519_CODEC = b'\xed\x01'

class AgentIdentity:
    def __init__(
        self,
        seed: Optional[bytes] = None,
        keystore: Optional['KeyStore'] = None,
        identifier: Optional[str] = None
    ):
        """
        Initialize an identity with optional persistent storage.

        Args:
            seed: Optional 32-byte Ed25519 seed. If provided, uses this specific seed.
            keystore: Optional KeyStore instance for persistent identity storage.
            identifier: Optional identifier for keystore lookup (required if keystore provided).

        Behavior:
            - If seed provided: Uses the provided seed (optionally saves to keystore if both provided)
            - If keystore and identifier provided (no seed): Attempts to load from keystore,
              generates new identity and saves to keystore if not found
            - If neither seed nor keystore: Generates new random ephemeral identity

        Raises:
            ValueError: If keystore provided without identifier, or vice versa
        """
        # Validate keystore parameters
        if keystore is not None and identifier is None:
            raise ValueError("identifier is required when keystore is provided")
        if identifier is not None and keystore is None:
            raise ValueError("keystore is required when identifier is provided")

        self.keystore = keystore
        self.identifier = identifier

        # Determine seed source
        if seed is not None:
            # SECURITY: Validate seed before passing to PyNaCl C boundary
            # Reference: SECURITY_FINDINGS.md CRIT-1, Issue #4
            if not isinstance(seed, bytes):
                raise TypeError("seed must be bytes")
            if len(seed) != 32:
                raise ValueError(f"seed must be exactly 32 bytes, got {len(seed)}")
            # Use provided seed
            self.signing_key = SigningKey(seed, encoder=RawEncoder)
            # Optionally save to keystore if configured
            if self.keystore and self.identifier:
                self.keystore.save_seed(self.identifier, seed)
        elif self.keystore and self.identifier:
            # Try to load from keystore
            stored_seed = self.keystore.load_seed(self.identifier)
            if stored_seed:
                self.signing_key = SigningKey(stored_seed, encoder=RawEncoder)
            else:
                # Generate new identity and save to keystore
                self.signing_key = SigningKey.generate()
                seed_bytes = bytes(self.signing_key)[:32]  # Extract seed
                self.keystore.save_seed(self.identifier, seed_bytes)
        else:
            # Generate ephemeral identity
            self.signing_key = SigningKey.generate()

        self.verify_key = self.signing_key.verify_key
        self.did = self._derive_did()

    def _derive_did(self) -> str:
        """Derive the did:key string from the public key."""
        # 1. Get raw bytes
        pub_bytes = self.verify_key.encode(encoder=RawEncoder)
        # 2. Prepend the Multicodec identifier
        prefixed_bytes = ED25519_CODEC + pub_bytes
        # 3. Encode with Base58-BTC (z-prefix) using Multibase
        mb_key = multibase.encode('base58btc', prefixed_bytes)
        # 4. Format as DID
        return f"did:key:{mb_key.decode('utf-8')}"

    def sign(self, message: bytes) -> bytes:
        """Sign raw bytes."""
        return self.signing_key.sign(message).signature

    def to_jwk(self, include_private: bool = True) -> dict:
        """
        Export the key as a JSON Web Key (JWK).

        Args:
            include_private: If True, exports private key material (default: True)

        Returns:
            A dictionary containing the JWK representation

        Note:
            JWK format for Ed25519 uses:
            - kty: "OKP" (Octet Key Pair)
            - crv: "Ed25519"
            - x: base64url-encoded public key (32 bytes)
            - d: base64url-encoded private key (32 bytes, only if include_private=True)
        """
        # Get public key bytes
        public_key_bytes = self.verify_key.encode(encoder=RawEncoder)

        # Base64url encode without padding
        x = base64.urlsafe_b64encode(public_key_bytes).rstrip(b'=').decode('utf-8')

        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x
        }

        if include_private:
            # Get private key bytes (seed)
            private_key_bytes = bytes(self.signing_key)[:32]  # First 32 bytes are the seed
            d = base64.urlsafe_b64encode(private_key_bytes).rstrip(b'=').decode('utf-8')
            jwk["d"] = d

        return jwk

    @classmethod
    def from_jwk(cls, jwk: dict) -> 'AgentIdentity':
        """
        Import an AgentIdentity from a JSON Web Key (JWK).

        Args:
            jwk: A dictionary containing the JWK representation

        Returns:
            A new AgentIdentity instance

        Raises:
            ValueError: If the JWK is invalid or missing required fields
        """
        # Validate JWK format
        if jwk.get("kty") != "OKP":
            raise ValueError("Invalid JWK: kty must be 'OKP' for Ed25519 keys")
        if jwk.get("crv") != "Ed25519":
            raise ValueError("Invalid JWK: crv must be 'Ed25519'")
        if "d" not in jwk:
            raise ValueError("Invalid JWK: missing private key 'd' field (cannot create AgentIdentity from public key only)")

        # Decode private key (with padding)
        d_padded = jwk["d"] + "=" * (4 - len(jwk["d"]) % 4)
        private_key_bytes = base64.urlsafe_b64decode(d_padded)

        if len(private_key_bytes) != 32:
            raise ValueError(f"Invalid JWK: private key must be 32 bytes, got {len(private_key_bytes)}")

        # Create AgentIdentity from the seed
        return cls(seed=private_key_bytes)

    def to_pem(self, include_private: bool = True) -> str:
        """
        Export the key as a PEM-encoded string.

        Args:
            include_private: If True, exports private key in PEM format (default: True)
                           If False, exports public key only

        Returns:
            A PEM-encoded string

        Note:
            PEM format is the traditional format used by OpenSSL and other tools.
            Private keys use PKCS8 format, public keys use SubjectPublicKeyInfo format.
        """
        if include_private:
            # Get private key bytes (seed)
            private_key_bytes = bytes(self.signing_key)[:32]

            # Create cryptography Ed25519 private key
            crypto_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

            # Serialize to PEM
            pem_bytes = crypto_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            return pem_bytes.decode('utf-8')
        else:
            # Get public key bytes
            public_key_bytes = self.verify_key.encode(encoder=RawEncoder)

            # Create cryptography Ed25519 public key
            crypto_public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

            # Serialize to PEM
            pem_bytes = crypto_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem_bytes.decode('utf-8')

    @classmethod
    def from_pem(cls, pem_string: str) -> 'AgentIdentity':
        """
        Import an AgentIdentity from a PEM-encoded string.

        Args:
            pem_string: A PEM-encoded private key string

        Returns:
            A new AgentIdentity instance

        Raises:
            ValueError: If the PEM is invalid or contains a public key only
        """
        pem_bytes = pem_string.encode('utf-8')

        try:
            # Try to load as private key
            crypto_private_key = serialization.load_pem_private_key(
                pem_bytes,
                password=None,
                backend=default_backend()
            )

            # Verify it's an Ed25519 key
            if not isinstance(crypto_private_key, ed25519.Ed25519PrivateKey):
                raise ValueError("Invalid PEM: key must be Ed25519")

            # Extract the private key bytes (seed)
            private_key_bytes = crypto_private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Create AgentIdentity from the seed
            return cls(seed=private_key_bytes)

        except ValueError as e:
            error_msg = str(e).lower()
            if any(keyword in error_msg for keyword in ["public key", "could not deserialize", "no begin/end delimiters for a private key"]):
                raise ValueError("Invalid PEM: cannot create AgentIdentity from public key only (private key required)")
            raise

def resolve_did_to_key(did: str) -> VerifyKey:
    """
    Static method to 'Resolve' a did:key string back to a Verifiable Public Key.
    No network calls required.
    """
    if not did.startswith("did:key:"):
        raise ValueError("Invalid DID format. Must start with did:key:")

    # Extract the multibase string (everything after 'did:key:')
    mb_string = did.split(":", 2)[2]

    # Decode Multibase
    decoded_bytes = multibase.decode(mb_string)

    # SECURITY: Validate minimum length (2-byte prefix + 32-byte key = 34 total)
    # Reference: SECURITY_FINDINGS.md CRIT-3, Issue #5
    if len(decoded_bytes) < 34:
        raise ValueError(
            f"Invalid DID: decoded key must be at least 34 bytes "
            f"(2 prefix + 32 key), got {len(decoded_bytes)}"
        )

    # SECURITY: Validate multicodec prefix is Ed25519 (0xed01)
    # Reference: SECURITY_FINDINGS.md CRIT-4, Issue #5
    if decoded_bytes[:2] != ED25519_CODEC:
        raise ValueError(
            f"Invalid DID: expected Ed25519 multicodec prefix 0xed01, "
            f"got 0x{decoded_bytes[:2].hex()}"
        )

    # Remove the 2-byte Multicodec prefix
    raw_pub_key = decoded_bytes[2:]

    # SECURITY: Validate key size before passing to PyNaCl C boundary
    # Reference: SECURITY_FINDINGS.md CRIT-2, Issue #5
    if len(raw_pub_key) != 32:
        raise ValueError(
            f"Invalid DID: Ed25519 public key must be 32 bytes, "
            f"got {len(raw_pub_key)}"
        )

    return VerifyKey(raw_pub_key, encoder=RawEncoder)

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder
import multibase
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend

# W3C Multicodec prefix for Ed25519 public keys (0xed01)
# See: https://github.com/multiformats/multicodec/blob/master/table.csv
ED25519_CODEC = b'\xed\x01'

class AgentIdentity:
    def __init__(self, seed=None):
        """
        Initialize an identity.
        If seed is provided (32 bytes), loads existing identity.
        If None, generates a new random identity.
        """
        if seed:
            self.signing_key = SigningKey(seed, encoder=RawEncoder)
        else:
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
    
    # Remove the 2-byte Multicodec prefix (0xed01)
    # In a full lib, we would check these bytes to ensure it's Ed25519
    raw_pub_key = decoded_bytes[2:]
    
    return VerifyKey(raw_pub_key, encoder=RawEncoder)

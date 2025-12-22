from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder
import multibase
import base64

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

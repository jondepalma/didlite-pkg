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

"""Key storage backends for persistent identity management"""

from __future__ import annotations

from abc import ABC, abstractmethod
import os
import json
import base64
from typing import Optional, TYPE_CHECKING

# SECURITY: Lazy import for cryptography dependency (lite philosophy)
# Reference: PHASE_5 VULN-3, Issue #35
# Only imported when FileKeyStore is used, not required for Memory/Env stores
#
# PyO3 Compatibility: Import at module level (not in functions) to avoid
# reinitialization errors with pytest --import-mode=importlib
if TYPE_CHECKING:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Lazy singleton pattern - import once on first FileKeyStore use
_crypto_imported = False
_Fernet = None
_hashes = None
_PBKDF2HMAC = None

def _ensure_crypto_imported():
    """Import cryptography modules once on first use"""
    global _crypto_imported, _Fernet, _hashes, _PBKDF2HMAC
    if not _crypto_imported:
        from cryptography.fernet import Fernet as FernetClass
        from cryptography.hazmat.primitives import hashes as hashes_module
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as PBKDF2HMACClass

        _Fernet = FernetClass
        _hashes = hashes_module
        _PBKDF2HMAC = PBKDF2HMACClass
        _crypto_imported = True


class KeyStore(ABC):
    """
    Abstract base class for key storage backends.

    Implementations provide different storage mechanisms for Ed25519 seeds,
    enabling persistent identity across application restarts.
    """

    @abstractmethod
    def save_seed(self, identifier: str, seed: bytes) -> None:
        """
        Save a 32-byte Ed25519 seed.

        Args:
            identifier: Unique identifier for this seed (e.g., agent name, DID)
            seed: 32-byte Ed25519 seed

        Raises:
            ValueError: If seed is not exactly 32 bytes
        """
        pass

    @abstractmethod
    def load_seed(self, identifier: str) -> Optional[bytes]:
        """
        Load a previously saved seed.

        Args:
            identifier: Unique identifier for the seed to load

        Returns:
            32-byte Ed25519 seed, or None if not found

        Raises:
            ValueError: If stored seed is corrupted or invalid
        """
        pass

    @abstractmethod
    def delete_seed(self, identifier: str) -> bool:
        """
        Delete a saved seed.

        Args:
            identifier: Unique identifier for the seed to delete

        Returns:
            True if seed was deleted, False if it didn't exist
        """
        pass


class MemoryKeyStore(KeyStore):
    """
    In-memory key storage for testing and ephemeral use.

    Seeds are stored in memory and lost when the process exits.
    Useful for testing or temporary identities.
    """

    def __init__(self):
        self._storage = {}

    def save_seed(self, identifier: str, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError(f"Seed must be exactly 32 bytes, got {len(seed)}")
        self._storage[identifier] = seed

    def load_seed(self, identifier: str) -> Optional[bytes]:
        return self._storage.get(identifier)

    def delete_seed(self, identifier: str) -> bool:
        if identifier in self._storage:
            del self._storage[identifier]
            return True
        return False


class EnvKeyStore(KeyStore):
    """
    Environment variable key storage for containerized deployments.

    Seeds are stored in environment variables (base64-encoded).
    Suitable for Docker, Kubernetes, and cloud deployments where
    environment variables are the standard secret management approach.

    Security Note: Environment variables are accessible to the process
    and may appear in process listings. Use with appropriate container
    security (secrets management, restricted process access).
    """

    def __init__(self, prefix: str = "DIDLITE_SEED_"):
        """
        Initialize environment variable key store.

        Args:
            prefix: Prefix for environment variable names (default: "DIDLITE_SEED_")
        """
        self.prefix = prefix

    def save_seed(self, identifier: str, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError(f"Seed must be exactly 32 bytes, got {len(seed)}")

        # Encode seed as base64 for environment variable storage
        encoded = base64.b64encode(seed).decode('ascii')
        env_var = f"{self.prefix}{identifier.upper()}"
        os.environ[env_var] = encoded

    def load_seed(self, identifier: str) -> Optional[bytes]:
        env_var = f"{self.prefix}{identifier.upper()}"
        encoded = os.environ.get(env_var)

        if encoded is None:
            return None

        try:
            seed = base64.b64decode(encoded)
            if len(seed) != 32:
                raise ValueError(f"Stored seed must be 32 bytes, got {len(seed)}")
            return seed
        except ValueError as e:
            # Re-raise our own controlled error messages
            if "Stored seed must be 32 bytes" in str(e):
                raise
            # SECURITY: Don't expose env var name or details for other errors
            # Reference: PHASE_1.4_FINDINGS.md LOW-3, Issue #16
            raise ValueError("Failed to decode seed from environment: invalid format")

    def delete_seed(self, identifier: str) -> bool:
        env_var = f"{self.prefix}{identifier.upper()}"
        if env_var in os.environ:
            del os.environ[env_var]
            return True
        return False


class FileKeyStore(KeyStore):
    """
    Encrypted file-based key storage for local deployments.

    Seeds are stored in encrypted files on disk, suitable for edge devices,
    development machines, and environments with persistent filesystem storage.

    Encryption uses Fernet (AES-128-CBC with HMAC) derived from a password
    via PBKDF2-SHA256 with 480,000 iterations.

    Security Notes:
    - Password must be provided and stored securely (e.g., separate config file, HSM)
    - File permissions should restrict access to the application user only
    - Not suitable for scenarios requiring hardware-backed key storage
    """

    def __init__(self, storage_dir: str, password: str, iterations: int = 480000):
        """
        Initialize file-based key store with encryption.

        Args:
            storage_dir: Directory path for storing encrypted seed files
            password: Password/passphrase for encrypting seeds
            iterations: PBKDF2 iterations (default: 480000 per OWASP 2023)

        Raises:
            ValueError: If password is empty or storage_dir cannot be created
        """
        if not password:
            raise ValueError("Password cannot be empty for FileKeyStore")

        self.storage_dir = storage_dir
        self.password = password.encode('utf-8')
        self.iterations = iterations

        # Create storage directory if it doesn't exist
        os.makedirs(storage_dir, mode=0o700, exist_ok=True)

    def _get_file_path(self, identifier: str) -> str:
        """Get the file path for a given identifier"""
        # SECURITY: Use basename to prevent any path traversal
        # Reference: PHASE_1.1_FINDINGS.md MED-2, Issue #10
        safe_id = os.path.basename(identifier)
        # Additionally sanitize special characters
        safe_id = safe_id.replace('/', '_').replace('\\', '_')
        return os.path.join(self.storage_dir, f"{safe_id}.enc")

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        _ensure_crypto_imported()

        kdf = _PBKDF2HMAC(
            algorithm=_hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.password))

    def save_seed(self, identifier: str, seed: bytes) -> None:
        _ensure_crypto_imported()

        if len(seed) != 32:
            raise ValueError(f"Seed must be exactly 32 bytes, got {len(seed)}")

        # Generate random salt for PBKDF2
        salt = os.urandom(16)

        # Derive encryption key
        key = self._derive_key(salt)
        fernet = _Fernet(key)

        # Encrypt seed
        encrypted_seed = fernet.encrypt(seed)

        # Store salt and encrypted seed together
        data = {
            'salt': base64.b64encode(salt).decode('ascii'),
            'encrypted_seed': base64.b64encode(encrypted_seed).decode('ascii')
        }

        file_path = self._get_file_path(identifier)

        # SECURITY: Atomic file creation with secure permissions (prevent TOCTOU race)
        # Reference: PHASE_5 VULN-7, Issue #39
        # Use os.open() with O_CREAT | O_EXCL to create file atomically with mode 0o600
        # This prevents the race condition where file is created with default perms
        # before chmod is called
        fd = os.open(file_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(data, f)
        except:
            # If write fails, close the file descriptor
            os.close(fd)
            raise

    def load_seed(self, identifier: str) -> Optional[bytes]:
        _ensure_crypto_imported()

        file_path = self._get_file_path(identifier)

        if not os.path.exists(file_path):
            return None

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # Decode salt and encrypted seed
            salt = base64.b64decode(data['salt'])
            encrypted_seed = base64.b64decode(data['encrypted_seed'])

            # Derive decryption key
            key = self._derive_key(salt)
            fernet = _Fernet(key)

            # Decrypt seed
            seed = fernet.decrypt(encrypted_seed)

            if len(seed) != 32:
                raise ValueError(f"Decrypted seed must be 32 bytes, got {len(seed)}")

            return seed

        except ValueError as e:
            # Re-raise our own controlled error messages
            if "Decrypted seed must be 32 bytes" in str(e):
                raise
            # SECURITY: Sanitize other errors to prevent path disclosure
            # Reference: PHASE_1.4_FINDINGS.md LOW-2, Issue #15
            raise ValueError(f"Failed to load seed: {type(e).__name__}")
        except Exception as e:
            # SECURITY: Sanitize all other exceptions
            # Reference: PHASE_1.4_FINDINGS.md LOW-2, Issue #15
            raise ValueError(f"Failed to load seed: {type(e).__name__}")

    def delete_seed(self, identifier: str) -> bool:
        file_path = self._get_file_path(identifier)

        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        return False

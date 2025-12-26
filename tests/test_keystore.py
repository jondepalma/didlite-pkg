"""Unit tests for didlite.keystore module"""

import pytest
import os
import tempfile
import shutil
from didlite.keystore import KeyStore, MemoryKeyStore, EnvKeyStore, FileKeyStore
from didlite.core import AgentIdentity


class TestMemoryKeyStore:
    """Tests for MemoryKeyStore"""

    def test_save_and_load_seed(self):
        """Test saving and loading a seed"""
        store = MemoryKeyStore()
        seed = os.urandom(32)

        store.save_seed("test_agent", seed)
        loaded = store.load_seed("test_agent")

        assert loaded == seed

    def test_load_nonexistent_seed(self):
        """Test loading a seed that doesn't exist"""
        store = MemoryKeyStore()

        loaded = store.load_seed("nonexistent")
        assert loaded is None

    def test_delete_seed(self):
        """Test deleting a seed"""
        store = MemoryKeyStore()
        seed = os.urandom(32)

        store.save_seed("test_agent", seed)
        assert store.delete_seed("test_agent") is True
        assert store.load_seed("test_agent") is None

    def test_delete_nonexistent_seed(self):
        """Test deleting a seed that doesn't exist"""
        store = MemoryKeyStore()

        assert store.delete_seed("nonexistent") is False

    def test_invalid_seed_size(self):
        """Test that invalid seed size raises error"""
        store = MemoryKeyStore()

        with pytest.raises(ValueError, match="Seed must be exactly 32 bytes"):
            store.save_seed("test", b"too_short")

    def test_multiple_seeds(self):
        """Test storing multiple seeds"""
        store = MemoryKeyStore()
        seed1 = os.urandom(32)
        seed2 = os.urandom(32)

        store.save_seed("agent1", seed1)
        store.save_seed("agent2", seed2)

        assert store.load_seed("agent1") == seed1
        assert store.load_seed("agent2") == seed2


class TestEnvKeyStore:
    """Tests for EnvKeyStore"""

    def setup_method(self):
        """Clean up environment variables before each test"""
        # Remove any test environment variables
        for key in list(os.environ.keys()):
            if key.startswith("DIDLITE_SEED_") or key.startswith("TEST_"):
                del os.environ[key]

    def test_save_and_load_seed(self):
        """Test saving and loading a seed from environment"""
        store = EnvKeyStore()
        seed = os.urandom(32)

        store.save_seed("test_agent", seed)
        loaded = store.load_seed("test_agent")

        assert loaded == seed

    def test_custom_prefix(self):
        """Test using a custom environment variable prefix"""
        store = EnvKeyStore(prefix="TEST_SEED_")
        seed = os.urandom(32)

        store.save_seed("myagent", seed)

        # Check that the environment variable was created with correct prefix
        assert "TEST_SEED_MYAGENT" in os.environ
        loaded = store.load_seed("myagent")
        assert loaded == seed

    def test_load_nonexistent_seed(self):
        """Test loading a seed that doesn't exist"""
        store = EnvKeyStore()

        loaded = store.load_seed("nonexistent")
        assert loaded is None

    def test_delete_seed(self):
        """Test deleting a seed from environment"""
        store = EnvKeyStore()
        seed = os.urandom(32)

        store.save_seed("test_agent", seed)
        assert store.delete_seed("test_agent") is True
        assert store.load_seed("test_agent") is None

    def test_invalid_seed_size(self):
        """Test that invalid seed size raises error"""
        store = EnvKeyStore()

        with pytest.raises(ValueError, match="Seed must be exactly 32 bytes"):
            store.save_seed("test", b"too_short")

    def test_identifier_case_insensitive(self):
        """Test that identifiers are stored uppercase"""
        store = EnvKeyStore()
        seed = os.urandom(32)

        store.save_seed("MyAgent", seed)

        # Should be stored as uppercase
        assert "DIDLITE_SEED_MYAGENT" in os.environ

    def test_load_corrupted_seed_wrong_size(self):
        """Test that loading corrupted seed with wrong size raises error (Issue #11)"""
        import base64
        store = EnvKeyStore()

        # Manually set environment variable with wrong-sized seed (16 bytes instead of 32)
        wrong_seed = base64.b64encode(b"a" * 16).decode('ascii')
        os.environ["DIDLITE_SEED_CORRUPTED"] = wrong_seed

        with pytest.raises(ValueError, match="Stored seed must be 32 bytes"):
            store.load_seed("corrupted")

    def test_load_invalid_base64_encoding(self):
        """Test that loading seed with invalid base64 raises error (Issue #11)"""
        store = EnvKeyStore()

        # Set environment variable with invalid base64
        os.environ["DIDLITE_SEED_INVALID"] = "INVALID_BASE64_@@@_NOT_VALID"

        with pytest.raises(ValueError, match="Failed to decode seed"):
            store.load_seed("invalid")


class TestFileKeyStore:
    """Tests for FileKeyStore"""

    def setup_method(self):
        """Create a temporary directory for test files"""
        self.test_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up temporary directory"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_save_and_load_seed(self):
        """Test saving and loading an encrypted seed"""
        store = FileKeyStore(self.test_dir, password="test_password")
        seed = os.urandom(32)

        store.save_seed("test_agent", seed)
        loaded = store.load_seed("test_agent")

        assert loaded == seed

    def test_load_nonexistent_seed(self):
        """Test loading a seed that doesn't exist"""
        store = FileKeyStore(self.test_dir, password="test_password")

        loaded = store.load_seed("nonexistent")
        assert loaded is None

    def test_delete_seed(self):
        """Test deleting an encrypted seed file"""
        store = FileKeyStore(self.test_dir, password="test_password")
        seed = os.urandom(32)

        store.save_seed("test_agent", seed)
        assert store.delete_seed("test_agent") is True
        assert store.load_seed("test_agent") is None

    def test_wrong_password(self):
        """Test that wrong password fails to decrypt"""
        store1 = FileKeyStore(self.test_dir, password="correct_password")
        seed = os.urandom(32)

        store1.save_seed("test_agent", seed)

        # Try to load with wrong password
        store2 = FileKeyStore(self.test_dir, password="wrong_password")
        with pytest.raises(ValueError, match="Failed to load seed"):
            store2.load_seed("test_agent")

    def test_invalid_seed_size(self):
        """Test that invalid seed size raises error"""
        store = FileKeyStore(self.test_dir, password="test_password")

        with pytest.raises(ValueError, match="Seed must be exactly 32 bytes"):
            store.save_seed("test", b"too_short")

    def test_empty_password_raises_error(self):
        """Test that empty password raises error"""
        with pytest.raises(ValueError, match="Password cannot be empty"):
            FileKeyStore(self.test_dir, password="")

    def test_file_permissions(self):
        """Test that encrypted files have secure permissions"""
        store = FileKeyStore(self.test_dir, password="test_password")
        seed = os.urandom(32)

        store.save_seed("test_agent", seed)

        file_path = os.path.join(self.test_dir, "test_agent.enc")
        stat_info = os.stat(file_path)
        permissions = oct(stat_info.st_mode)[-3:]

        # Should be 600 (read/write for owner only)
        assert permissions == "600"

    def test_path_traversal_protection(self):
        """Test that path traversal attempts are sanitized"""
        store = FileKeyStore(self.test_dir, password="test_password")
        seed = os.urandom(32)

        # Try to use path traversal in identifier
        store.save_seed("../../../etc/passwd", seed)

        # Should be saved in the test directory with basename only
        # os.path.basename() strips all directory components (Issue #10)
        expected_file = os.path.join(self.test_dir, "passwd.enc")
        assert os.path.exists(expected_file)

        # Verify it's in the test directory (not traversed)
        assert os.path.dirname(expected_file) == self.test_dir

        # Verify we can load it back
        loaded = store.load_seed("../../../etc/passwd")
        assert loaded == seed

    def test_path_traversal_comprehensive(self):
        """Comprehensive path traversal protection tests (Issue #10)"""
        store = FileKeyStore(self.test_dir, password="test_password")
        seed = os.urandom(32)

        # Test various attack patterns
        attack_patterns = [
            ("../../../etc/passwd", "passwd.enc"),
            ("/tmp/evil", "evil.enc"),
            ("subdir/../../etc/passwd", "passwd.enc"),
            ("./../../etc/shadow", "shadow.enc"),
        ]

        # On Windows, also test Windows-style paths
        if os.name == 'nt':
            attack_patterns.append(("C:\\Windows\\System32\\evil", "evil.enc"))

        for attack, expected in attack_patterns:
            # Save with attack identifier
            store.save_seed(attack, seed)

            # Verify file is created with sanitized name in test_dir
            expected_file = os.path.join(self.test_dir, expected)
            assert os.path.exists(expected_file), f"Expected {expected_file} for attack {attack}"

            # Verify it's in the test directory (not traversed)
            assert os.path.dirname(expected_file) == self.test_dir

            # Verify we can load it back
            loaded = store.load_seed(attack)
            assert loaded == seed

            # Cleanup for next iteration
            os.remove(expected_file)

    def test_multiple_seeds(self):
        """Test storing multiple encrypted seeds"""
        store = FileKeyStore(self.test_dir, password="test_password")
        seed1 = os.urandom(32)
        seed2 = os.urandom(32)

        store.save_seed("agent1", seed1)
        store.save_seed("agent2", seed2)

        assert store.load_seed("agent1") == seed1
        assert store.load_seed("agent2") == seed2

    def test_load_corrupted_file_wrong_seed_size(self):
        """Test that loading file with corrupted seed size raises error (Issue #11)"""
        from cryptography.fernet import Fernet
        import json
        import base64

        store = FileKeyStore(self.test_dir, password="test_password")

        # Create a manually corrupted file with wrong-sized seed
        salt = os.urandom(16)
        key = store._derive_key(salt)
        fernet = Fernet(key)

        # Encrypt a wrong-sized seed (16 bytes instead of 32)
        wrong_seed = b"a" * 16
        encrypted_seed = fernet.encrypt(wrong_seed)

        data = {
            'salt': base64.b64encode(salt).decode('ascii'),
            'encrypted_seed': base64.b64encode(encrypted_seed).decode('ascii')
        }

        file_path = os.path.join(self.test_dir, "corrupted.enc")
        with open(file_path, 'w') as f:
            json.dump(data, f)

        with pytest.raises(ValueError, match="Decrypted seed must be 32 bytes"):
            store.load_seed("corrupted")


class TestAgentIdentityWithKeyStore:
    """Tests for AgentIdentity integration with KeyStore"""

    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        # Clean environment variables
        for key in list(os.environ.keys()):
            if key.startswith("DIDLITE_SEED_"):
                del os.environ[key]

    def teardown_method(self):
        """Clean up test environment"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_agent_with_memory_keystore(self):
        """Test creating agent with MemoryKeyStore"""
        store = MemoryKeyStore()

        # Create agent with keystore
        agent1 = AgentIdentity(keystore=store, identifier="my_agent")
        did1 = agent1.did

        # Create another agent with same identifier - should load same identity
        agent2 = AgentIdentity(keystore=store, identifier="my_agent")
        did2 = agent2.did

        assert did1 == did2

    def test_agent_with_file_keystore(self):
        """Test creating agent with FileKeyStore"""
        store = FileKeyStore(self.test_dir, password="test_password")

        # Create agent with keystore
        agent1 = AgentIdentity(keystore=store, identifier="my_agent")
        did1 = agent1.did

        # Create another agent with same identifier - should load same identity
        agent2 = AgentIdentity(keystore=store, identifier="my_agent")
        did2 = agent2.did

        assert did1 == did2

    def test_agent_with_env_keystore(self):
        """Test creating agent with EnvKeyStore"""
        store = EnvKeyStore()

        # Create agent with keystore
        agent1 = AgentIdentity(keystore=store, identifier="my_agent")
        did1 = agent1.did

        # Create another agent with same identifier - should load same identity
        agent2 = AgentIdentity(keystore=store, identifier="my_agent")
        did2 = agent2.did

        assert did1 == did2

    def test_agent_with_provided_seed_saves_to_keystore(self):
        """Test that providing a seed also saves it to keystore"""
        store = MemoryKeyStore()
        seed = os.urandom(32)

        # Create agent with both seed and keystore
        agent = AgentIdentity(seed=seed, keystore=store, identifier="my_agent")

        # Verify seed was saved to keystore
        loaded_seed = store.load_seed("my_agent")
        assert loaded_seed == seed

    def test_agent_persistence_across_restarts(self):
        """Test that agent identity persists across simulated restarts"""
        store = FileKeyStore(self.test_dir, password="test_password")

        # First "session"
        agent1 = AgentIdentity(keystore=store, identifier="persistent_agent")
        did1 = agent1.did
        message = b"Test message"
        signature1 = agent1.sign(message)

        # Simulate restart - create new agent with same keystore
        agent2 = AgentIdentity(keystore=store, identifier="persistent_agent")
        did2 = agent2.did

        # Should have same DID
        assert did1 == did2

        # Should be able to verify signature from first agent
        agent2.verify_key.verify(message, signature1)

    def test_keystore_without_identifier_raises_error(self):
        """Test that providing keystore without identifier raises error"""
        store = MemoryKeyStore()

        with pytest.raises(ValueError, match="identifier is required when keystore is provided"):
            AgentIdentity(keystore=store)

    def test_identifier_without_keystore_raises_error(self):
        """Test that providing identifier without keystore raises error"""
        with pytest.raises(ValueError, match="keystore is required when identifier is provided"):
            AgentIdentity(identifier="my_agent")

    def test_different_identifiers_produce_different_dids(self):
        """Test that different identifiers in same keystore produce different DIDs"""
        store = MemoryKeyStore()

        agent1 = AgentIdentity(keystore=store, identifier="agent1")
        agent2 = AgentIdentity(keystore=store, identifier="agent2")

        assert agent1.did != agent2.did

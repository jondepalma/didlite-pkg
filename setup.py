from setuptools import setup, find_packages

setup(
    name="didlite",
    version="0.2.2",
    description="Lightweight, web-only DID:KEY (Ed25519) implementation for Agents",
    packages=find_packages(),
    install_requires=[
        "pynacl>=1.5.0",
        "py-multibase>=1.0.0",
        "cryptography>=41.0.0",  # Required for PEM export/import and keystore encryption
    ],
    extras_require={
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "authlib>=1.0.0",  # For integration tests
            "hypothesis>=6.0.0"  # For property-based testing and fuzzing
        ]
    },
    python_requires=">=3.8",
)
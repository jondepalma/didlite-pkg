from setuptools import setup, find_packages

setup(
    name="didlite",
    version="0.1.5",
    description="Lightweight, web-only DID:KEY (Ed25519) implementation for Agents",
    packages=find_packages(),
    install_requires=[
        "pynacl>=1.5.0",
        "py-multibase>=1.0.0",
    ],
    extras_require={
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "authlib>=1.0.0"  # For integration tests
        ]
    },
    python_requires=">=3.8",
)
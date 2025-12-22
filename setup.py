from setuptools import setup, find_packages

setup(
    name="didlite",
    version="0.1.0",
    description="Lightweight, web-only DID:KEY (Ed25519) implementation for Agents",
    packages=find_packages(),
    install_requires=[
        "pynacl>=1.5.0",
        "python-multibase>=1.0.3",
        "python-jose[cryptography]>=3.3.0"  # For standard JWT handling
    ],
    extras_require={
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0"
        ]
    },
    python_requires=">=3.8",
)
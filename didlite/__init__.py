"""
didlite: Lightweight Identity for Agents & IoT
"""

__version__ = "0.1.0"
__author__ = "Jon DePalma"

# Expose the main classes to the top level
from .core import AgentIdentity, resolve_did_to_key
from .jws import create_jws, verify_jws

# Define what happens when someone does `from didlite import *`
__all__ = [
    "AgentIdentity", 
    "resolve_did_to_key", 
    "create_jws", 
    "verify_jws"
]

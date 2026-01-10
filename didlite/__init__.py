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

"""
didlite: Lightweight Identity for Agents & IoT
"""

__version__ = "0.2.5"
__author__ = "Jon DePalma"

# Expose the main classes to the top level
from .core import AgentIdentity, resolve_did_to_key
from .jws import create_jws, verify_jws, extract_signer_did

# Define what happens when someone does `from didlite import *`
__all__ = [
    "AgentIdentity",
    "resolve_did_to_key",
    "create_jws",
    "verify_jws",
    "extract_signer_did"
]

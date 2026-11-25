"""The released JMessage reference client, packaged for the exercise kit.

`Client` is the handout §3 protocol core; `pkcs7_pad`/`pkcs7_unpad` are the
Part 0 answer key. The shared wire/codec/transport support is vendored under
`jmessage_reference._support` so this package is self-contained and never
collides with the student's top-level `jmessage_support` or `padding`.
"""

from .protocol import Client
from .padding import pkcs7_pad, pkcs7_unpad

__all__ = ["Client", "pkcs7_pad", "pkcs7_unpad"]

"""Staff reference for handout Part 0: PKCS#7 padding.

Block sizes 1 through 255 are supported. Padding always appends between 1 and
block_size bytes, so an aligned input gains a full block. Unpadding raises
ValueError for an invalid block size, empty or non-aligned input, or padding
bytes that are not all equal to the pad length.

Where it sits
-------------
The record layer of suite JM1 (spec §7.1-§7.2) is its only user:

    protect():    plaintext || T  --pkcs7_pad-->  P  --AES-128-CBC-->  ciphertext
    unprotect():  ciphertext  --AES-128-CBC-->  P  --pkcs7_unpad-->  plaintext || T

What to compare with your own version
-------------------------------------
* The pad length is computed so it is never 0: an aligned input gets a whole
  block, as both the handout and spec §7.1 require (the Appendix A vector
  "16 bytes: JM1 P gets a full 16-byte padding block" shows it on the wire).
* Unpadding checks, in order: the block size; that the input is nonempty and
  block-aligned; that the last byte is a possible pad length (1..block_size);
  and that every pad byte equals that length. Each failure is a ValueError,
  which `unprotect` in protocol.py maps to the §7.2 step 3.2 outcome.
* Both functions return `bytes` even if given a `bytearray` or `memoryview`.
"""


def _check_block_size(block_size):
    """Raise ValueError unless `block_size` is an `int` from 1 to 255.

    The upper bound is 255 because the pad length is stored in one byte. The
    `type(...) is not int` test also rejects `True` (a bool) and floats.
    """
    if type(block_size) is not int or not 1 <= block_size <= 255:
        raise ValueError("block size must be an integer from 1 to 255")


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Return `data` followed by N bytes of value N, where 1 <= N <= block_size.

    Args:
        data: the bytes to pad (any length, including empty).
        block_size: the block size in bytes, 1..255.

    Returns:
        New `bytes` whose length is the next multiple of `block_size` that is
        strictly greater than `len(data)`.

    Raises:
        ValueError: for an invalid block size.

    Example: 15 bytes pad with one 0x01; 16 bytes pad with sixteen 0x10.
    """
    _check_block_size(block_size)
    # len % block_size is 0..block_size-1, so pad_len is 1..block_size. When
    # the input is aligned the remainder is 0 and a full block is added.
    pad_len = block_size - (len(data) % block_size)   # 1..block_size, never 0
    return bytes(data) + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Remove and check PKCS#7 padding.

    Args:
        data: padded bytes; must be a nonempty multiple of `block_size`.
        block_size: the block size in bytes, 1..255.

    Returns:
        The bytes before the padding (possibly empty).

    Raises:
        ValueError: for an invalid block size; empty or non-aligned input; a
            last byte of 0 or greater than `block_size`; or any of the last
            N bytes differing from N. These are the conditions of spec §7.2
            step 3.2.
    """
    _check_block_size(block_size)
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("padded input must be a nonempty multiple of the block size")
    pad_len = data[-1]
    # 0 is never a valid pad length (padding always adds at least one byte),
    # and a length above block_size cannot have come from pkcs7_pad.
    if not 1 <= pad_len <= block_size:
        raise ValueError("invalid padding length")
    # Every one of the last pad_len bytes must equal pad_len, not only the last.
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding bytes")
    return bytes(data[:-pad_len])

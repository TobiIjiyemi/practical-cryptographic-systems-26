"""JMessage 2026 staff reference implementation (specification §§5-7).

What this file is
-----------------
The staff answer key for the protocol core: a complete `Client` with the
handout §3 interface, following the specification literally. The autograder
and graders compare student clients against it. Students receive it after the
client checkpoint, as a worked example of the specification; until then it is
staff only. It is written for clarity rather than speed. Section references in
comments are to specification.md unless they say "handout".

Where it sits
-------------

      driver (client.py / Runtime) or tests (testing.Network, grading harness)
                    |  start_handshake / send_text / receive / ...
                    v
      Client  (this file: state machine, §§5, 6.4-6.9, 7)
        |  calls
        +-- pure functions (this file): fingerprint_of, th_r, th_i, th_keys,
        |   x25519_shared, key_schedule_ikm, derive_okm, split_okm,
        |   protect, protected_length_ok, unprotect, reject_signed_bytes
        +-- jmessage_support.messages: encode_* / parse_* (wire format)
        +-- padding.pkcs7_pad / pkcs7_unpad (JM1 only)
        +-- cryptography: Ed25519, X25519, ML-KEM-768, HKDF, AES-GCM, AES-CBC

Layout:
  * constants and labels (§§3, 6)
  * pure message encoders/parsers (§§6.3-6.8, 7.1, 7.3)
  * pure transcript, key-schedule and record functions (§§6.5-6.7, 7.1-7.2)
  * entropy hook (fixed values for test vectors)
  * the Client state machine (§§5, 6.4-6.9, 7)

The pure functions are module-level so that the test-vector generator and the
conformance tests can call them with explicit inputs.

How to read it (suggested order)
--------------------------------
1. The labels, then `th_r` / `th_i` / `th_keys` and `reject_signed_bytes`:
   exactly which bytes each hash and signature covers.
2. `key_schedule_ikm`, `derive_okm`, `split_okm`: §6.7 in three steps.
3. `protect` and `unprotect`: §7.1 and §7.2 for both suites.
4. `Client._initiate`, `_on_hello`, `_on_reply`, `_on_finish`, `_on_reject`:
   the handshake, in the order messages flow.
5. `_on_data`, `_on_control`, `_send_data`: records after establishment.
6. The helpers at the end, especially `_pending_for` (which enforces "only in
   this state, only from this peer") and `_handshake_failed`.

Comments of the form "if omitted, ..." say what would go wrong for
interoperability or conformance without that line. Where the spec allows a
choice (a MAY), the comment says which option this implementation takes.

What it deliberately does NOT do
--------------------------------
No HTTP, JSON, base64, threads or terminal output: it receives decoded bytes
and reports everything through `emit` (handout §3). It keeps all state in
memory (§6.9 allows that).
"""

from dataclasses import dataclass, field
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ._support.codec import (DecodeError, Reader, decode_text, encode_text, str8, u8, u16,
                                    u32, u64, username)
from ._support.transport import PeerKeyUnavailable
from ._support.messages import (  # wire format is supplied to students too
    JM1, JM2, PREFERENCE, REASON_HYBRID_INVALID, REASON_NO_COMMON_SUITE,
    SID_LEN, X25519_LEN, MLKEM_EK_LEN, MLKEM_CT_LEN, SIG_LEN,
    T_HELLO, T_REPLY, T_FINISH, T_REJECT, T_DATA, T_RECEIPT, T_RESEND,
    Hello, Reply, Finish, Reject, Data, Control,
    encode_hello, parse_hello, encode_reply_core, parse_reply, encode_finish, parse_finish,
    encode_reject, parse_reject, encode_data, parse_data, encode_control, parse_control)

from .padding import pkcs7_pad, pkcs7_unpad

# ---------------------------------------------------------------------------
# Constants (§§2, 3, 6)
# Sizes and limits not already defined in jmessage_support.messages, and the
# exact label strings that go into every hash and signature.
# ---------------------------------------------------------------------------

# §6.5 step 1: "a supported suite it offered". The set of suites this client
# implements, used to reject a REPLY naming any other value.
SUPPORTED = frozenset(PREFERENCE)



GCM_TAG_LEN = 16                 # §7.1: AES-GCM tag at the end of `protected`
MAC_LEN = 32                     # §7.1: HMAC-SHA256 output T
BLOCK = 16                       # AES block size: CBC IV length and PKCS#7 block (§7.1)
MAX_SEQ = 2**64 - 1              # Appendix B counter exhaustion

HANDSHAKE_TIMEOUT = 60.0         # Appendix B handshake expiry, seconds of now()

# §3: quoted strings are exact ASCII bytes. Note the trailing space in the
# HKDF info label.
# Each hash and signature has its own label (domain separation), so a value
# computed for one purpose can never be valid for another: a responder
# signature over TH_R, for example, can never verify as a REJECT signature.
# A single wrong character here breaks interoperability with every peer,
# while two copies of the same wrong code still agree with each other.
LABEL_FINGERPRINT = b"JMessage-2026 fingerprint"
LABEL_TH_R = b"JMessage-2026 TH-R"
LABEL_TH_I = b"JMessage-2026 TH-I"
LABEL_TH_KEYS = b"JMessage-2026 keys"
LABEL_SIG_R = b"JMessage-2026 responder"
LABEL_SIG_I = b"JMessage-2026 initiator"
LABEL_REJECT = b"JMessage-2026 reject"
LABEL_HKDF_INFO = b"JMessage-2026 "

# §6.9 roles and pending states. ("established" is not a value here: an
# established session lives in Client._sessions instead of Client._pending.)
ROLE_I, ROLE_R = "I", "R"
PENDING_REPLY, PENDING_FINISH = "pending-reply", "pending-finish"


# ---------------------------------------------------------------------------
# §5 Fingerprints
# ---------------------------------------------------------------------------

def fingerprint_of(id_pk: bytes) -> str:
    """§5: first 10 bytes of SHA256(label || idPK), as spaced uppercase hex.

    Args:
        id_pk: a raw 32-byte Ed25519 public key.

    Returns:
        A `str` such as "F1 26 31 C6 16 5D E6 90 8D 9A" (Appendix A, alice).

    Interoperability: users compare these strings by eye or by voice, so the
    format matters as much as the bytes. `{b:02X}` gives two uppercase hex
    digits, keeping a leading zero ("0C", not "C").
    """
    digest = hashlib.sha256(LABEL_FINGERPRINT + id_pk).digest()[:10]
    return " ".join(f"{b:02X}" for b in digest)


# ---------------------------------------------------------------------------
# Message encoders and parsers live in jmessage_support.messages (supplied to
# students). Only the REJECT *signed bytes* are defined here: what a signature
# covers is protocol logic, not wire format.
# ---------------------------------------------------------------------------

def reject_signed_bytes(sid, reason, initiator):
    """§6.8: the message the responder signs for a REJECT.

    Args:
        sid: the 16-byte session identifier from the rejected HELLO.
        reason: the `int` reason code.
        initiator: the initiator's username (`str`).

    Returns:
        "JMessage-2026 reject" || sid || u8 reason || str8(I), as `bytes`.

    Note that this is not the REJECT body: the body has the type byte and no
    label or username. Both sides must build these exact bytes, the responder
    to sign and the initiator to verify; including str8(I) means a REJECT
    addressed to one initiator does not verify for another.
    """
    # §6.8 signed message: "JMessage-2026 reject" || sid || u8 reason || str8(I)
    return LABEL_REJECT + sid + u8(reason) + str8(initiator)


# ---------------------------------------------------------------------------
# Transcripts and key schedule (§§6.5-6.7)
# Three transcript hashes over the same ingredients with different labels and
# different final components, followed by the HKDF key schedule.
#
#   TH_R = SHA256(label_R || str8(I) || str8(R) || HELLO || REPLY_core)   (§6.5)
#   TH_I = SHA256(label_I || str8(I) || str8(R) || HELLO || REPLY)        (§6.6)
#   TH   = SHA256(label_K || str8(I) || str8(R) || HELLO || REPLY)        (§6.7)
#
# The usernames are always in role order (initiator first), whichever side is
# computing. Getting that backwards breaks interoperability, yet two copies
# of the same mistaken client still agree with each other.
# ---------------------------------------------------------------------------

def th_r(initiator, responder, hello, reply_core):
    """§6.5 TH_R: what the responder signs in REPLY.

    Args:
        initiator, responder: usernames in role order (`str`).
        hello: the exact HELLO bytes. The responder uses the bytes it
            received; the initiator uses the bytes it sent (§6.5 step 2).
        reply_core: REPLY_core, the REPLY without sig_R.

    Returns:
        The 32-byte SHA-256 digest.

    REPLY_core rather than REPLY, because the signature cannot cover itself.
    """
    # §6.5 TH_R = SHA256("JMessage-2026 TH-R" || str8(I) || str8(R) || HELLO || REPLY_core)
    return hashlib.sha256(LABEL_TH_R + str8(initiator) + str8(responder) + hello
                          + reply_core).digest()


def th_i(initiator, responder, hello, reply):
    """§6.6 TH_I: what the initiator signs in FINISH.

    Args:
        initiator, responder: usernames in role order.
        hello: the exact HELLO bytes (sent by I, received by R).
        reply: the complete REPLY bytes, including sig_R (received by I, sent
            by R).

    Returns:
        The 32-byte SHA-256 digest.
    """
    # §6.6 TH_I = SHA256("JMessage-2026 TH-I" || str8(I) || str8(R) || HELLO || REPLY)
    return hashlib.sha256(LABEL_TH_I + str8(initiator) + str8(responder) + hello
                          + reply).digest()


def th_keys(initiator, responder, hello, reply):
    """§6.7 TH: the transcript hash used as the HKDF salt.

    Args and return value as for `th_i`, with the "keys" label.

    Because the salt depends on the whole HELLO and REPLY, the two sides
    derive the same keys only if they agree on every byte of both messages.
    """
    # §6.7 TH = SHA256("JMessage-2026 keys" || str8(I) || str8(R) || HELLO || REPLY)
    return hashlib.sha256(LABEL_TH_KEYS + str8(initiator) + str8(responder) + hello
                          + reply).digest()


def x25519_shared(private_key, peer_public_bytes):
    """§2: X25519 with the all-zero check. Raises ValueError on any failure.

    Args:
        private_key: this side's ephemeral `X25519PrivateKey`.
        peer_public_bytes: the peer's 32-byte X25519 public key from the wire.

    Returns:
        The 32-byte shared secret `dh`.

    Raises:
        ValueError: if the public key cannot be imported, the library refuses
            the exchange, or the result is all zeros (§2 "Clients MUST reject
            an X25519 shared secret that is all zeros"). Callers treat this as
            a handshake failure, never as a reason for suite fallback (§2).
    """
    shared = private_key.exchange(X25519PublicKey.from_public_bytes(peer_public_bytes))
    if not any(shared):     # the library already refuses this; keep the spec check visible
        raise ValueError("all-zero X25519 shared secret")
    return shared


def key_schedule_ikm(suite, dh, ss_pq):
    """§6.7 input keying material for HKDF.

    Args:
        suite: JM1 or JM2.
        dh: the 32-byte X25519 shared secret.
        ss_pq: the 32-byte ML-KEM shared secret for JM2; b"" for JM1.

    Returns:
        `ss_pq || dh` for JM2 (64 bytes), or `dh` for JM1 (32 bytes).

    The order matters: the post-quantum secret comes first. Swapping it gives
    different keys and no interoperability.
    """
    # §6.7 ikm = ss_pq || dh (JM2); ikm = dh (JM1)
    return ss_pq + dh if suite == JM2 else dh


def derive_okm(suite, ikm, th):
    """§6.7 HKDF-SHA256 with salt = TH and info = "JMessage-2026 " || u16 suite.

    Args:
        suite: JM1 or JM2; selects the info string and the output length.
        ikm: from `key_schedule_ikm`.
        th: from `th_keys`, used as the salt.

    Returns:
        OKM: 64 bytes for JM2, 96 bytes for JM1 (the §6.7 table).

    The info string includes the suite code, so the two suites can never
    produce the same keys even from identical inputs. Note the space before
    the suite bytes (§3); Appendix A shows hkdf_info as
    4a4d6573736167652d32303236200001 for JM1.
    """
    # §6.7 OKM = HKDF-SHA256(salt = TH, ikm, info = "JMessage-2026 " || u16 suite, L)
    length = 64 if suite == JM2 else 96
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=th,
                info=LABEL_HKDF_INFO + u16(suite)).derive(ikm)


@dataclass(frozen=True)
class DirectionKeys:
    """Keys for one traffic direction. JM2 uses only `enc` (k); JM1 uses enc and mac.

    Attributes:
        enc: the AES key: 32 bytes for JM2 (k_IR or k_RI), 16 for JM1
            (enc_IR or enc_RI).
        mac: the 32-byte HMAC key for JM1 (mac_IR or mac_RI); None for JM2.
    """
    enc: bytes
    mac: bytes = None


def split_okm(suite, okm):
    """§6.7 split. Returns (IR, RI) direction keys.

    Args:
        suite: JM1 or JM2.
        okm: the HKDF output from `derive_okm`.

    Returns:
        A pair `(ir, ri)` of `DirectionKeys`: IR protects records from
        initiator to responder, RI from responder to initiator. The initiator
        sends with IR and receives with RI; the responder does the opposite.

    The byte boundaries are fixed by the §6.7 table. An off-by-one here still
    "works" between two copies of the same code.
    """
    if suite == JM2:
        return DirectionKeys(okm[0:32]), DirectionKeys(okm[32:64])          # k_IR, k_RI
    return (DirectionKeys(okm[0:16], okm[16:48]),                           # enc_IR, mac_IR
            DirectionKeys(okm[48:64], okm[64:96]))                          # enc_RI, mac_RI


# ---------------------------------------------------------------------------
# Record protection (§§7.1-7.2)
# `protect` builds the `protected` field of DATA; `unprotect` reverses it and
# classifies the result into one of the three §7.2 outcomes below.
# ---------------------------------------------------------------------------

# §7.2 outcomes:
#   OK           authentication succeeded (step 4): RECEIPT, then deliver text
#   AUTH_FAILED  authentication failed (step 5): RESEND, recv_seq unchanged
#   MALFORMED    JM1 padding invalid (step 3.2): silent discard
OK, AUTH_FAILED, MALFORMED = "ok", "auth-failed", "malformed"   # §7.2 outcomes


def jm2_nonce(seq):
    """§7.1 JM2 nonce: four zero bytes then the 8-byte big-endian sequence number.

    The 12-byte nonce is unique per record under a given direction key
    because `seq` is never reused in that direction (§7.1), and the two
    directions have different keys, so the same `seq` value in opposite
    directions is not a nonce reuse.
    """
    return u32(0) + u64(seq)                     # §7.1 nonce = u32 0 || u64 seq


def protect(suite, keys, sid, seq, plaintext, iv=None):
    """§7.1: build `protected` for DATA. JM1 needs a fresh 16-byte IV.

    Args:
        suite: the session's suite.
        keys: the sender's `DirectionKeys` (IR if sending as initiator).
        sid: the 16-byte session identifier.
        seq: the record's sequence number.
        plaintext: the UTF-8 text bytes (at most 4096).
        iv: for JM1, 16 fresh random bytes from the entropy hook; ignored for
            JM2, which has no IV.

    Returns:
        JM2: ciphertext || 16-byte tag, with no nonce prepended.
        JM1: iv || AES-128-CBC(enc, iv, PKCS7(plaintext || T)).
    """
    if suite == JM2:
        # protected = ciphertext || tag; aad = sid || u64 seq; no nonce prepended
        # The AAD binds the record to its session and position: a record moved
        # to another sid or seq fails authentication at the receiver.
        return AESGCM(keys.enc).encrypt(jm2_nonce(seq), plaintext, sid + u64(seq))
    # JM1 MAC-then-encrypt
    # T = HMAC-SHA256(mac, sid || u64 seq || plaintext): the MAC input is the
    # same session-and-position binding as JM2's AAD, plus the plaintext.
    tag = hmac.new(keys.mac, sid + u64(seq) + plaintext, hashlib.sha256).digest()
    # P = PKCS7-Pad(plaintext || T, 16): the tag is inside the padding, and
    # both are encrypted.
    padded = pkcs7_pad(plaintext + tag, BLOCK)
    encryptor = Cipher(algorithms.AES(keys.enc), modes.CBC(iv)).encryptor()
    # The IV is sent in the clear in front of the ciphertext (§7.1).
    return iv + encryptor.update(padded) + encryptor.finalize()


def protected_length_ok(suite, protected):
    """§7.2 step 1 structural length checks.

    Returns:
        True if `protected` could be a well-formed record for `suite`: JM2
        needs at least the 16-byte tag; JM1 needs a whole number of 16-byte
        blocks and at least two of them (the IV plus one ciphertext block).

    A record failing this is discarded silently, before any decryption. If
    omitted, a short JM1 record would reach AES-CBC and raise a library error
    inside `receive`, which handout §3 forbids.
    """
    if suite == JM2:
        return len(protected) >= GCM_TAG_LEN
    return len(protected) >= 32 and len(protected) % BLOCK == 0


def unprotect(suite, keys, sid, seq, protected):
    """§7.2 steps 2-3. Returns (outcome, plaintext-or-None).

    Callers must already have applied the step-1 length, session, peer and
    sequence checks.

    Args:
        suite: the session's suite.
        keys: the receiver's view of the sender's `DirectionKeys` (RI if
            receiving as initiator).
        sid, seq: from the DATA header; they are authenticated here (JM2 AAD,
            JM1 MAC input), so a header that was altered fails.
        protected: the rest of the DATA body.

    Returns:
        `(OK, plaintext_bytes)`, `(AUTH_FAILED, None)` or `(MALFORMED, None)`.
        This function never touches session state; `_on_data` acts on the
        outcome.
    """
    if suite == JM2:
        try:
            return OK, AESGCM(keys.enc).decrypt(jm2_nonce(seq), protected, sid + u64(seq))
        except InvalidTag:
            return AUTH_FAILED, None                     # step 2 -> step 5
    # JM1: the steps of §7.2 step 3, in the order the spec lists them.
    iv, ciphertext = protected[:BLOCK], protected[BLOCK:]
    decryptor = Cipher(algorithms.AES(keys.enc), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()      # step 3.1
    try:
        unpadded = pkcs7_unpad(padded, BLOCK)                         # step 3.2
    except ValueError:
        return MALFORMED, None                                        # silent discard
    # Fewer than 32 bytes left cannot hold T; §7.2 classifies this as an
    # authentication failure (step 5), not as malformed.
    if len(unpadded) < MAC_LEN:                                       # step 3.3
        return AUTH_FAILED, None
    plaintext, tag = unpadded[:-MAC_LEN], unpadded[-MAC_LEN:]         # step 3.4
    expected = hmac.new(keys.mac, sid + u64(seq) + plaintext, hashlib.sha256).digest()
    # §7.2 step 3.4 requires a constant-time comparison. `tag == expected` may
    # stop at the first differing byte, so its running time depends on how
    # many leading bytes match; compare_digest does not.
    if not hmac.compare_digest(tag, expected):                        # constant time
        return AUTH_FAILED, None
    return OK, plaintext


# ---------------------------------------------------------------------------
# Entropy hook
# Every random value the client needs comes through one small object, so tests
# and the Appendix A generator can substitute fixed values without patching
# the library.
# ---------------------------------------------------------------------------

class SystemEntropy:
    """CSPRNG-backed source of sids, IVs, ephemeral keys and Encaps (§2).

    Tests and the vector generator replace `client.entropy` with an object that
    has the same five methods and returns fixed values.
    """

    def sid(self):
        """A fresh random 16-byte session identifier (§6.3), from os.urandom."""
        return os.urandom(SID_LEN)

    def iv(self):
        """A fresh random 16-byte CBC IV for one JM1 record (§7.1)."""
        return os.urandom(BLOCK)

    def x25519(self):
        """A fresh ephemeral X25519 private key, one per handshake per side (§6.3, §6.4)."""
        return X25519PrivateKey.generate()

    def mlkem(self):
        """A fresh ML-KEM-768 private key (dk_I) for one JM2 offer (§6.3)."""
        return MLKEM768PrivateKey.generate()

    def encapsulate(self, ek_pub):
        """§6.4 step 4: ML-KEM.Encaps. A hook only because the library exposes
        no way to supply the encapsulation randomness, which test vectors need.

        Args:
            ek_pub: the initiator's `MLKEM768PublicKey`.

        Returns:
            `(ss_pq, ct)`: the 32-byte shared secret and the 1088-byte
            ciphertext.
        """
        return ek_pub.encapsulate()


# ---------------------------------------------------------------------------
# Handshake and session state (§6.9)
# Three record types: Attempt (one user-visible handshake attempt, shared by
# its fallback retry), Pending (a handshake in progress, either role) and
# Session (an established session).
# ---------------------------------------------------------------------------

@dataclass
class Attempt:
    """One user-visible handshake attempt; its single fallback retry shares it (§6.9).

    Attributes:
        initial_jm1_only: whether the original HELLO offered only JM1. §6.9:
            a hybrid_invalid REJECT for such an attempt terminates it, because
            there is nothing to fall back to.
        retry_used: set when the one §6.8 retry has been made. The retry HELLO
            gets a new sid but shares this object, so the budget carries over
            ("A retry uses a new identifier but retains the original attempt's
            retry budget", §6.9).
    """
    initial_jm1_only: bool
    retry_used: bool = False


@dataclass
class Session:
    """§6.9 established-session state.

    Attributes:
        sid: the session identifier.
        peer: the other party's username; every incoming message for this sid
            must come from this user (§6.9).
        role: ROLE_I or ROLE_R; decides which direction keys are send/receive.
        suite: JM1 or JM2.
        send_keys, recv_keys: `DirectionKeys`. For the initiator these are
            (IR, RI); for the responder (RI, IR).
        hello, reply: the handshake bytes (§6.9 lists them as session state).
        send_seq: the next sequence number to allocate; starts at 0 (§6.9).
        recv_seq: the only sequence number the next DATA may carry (§7.2).
        sent: seq -> the exact DATA body sent, so a RESEND can be answered
            with identical bytes (§7.3).
        resent: seqs already resent once; §7.3 allows at most one automatic
            resend per record.
        receipted: seqs whose RECEIPT has been reported; §7.3 reports each
            receipt at most once.
    """
    sid: bytes
    peer: str
    role: str
    suite: int
    send_keys: DirectionKeys
    recv_keys: DirectionKeys
    hello: bytes
    reply: bytes
    send_seq: int = 0
    recv_seq: int = 0
    sent: dict = field(default_factory=dict)      # seq -> exact DATA body, for RESEND
    resent: set = field(default_factory=set)      # seqs already resent once (§7.3)
    receipted: set = field(default_factory=set)   # seqs whose RECEIPT was reported


@dataclass
class Pending:
    """§6.9 pending handshake state (either role).

    Attributes:
        sid, role, peer: as for `Session`.
        state: PENDING_REPLY (initiator waiting for REPLY or REJECT) or
            PENDING_FINISH (responder waiting for FINISH).
        peer_key: the peer's identity key, fetched once when the handshake
            began and used for every signature check in it (§5).
        started: `now()` at creation, for Appendix B expiry.
        hello: the exact HELLO bytes: sent (initiator) or received (responder).
        offered, x_priv, dk, attempt: initiator only. The suites offered, the
            ephemeral X25519 key x_I, the ML-KEM key dk_I (None without JM2),
            and the shared `Attempt` (retry budget).
        reply, session: responder only. The REPLY sent, and the `Session`
            derived with it, which becomes established when FINISH verifies.
            The responder derives keys before sending REPLY (§6.4 step 5), so
            the session object already exists while pending.
    """
    sid: bytes
    role: str
    state: str
    peer: str
    peer_key: Ed25519PublicKey     # §5 the exact key stored for this handshake
    started: float
    hello: bytes                   # I: HELLO sent; R: HELLO received
    # Initiator-only fields
    offered: tuple = ()
    x_priv: X25519PrivateKey = None
    dk: MLKEM768PrivateKey = None
    attempt: Attempt = None
    # Responder-only: REPLY sent, and the session derived from it
    reply: bytes = None
    session: Session = None


def _event_peer(peer):
    """Error/warning events carry a valid username or None (handout §3).

    Returns `peer` if it is a valid username, otherwise None, so that an
    error about a malformed name can still be emitted without failing
    `validate_event`.
    """
    try:
        return username(peer)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# The Client state machine (§§5, 6.4-6.9, 7)
# ---------------------------------------------------------------------------

class Client:
    """Handout §3 protocol-core interface.

    State overview (all in memory, §6.9):

        _pending   sid -> Pending       handshakes in progress, either role
        _sessions  sid -> Session       established sessions
        _retired   {sid}                never accept or reuse again
        _latest    peer -> sid          most recent local establishment
        _queue     peer -> [text]       text waiting for a session
        _known_keys peer -> idPK        first key seen (Appendix B)

    A sid is "in use" (§6.4 step 1) if it appears in any of the first three.
    """

    def __init__(self, username, identity_private_key, lookup_peer_key, emit, now,
                 *, jm1_only=False):
        """Handout §3 constructor. See the starter protocol.py for the arguments.

        The raw identity key is imported once, so an invalid key fails here
        rather than in the middle of a handshake.
        """
        self.username = username
        self.lookup_peer_key = lookup_peer_key
        self.emit = emit
        self.now = now
        self.jm1_only = jm1_only
        self.entropy = SystemEntropy()
        # §5 the identity key stays fixed for the life of the client.
        self._id_sk = Ed25519PrivateKey.from_private_bytes(identity_private_key)
        self._id_pk = self._id_sk.public_key().public_bytes_raw()
        self._pending = {}         # sid -> Pending
        self._sessions = {}        # sid -> Session (established)
        self._retired = set()      # §6.9 sids never to be reused or accepted again
        self._latest = {}          # peer -> sid of most recent local establishment
        self._queue = {}           # peer -> [text, ...] waiting for a session (§6.9)
        self._known_keys = {}      # peer -> idPK first seen (Appendix B key change)

    # ----- public interface (handout §3) ----------------------------------

    def fingerprint(self, peer=None):
        """§5. PeerKeyUnavailable propagates; the driver reports it.

        Returns the formatted fingerprint of this client's key (peer=None) or
        of the key the directory currently returns for `peer`. This is a
        display operation only; it does not pin or record the key.
        """
        if peer is None:
            return fingerprint_of(self._id_pk)
        return fingerprint_of(self.lookup_peer_key(peer))

    def start_handshake(self, peer):
        """§6.3: begin a fresh handshake even if a session already exists.

        Each call is a new user-visible attempt with its own retry budget.
        The offer follows the local `jm1_only` option (§6.1).
        """
        self._initiate(peer, Attempt(initial_jm1_only=self.jm1_only), jm1_only=self.jm1_only)

    def send_text(self, peer, text):
        """§§6.9, 7.1: send on the latest session, or queue and handshake.

        Order of decisions:
            1. Reject invalid or oversized text before anything else, so no
               sequence number is allocated for it (§7.1).
            2. If there is an established session, use the most recently
               established one (§6.9).
            3. Otherwise queue the text, and start a handshake unless one with
               this peer is already pending in either role (§6.9). If omitted,
               each queued message would start its own handshake and the peer
               would see a burst of HELLOs.
        """
        try:
            encode_text(text)          # §7.1 reject > 4096 bytes before allocating a seq
        except (ValueError, UnicodeError, AttributeError):
            self._error(peer, "text is not valid UTF-8 within 4096 bytes; not sent")
            return
        session = self._sessions.get(self._latest.get(peer))
        if session is not None:
            self._send_data(session, text)
            return
        self._queue.setdefault(peer, []).append(text)
        if not any(p.peer == peer for p in self._pending.values()):
            self.start_handshake(peer)

    def receive(self, sender, recipient, body):
        """Process one decoded body (§6.4 preamble: envelope checks come first).

        Envelope checks, before looking at the message type: the sender must
        be a valid username and the recipient must be this client (§6.4); an
        empty body has no type and is discarded. Then dispatch on the first
        byte; an unknown type is silently discarded (§6.2). Each handler
        parses its own body and discards on DecodeError (§6.2, §3).
        """
        try:
            username(sender)
        except ValueError:
            return
        if recipient != self.username or not isinstance(body, bytes) or not body:
            return
        handler = {
            T_HELLO: self._on_hello, T_REPLY: self._on_reply, T_FINISH: self._on_finish,
            T_REJECT: self._on_reject, T_DATA: self._on_data,
            T_RECEIPT: self._on_control, T_RESEND: self._on_control,
        }.get(body[0])
        if handler is None:
            return                     # §6.2 unknown type: silent discard
        handler(sender, body)

    def check_timeouts(self):
        """Appendix B: expire pending handshakes 60 s after creation.

        Called after every poll. `list(...)` takes a snapshot because expiring
        a handshake removes it from `_pending` during the loop.
        """
        for pending in list(self._pending.values()):
            self._expire_if_due(pending)

    def reset_peer_trust(self, peer):
        """Appendix B: explicit local trust reset; abandon everything with `peer`.

        Forgetting the recorded key lets the next lookup pin whatever key the
        directory now returns. Only ever called by an explicit user command.
        """
        self._drop_peer(peer)
        self._known_keys.pop(peer, None)

    def transport_failed(self, peer=None):
        """Appendix B: abandon affected sessions (all after an uncertain receive).

        With a peer (failed send): drop that peer's handshakes and sessions.
        With None (failed receive): any session may have lost a batch, so drop
        every peer that has a session or pending handshake. Dropped sids are
        retired, so their counters are never reused with the same keys (§4.6).
        """
        peers = {peer} if peer is not None else (
            {s.peer for s in self._sessions.values()} | {p.peer for p in self._pending.values()})
        for name in peers:
            self._drop_peer(name)

    # ----- §6.3 initiating ----------------------------------------------

    def _initiate(self, peer, attempt, *, jm1_only, peer_key=None):
        """Build and send a HELLO; enter pending-reply (§6.3, §6.9 row 1).

        Args:
            peer: the responder's username.
            attempt: the `Attempt` this HELLO belongs to (new for
                start_handshake; the original one for a §6.8 retry).
            jm1_only: offer only JM1 (the local option, or a §6.8 retry).
            peer_key: for a retry, the key pinned by the original attempt;
                None to fetch it now.
        """
        # §5: obtain the peer's key before starting, and keep it for the whole
        # handshake. §6.8: a retry reuses the original pinned key instead of
        # fetching again.
        if peer_key is None:
            peer_key = self._peer_key(peer)
            if peer_key is None:
                # _peer_key already emitted the error; this returns any queued
                # text as unsent (§6.9) without a second message.
                self._handshake_failed(peer, None)
                return
        sid = self._fresh_sid()
        offered = (JM1,) if jm1_only else (JM2, JM1)         # §6.1 ordinary offer [0x0002, 0x0001]
        x_priv = self.entropy.x25519()
        # §6.3: an ML-KEM keypair only when JM2 is offered; otherwise ek_I is
        # empty, as §3 requires (a peer discards a JM1-only HELLO with an ek_I).
        dk = self.entropy.mlkem() if JM2 in offered else None
        ek = dk.public_key().public_bytes_raw() if dk is not None else b""
        hello = encode_hello(sid, offered, x_priv.public_key().public_bytes_raw(), ek)
        # Store the exact bytes sent: §6.5 step 2 hashes "the HELLO bytes it
        # sent", and the private keys are needed again in §6.5 steps 3-4.
        self._pending[sid] = Pending(sid=sid, role=ROLE_I, state=PENDING_REPLY, peer=peer,
                                     peer_key=peer_key, started=self.now(), hello=hello,
                                     offered=offered, x_priv=x_priv, dk=dk, attempt=attempt)
        try:
            self._send(peer, hello)
        except BaseException:
            # The HELLO may or may not have arrived (§4.6). Retire the sid so a
            # late REPLY for it is discarded, then let the driver stop.
            self._retire_pending(sid)
            raise

    # ----- §6.4 responder: HELLO -----------------------------------------

    def _on_hello(self, sender, body):
        """§6.4: process a HELLO as responder, in the spec's five steps.

        Outcomes: silent discard (step 1); a signed REJECT (steps 2-3); an
        error with no reply (step 4 key unavailable, step 5 failure); or a
        REPLY and a new pending-finish handshake (step 5). The step order is
        normative: §6.4 puts suite selection and the ek_I checks before the
        key lookup so that a REJECT can reach a peer whose key is unavailable.
        """
        # Step 1: parse; discard if sid already in use (active or retired).
        try:
            hello = parse_hello(body)
        except DecodeError:
            return
        # If omitted, a duplicate or replayed HELLO would overwrite live state
        # for that sid, or revive a retired one (§6.9 "never reuse them").
        if self._sid_in_use(hello.sid):
            return
        # Step 2: suite selection by our fixed preference order.
        # The responder's order (JM2, then JM1) decides, not the order in the
        # HELLO (§6.1 "Suite selection follows the responder's fixed
        # preference order"). Unknown codes are simply never matched (§3).
        suite = next((s for s in PREFERENCE if s in hello.suites), None)
        if suite is None:
            self._send_reject(sender, hello.sid, REASON_NO_COMMON_SUITE)
            return
        # Step 3: JM2 encapsulation-key checks (length and FIPS 203 §7.2).
        # §3: a fully present ek_I of the wrong length (including empty) when
        # JM2 is offered is a step-3 failure answered with hybrid_invalid, not
        # a silent discard. The import performs the FIPS 203 modulus check.
        ek_pub = None
        if suite == JM2:
            try:
                if len(hello.ek) != MLKEM_EK_LEN:
                    raise ValueError("wrong ek length")
                ek_pub = MLKEM768PublicKey.from_public_bytes(hello.ek)   # import-time check
            except ValueError:
                self._send_reject(sender, hello.sid, REASON_HYBRID_INVALID)
                return
        # §5: obtain and pin the peer's identity key before accepting.
        # Step 4 in the spec. On failure: retire the sid, report (done inside
        # _peer_key), send nothing.
        peer_key = self._peer_key(sender)
        if peer_key is None:
            self._retired.add(hello.sid)
            return
        # Step 4: fresh X25519 keypair; for JM2, Encaps.
        ss_pq, ct = b"", b""
        if suite == JM2:
            try:
                ss_pq, ct = self.entropy.encapsulate(ek_pub)
            except ValueError:            # Encaps-time ek check failure: same as step 3
                # §6.4 step 3: some libraries check the key only at Encaps;
                # a failure here is treated exactly like an import failure.
                self._send_reject(sender, hello.sid, REASON_HYBRID_INVALID)
                return
        x_priv = self.entropy.x25519()
        # Step 5: dh with §2 checks, REPLY, keys. A failure discards without REPLY.
        try:
            dh = x25519_shared(x_priv, hello.x_pub)
        except ValueError:
            # A cryptographic failure in step 5 is a local error, not a reason
            # to REJECT or fall back (§2, §6.4 step 5); report it (§6.9).
            self._retired.add(hello.sid)
            self._error(sender, "X25519 failure processing HELLO; handshake discarded")
            return
        # §6.5: REPLY_core, then sig_R over TH_R. `body` is the exact HELLO as
        # received; re-encoding the parsed HELLO is unnecessary and would only
        # add a way to get the bytes wrong.
        reply_core = encode_reply_core(hello.sid, suite, x_priv.public_key().public_bytes_raw(),
                                       ct)
        sig_r = self._id_sk.sign(LABEL_SIG_R + th_r(sender, self.username, body, reply_core))
        reply = reply_core + sig_r
        # §6.7 keys over the full REPLY (with signature). The sender is the
        # initiator, so the usernames are (sender, self.username).
        ir, ri = split_okm(suite, derive_okm(suite, key_schedule_ikm(suite, dh, ss_pq),
                                             th_keys(sender, self.username, body, reply)))
        # Responder sends with RI and receives with IR.
        session = Session(sid=hello.sid, peer=sender, role=ROLE_R, suite=suite,
                          send_keys=ri, recv_keys=ir, hello=body, reply=reply)
        # §6.4 step 5: store pending-finish only after everything succeeded,
        # then send. The session is not usable until FINISH verifies (§6.6).
        self._pending[hello.sid] = Pending(sid=hello.sid, role=ROLE_R, state=PENDING_FINISH,
                                           peer=sender, peer_key=peer_key, started=self.now(),
                                           hello=body, reply=reply, session=session)
        try:
            self._send(sender, reply)
        except BaseException:
            self._retire_pending(hello.sid)
            raise

    def _send_reject(self, initiator, sid, reason):
        """Send a signed §6.8 REJECT and retire the sid.

        §6.4 step 5: "Whenever R sends a REJECT, it retires the sid." The
        signature lets the initiator tell a genuine REJECT from a forged one
        (§6.8); an unsigned REJECT would be ignored by a conforming peer.
        """
        # §6.8 REJECT, signed over label || sid || u8 reason || str8(I).
        self._retired.add(sid)        # a duplicate HELLO for this sid is now discarded
        sig = self._id_sk.sign(reject_signed_bytes(sid, reason, initiator))
        self._send(initiator, encode_reject(sid, reason, sig))

    # ----- §6.5 initiator: REPLY -----------------------------------------

    def _on_reply(self, sender, body):
        """§6.5: process a REPLY as initiator, then send FINISH (§6.6).

        A REPLY that does not parse, names a sid that is not pending-reply, or
        comes from the wrong peer is silently discarded without any state
        change (§6.5). Once it passes those gates, any failed check aborts the
        handshake (§6.5 "If any check fails, I aborts").
        """
        try:
            reply = parse_reply(body)
        except DecodeError:
            return
        pending = self._pending_for(reply.sid, sender, ROLE_I, PENDING_REPLY)
        if pending is None:
            return
        peer = pending.peer
        # Step 1: suite offered and supported; ct length matches the suite.
        # If omitted, a REPLY could select a suite this client never offered
        # (or does not implement), and the ct length mismatch would surface
        # later as a library error instead of a clean abort.
        expected_ct = MLKEM_CT_LEN if reply.suite == JM2 else 0
        if reply.suite not in SUPPORTED or reply.suite not in pending.offered \
                or len(reply.ct) != expected_ct:
            self._abort(pending, "REPLY names a suite we did not offer or has a bad ciphertext")
            return
        # Step 2: verify sig_R over TH_R computed with the HELLO we sent.
        # pending.hello is the stored copy of what we sent; pending.peer_key is
        # the key pinned when the handshake began (§5). Using a freshly
        # fetched key here would break §5 ("do not re-fetch a key to make a
        # failed signature pass").
        transcript_r = th_r(self.username, peer, pending.hello, reply.core)
        try:
            pending.peer_key.verify(reply.sig, LABEL_SIG_R + transcript_r)
        except InvalidSignature:
            self._abort(pending, "REPLY signature invalid")
            return
        # Steps 3-4: dh with §2 checks; JM2 Decaps with the retained dk_I.
        # A library failure here aborts; it never triggers fallback (§6.5 step 4).
        try:
            dh = x25519_shared(pending.x_priv, reply.x_pub)
            ss_pq = pending.dk.decapsulate(reply.ct) if reply.suite == JM2 else b""
        except ValueError:
            self._abort(pending, "key agreement failed")
            return
        # Step 5: keys, then FINISH (§6.6).
        # `body` is the full REPLY as received; both TH and TH_I cover it.
        ir, ri = split_okm(reply.suite,
                           derive_okm(reply.suite, key_schedule_ikm(reply.suite, dh, ss_pq),
                                      th_keys(self.username, peer, pending.hello, body)))
        sig_i = self._id_sk.sign(LABEL_SIG_I + th_i(self.username, peer, pending.hello, body))
        # Initiator sends with IR and receives with RI.
        session = Session(sid=reply.sid, peer=peer, role=ROLE_I, suite=reply.suite,
                          send_keys=ir, recv_keys=ri, hello=pending.hello, reply=body)
        del self._pending[reply.sid]      # ephemeral secrets are dropped with it
        try:
            self._send(peer, encode_finish(reply.sid, sig_i))
        except BaseException:
            self._retired.add(reply.sid)  # FINISH not accepted: never establish (§6.6)
            raise
        self._establish(session)          # §6.6 established on transport acceptance

    # ----- §6.6 responder: FINISH ----------------------------------------

    def _on_finish(self, sender, body):
        """§6.6: verify FINISH as responder and establish the session.

        Only a FINISH for a pending-finish sid from the expected peer is
        considered (§6.9); others, including a duplicate FINISH after
        establishment, are silently discarded. An invalid signature abandons
        the handshake with an error (§6.6 "Otherwise R discards the session").
        """
        try:
            finish = parse_finish(body)
        except DecodeError:
            return
        pending = self._pending_for(finish.sid, sender, ROLE_R, PENDING_FINISH)
        if pending is None:
            return
        # TH_I over the HELLO received and the REPLY sent, verified under the
        # key pinned in §6.4 step 4 (§5, §6.6).
        transcript_i = th_i(sender, self.username, pending.hello, pending.reply)
        try:
            pending.peer_key.verify(finish.sig, LABEL_SIG_I + transcript_i)
        except InvalidSignature:
            self._abort(pending, "FINISH signature invalid")
            return
        # §6.9 row "pending-finish + valid FINISH -> established". Until this
        # point the session is not in _sessions, so DATA for it was discarded
        # (§6.6 "R MUST discard any DATA for a session that is still
        # pending-finish").
        del self._pending[finish.sid]
        self._establish(pending.session)

    # ----- §6.8 initiator: REJECT ----------------------------------------

    def _on_reject(self, sender, body):
        """§6.8: process a REJECT as initiator.

        Accepted only in pending-reply from the expected peer (§6.9). The
        signature is checked under the pinned key; an invalid one is ignored
        and the handshake stays pending (§6.8, deliberately unlike an invalid
        REPLY signature, which aborts). A valid REJECT retires the sid; then:

            hybrid_invalid, first time, original offer included JM2
                -> one retry: new sid, new ephemerals, JM1 only, same pinned key
            hybrid_invalid otherwise (retry used, or original was JM1-only)
                -> terminate the attempt with an error (§6.9)
            any other reason
                -> abandon with an error (§6.8)
        """
        try:
            reject = parse_reject(body)
        except DecodeError:
            return
        pending = self._pending_for(reject.sid, sender, ROLE_I, PENDING_REPLY)
        if pending is None:
            return
        try:
            pending.peer_key.verify(reject.sig, reject_signed_bytes(reject.sid, reject.reason,
                                                                     self.username))
        except InvalidSignature:
            return                                   # §6.8 invalid REJECT is ignored
        self._retire_pending(reject.sid)             # §6.9 retire the old sid
        attempt = pending.attempt
        if reject.reason == REASON_HYBRID_INVALID:
            # §6.8 "at most once per original HELLO" and §6.9 "A second
            # hybrid_invalid, or one for an attempt that offered only JM1
            # initially, terminates the attempt". If omitted, two clients that
            # disagree about ML-KEM keys could exchange HELLOs indefinitely.
            if attempt.initial_jm1_only or attempt.retry_used:
                self._handshake_failed(pending.peer,
                                       "hybrid_invalid after JM1-only offer or retry; giving up")
                return
            attempt.retry_used = True
            # §6.8 one retry: fresh sid and ephemerals, only JM1, same pinned key.
            self._initiate(pending.peer, attempt, jm1_only=True, peer_key=pending.peer_key)
            return
        self._handshake_failed(pending.peer,
                               f"peer rejected handshake (reason 0x{reject.reason:02x})")

    # ----- §7.2 receiving DATA ---------------------------------------------

    def _on_data(self, sender, body):
        """§7.2: receive a DATA record, in the spec's order of checks.

        The order, and what each failure does:
            parse                         -> silent discard (§3, §6.2)
            established session for sid   -> silent discard (§6.9, §6.6)
            sender is the session's peer  -> silent discard (§6.9)
            step 1 length checks          -> silent discard
            seq == recv_seq               -> silent discard
            steps 2-3 decrypt/verify      -> MALFORMED: silent discard
                                             AUTH_FAILED: RESEND, recv_seq unchanged
            step 4 success                -> recv_seq += 1, RECEIPT, then
                                             deliver text or report bad UTF-8

        All the header checks come before any decryption (§7.2 step 1 "Apply
        the session, peer, and sequence checks before decryption").
        """
        try:
            data = parse_data(body)
        except DecodeError:
            return
        session = self._sessions.get(data.sid)     # pending-finish DATA is not here: discarded
        if session is None or session.peer != sender:
            return
        if not protected_length_ok(session.suite, data.protected):    # step 1
            return
        # Only the next expected record is processed. A replayed or duplicate
        # record (seq < recv_seq) is discarded here, which is why an accepted
        # record never gets a second RECEIPT (§7.3); a gap (seq > recv_seq) is
        # discarded too, since the record layer does not reorder (§4.6).
        if data.seq != session.recv_seq:
            return
        outcome, plaintext = unprotect(session.suite, session.recv_keys, data.sid, data.seq,
                                       data.protected)
        if outcome == MALFORMED:
            return                                    # step 3.2 silent discard
        if outcome == AUTH_FAILED:
            # §7.2 step 5: ask for a retransmission; recv_seq does not move, so
            # the resent copy (same seq) will be accepted.
            self._send(sender, encode_control(T_RESEND, data.sid, data.seq))   # step 5
            return
        # Step 4: advance recv_seq and RECEIPT the received seq, then deliver.
        # The RECEIPT names data.seq (the received number), not the new
        # recv_seq. If the counter were not advanced, the peer's next record
        # would be discarded by the sequence check above.
        session.recv_seq += 1
        self._send(sender, encode_control(T_RECEIPT, data.sid, data.seq))
        try:
            text = decode_text(plaintext)
        except DecodeError:
            # §7.2 step 4: authentic but not valid text. The seq is consumed and
            # the RECEIPT was sent; report locally, no RESEND.
            self._error(sender, f"record {data.seq} is not valid UTF-8 text within 4096 bytes")
            return
        # Delivered exactly once: a repeat of this record fails the seq check.
        self.emit({"type": "message", "peer": sender, "sid": data.sid, "seq": data.seq,
                   "text": text})

    # ----- §7.3 RECEIPT and RESEND -----------------------------------------

    def _on_control(self, sender, body):
        """§7.3: process a RECEIPT or RESEND.

        Accepted only for an established session, from its peer, naming a seq
        this session has already sent (seq < send_seq). Never answered with
        another control message (§7.3), which is what prevents two clients
        from acknowledging each other's acknowledgements forever.

        RECEIPT: report it once per seq; duplicates change nothing.
        RESEND: this implementation takes the §7.3 MAY: resend the exact cached
        DATA body once per record; later requests (or an uncached record) only
        produce a warning.
        """
        try:
            control = parse_control(body)
        except DecodeError:
            return
        session = self._sessions.get(control.sid)
        if session is None or session.peer != sender or control.seq >= session.send_seq:
            return                                    # never sent that seq: discard
        # Never answer a control message with RECEIPT or RESEND.
        if control.kind == T_RECEIPT:
            if control.seq not in session.receipted:  # duplicates change nothing
                session.receipted.add(control.seq)
                self.emit({"type": "receipt", "peer": sender, "sid": control.sid,
                           "seq": control.seq})
            return
        cached = session.sent.get(control.seq)
        if cached is not None and control.seq not in session.resent:
            session.resent.add(control.seq)           # at most one automatic resend
            self._warning(sender, f"peer requested resend of record {control.seq}; "
                                  "resending cached record")
            # The identical bytes: same seq, and for JM1 the same IV, for JM2
            # the same tag. §7.3 forbids rebuilding a record under an old seq.
            self._send(sender, cached)                # exact bytes, same IV/tag and seq
        else:
            self._warning(sender, f"peer requested resend of record {control.seq}; not resending")

    # ----- helpers -------------------------------------------------------

    def _send(self, peer, body):
        """Emit a "send" event. Returns only once the transport accepted it."""
        self.emit({"type": "send", "to": peer, "body": body})

    def _error(self, peer, message):
        """Emit an "error" event (handout §3); `peer` is sanitised to a username or None."""
        self.emit({"type": "error", "peer": _event_peer(peer), "message": message})

    def _warning(self, peer, message):
        """Emit a "warning" event (handout §3); `peer` is sanitised to a username or None."""
        self.emit({"type": "warning", "peer": _event_peer(peer), "message": message})

    def _sid_in_use(self, sid):
        """§6.4 step 1: a sid is in use if pending (either role), established or retired."""
        return sid in self._pending or sid in self._sessions or sid in self._retired

    def _fresh_sid(self):
        """Return a random sid not currently in use (§6.3, §6.9 never reuse).

        With 16 random bytes a collision is astronomically unlikely; the loop
        matters for the test entropy hooks, which may return repeated values.
        """
        while True:
            sid = self.entropy.sid()
            if not self._sid_in_use(sid):
                return sid

    def _peer_key(self, peer):
        """§5: fetch and import the peer key, or report an error and return None.

        Returns:
            An `Ed25519PublicKey` to pin in the handshake state, or None after
            emitting an error if the key is unavailable, cannot be imported,
            or differs from the key first seen for this peer (Appendix B).
        """
        try:
            raw = self.lookup_peer_key(peer)
            key = Ed25519PublicKey.from_public_bytes(raw)
        except (PeerKeyUnavailable, ValueError, TypeError) as exc:
            self._error(peer, f"no usable identity key for {peer}: {exc}")
            return None
        known = self._known_keys.setdefault(peer, raw)
        if known != raw:      # Appendix B: require an explicit reset_peer_trust
            self._error(peer, f"identity key for {peer} changed; reset trust before continuing")
            return None
        return key

    def _pending_for(self, sid, sender, role, state):
        """§6.9: pending state for sid only in the given role/state, from its peer.

        Returns the `Pending` if the sid is pending in exactly `role` and
        `state`, `sender` is its stored peer, and it has not expired; else
        None, and the caller discards the message without changing state.
        This one gate implements §6.9's "Only process REPLY and REJECT in
        pending-reply, and FINISH in pending-finish" and the "from MUST match
        the stored peer" rule. Expiry is checked before processing an incoming
        message, as Appendix B recommends.
        """
        pending = self._pending.get(sid)
        if pending is None or pending.role != role or pending.state != state \
                or pending.peer != sender:
            return None                               # out-of-state or wrong peer: discard
        if self._expire_if_due(pending):
            return None
        return pending

    def _expire_if_due(self, pending):
        """Abort `pending` if 60 s or more have passed since it began (Appendix B).

        Returns True if it was expired (and is now abandoned and reported).
        """
        if self.now() - pending.started < HANDSHAKE_TIMEOUT:
            return False
        self._abort(pending, "handshake timed out")
        return True

    def _retire_pending(self, sid):
        """Remove pending state for `sid` (dropping its secrets) and retire the sid."""
        self._pending.pop(sid, None)
        self._retired.add(sid)

    def _abort(self, pending, message):
        """§6.9: abandon a pending handshake and report failure."""
        self._retire_pending(pending.sid)
        self._handshake_failed(pending.peer, message)

    def _handshake_failed(self, peer, message):
        """Report a handshake failure and, if appropriate, return queued text.

        Args:
            peer: the peer whose handshake failed.
            message: the error text, or None if an error was already emitted.

        §6.9: queued text "remains associated with its peer"; if that peer's
        handshake fails, report it and return the text as unsent rather than
        retrying automatically. The text is kept if something else can still
        carry it: an established session, or another pending handshake with
        the same peer.
        """
        if message is not None:
            self._error(peer, message)
        # §6.9: if nothing else can carry the queued text, return it as unsent.
        if peer in self._queue and peer not in self._latest \
                and not any(p.peer == peer for p in self._pending.values()):
            unsent = self._queue.pop(peer)
            self._error(peer, f"{len(unsent)} queued message(s) not sent: {unsent!r}")

    def _establish(self, session):
        """Mark `session` established, announce it, and flush queued text (§6.9).

        The latest local establishment becomes the session for new outgoing
        text; older sessions stay in `_sessions` and keep accepting incoming
        records (§6.9). Queued text goes on whichever session with the peer is
        established first, in either role.
        """
        self._sessions[session.sid] = session
        self._latest[session.peer] = session.sid     # §6.9 latest local establishment
        self.emit({"type": "established", "peer": session.peer, "sid": session.sid,
                   "suite": session.suite})
        for text in self._queue.pop(session.peer, []):
            self._send_data(session, text)

    def _send_data(self, session, text):
        """§7.1: allocate the next seq, protect `text`, cache and send the DATA.

        The sequence number is consumed before the send is attempted, so even
        if the send fails it is never paired with other plaintext later
        (§7.1 "Never assign different plaintext to an already used sequence
        number"). The exact body is cached for a possible RESEND (§7.3).
        """
        plaintext = encode_text(text)
        if session.send_seq > MAX_SEQ:                # Appendix B: never wrap
            self._error(session.peer, "send direction exhausted; start a new session")
            return
        seq = session.send_seq
        session.send_seq += 1                         # allocated before the send attempt
        # JM1 takes a fresh random IV per record; JM2 derives its nonce from seq.
        iv = self.entropy.iv() if session.suite == JM1 else None
        body = encode_data(session.sid, seq,
                           protect(session.suite, session.send_keys, session.sid, seq,
                                   plaintext, iv))
        session.sent[seq] = body
        self._send(session.peer, body)

    def _drop_peer(self, peer):
        """Abandon every handshake and session with `peer` (Appendix B helpers).

        All affected sids are retired, so their keys and counters are never
        used again (§4.6 "MUST NOT reset sequence counters while keeping the
        same keys"). Any queued text is returned to the user as unsent.
        """
        for sid in [s for s, p in self._pending.items() if p.peer == peer]:
            self._retire_pending(sid)
        for sid in [s for s, sess in self._sessions.items() if sess.peer == peer]:
            del self._sessions[sid]
            self._retired.add(sid)
        self._latest.pop(peer, None)
        unsent = self._queue.pop(peer, None)
        if unsent:
            self._error(peer, f"{len(unsent)} queued message(s) not sent: {unsent!r}")

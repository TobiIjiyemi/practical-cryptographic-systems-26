"""Student implementation of specification §§5-7. Supplied methods are stubs.

What this file is for
---------------------
This is your protocol core: the `Client` class whose interface is fixed by
handout §3. Everything cryptographic in JMessage happens here: fingerprints,
the HELLO/REPLY/FINISH handshake with suite negotiation and REJECT, the key
schedule, record protection for both suites, receipts and resend requests.

Where it sits
-------------

      client.py / your UI          tests (testing.Network)
              \\                       /
               Runtime.call(...)  or direct calls
                         |
                         v
      +---------------- Client (this file) ----------------+
      |  inputs:  start_handshake, send_text, receive,     |
      |           fingerprint, check_timeouts, ...         |
      |  outputs: self.emit({"type": "send" | "established"|
      |           | "message" | "receipt" | "warning"      |
      |           | "error", ...})                         |
      +----------------------------------------------------+
           |  uses                          |  uses
      jmessage_support/messages.py      cryptography (library primitives)
      jmessage_support/codec.py         padding.py (your Part 0 functions)

    You never touch HTTP, JSON, base64, threads or the terminal: the driver
    does that. You receive decoded bytes and emit events.

How to use this skeleton
------------------------
The sections below are in the order we suggest you build them. Each one says
which spec sections it implements, what goes in and comes out, what must be
true afterwards, and which row of the "What counts as explained" table in
AGENTS.md it belongs to (that table lists what you should be able to say
about each review-critical region before, or instead of, asking an agent to
write it). Every method still raises NotImplementedError or does nothing;
replacing those bodies, and adding whatever helper functions, classes and
state you need, is the assignment.

    1. State                    __init__                        §6.9
    2. Fingerprint              fingerprint                     §5
    3. Handshake as initiator   start_handshake (+ REPLY,       §§6.3, 6.5, 6.6, 6.8
                                FINISH, REJECT in receive)
    4. Handshake as responder   receive (HELLO, FINISH)         §§6.2, 6.4, 6.5, 6.6
    5. Key schedule             (your helpers)                  §6.7
    6. Records                  send_text (+ DATA in receive)   §§6.9, 7.1, 7.2
    7. Control messages         (RECEIPT, RESEND in receive)    §7.3
    8. Timeouts and robustness  check_timeouts, reset_peer_trust, Appendix B
                                transport_failed

A suggested route: get sections 1-6 working for JM1 only (`--jm1-only`, and
`run_checks.py review_eligible`), then add JM2, then section 7, then 8.

Rules that apply everywhere
---------------------------
* Malformed or unexpected peer input is discarded or reported as the spec
  says; it must never escape `receive` as an exception (handout §3). The
  supplied parsers raise `DecodeError` for structural errors; catch it.
* Emit events in processing order, and finish cryptographic processing before
  emitting an event that exposes plaintext (handout §3).
* `emit` of a "send" event returns only after the transport accepted it, and
  raises if delivery failed or is uncertain (handout §3, spec §4.6). It never
  calls back into your Client.
* Use library implementations of every primitive and a CSPRNG for keys, sids
  and IVs (spec §2). Do not implement ML-KEM, X25519, Ed25519, AES, HMAC or
  HKDF yourself (handout §3).
* Use the constants and encoders in `jmessage_support.messages` rather than
  writing magic numbers.
"""
import cryptography
import secrets
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization

from cryptography.exceptions import InvalidSignature, InvalidTag
from hashlib import sha256
from jmessage_support.messages import (
    JM1, JM2, PREFERENCE, T_HELLO, T_REPLY, T_DATA,
    T_FINISH, T_RECEIPT, T_RESEND, T_REJECT, MLKEM_EK_LEN, MLKEM_CT_LEN, encode_hello,
    encode_reply_core, encode_reject, encode_data, encode_finish, encode_control,
    parse_hello, parse_reply, parse_finish, parse_data, parse_control,
    REASON_HYBRID_INVALID, REASON_NO_COMMON_SUITE)
from jmessage_support.transport import PeerKeyUnavailable
from jmessage_support import messages
from jmessage_support.codec import DecodeError, username, u16, u64
from padding import pkcs7_pad, pkcs7_unpad

def encode_str8(value):
    raw = value.encode("utf-8")

    if len(raw) > 255:
        raise ValueError("username is too long for encoding with utf8")

    return bytes([len(raw)]) + raw 

class Client:
    """The handout §3 protocol-core interface. One instance per local account.

    The driver constructs exactly one `Client` and calls it from one thread,
    one call at a time, so you need no locks (see jmessage_support/runtime.py).
    """

    # ----- 1. State (§6.9) ---------------------------------------------------
    # Core zone (AGENTS.md, "Core"): you design the per-sid state yourself.
    #
    # Spec §6.9 says what a session holds: the peer, the role (I or R), the
    # suite, the record keys, send_seq, recv_seq and the handshake bytes; and
    # what pending state additionally retains: the ephemeral private keys it
    # still needs, the peer identity key pinned for this handshake (§5), the
    # start time, and whether the single fallback retry has been used (§6.8).
    # It also requires you to remember retired session identifiers for the
    # life of the process (§6.9), to know the most recently established
    # session per peer, and to queue text for a peer that has no session yet.
    # The state table in §6.9 lists the states and the events each accepts.

    #send all the text queued in pending_text_by_peer AFTER handshake has been established
    def _flush_pending_text(self, peer):
        queued = self.pending_text_by_peer.pop(peer, [])
        for text in queued:
            self.send_text(peer, text)

    def derive_session_keys(
            self,
            suite, #(Jm1, jm2)
            dh, #diffie helman exchange
            ss_pq, #shared secret
            initiator,
            responder,
            hello_bytes,
            reply_bytes
        ):
        ikm = None
        length = None
        if suite == JM1:
            ikm = dh
            length = 96
        elif suite == JM2:
            ikm = ss_pq + dh
            length = 64
        else:
            raise ValueError("unsupported suite")
    
        th = sha256(b"JMessage-2026 keys" + encode_str8(initiator) + encode_str8(responder) + hello_bytes + reply_bytes).digest()
        #using sha256 as the key derivation function, using the transcript hash as the salt, the suite and Jmessage-2026 as the info and length depending on the suite,
        #derivte the output keying material giving the input keymaterial  
        okm = HKDF(
            algorithm = hashes.SHA256(),
            salt = th,
            info = b"JMessage-2026 " + u16(suite),
            length = length
        ).derive(ikm)


        #k_ir, k_ri, enc_ir, mac_ir, enc_ri, mac_ri: first two are for JM2, key for the initiator to the responder and then key for the responder to the initiator
        #next 4 are JM1: encryption and mac keys for the initiator to the responder, and vice versa
        if suite == JM2:
            return {
                "k_ir": okm[:32],
                "k_ri": okm[32:64]
            }
        return {
            "enc_ir": okm[:16],
            "mac_ir": okm[16:48],
            "enc_ri": okm[48:64],
            "mac_ri": okm[64:96]
        }
    def __init__(self, username, identity_private_key, lookup_peer_key, emit, now,
                 *, jm1_only=False):
        """Store the handout §3 constructor arguments and create empty state.

        Args:
            username: this client's own username (`str`). Envelopes whose
                recipient is not this name are discarded (§6.4, §6.9).
            identity_private_key: the raw 32-byte Ed25519 private key idSK
                (§5). Keep the identity key fixed for the life of the client.
            lookup_peer_key: a callable `lookup_peer_key(name) -> bytes`
                returning a raw 32-byte Ed25519 public key. It raises
                `jmessage_support.transport.PeerKeyUnavailable` (a
                `LookupError`) if the user has no usable key; report an error
                and do not proceed with that handshake (§5). It may also raise
                `TransportError`, which you should let propagate.
            emit: the synchronous event callback (handout §3 table).
            now: a callable returning monotonic seconds (`float`). Use it, not
                `time.time()`, for handshake start times (Appendix B); the
                tests substitute a fake clock.
            jm1_only: the local compatibility-test option of §6.1. When True,
                handshakes this client *initiates* offer only JM1. It does not
                change what this client accepts as a responder (§6.1).

        Afterwards:
            No messages have been sent and no events emitted. All your
            per-session and per-peer state exists and is empty.
        """
        self.username = username
        self.identity_private_key = identity_private_key
        self.lookup_peer_key = lookup_peer_key
        self.emit = emit
        self.now = now
        self.jm1_only = jm1_only

        self.sessions_by_sid = {}
        self.latest_session_by_peer = {}
        self.pending_text_by_peer = {}
        self.retired_sids = set()
        # TODO: Design your handshake and session state. See specification §6.9.

    # ----- 2. Fingerprint (§5) -----------------------------------------------
    # Core zone (AGENTS.md, "Core"). A good first function: it exercises
    # hashing, byte concatenation and formatting, and you can check it against
    # the course server's `echo` fingerprint in handout §3 and the values in
    # spec Appendix A.

    def fingerprint(self, peer=None):
        """Return the §5 display string for self, or a named peer.
        
        Implements spec §5: the fingerprint of a user is derived from that
        user's raw 32-byte public key idPK and shown as ten uppercase hex
        pairs separated by single spaces.

        Args:
            peer: a username (`str`), or None for this client's own key.

        Returns:
            The formatted fingerprint `str`, for example
            "93 AF 70 ED 10 00 82 91 02 74".

        Raises:
            PeerKeyUnavailable: may propagate from `lookup_peer_key` for a peer
                with no usable key; the driver reports it. (This is the one
                method that returns a value instead of only emitting events.)

        Afterwards:
            No state has changed and nothing has been emitted. Displaying a
            fingerprint does not authenticate it (§5).
        """
        fingerprint_b = None
        if peer is None:
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                self.identity_private_key
            )
            public_key = private_key.public_key()
            local_pub_key = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            digest = sha256(b"JMessage-2026 fingerprint" + local_pub_key).digest()
            fingerprint_b = digest[:10]
        else:
            peer_key = self.lookup_peer_key(peer)
            digest = sha256(b"JMessage-2026 fingerprint" + peer_key).digest()
            fingerprint_b = digest[:10]

        fingerprint = " ".join(f"{byte:02X}" for byte in fingerprint_b)
        return fingerprint

    # ----- 3. Handshake as initiator (§§6.3, 6.5, 6.6, 6.8) ------------------
    # Review-critical (AGENTS.md "What counts as explained": rows "Transcript &
    # signatures" and "State machine").
    #
    # The initiator's side of the handshake spans several inputs:
    #   start_handshake       build and send HELLO; enter pending-reply (§6.3)
    #   REPLY via receive     the five numbered checks and actions of §6.5,
    #                         ending in FINISH (§6.6) and establishment
    #   REJECT via receive    verify, then act on the reason (§6.8)
    # Before writing any of it, be able to say: which bytes TH_R and TH_I
    # cover and in what order; which copy of HELLO the initiator hashes (§6.5
    # step 2 says); which key verifies sig_R and where it came from (§5); and
    # what each failure does (abort for a REPLY, ignore for a bad REJECT
    # signature, §6.8).

    def start_handshake(self, peer):

        #peer's Ed25519 public identity key 

        try:
            peer_identity_key = self.lookup_peer_key(peer)
        except:
        #if lookup key isn't available then send an error,
            self.emit({
                "type": "error",
                "peer": peer, 
                "message": "Peer Key couldn't be found"
            })
            return


        #define list of suites to use,
        #check if those are objects or those are supposed to be strings
        if self.jm1_only:
            suites = (JM1,)
        else:
            suites = (JM2, JM1)


        #generate random 16 byte sid. something cryptographically secure and random.
        #research other ways to generate sids but token_bytes works for nwo
        generated_sid = secrets.token_bytes(messages.SID_LEN)

        #to ensure we dont' reuse a current or previous generated sid
        while generated_sid in self.sessions_by_sid.keys() or generated_sid in self.retired_sids:
            generated_sid = secrets.token_bytes(messages.SID_LEN)
        
        #generating keypair with cryptograhpy library       
        x_private = X25519PrivateKey.generate()
        X_I = x_private.public_key()

        raw_public_x = X_I.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        mlkem_priv, raw_mlkem_pub = None, b""
        if JM2 in suites:
            mlkem_priv = MLKEM768PrivateKey.generate()
            ek_I = mlkem_priv.public_key()
            raw_mlkem_pub = ek_I.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

        #build the hello bytes: sid, suites, x_public, ek
        hello_bytes = encode_hello(
            generated_sid, suites, raw_public_x, raw_mlkem_pub
        )

        session_entry = {
            "sid": generated_sid,
            "peer": peer,
            "role": "initiator",
            "state": "pending-reply",
            "suites": suites,
            "hello_bytes": hello_bytes,
            "peer_identity_key": peer_identity_key,
            "x_private": x_private,
            "mlkem_private": mlkem_priv,
            "start_time": self.now(),
            "fallback_used": False,
            "send_seq": 0,
            "recv_seq": 0,
            "key": None,
            #per session bookkeeping
            #maps sequence numbers to DATA , resend has to transmit original bytes
            "sent_records": {},
            #prevents duplicate RECEIPT events (next two combined help stop replay attacks maybe?)
            "received_receipts": set(),
            #limits automatic resending to once per sequence number
            "resend_counts": {},
        }
        
        self.sessions_by_sid[generated_sid] = session_entry

        #sending the HELLO bytes
        self.emit({
            "type": "send",
            "to": peer,
            "body": hello_bytes,
        })

        #is emit a function to send stuf over? do I call emit with "HELLO" in bytes? 
        #generate_sid -> involving some random generation. add to pending_reply mapping?
        # are we sending a key over start_handshake?
        """Begin a fresh handshake (§6), even if another session exists.

        Implements spec §6.3 (HELLO), with the offer rules of §6.1 and the key
        pinning rule of §5.

        Args:
            peer: the username to handshake with.

        Returns:
            None. Communicates only through `emit`.

        Emits:
            A "send" event carrying a HELLO to `peer`; or, if the peer's
            identity key is unavailable, an "error" event and nothing else
            (§5: "report an error and do not proceed").

        Afterwards (spec §6.9 state table, row 1):
            A new, never-before-used `sid` is in the pending-reply state with
            everything §6.9 says pending state retains, including the exact
            HELLO bytes you sent. The offer is [JM2, JM1] normally and [JM1]
            when `jm1_only` is set (§6.1); ek_I is present exactly when JM2 is
            offered (§6.3). Any existing sessions with `peer` are unaffected.
        """

    # ----- 4. Handshake as responder (§§6.2, 6.4, 6.5, 6.6) ------------------
    # Review-critical (AGENTS.md "What counts as explained": rows "Transcript &
    # signatures" and "State machine").
    #
    # The responder's side, also reached through `receive`:
    #   HELLO via receive     the five ordered steps of §6.4: parse and sid
    #                         check; suite selection by the responder's fixed
    #                         preference; the JM2 encapsulation-key checks;
    #                         pin the initiator's key; derive, store
    #                         pending-finish, send REPLY (§6.5)
    #   FINISH via receive    verify sig_I under the pinned key over the HELLO
    #                         and REPLY bytes you received and sent; establish
    #                         or discard (§6.6)
    # §6.4 also says when to send REJECT (§6.8) and that every REJECT retires
    # its sid. §3 says which malformed HELLOs are discarded silently and which
    # reach §6.4 step 3.

    def receive(self, sender, recipient, body):
        """Process a decoded binary body; emit outputs through self.emit.

        The single entry point for every message from the network. It
        implements the dispatch and discard rules of §6.2 and the envelope
        checks of §6.4 and §6.9, then hands each message type to the logic
        described in sections 3-7 of this file.

        Args:
            sender: the envelope's "from" username, as set by the server.
            recipient: the envelope's "to" username.
            body: the message body as `bytes` (already base64-decoded). Its
                first byte is the message type (§3, §6.2).

        Returns:
            None. Communicates only through `emit`.

        Raises:
            Nothing for any peer input, however malformed (handout §3). A
            `TransportError` from a failed `emit` may propagate.

        Rules from the spec that apply before any type-specific logic:
            * Discard envelopes whose usernames are invalid or whose recipient
              is not this client, before processing any message type (§6.4).
            * Silently discard an unrecognised type or a body that fails to
              parse (§6.2).
            * For any existing session or handshake, the sender must match
              the stored peer; discard mismatches without changing state
              (§6.9).
            * Process REPLY and REJECT only in pending-reply, FINISH only in
              pending-finish, DATA and control messages only for established
              sessions; silently discard everything else (§6.9).

        Afterwards:
            Exactly the state change the §6.9 table allows for this message in
            the current state, or none at all.
        """

        #validation
        
        #Make sure to catch TypeError and ValueError, so they don't silently discard
        try:
            username(sender)
            username(recipient)
        except (TypeError, ValueError):
            return

        if recipient != self.username:
            return
        
        #if body isn't in bytes or body isn't empty at all, as opposed to just if not body
        if not isinstance(body, bytes) or not body:
            return
        
        if body[0] == T_HELLO:
            #parse hello_bytes in body, catch DecodeError
            try:
                hello = parse_hello(body)
            except DecodeError:
                return

            #save hello_bytes exactly as it was received
            hello_bytes = body

            #define inititator and responder usernames
            initiator = sender
            responder = self.username

            #define helper function to format reject_bytes body 
            #with the proper structured data and key generation for signing
            def send_reject(reason):
                reason_bytes = bytes([reason])
                reject_signed_data = (
                    b"JMessage-2026 reject"
                    + hello.sid
                    + reason_bytes
                    + encode_str8(sender)
                )

                ipk = ed25519.Ed25519PrivateKey.from_private_bytes(
                    self.identity_private_key
                )

                reject_signature = ipk.sign(reject_signed_data)

                reject_bytes = encode_reject(
                    hello.sid,
                    reason,
                    reject_signature
                )

                self.retired_sids.add(hello.sid)

                self.emit({
                    "type": "send",
                    "to": sender,
                    "body": reject_bytes
                })


            #if extracted sid already in use or in retired_sids then silently discard and return
            if hello.sid in self.sessions_by_sid.keys() or hello.sid in self.retired_sids:
                return

            #try suites in order of preference and keep first one that's in hello.suites
            suite = None
            for candidate in PREFERENCE:
                if candidate in hello.suites:
                    suite = candidate
                    break
            
            #send an error if no suite was chosen
            if suite is None:
                send_reject(REASON_NO_COMMON_SUITE)
                return
            
            if suite == JM2 and len(hello.ek) != MLKEM_EK_LEN:
                #if mlkem public key bytes has incorrect length then fail and stop processing
                send_reject(REASON_HYBRID_INVALID)
                return
            
            try:
                initiator_identity_key = self.lookup_peer_key(sender)
            except PeerKeyUnavailable:
                self.retired_sids.add(hello.sid)
                self.emit({
                    "type": "error",
                    "peer": sender,
                    "message": "Peer identity key is unavailable",
                })
                return
            
            #generating repsonder key pairs
            x_priv = X25519PrivateKey.generate()
            x_pub = x_priv.public_key()
            x_pub_raw = x_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            dh = None
            #complete diffie hellman exchange or throw error for invalid X25519
            try:
                #need to serialize initiator public key bytes into proper public key object
                initiator_x_pub = X25519PublicKey.from_public_bytes(hello.x_pub)
                dh = x_priv.exchange(initiator_x_pub)
            except ValueError:
                self.retired_sids.add(hello.sid)
                self.emit({
                    "type": "error",
                    "peer": sender,
                    "message": "Invalid X25519 public key",
                })
                return

            #ss_pq is a MLKEM shared secret/keyschedule
            ss_pq = b""
            ciphertext = b""

            if suite == JM2:
                try:
                    #take initiator public bytes and serialize to get initiator public key object
                    initiator_ek = MLKEM768PublicKey.from_public_bytes(hello.ek)
                    #encapsulate and generate shared secret and ciphertext
                    ss_pq, ciphertext = initiator_ek.encapsulate()
                except (ValueError, TypeError):
                    send_reject(REASON_HYBRID_INVALID)
                    return
            
            reply_core = encode_reply_core(
                hello.sid,
                suite,
                x_pub_raw,
                ciphertext
            )

            th_r = sha256(
                b"JMessage-2026 TH-R"
                + encode_str8(sender)
                + encode_str8(self.username)
                + hello_bytes
                + reply_core
            ).digest()

            identity_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                self.identity_private_key
            )

            reply_signature = identity_private_key.sign(
                b"JMessage-2026 responder" + th_r
            )

            reply_bytes = reply_core + reply_signature
            
            keys = self.derive_session_keys(
                suite=suite, 
                dh=dh, 
                ss_pq=ss_pq, 
                initiator=initiator, 
                responder=responder,
                hello_bytes=hello_bytes,
                reply_bytes=reply_bytes
            )
            #create session_entry
            session_entry = {
                "sid": hello.sid,
                "peer": sender,
                "role": "responder",
                "state": "pending-finish",
                "suite": suite,
                "hello_bytes": hello_bytes,
                "reply_bytes": reply_bytes,
                "peer_identity_key": initiator_identity_key,
                "x_private": x_priv,
                "dh": dh,
                "ss_pq": ss_pq,
                "send_seq": 0,
                "recv_seq": 0,
                "start_time": self.now(),
                "fallback_used": False,
                "keys": keys,
                "sent_records": {},
                "received_receipts": set(),
                "resend_counts": {},
            }

            self.sessions_by_sid[hello.sid] = session_entry

            self.emit({
                "type": "send",
                "to": sender,
                "body": reply_bytes,
            })
        elif body[0] == T_REPLY:
            try:
                reply = parse_reply(body)
            except DecodeError:
                return
            
            session = self.sessions_by_sid.get(reply.sid)
            if session is None:
                return
            
            if (
                session["state"] != "pending-reply" 
                or session["role"] != "initiator" 
                or session["peer"] != sender
            ):
                return
        
            suite = reply.suite

            if suite not in session["suites"]:
                self.sessions_by_sid.pop(reply.sid, None)
                return
            
            if suite == JM2:
                if len(reply.ct) != MLKEM_CT_LEN:
                    self.sessions_by_sid.pop(reply.sid, None)
                    return
            elif suite == JM1:
                #should be no ciphertext in reply if JM1
                if reply.ct:
                    self.sessions_by_sid.pop(reply.sid, None)
                    return
            else:
                #if no suite then terminate session
                self.sessions_by_sid.pop(reply.sid, None)
                return
            
            th_r = sha256(b"JMessage-2026 TH-R" + encode_str8(self.username) + encode_str8(sender) + session["hello_bytes"] + reply.core).digest()

            #verify the reply signature with peer_identity_key and prefix + transcript responder hash.
            try:
                peer_public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                    session["peer_identity_key"]
                )
                peer_public_key.verify(
                    reply.sig,
                    b"JMessage-2026 responder" + th_r,
                )
            #Catch ValueError, TypeError, AND InvalidSignature
            except (ValueError, TypeError, InvalidSignature):
                self.sessions_by_sid.pop(reply.sid, None)
                return
            
            x_private = session["x_private"]

            #diffie hellman exchange with self private key from the session and reply public key
            try:
                responder_x_pub = X25519PublicKey.from_public_bytes(reply.x_pub)
                dh = x_private.exchange(responder_x_pub)
            except ValueError:
                self.sessions_by_sid.pop(reply.sid, None)
                return
            
            ss_pq = b""

            if suite == JM2:
                mlkem_private = session["mlkem_private"]
                try:
                    ss_pq = mlkem_private.decapsulate(reply.ct)
                except (ValueError, TypeError):
                    self.sessions_by_sid.pop(reply.sid, None)
                    return
            
            reply_bytes = body
            keys = self.derive_session_keys(
                suite= suite,
                dh = dh,
                ss_pq = ss_pq,
                initiator = self.username,
                responder = sender,
                hello_bytes = session["hello_bytes"],
                reply_bytes = reply_bytes,
            )

            session.update({
                "suite": suite,
                "reply_bytes": reply_bytes,
                "dh": dh,
                "ss_pq": ss_pq,
                "keys": keys
            })

            th_i = sha256(
                b"JMessage-2026 TH-I" + encode_str8(self.username) + encode_str8(sender) + session["hello_bytes"] + reply_bytes).digest()
            
            identity_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                self.identity_private_key
            )

            finish_signature = identity_private_key.sign(
                b"JMessage-2026 initiator" + th_i
            )

            finish_bytes = encode_finish(
                reply.sid,
                finish_signature,
            )

            self.emit({
                "type": "send",
                "to": sender,
                "body": finish_bytes,
            })

            session["state"] = "established"
            self.latest_session_by_peer[sender] = reply.sid
            

            self.emit({
                "type": "established",
                "peer": sender,
                "sid": reply.sid,
                "suite": suite,
            })
            self._flush_pending_text(sender)
        elif body[0] == T_FINISH:
            try:
                finish = parse_finish(body)
            except DecodeError:
                return

            session = self.sessions_by_sid.get(finish.sid)
            if session is None:
                return
            
            if (
                session["state"] != "pending-finish"
                or session["role"] != "responder"
                or session["peer"] != sender
            ): 
                return

            #recompute stored transcript hash from the initiator to verify
            th_i = sha256(
                b"JMessage-2026 TH-I"
                + encode_str8(sender)
                + encode_str8(self.username)
                + session["hello_bytes"]
                + session["reply_bytes"]
            ).digest()


            try:
                initiator_public_key = (
                    ed25519.Ed25519PublicKey.from_public_bytes(
                        session["peer_identity_key"]
                    )
                )

                #compare parse signature and computed signature to make sure initiator matches
                initiator_public_key.verify(
                    finish.sig,
                    b"JMessage-2026 initiator" + th_i,
                )
            except (ValueError, TypeError, InvalidSignature):
                self.sessions_by_sid.pop(finish.sid, None)
                self.retired_sids.add(finish.sid)
                return
            
            #after validating finish signature, move session state to established
            session["state"] = "established"
            self.latest_session_by_peer[sender] = finish.sid

            self.emit({
                "type": "established",
                "peer": sender,
                "sid": finish.sid,
                "suite": session["suite"],
            })
            self._flush_pending_text(sender)
        elif body[0] == T_REJECT:
            #same flow as always, try to parse reject and put in reject object
            try:
                reject = messages.parse_reject(body)
            except DecodeError:
                return

            #if session isn't valid through state, role, or peer then silently discard
            session = self.sessions_by_sid.get(reject.sid)
            if (
                session is None
                or session["state"] != "pending-reply"
                or session["role"] != "initiator"
                or session["peer"] != sender
            ):
                return

            #verify reject signature with peer identity key and compute signed with sid, reason, and sender. 
            try:
                peer_public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                    session["peer_identity_key"]
                )
                signed = (
                    b"JMessage-2026 reject"
                    + reject.sid
                    + bytes([reject.reason])
                    + encode_str8(sender)
                )
                peer_public_key.verify(reject.sig, signed)
            except (ValueError, TypeError, InvalidSignature):
                # forged reject shouldn't end a pending handshake.
                #so people can't tamper by just stalling connections
                return

            #if valid reject then pop sid from current sessions and retire that sid
            old_sid = reject.sid
            self.sessions_by_sid.pop(old_sid, None)
            self.retired_sids.add(old_sid)

            #emit the reason for the rejection
            if reject.reason != REASON_HYBRID_INVALID:
                self.emit({
                    "type": "error",
                    "peer": sender,
                    "message": "Peer rejected the handshake",
                })
                return

            if session.get("fallback_used") or JM2 not in session.get("suites", ()):
                self.emit({
                    "type": "error",
                    "peer": sender,
                    "message": "JM1 fallback already used",
                })
                return

            #generate random fallback_sid, ensure that it isn't already in use or already retired.
            fallback_sid = secrets.token_bytes(messages.SID_LEN)
            while (
                fallback_sid in self.sessions_by_sid
                or fallback_sid in self.retired_sids
            ):
                fallback_sid = secrets.token_bytes(messages.SID_LEN)

            #generate fallback keypairs and public helo bytes.
            fallback_private = X25519PrivateKey.generate()
            fallback_public = fallback_private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            fallback_hello = encode_hello(
                fallback_sid,
                (JM1,),
                fallback_public,
                b"",
            )

            #send a session downgrading the suite to just JM1 and restart with a fallback hello
            self.sessions_by_sid[fallback_sid] = {
                "sid": fallback_sid,
                "peer": sender,
                "role": "initiator",
                "state": "pending-reply",
                "suites": (JM1,),
                "hello_bytes": fallback_hello,
                "peer_identity_key": session["peer_identity_key"],
                "x_private": fallback_private,
                "mlkem_private": None,
                "start_time": self.now(),
                "fallback_used": True,
                "send_seq": 0,
                "recv_seq": 0,
                "key": None,
                "sent_records": {},
                "received_receipts": set(),
                "resend_counts": {},
            }
            self.emit({
                "type": "send",
                "to": sender,
                "body": fallback_hello,
            })
        elif body[0] == T_DATA:
            #parse the body with the parse_data function (same start as always)
            try:
                data = parse_data(body)
            except DecodeError:
                return
            
            #get session by sid
            session = self.sessions_by_sid.get(data.sid)
            if session is None:
                return
            
            #if the session isn't established or the stored peer doesn't equal the sender
            #do not accept that data
            if (
                session["state"] != "established"
                or session["peer"] != sender
            ):
                return
            
            if data.seq != session["recv_seq"]:
                return
            
            #control break, work on implementing receiving data if suite is JM2 first
            if session["suite"] == JM2:
                if len(data.protected) < 16:
                    return
                
                #depending on the direction, grab the corresponding key
                if session["role"] == "initiator":
                    direction = "ri"
                else:
                    direction = "ir"
                
                key = session["keys"][f"k_{direction}"]
                
                #compose nonce and associated data
                nonce = b"\x00\x00\x00\x00" + u64(data.seq)
                aad = data.sid + u64(data.seq)

                #decrypt with AESGCM given the key, nonce, encrypted data, and associated data
                try:
                    plaintext = AESGCM(key).decrypt(
                        nonce,
                        data.protected,
                        aad,
                    )
                except InvalidTag:
                    #resend body back if there's an invalid tag?
                    resend_body = encode_control(
                        T_RESEND,
                        data.sid,
                        data.seq,
                    )

                    self.emit({
                        "type": "send",
                        "to": sender,
                        "body": resend_body
                    })
                    return
                
                #after data has been properly received then increment received_sequence by 1
                #to match the ses_seq
                session["recv_seq"] = data.seq + 1

                receipt_body = encode_control(
                    T_RECEIPT,
                    data.sid,
                    data.seq,
                )
                self.emit({
                    "type": "send",
                    "to": sender,
                    "body": receipt_body,
                })

                try:
                    text = plaintext.decode("utf-8")
                except UnicodeDecodeError:
                    self.emit({
                        "type": "error",
                        "peer": sender,
                        "message": "Authenticated DATA is not valid UTF-8",
                    })
                    return

                if len(plaintext) > 4096:
                    self.emit({
                        "type": "error",
                        "peer": sender,
                        "message": "Authenticated DATA exceeds maximum length of 4096 bytes",
                    })
                    return
                
                self.emit({
                    "type": "message",
                    "peer": sender,
                    "sid": data.sid,
                    "seq": data.seq,
                    "text": text,
                })
                return
            elif session["suite"] == JM1:
                #if the only data is the tag which is 32 bytes long or it's not block aligned reject!
                if (
                    len(data.protected) < 32
                    or len(data.protected) % 16 != 0
                ): 
                    return
                
                if session["role"] == "initiator":
                    direction = "ri"
                else:
                    direction = "ir"
                
                enc_key = session["keys"][f"enc_{direction}"]
                mac_key = session["keys"][f"mac_{direction}"]

                iv = data.protected[:16]
                ciphertext = data.protected[16:]

                padded = None
                try:
                    decryptor = Cipher(
                        algorithms.AES(enc_key),
                        modes.CBC(iv),
                    ).decryptor()

                    padded = decryptor.update(ciphertext) + decryptor.finalize()
                except ValueError:
                    resend_body = encode_control(
                        T_RESEND,
                        data.sid,
                        data.seq,
                    )
                    self.emit({
                        "type": "send",
                        "to": sender,
                        "body": resend_body,
                    })
                    return

                try:
                    unpadded = pkcs7_unpad(padded, 16)
                except ValueError:
                    return
                
                if len(unpadded) < 32:
                    resend_body = encode_control(
                        T_RESEND,
                        data.sid,
                        data.seq,
                    )
                    self.emit({
                        "type": "send",
                        "to": sender,
                        "body": resend_body,
                    })
                    return
                
                #split the plaintext and received MAC
                plaintext = unpadded[:-32]
                received_mac = unpadded[-32:]

                mac_input = data.sid + u64(data.seq) + plaintext

                verifier = hmac.HMAC(
                    mac_key,
                    hashes.SHA256(),
                )

                verifier.update(mac_input)
                #compute mac tag given the data.sid, data.seq and plaintext decrypted
                expected_mac = verifier.finalize()

                #compare received mac and computed mac to see if they match
                if not secrets.compare_digest(received_mac, expected_mac):
                    resend_body = encode_control(
                        T_RESEND,
                        data.sid,
                        data.seq,
                    )
                    self.emit({
                        "type": "send",
                        "to": sender,
                        "body": resend_body,
                    })
                    return
                
                session["recv_seq"] = data.seq + 1

                receipt_body = encode_control(
                    T_RECEIPT,
                    data.sid,
                    data.seq,
                )

                self.emit({
                    "type": "send",
                    "to": sender,
                    "body": receipt_body
                })
                
                try:
                    text = plaintext.decode("utf-8")
                except UnicodeDecodeError:
                    self.emit({
                        "type": "error",
                        "peer": sender,
                        "message": "Authenticated DATA is not valid UTF-8",
                    })
                    return
                
                if len(plaintext) > 4096:
                    self.emit({
                        "type": "error",
                        "peer": sender,
                        "message": (
                            "Aunthenticated DATA exceeds maximum length of 4096 bytes "
                        ),
                    })
                    return
                
                self.emit({
                    "type": "message",
                    "peer": sender,
                    "sid": data.sid,
                    "seq": data.seq,
                    "text": text,
                })
                return


        elif body[0] in (T_RECEIPT, T_RESEND):
            try:
                control = parse_control(body)
            except DecodeError:
                return
            
            session = self.sessions_by_sid.get(control.sid)
            if session is None:
                return

            if (
                session["state"] != "established"
                or session["peer"] != sender
            ):
                return
            
            #control message sequence number out of the range of previously stored sequence numbers
            if control.seq >= session["send_seq"]:
                return
            
            if control.kind == T_RECEIPT:
                #if receipt has already been received then quit
                if control.seq in session["received_receipts"]:
                    return
                
                session["received_receipts"].add(control.seq)

                self.emit({
                    "type": "receipt",
                    "peer": sender,
                    "sid": control.sid,
                    "seq": control.seq,
                })
                return

            if control.kind == T_RESEND:
                resend_count = session["resend_counts"].get(control.seq, 0)

                #prevents multiple resends of the same sequence number
                if resend_count >= 1:
                    self.emit({
                        "type": "warning",
                        "peer": sender,
                        "message": (
                            f"Not resending sequence {control.seq} more than once"
                        ),
                    })
                    return

                cached_body = session["sent_records"].get(control.seq)
                if cached_body is None:
                    self.emit({
                        "type": "warning",
                        "peer": sender,
                        "message": (
                            f"No cached DATA record for sequence {control.seq}"
                        )
                    })
                    return
                
                self.emit({
                    "type": "send",
                    "to": sender,
                    "body": cached_body,
                })

                session["resend_counts"][control.seq] = resend_count + 1
                return            


        


    # ----- 5. Key schedule (§6.7) ---------------------------------------------
    # Review-critical (AGENTS.md "What counts as explained": row "Key
    # schedule"). No stub method: this is called from your handshake code in
    # both roles, and how you structure it is up to you.
    #
    # Inputs:  the suite; dh = X25519 shared secret (after §2's checks); for
    #          JM2, ss_pq from ML-KEM; both usernames; the exact HELLO and
    #          REPLY bytes of this handshake.
    # Outputs: the directional record keys of the §6.7 table, IR (initiator to
    #          responder) and RI (responder to initiator).
    # Spec:    §6.7 defines ikm, the transcript hash used as the HKDF salt, the
    #          info string (note §3: the label ends with a space), the output
    #          length L and the split.
    # Afterwards: both sides hold identical IR and RI keys. Each side sends
    #          with its own direction's key and receives with the other's,
    #          so which key is "mine" depends on the role.

    # ----- 6. Records (§§6.9, 7.1, 7.2) ----------------------------------------
    # Core and review-critical (AGENTS.md "Core": the JM1 record functions and
    # the JM2 AEAD calls; "What counts as explained": row "Record receive").
    #
    # Sending (send_text below, §7.1): build `protected` for the session's
    # suite and wrap it in DATA. Receiving (DATA via receive, §7.2): the five
    # ordered steps, whose outcomes are a silent discard, a RESEND, or a
    # RECEIPT plus delivery (or a local error for invalid UTF-8). Use your
    # Part 0 `pkcs7_pad`/`pkcs7_unpad` for JM1.

    def send_text(self, peer, text):
        """Send or queue text using the appropriate session (§§6.9 and 7).

        Implements the session-selection and queueing rules of §6.9 and DATA
        construction in §7.1.

        Args:
            peer: the recipient username.
            text: the message `str`. Empty text is allowed (§7.1).

        Returns:
            None. Communicates only through `emit`.

        Emits:
            A "send" event with a DATA body if a session with `peer` is
            established; otherwise possibly a HELLO, if no handshake with that
            peer is pending in either role (§6.9). An "error" event if the
            text is invalid or too long.

        Afterwards:
            * Text over 4096 UTF-8 bytes (or not encodable as UTF-8) was
              rejected before any sequence number was allocated (§7.1).
            * If a DATA record was sent: it used the most recently established
              session with `peer` (§6.9), that session's send_seq was used
              once and then advanced by one, and its sequence number was never
              before paired with different plaintext under these keys (§7.1).
              JM1 used a fresh random IV; JM2 used the nonce §7.1 defines.
            * Otherwise the text is queued for `peer`, to be sent on whichever
              session with that peer is established first (§6.9).
        """

        #encode text with utf-8 catch encode error and emit an error message
        try:
            plaintext = text.encode("utf-8")
        except UnicodeEncodeError:
            self.emit({
                "type": "error",
                "peer": peer,
                "message": "Text is not valid UTF-8",
            })
            return
        
        if len(plaintext) > 4096:
            self.emit({
                "type": "error",
                "peer": peer,
                "message": "Text exceeds the required length of 4096 bytes" 
            })
            return
        
        #retrieved the sid of latest used session
        sid = self.latest_session_by_peer.get(peer)

        #access the session through that sid
        session = self.sessions_by_sid.get(sid) if sid is not None else None

        if session is None or session["state"] != "established":
            #queue structure for text to be sent; list of strings contained in the queue
            self.pending_text_by_peer.setdefault(peer, []).append(text)

            #grab any sessions that has "peer" equal to peer, state in "pending-reply" or "pending-finish"
            #and save that to "has_pending_handshake"
            has_pending_handshake = any(
                entry["peer"] == peer 
                and entry["state"] in ("pending-reply", "pending-finish")
                for entry in self.sessions_by_sid.values()
            )

            if not has_pending_handshake:
                self.start_handshake(peer)
            
            return
        
        #grab sequence number from the session
        seq = session["send_seq"]

        #before we increment, check to make sure it hasn't reached the limit 2^64 - 1
        if seq >= 2**64 - 1:
            self.emit({
                "type": "error",
                "peer": peer,
                "message": "Send sequence exhausted"
            })
        
        if session["role"] == "initiator":
            direction = "ir"
        else:
            direction = "ri"
        
        key, enc_key, mac_key = None, None, None
        
        if session["suite"] == JM2:
            key = session["keys"][f"k_{direction}"]
        else:
            enc_key = session["keys"][f"enc_{direction}"]
            mac_key = session["keys"][f"mac_{direction}"]
        
        if session["suite"] == JM2:
            #nonce is 12 bytes long
            nonce = b"\x00\x00\x00\x00" + u64(seq)

            #define associated data with sid and sequence number
            aad = sid + u64(seq)
            
            #create encryption object with post quantum safe key
            aesgcm = AESGCM(key)
            #encrypted with nonce, plaintext, and aad
            protected = aesgcm.encrypt(
                nonce,
                plaintext,
                aad,
            )
            data_body = encode_data(
                sid,
                seq,
                protected,
            )

            self.emit({
                "type": "send",
                "to": peer,
                "body": data_body,
            })

            #map the sequence number to data_body that was sent, in case of RESEND; making sure to cache AFTER successful emit
            session["sent_records"][seq] = data_body

            #only increment send seq after UT8-validation, verified established session
            #exists, and after encryption succeeds,
            session["send_seq"] = seq + 1
        elif session["suite"] == JM1:

            #create mac_input with sid + sequence number and plaintext
            mac_input = sid + u64(seq) + plaintext

            #setup hmac function with key and sha256 hashing algorithmn 
            mac = hmac.HMAC(
                mac_key,
                hashes.SHA256(),
            )

            #createa  tag with hmac function and mac_input. function set up with key with input (sid + seq# + plaintext) = tag
            mac.update(mac_input)
            tag = mac.finalize()

            #pad plaintext and tag together
            padded = pkcs7_pad(plaintext + tag, 16)

            #generate random iv bits
            iv = secrets.token_bytes(16)
            #set up AES cipher with the encryption key and CBC mode with a randomized Initialization vector
            encryptor = Cipher(
                #not even using AESGCM, just plain AES with CBC??? definitely vulnerable to some kinda attack
                algorithms.AES(enc_key),
                modes.CBC(iv),
            ).encryptor()

            #encrypt padded material (plaintext + tag)
            ciphertext = encryptor.update(padded) + encryptor.finalize()

            #append the same random iv? to the ciphertext and then encode/encrypt that with sid, seq#, and protected
            protected = iv + ciphertext

            data_body = encode_data(
                sid,
                seq,
                protected,
            )

            self.emit({
                "type": "send",
                "to": peer,
                "body": data_body,
            })

            session["sent_records"][seq] = data_body
            session["send_seq"] = seq + 1
            return






        return

    # ----- 7. Control messages (§7.3) -------------------------------------------
    # Part of AGENTS.md "What counts as explained", row "Record receive".
    # No stub method: RECEIPT and RESEND arrive through `receive`, and you send
    # them from your DATA-receive path.
    #
    # §7.3 says: never answer a control message with a control message; accept
    # one only for an established session, from the expected peer, naming a
    # seq this session has already sent; report a given receipt at most once;
    # on RESEND, either warn, or resend the exact cached DATA body (at most
    # once per record), never a re-encryption. Both messages are
    # unauthenticated: a RECEIPT is a delivery indication, not proof.

    # ----- 8. Timeouts and robustness (Appendix B) ------------------------------
    # Optional and not graded (handout §3, spec Appendix B). These methods must
    # exist; they may remain no-ops. The supplied driver stops on any transport
    # failure, so it does not depend on them.

    def check_timeouts(self):
        """Optional Appendix B robustness; this method may remain a no-op.

        Called by the driver after every poll, and by `Network.advance` in
        tests. Appendix B recommends expiring a pending handshake once 60 s or
        more of `self.now()` have elapsed since it was created, abandoning it
        with an error report (§6.9).

        Returns:
            None.
        """

    def reset_peer_trust(self, peer):
        """Optional Appendix B robustness; this method may remain a no-op.

        An explicit local user action (the `reset-trust` command), never an
        automatic response to a peer message (handout §3). Appendix B: after
        a peer's directory key changes, require this reset, which abandons
        that peer's handshakes and sessions, before using the new key.

        Args:
            peer: the username whose trust state to reset.

        Returns:
            None.
        """

    def transport_failed(self, peer=None):
        """Optional Appendix B robustness; the supplied live driver stops on failure.

        Called once by the driver after a transport failure: with the affected
        `peer` after a failed send, or with `None` after an uncertain receive,
        which may have lost mail for any session (handout §3). Appendix B
        suggests abandoning the affected sessions. Whatever you do, never
        reset sequence counters while keeping the same keys (§4.6).

        Args:
            peer: the affected username, or None for "all sessions".

        Returns:
            None.
        """

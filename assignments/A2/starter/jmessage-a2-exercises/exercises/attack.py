"""Your Parts 2 and 3 attacks. Fill in the entry points below.

The runner starts a fresh sandbox, calls `start` for you, and then calls one of
these functions with an `ExerciseAPI` object `api` (see API.md). You act as the
malicious relay: inspect the queue, deliver, drop, and inject protocol bodies.
You never see plaintext, keys, or any padding/MAC flag — only the wire messages
the bots emit and the limited status fields.

Copy this exercises/ directory into your client directory (your submission),
then run from the extracted kit, with <dir> that client directory:

    python run_exercises.py --submission <dir> --part 2 --output <dir>/run-part2
    python run_exercises.py --submission <dir> --part 3 --output <dir>/run-part3
    python run_exercises.py --submission <dir> --part chain --output <dir>/run-chain
    python run_exercises.py --submission <dir> --part experiment --output <dir>/run-exp

See EXERCISES.md for the task, the threat model, the evidence to submit, and the
resource limits. `recover_byte` is yours to write by hand (handout Revision 3).
"""
T_HELLO, T_REPLY, T_FINISH, T_REJECT = 0x01, 0x02, 0x03, 0x04

def parse_hello(body: bytes) -> dict:
    if len(body) < 18 or body[0] != T_HELLO:
        raise ValueError("not a HELLo")
    sid = body[1:17]
    n = body[17] # of suites? or suite prefix
    suites_end = 18 + 2 * n 
    if len(body) < suites_end + 32 + 2:
        raise ValueError("HELLO truncated before ek_I length")
    
    suites = [int.from_bytes(body[i: i+2], "big") for i in range(18, suites_end, 2)]
    x_I = body[suites_end: suites_end + 32]
    ek_off = suites_end + 32 #where ek_I information starts
    ek_len = int.from_bytes(body[ek_off: ek_off + 2], "big")
    ek_I = body[ek_off + 2: ek_off + 2 + ek_len]
    if len(ek_I) != ek_len:
        raise ValueError("ek_I truncated relative to its length prefix")
    
    return {"sid": sid, "suites": suites, "x_I": x_I, "ek_off": ek_off, "ek_len": ek_len, "ek_I": ek_I}

def probe(api, sid: bytes, seq: int, protected: bytes) -> bool:
    # True if AND ONLY IF Bob emitted a RESEND (valid padding on the last block)
    body = bytes([0x10]) + sid + seq.to_bytes(8, "big") + protected #build body with protected bytes
    emitted = api.inject("alice", "bob", body)
    return any(e["from"] == "bob" and e["body"][:1] == bytes([0x12]) for e in emitted) #if there was a valid padding on that block, a resend will be emitted


def downgrade(api) -> bytes:
    """Part 2. Make the two honest bots establish a JM1 session.

    Alice's initial HELLO (offering JM2 then JM1) is already queued. Using only
    the adversary operations, cause both bots to establish JM1, and return that
    session's 16-byte `sid`. For a chained run, leave the challenge DATA
    unaccepted by Bob. The runner checks both bots' real session state; a
    returned sid is a claim, not proof.
    """
    #locate alice's hello in the queue
    hello = next(e for e in api.queue()
                if e["from"] == "alice" and e["to"] == "bob"
                and e["body"][:1] == bytes([T_HELLO]))
    parse_h = parse_hello(hello["body"])

    #send hello to Bob with same sid and suitelist but malformed ek_I length (don't read any bytes past that ek_off)
    #since ek_I still shows as one of the suites, Bob will send a reject with reasons 0x01 because ek_I length doesn't equal 1184 bytes
    #reject signature only covers sid||reason|| I so it should verify for Alice, because she's unable to verify that her HELLO was properly sent

    malform = hello["body"][:parse_h["ek_off"]] + b"\x00\x00"
    emitted = api.inject("alice", "bob", malform)

    reject = next(e for e in emitted
                if e["from"] == "bob" and e["body"][:1] == bytes([T_REJECT]))
    if reject["body"][1: 17] != parse_h["sid"]:
        raise RuntimeError("REJECT sid doesn't match original HELLO")
    if reject["body"][17] != 0x01:
        raise RuntimeError(f"expected hybrid_invalid, got reason {reject['body'][17]}")

    #don't allow Alice eto see untouched original, she only sees REJECT
    api.drop(hello["id"])

    #deliver reject to Alice and obtain NEW Hello envelope
    retry = api.deliver(reject["id"])
    retry_hello = next(e for e in retry if e["from"] == "alice" and e["body"][:1] == bytes([T_HELLO]))
    retry_parse = parse_hello(retry_hello["body"])

    #downgrade failed
    if retry_parse["suites"] != [0x0001]:
        raise RuntimeError(f"fallback HELLO offers more than just JM1: {retry_parse["suites"]}")
    if retry_parse["ek_len"] != 0:
        raise RuntimeError("Fallback HELLO has non-empty ek_I")
    
    bob_out = api.deliver(retry_hello["id"])
    reply  = next(e for e in bob_out if e["body"][:1] == bytes([T_REPLY]))
    if int.from_bytes(reply["body"][17:19], "big") != 0x0001:
        raise RuntimeError("Bob did not select JM1 on the retry")
    alice_out = api.deliver(reply["id"])
    finish = next(e for e in alice_out if e["body"][:1] == bytes([T_FINISH]))
    api.deliver(finish["id"])

    #both sides should have established a JM1 session.
    st = api.status()
    neg = st["negotiation"]

    #final check to make sure downgrade didn't fail
    if not neg or neg["suite"] != 1:
        raise RuntimeError(f"no Jm1 session establisehd: {st["negotiation"]}")
    return neg["sid"]


def recover_byte(prev_block: bytes, forged_prev: bytes, position: int) -> int:
    """Return the plaintext byte at `position` of the target block. WRITE THIS YOURSELF.

    This is the one piece of the attack you must write by hand, not generate
    (handout Revision 3, "Write this yourself"). Above it, add a two- or
    three-line comment deriving it from how CBC decryption works.

    `prev_block` is the genuine ciphertext block (or the IV) that precedes the
    target block in the record. `forged_prev` is the previous block you sent
    that made the oracle report valid padding, with the bytes after `position`
    already fixed to produce the matching padding value. Return the recovered
    plaintext byte (0-255).

    Your `recover` must call this for every byte it reports.
    """

    # starting from pad_val = forged_prev[i] ^ D(c_i). this being confirmed and denied by the probe,
    #  D(c_i) = forged_prev[i] ^ pad_val , pad_val is calculated by 16 - pos
    # we're recomputing the value of D(c_i) because we've already attained a succesful probe and accurately guessed the value 
    # of forged_prev[i] for that specific pad_val.
    pad_val = 16 - position
    dc_i = forged_prev[position] ^ pad_val
    # know we know D(c_i), we have two of the three ingredients in the equation to solve for p_i
    # P_i = D(c_i) XOR c_i-1
    return dc_i ^ prev_block[position]


def recover(api, target) -> dict:
    """Part 3. Recover the plaintext of the captured JM1 record `target`.

    `target` is the decoded original DATA envelope (its `body` is bytes). Return:

        {"plaintext": <bytes or None>, "blocks": {block_index: <16 bytes>, ...}}

    `plaintext` excludes the HMAC and padding. `blocks` is optional evidence of
    progress: each value is a recovered 16-byte block of the CBC-decrypted
    padded string, zero-indexed in ciphertext order (the IV is not block 0).
    Return None for `plaintext` if you did not recover the whole message.
    Obtain every recovered byte through `recover_byte`.
    """
    body = target["body"]
    if body[0] != 0x10:
        raise ValueError("target is not a DATA record")
    
    sid = body[1:17]
    seq = int.from_bytes(body[17:25], "big")
    protected = body[25:]
    if len(protected) < 32 or len(protected) % 16 != 0:
        raise ValueError("bad Jm1 protected length")
    
    iv, cts = protected[:16], protected[16:]
    nblocks = len(cts) // 16
    #divide ciphertext into iv and 16 byte length blocks
    c = [iv] + [cts[i*16: (i+1)*16] for i in range(nblocks)] # c[0] = IV, c[1..] = C_i

    P = bytearray()
    blocks = {}

    #for each of the blocks
    for j in range(nblocks):
        C_j = c[j + 1] # the ciphertext block we decrypt
        prev = c[j] # prev block

        forged = bytearray(16)
        recovered = bytearray(16)

        for pos in range(15, -1, -1):
            pad_val = 16 - pos 

            if pos < 15:
                # fix up already-recovered bytes to produce pad_val
                for k in range(pos + 1, 16):
                    # forged[k] = D(c_i) xor pad_val. D(c_i) = recovered ^ prev[k]
                    forged[k] = recovered[k] ^ prev[k] ^ pad_val
            found = None
            for guess in range(256):
                forged[pos] = guess
                #oracle examines last plaintext block.
                #feed forged followed by C_j so D(C_j) XOR forged is last.
                if probe(api, sid, seq, bytes(forged) + C_j):
                    # padding is valid. we've found the guess that makes guess ^ C_j[pos] = pad_val
                    found = guess
                    break
            if found is None:
                raise RuntimeError(f"no valid byte at block {j} pos {pos}")
            
            #recover_byte turns (prev, forged, pos) into the plaintext byte
            recovered[pos] = recover_byte(prev, bytes(forged), pos)
            P_byte_plain = recovered[pos]

        P.extend(recovered)
        blocks[j] = bytes(recovered)
    
    padlen = P[-1]
    if not (1 <= padlen <= 16) or P[-padlen:] != bytes([padlen]) * padlen:
        raise RuntimeError("final padding invalid; something went wrong")
    plaintext = bytes(P[:-padlen][:-32])
    return {"plaintext": plaintext, "blocks": blocks}



def experiment(api) -> None:
    """Optional diagnostic for Part 2's write-up (offer-stripping).

    A fresh negotiation sandbox is started for you. Try to strip JM2 from the
    HELLO and observe why the handshake does not complete. This produces a
    transport trace you can cite; it earns no execution verdict by itself and
    is expected not to establish a session.
    """
    hello = next(e for e in api.queue() if e["from"] == "alice" and e["body"][:1] == bytes([T_HELLO]))
    parse_h = parse_hello(hello["body"])

    #rewrite sutie list to [JM1], and keep ek_I empty
    suite_bytes = b"".join(s.to_bytes(2, "big") for s in parse_h["suites"] if s != 0x0002)
    new_n = len(suite_bytes) // 2
    stripped = (hello["body"][:17] + bytes([new_n]) + suite_bytes + parse_h["x_I"] + b"\x00\x00")

    if new_n == 0:
        raise RuntimeError("nothing left after stripping JM2, not even JM1 offered")
    
    bob_out = api.inject("alice", "bob", stripped)
    reply = next((e for e in bob_out if e["body"][:1]  == bytes([T_REPLY])), None)
    if reply is None:
        #bob either discarded or rejected
        api.drop(hello["id"])
        return
    
    #relay Bob's authentic JM1 reply to Alice. 
    #TH_R is computed over original HELLO, so sig_R fails
    alice_out = api.deliver(reply["id"])
    if any(e["body"][:1] == bytes([T_FINISH]) for e in alice_out):
        raise RuntimeError("Alice accepted the stripped-offer REPLY")
    if api.status()["negotiation"] is not None:
        raise RuntimeError("negotation established??")
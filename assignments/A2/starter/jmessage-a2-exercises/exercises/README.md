# Parts 2 and 3 — your explanation and evidence

Fill this in. It is graded separately from whether your attacks executed:
a clear account of a partial result earns partial credit, and a working attack
you cannot explain does not earn full marks. Keep it concise — a page or two.
Put the repair analysis in `written.md` (Part 4) and cross-reference it here
rather than repeating it.

## How to run my attacks

- Which parts are complete: downgrade, experiment, recover, recover_byte
- Commands I ran (and which `run-*/result.json` backs each claim):

python run_exercises.py --submission /home/tobi/Crypto/practicalcrypto2026/assignments/A2/starter/ --part experiment --output /home/tobi/Crypto/practicalcrypto2026/assignments/A2/starter/run-exp
python run_exercises.py --submission /home/tobi/Crypto/practicalcrypto2026/assignments/A2/starter/jmessage-a2-exercises/ --part 2 --output /home/tobi/Crypto/practicalcrypto2026/assignments/A2/starter/run-part2
python run_exercises.py --submission /home/tobi/Crypto/practicalcrypto2026/assignments/A2/starter/jmessage-a2-exercises/ --part 3 --output /home/tobi/Crypto/practicalcrypto2026/assignments/A2/starter/run-part3

run-exp/result.json helps back the experiment claim that trying to downgrade by malforming hello by excluding a suite will cause handshake to fail
run-part2/result.json backs the downgrade claim by showing that if you keep both offered suites but malform ek_I length so it's not equal to 1184 bytes,
a valid and signed reject is sent which forces a downgrade and establishes a new JM1 session
run-part3/result.json shows that indeed CBC can be broken through padding oracles and XOR operations.

## Part 2 — downgrade

- Alice's original offer (the suites, in order): Jm2, jm1
- The interventions I made, as a short sequence of relay operations:

Alice sends HELLO, I capture that HELLO and malform the ek_I length, inject with the API
and send to Bob. Bob receives malformed HELLO and while he's processing it, finds that the
ek_I length is wrong and REJECTS with reason 0x01.
Alice receives REJECT and retries establishment with new HELLO and only Jm1 suite offered.
Bob receives and accepts Jm1 suite and sends a REPLY.
Alice sends a FINISH and they can start exchanging records..

- Evidence that **both** bots established JM1 (cite `result.json` /
  `transport-trace.jsonl`):

"negotation": "pass" and "sid": "71945d747dae62a933b767dfb1df2641"
and we see the length of the record decrease significantly from 1000> bytes, when Jm2 was offered with the key of 1184 bytes, to just <100 bytes with jm1

- **Offer-stripping experiment.** What I changed, what the responder did, and
  why the handshake failed at the transcript-verification step (name the check):
  Instead of malforming the ek_I length, offer-stripping tried to fully discard Jm2 out of the provided suites in the HELLO. However
  once responder sends a REPLY with those malformed hello bytes, the initiator verifies with a signature and the signature fails because
  those aren't the same HELLO bytes that the initiator sends and the handshake fails.

## Part 3 — record recovery

- The observable distinction I used as the oracle: The Resend policy when the padding is valid and silence when the padding is invalid.
- A few representative probes and the responses they drew (not the whole log): 

{"op": 3138, "method": "POST", "path": "/adv/inject", "status": 200, "delivered_id": 3167, "injected": {"from": "alice", "to": "bob", "type": "DATA", "len": 57, "b64": "EHyuAbqWnctkpxWY3L73uiMAAAAAAAAAAAAAAAAAAEpxPRuXT+m1RLbutXCh0Ww/dANhg39Cd0IP", "id": 3167, "sid": "7cae01ba969dcb64a71598dcbef7ba23", "seq": 0}, "emitted": []}

{"op": 3139, "method": "POST", "path": "/adv/inject", "status": 200, "delivered_id": 3168, "injected": {"from": "alice", "to": "bob", "type": "DATA", "len": 57, "b64": "EHyuAbqWnctkpxWY3L73uiMAAAAAAAAAAAAAAAAAAEtxPRuXT+m1RLbutXCh0Ww/dANhg39Cd0IP", "id": 3168, "sid": "7cae01ba969dcb64a71598dcbef7ba23", "seq": 0}, "emitted": []}

{"op": 3140, "method": "POST", "path": "/adv/inject", "status": 200, "delivered_id": 3169, "injected": {"from": "alice", "to": "bob", "type": "DATA", "len": 57, "b64": "EHyuAbqWnctkpxWY3L73uiMAAAAAAAAAAAAAAAAAAExxPRuXT+m1RLbutXCh0Ww/dANhg39Cd0IP", "id": 3169, "sid": "7cae01ba969dcb64a71598dcbef7ba23", "seq": 0}, "emitted": []}

{"op": 3141, "method": "POST", "path": "/adv/inject", "status": 200, "delivered_id": 3170, "injected": {"from": "alice", "to": "bob", "type": "DATA", "len": 57, "b64": "EHyuAbqWnctkpxWY3L73uiMAAAAAAAAAAAAAAAAAAE1xPRuXT+m1RLbutXCh0Ww/dANhg39Cd0IP", "id": 3170, "sid": "7cae01ba969dcb64a71598dcbef7ba23", "seq": 0}, "emitted": [{"from": "bob", "to": "alice", "type": "RESEND", "len": 25, "b64": "EnyuAbqWnctkpxWY3L73uiMAAAAAAAAAAA==", "id": 3171}]}


- Which sequence number my probes used, and why it stays usable: my probes use a sequence # of 0 and it stays usable because you're only incrementing sequence number on a 
correct prob with valid padding and a valid mac. We don't have a valid mac so the best we're getting is a resend with no increment (at worst, no response with no increment).
- How I resolved the last-byte padding ambiguity: mutate second to last byte, if padding holds then we did find forge value valid for pad_val 0x01. if padding fails then we happened to
coincidentally find forge value for padding 0x02 when we we're looking for 0x01 and keep trying again.
- Recovered output, or the blocks I recovered and how far I got: 6 blocks.
- Approximate query count: 12000
- My `recover_byte`: a sentence on the CBC relation it computes (you wrote it): Padding value = 16 - pos, the Decryption of ciphertext block i is known from XORing forged_prev with padding value and we can recover plaintext[k] by XORing the decryption of ciphertext block i[k] and previous ciphertext block i - 1[k].

## Security property and limits

- The security property that failed, in one or two sentences: Exposing padding validation through RESEND or silence. Or failing to verify HELLO before REJECT. 
- The assumptions my attack needs (what the relay can do, what it cannot): HELLo needs to stay unsigned, attacker needs to be in the middle of communication with the ability to receive and also inject messages. Attack needs to see whether any information about whether padding was validated or not (a distinct difference shown between a success and a failure)
- The limits of my evidence (what a single run does and does not show): Not completely sure.

## Interface, bot, or agent (Part 1 extra credit)

- Would the thing you built have shown the user the downgrade? If you built
  none, write "not applicable."

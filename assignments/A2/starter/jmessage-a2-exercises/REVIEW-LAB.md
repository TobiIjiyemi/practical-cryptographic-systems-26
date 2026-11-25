# Review Lab 2 — what to expect

The review lab is a 15-minute, in-person conversation about your own
submission, graded separately (the three labs are 25% of the course grade). No
tools, no notes, no agent. It is not a quiz on trivia; it is a chance to show
that you understand the code and the attacks you submitted.

The point allocation and the interviewer's script are staff documents; this
page tells you how to prepare and what the conversation looks like.

## It starts from your own trace

The first thing on the table is **your hand-traced handshake from `design.md`**
(Part 1b). Expect to walk through it: which bytes each hash covers, which copy
of the HELLO each side uses, which key verifies which signature. If you wrote
that trace yourself, this is the easiest part of the lab; if you did not, it is
the hardest.

## The progression

For each region, the interviewer moves through four steps. Prepare to do all
four, not just the first:

1. **Trace** — walk through what your code does on a concrete input.
2. **Explain** — say *why* it is correct: the invariant it maintains, the
   property a step provides.
3. **Predict** — say what it would do on an input you have not tried, and why.
4. **Modify** — make a small change live, or find a planted bug, and explain
   the effect.

## Regions you will be asked about

From Part 1 (see the starter's `AGENTS.md` for the full list): transcript
construction and signature checks; the key schedule; the record receive path
and its check order; and the handshake state machine, including REJECT and the
fallback retry.

From Parts 2 and 3:

- **The downgrade.** Why stripping JM2 from the offer is caught, and where. What
  the working downgrade relies on instead — which signature covers what, and why
  that leaves a gap. State the threat model: who the attacker is and what powers
  that assumes.
- **The record oracle.** The exact order in which JM1 checks a record, which
  outcome each failure produces on the wire, and why that difference leaks the
  plaintext. Be ready to explain your `recover_byte` from first principles: the
  CBC relation between a forged previous block, the padding value, and a
  recovered byte. Expect "your probe got a RESEND on guess 0x01 for the last
  byte — what are the two cases, and how did you tell them apart?"
- **Repairs.** For each attack, a repair, the property it restores, what it
  costs in compatibility, and a limitation it does not fix. This is also Part 4;
  the lab asks you to reason about it aloud, including a change like "bind the
  REJECT to the HELLO as received — does your downgrade still work? why not?"

## How to prepare

Re-read your own `design.md`, `written.md`, and `exercises/README.md`, and make
sure every claim in them is one you can defend without the text in front of you.
Run your attacks once more and watch the transport trace so you can describe,
concretely, what you sent and what came back. Practise making one small change
to each review-critical region and predicting its effect before you run it.
Passing the runner is not the same as being ready for the lab: two copies of a
mistaken idea can still agree.

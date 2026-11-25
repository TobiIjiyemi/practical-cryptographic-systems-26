# Written explanation and repair analysis

Answer handout Part 4, questions 1–6, here in your own words. Cite the relevant
functions where helpful. Put optional extra-credit answers under a separate
heading. These prompts are not completed answers.

What establishes the association between a username and an identity key? What does a valid signature establish when that association is untrusted?
The server directory establishes the association between a username and an identity key. When the server directory is untrusted or compromised (or somehow that association is untrusted), a valid signature only establishes that someone who controls that key tied to the specific username signed whatever transcript. Because the association is untrusted when can't say for sure that "Bob" signed the transcript, only that whoever owns Bob key signed the transcript.

Trace the initiator's and responder's inputs to the JM2 key schedule. Explain why they agree and why the two traffic directions use different keys.
dh = X25519(x_I, x_R)
ss_pq from Encaps and Decaps 
input key material = ss_pq || dh
compute the same sha256 hash using set prefix, usernames, HELLO, and REPLY on both sides.
output keying material is the output of the hash key derivation function initialized with computed hash as the salt, and a set prefix as info.

Key schedule agrees because computed sha256 hash is only the same if both sides agree on every handshake byte (same transcript for initiator and responder)
and both parties using diferent keys and two traffic directions to prevent nonce reuse under the same key. same seq value but opposite directions is okay.

Which negotiation data does each signature cover? Explain why checking one handshake transcript does not by itself establish the security of the application's broader negotiation policy.
sig_R covers both usernames, RECEIVED Hello bytes, sid, chosen suite, X_R, and then ct
sig_I covers transcript of the initiator which includes the HELLO sent and the REPLY received
sig_REJECT only covers the sid, reason, and initiator name but NOT HELLO or REPLY.

Checking something like HELLO -> REJECT -> HELLO -> REPLY -> FINISH doesn't establish the security of the applicatino's broader negoation policy because here it's not apparent to us that the responder could have received a malformed HELLO even though at each step of the way valid signatures are being provided and verified. The fallback policy is triggered and because we REJECT before HELLO can be verified, it allows the negotiation policy to be exploited.

Explain the distinct receive outcomes for JM1 and JM2 and their security implications. Evaluate a record-layer repair and describe the acceptance and rejection behavior it should have.
The different in receive outcomes for JM1 and Jm2 is that good padding vs bad padding can be revealed one bit at a time while in JM1 while in JM2 there is no indicator. A record-layer repair is rejecting both cases of bad padding and bad authentincation in the same way (as opposed to resending with good padding but bad mac). or remove the oracle entirely by encrypting then mac.

Propose a negotiation-policy repair. State the property restored, its compatibility cost, and a limitation it does not address.
Force the fallback retry offer to send the same suite list as opposed to stripping JM2. Now user can't force a downgrade with malformed ek_I bytes in HELLO, however overall security of the protocol is still at risk if one party ONLY accepts JM1.

Does adding ML-KEM make this entire protocol post-quantum secure? Distinguish key agreement from identity authentication, and explain what FINISH and RECEIPT do and do not confirm.
Key agreement is safe because hybrid Jm2 combines X25519 and ML-KEM which stays post quantum secure. Identity authentication, however, is covered under Ed25519 which is not post-quantum safe. Finish confirms that the initiator derived the keys and knows their own private key, but doesn't prove that the responder has decrypted anything yet. Receipt is supposed to show that recipient has been delivered a message however attackers can forge RECEIPTs. The entire protocol is safe in confidentiality but not authenticity when you add ML-KEM.
# Part 4 — Empirical analysis

## Procedure
<!-- corpus used, trials per cell, how keys/windows were sampled -->

## Key-length recovery (Part 2): fraction of exact recoveries

| k \ n | 100 | 200 | 500 | 1000 | 2000 | 5000 | 20000 |
|---|---|---|---|---|---|---|---|
| 3 | 0.04  | 0.08  | 0.52  | 0.92  | 1.0  | 1.0  | 1.0  |
| 5 | 0.04| 0.12| 0.68| 1.0| 1.0| 1.0| 1.0 |
| 7 | 0.16| 0.6| 0.8| 1.0| 1.0| 1.0| 1.0|
| 10 | 0.04| 0.4| 0.84| 1.0| 1.0| 1.0| 1.0 |
| 15 | 0.28| 0.72| 0.92| 1.0| 1.0| 1.0 | 1.0 |
| 20 | 0.24| 0.48| 1.0| 1.0| 1.0 | 1.0 | 1.0 |

## Key recovery (Part 3): fraction of exact recoveries

| k \ n | 100 | 200 | 500 | 1000 | 2000 | 5000 | 20000 |
|---|---|---|---|---|---|---|---|
| 3 | 0.04| 0.08 | 0.52| 0.92| 1.0| 1.0| 1.0|
| 5 | 0.04| 0.12| 0.68| 1.0| 1.0| 1.0| 1.0|
| 7 | 0.04| 0.44| 0.8| 1.0| 1.0| 1.0 | 1.0|
| 10 | 0.0| 0.24| 0.84| 1.0| 1.0| 1.0| 1.0|
| 15 | 0.0| 0.08| 0.52| 0.96| 1.0| 1.0| 1.0|
| 20 | 0.0 | 0.0| 0.52| 0.88| 1.0| 1.0| 1.0|

## Where and why it breaks (≤ 300 words, your own reasoning)
Keylength recovery for small ciphertext lengths and small key lengths (primarily small ciphertext lengths of 100 and 200 letters). Key recovery breaks for small ciphertexts in general but worse for small ciphertexts and large keys. Index of coincidence is estimating the probability two randomly selected letters are equal and we use IoC as a measure of how close an encrypted coset (shifted or not) resembles english text.  The IoC is calculated from the average of all the columns IoC and the keylength will determine the # of columsn. The more columsn & cosets there are, the less letters each coset has to acccurately estimate the IoC and that's the reason why keylength recovery becomes unreliable around 100 to 200 letters (for ciphertext of length 100 characters and keylength 10, each coset calculates it's IoC with 10 letters).
## Does Part 3 fail at the same boundary as Part 2? (one sentence)
Part 3 fails at the same or a lower boundary as Part 2 because if the keylength is wrong then the key is automatically wrong. 

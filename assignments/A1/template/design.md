# Design note (≤ 1 page)

## Key-length decision rule (Part 2)
My key-length decision rule was to take the maximum of the IoC's of the various keylegnths. However before automatically assigning a keylength of having a maximum, I check to see if the keylength that's about to become the next candidate is a multiple of the previous candidate, if so then the IoC needs to be greater by the current maximum by a threshold of >0.005, if it doesn't cross that threshold I assume that the keylength is just a multiple and carry on. If the new candidate legnth isn't a multiple of the previous length candidate then I just take the maximum.
<!-- What is scored for each candidate length? How do you choose among candidates?
     What happens at a multiple of the true length? Ties? -->

## Column-shift scoring (Part 3)
<!-- Which statistic? What are its reference quantities? Is the correct shift a
     minimum or a maximum, and why? How do you produce alternative candidates? -->
Column-shift scoring is using goodness of fit measure (chi squared). Correct shift should produce a minimum of the goodness of fit. I didn't implemenet trying to figure out alternate keys but if I were to I'd take the k smallest goodness of fit values from n columns and try all k^n combinations and use the key in which the shift produced the best goodness of fit for the text overall and highest IoC.

## Known failure cases
<!-- Short texts, long keys, non-English, degenerate keys (AAAA), other alphabets… -->
Known failure cases are short texts, short texts with long keys. I haven't tested with degenerate keys or other alphabets yet but my program was able to pass the bonus tests of the autograder.
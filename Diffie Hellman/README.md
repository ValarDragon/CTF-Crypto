# Diffie Hellman

Really most Diffie Hellman attacks are based upon solving the Discrete Logarithm Problem.
There are only a few methods for solving the Discrete Logarithm Problem, and most are inbuilt into Sage.
So I will just put examples of different attacks for those problems.

## Pollards Kangaroo Algorithm ( AKA Pollard's Lambda Algorithm)
This is an algorithm which is good if you have bounds on the exponent.
It runs in time O(sqrt(upperbound-lowerbound))
This algorithm works in any finite cyclic group

## Pohlig-Hellman
This is a way of reducing a Discrete Log Problem into simpler sub-problems. If the modulus for what we are working with is composite (thus it has multiple prime factors), we can use the fact that any relationship which is true Modulo N, is also true modulo a factor of N.

So what we do is we split the problem into then solving the DLP mod each prime factor of N. (In the case of repeated prime factors, mod primefactor^{its corresponding power})
We then CRT our solutions.

Since we have general purpose O(Sqrt(N)) algorithms for solving a discrete log, this reduces the complexity of solving the discrete log to O(sqrt(Largest prime factor of N))
It is because of this that the modulii for discrete log problems are safe primes.
(Since the order of a finite field is what is used, and the order of a finite field modulo prime p is p-1, you want it to have the largest prime factor it can, hence being a safe prime.)

This also works for all finite cyclic groups, such as Elliptic Curves.

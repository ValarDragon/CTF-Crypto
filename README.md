CTF Crypto
=======
This contains the code I use to perform various Cryptography Attacks in CTFs.
This only contains attacks on common cryptography systems, not custom cryptosystems / hashing functions made by the CTF creators.

All code is designed for python3, though it likely can be modified for python2 by removing timeouts.

## RSA Tool

Note that this is Linux only, due to my usage of "signal" for timeouts.

### Factorization Methods contained:

* Check FactorDB
* GCD for Multiple keys
* Sieved Fermat Factorization
* Wiener Attack
* Pollards P-1 (Not a good implementation)
* Pollards Rho (Fairly Broken)

### RSA specific methods
* Partial Key Recovery for n/2 bits of the private key
* TODO Partial Key Recovery for n/4 bits of the private key
* Decoding despite invalid Public Exponent
* Hastads attack

## Diffie Hellman

* Baby Step Giant Step Algorithm

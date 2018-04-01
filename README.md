CTF Crypto
=======
This contains the code I use to perform various Cryptography Attacks in CTFs.
This only contains attacks on common cryptography systems, not custom cryptosystems / hashing functions made by the CTF creators. If you have any suggestions for attacks to implement, raise a github issue.

The RSA tool is designed for python3, though it likely can be modified for python2 by removing timeouts.
The files with Sage in the name are designed for sage. the `.sage` extension is the human readable version, the `Sage.py` version is the preparsed version which you can import into sage.
*Please note this project is not abandoned. I am currently helping create a CTF, so there are certain things I can't commit to this repository until after the CTF is complete.*

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
* Chinese Remainder Theorem full private key recovery
* Decoding despite invalid Public Exponent

### Low Public Exponent
* Hastad's Broadcast Attack
* Hastad's Broadcast Attack with Linear Padding
* Common Modulus, Common public Exponent
* Python RSA bleichenbacher-06 signature forgery
* Known message format/prefix
* Coppersmith Shortpad Attack

## Diffie Hellman

* Baby Step Giant Step Algorithm
* Pollards Kangaroo/Lambda Algorithm

## Pairings

* Rogue Public Key for BLS signatures

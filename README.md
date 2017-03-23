CTF Crypto
=======
This contains the code I use to perform various Cryptography Attacks in CTFs.
This only contains attacks on common cryptography systems, not custom cryptosystems / hashing functions made by the CTF creators.


## RSA Tool

### Factorization Methods contained:

* Check FactorDB
* GCD for Multiple keys
* Fermat Factorization
* Wiener Attack
* Pollards P-1 (Not a good implementation)
* Pollards Rho (Fairly Broken)


### RSA specific methods
* Partial Key Recovery for n/2 bits of the private key
* TODO Partial Key Recovery for n/4 bits of the private key
* Decoding despite invalid Public Exponent

## Diffie Hellman

* Baby Step Giant Step Algorithm

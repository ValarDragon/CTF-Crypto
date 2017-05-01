RSA Tool
=======
This contains code to factor large RSA modulii, and perform other related RSA attacks.
I have used methods in here for every RSA problem I have encountered in CTFs.

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
* Hastad's Attack
* Hastad's Attack with Linear Padding (UNTESTED)
* Common Modulus, Common public Exponent
* Python RSA bleichenbacher-06 signature forgery

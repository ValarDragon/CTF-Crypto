# Franklin-Reiter attack against RSA.
# If two messages differ only by a known fixed difference between the two messages
# and are RSA encrypted under the same RSA modulus N
# then it is possible to recover both of them.

# Inputs are modulus, known difference, ciphertext 1, ciphertext2.
# Ciphertext 1 corresponds to smaller of the two plaintexts. (The one without the fixed difference added to it)
def franklinReiter(n,e,r,c1,c2):
    R.<X> = Zmod(n)[]
    f1 = X^e - c1
    f2 = (X + r)^e - c2
    # coefficient 0 = -m, which is what we wanted!
    return Integer(n-(compositeModulusGCD(f1,f2)).coefficients()[0])

  # GCD is not implemented for rings over composite modulus in Sage
  # so we do our own implementation. Its the exact same as standard GCD, but with
  # the polynomials monic representation
def compositeModulusGCD(a, b):
    if(b == 0):
        return a.monic()
    else:
        return compositeModulusGCD(b, a % b)

def CoppersmithShortPadAttack(e,n,C1,C2,eps=1/30):
    """
    Coppersmith's Shortpad attack!
    Figured out from: https://en.wikipedia.org/wiki/Coppersmith's_attack#Coppersmith.E2.80.99s_short-pad_attack
    """
    import binascii
    P.<x,y> = PolynomialRing(ZZ)
    ZmodN = Zmod(n)
    g1 = x^e - C1
    g2 = (x+y)^e - C2
    res = g1.resultant(g2)
    P.<y> = PolynomialRing(ZmodN)
    # Convert Multivariate Polynomial Ring to Univariate Polynomial Ring
    rres = 0
    for i in range(len(res.coefficients())):
        rres += res.coefficients()[i]*(y^(res.exponents()[i][1]))

    diff = rres.small_roots(epsilon=eps)
    recoveredM1 = franklinReiter(n,e,diff[0],C1,C2)
    print(recoveredM1)
    print("Message is the following hex, but potentially missing some zeroes in the binary from the right end")
    print(hex(recoveredM1))
    print("Message is one of:")
    for i in range(8):
        msg = hex(Integer(recoveredM1*pow(2,i)))
        if(len(msg)%2 == 1):
            msg = '0' + msg
        if(msg[:2]=='0x'):
            msg = msg[:2]
        print(binascii.unhexlify(msg))

def testCoppersmithShortPadAttack(eps=1/25):
    from Crypto.PublicKey import RSA
    import random
    import math
    import binascii
    M = "flag{This_Msg_Is_2_1337}"
    M = int(binascii.hexlify(M),16)
    e = 3
    nBitSize =  8192
    key = RSA.generate(nBitSize)
    #Give a bit of room, otherwhise the epsilon has to be tiny, and small roots will take forever
    m = int(math.floor(nBitSize/(e*e))) - 400
    assert (m < nBitSize - len(bin(M)[2:]))
    r1 = random.randint(1,pow(2,m))
    r2 = random.randint(r1,pow(2,m))
    M1 = pow(2,m)*M + r1
    M2 = pow(2,m)*M + r2
    C1 = Integer(pow(M1,e,key.n))
    C2 = Integer(pow(M2,e,key.n))
    CoppersmithShortPadAttack(e,key.n,C1,C2,eps)

def testFranklinReiter():
    p = random_prime(2^512)
    q = random_prime(2^512)
    n = p * q # 1024-bit modulus
    e = 11

    m = randint(0, n) # some message we want to recover
    r = randint(0, n) # random padding

    c1 = pow(m + 0, e, n)
    c2 = pow(m + r, e, n)
    print(m)
    recoveredM = franklinReiter(n,e,r,c1,c2)
    print(recoveredM)
    assert recoveredM==m
    print("They are equal!")
    return True

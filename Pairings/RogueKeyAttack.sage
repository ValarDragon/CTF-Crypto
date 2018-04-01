# The Rogue Public Key attack takes a given public key, and produces a second public key,
# such that the aggregate BLS signature of any message with the two public keys can be forged by
# the attacker, who knows nothing about the secret key for the first public key.


# GenFakeKeys Returns a point on C2 (the public key), and a number B which corresponds to the blinding done on the original pubkey
# B with the original public key,
def GenFakeKeys(pubkey1):
    # Assumes pubkey is on C2
    pubkey2 = pubkey1 * -1
    b = randint(0, order)
    blindingFactor = g2 * b
    pubkey2 = pubkey2 + blindingFactor
    assert pubkey2 + pubkey1 == blindingFactor
    return pubkey2, b

# GenFakeSignature Creates a fake signature, using the blinfing factor (b), and the message hashed onto G1
def GenFakeSignature(b, hashedMsg):
    aggsig = b * hashedMsg
    return aggsig

# This currently tests nothing. I'm trying to figure out how to undo the sextic
# twist on G2, in order to be able to use Sage's inbuilt Tate Pairing.
# I have tested this function with the bls12 implementation used in
# https://github.com/Project-Arda/bgls 's develop branch however, and it works correctly
def TestRoguePublicKey():
    numTests = 2
    for _ in range(numTests):
        x = randint(0, order)
        h = g1 * randint(0, order)
        pk1 = g2*x
        pk2, b = GenFakeKeys(pk1)
        sig = GenFakeSignature(b, h)
        # Needs to test that
        # e(sig, g2) = e(h, pk1 + pk2)
        # The results of this function have been tested to function correctly with
        # https://github.com/Project-Arda/bgls 's develop branch however

# BLS12-381 Curve parameters. Replace with your own curve parameters.
# Curve 1 is the curve which the signatures are on.
# Curve 2 is the curve which the public keys are on.
q = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
F1 = GF(q)
F2 = GF(q^2,"u",modulus=x^2 + 1)
C1 = EllipticCurve(F1,[0,4])
g1 = C1(3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507,1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569)
# This method of getting the order is unique to bls12.
x = -0xd201000000010000
x = x % q
cofactor1 = Integer(pow(x - 1, 2, q) / 3)
order = C1.order() // cofactor1

C2 = EllipticCurve(F2,[0,4*F2("1+u")])
g2 = C2(F2("3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758*u + 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160"),
    F2("927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582*u + 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905"))

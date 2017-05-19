"""
AES Meet in the middle attack for when a plaintext is encrypted twice, with two different keys.
You must know something about the key format, for example the sample keygen is written
with all but the last 24 bits being 0. Create a new key generator method according to your case.
"""

from Crypto.Cipher import AES

def solve(plaintext,ciphertext,KeyGen):
    encrypted = {}
    for key in KeyGen():
        AEScipher = newAES(key)
        encrypted[AEScipher.encrypt(plaintext)] = key
    for key in KeyGen():
        AEScipher = newAES(key)
        decrypted = AEScipher.decrypt(ciphertext)
        if(decrypted in encrypted):
            # We got a match!
            Key1 = encrypted[decrypted]
            Key2 = key
            return (Key1,Key2)

def newAES(key):
    return AES.new(key, mode=AES.MODE_ECB)

def sample_KeyGen():
    baseString = bytes([0])*29
    for a in range(256):
        StringA = baseString + bytes([a])
        for b in range(256):
            StringB = StringA + bytes([b])
            for c in range(256):
                yield StringB + bytes([c])

def testAESMITM():
    # Use 2013 Boston Key Party values
    import base64
    message1    =  base64.b64decode("QUVTLTI1NiBFQ0IgbW9kZSB0d2ljZSwgdHdvIGtleXM=")
    encrypted   =  base64.b64decode("THbpB4bE82Rq35khemTQ10ntxZ8sf7s2WK8ErwcdDEc=")
    (Key1,Key2) =  solve(message1,encrypted,sample_KeyGen)
    AES1 = newAES(Key1)
    AES2 = newAES(Key2)
    message2    =  base64.b64decode("RWFjaCBrZXkgemVybyB1bnRpbCBsYXN0IDI0IGJpdHM=")
    encrypted   =  base64.b64decode("01YZbSrta2N+1pOeQppmPETzoT/Yqb816yGlyceuEOE=")
    assert AES1.encrypt(message2) == AES2.decrypt(encrypted)
    print("Test passed")
    ciphertext  =  base64.b64decode("s5hd0ThTkv1U44r9aRyUhaX5qJe561MZ16071nlvM9U=")
    print("That years BKP flag: ")
    print(AES1.decrypt(AES2.decrypt(ciphertext)))

testAESMITM()

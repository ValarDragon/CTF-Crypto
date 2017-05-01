import binascii
import math
import random


def python_rsa_bleichenbacher(hashtype,msgHashed,modulusSize,e=3):
    """
    This can forge RSA signatures for low exponents for the python RSA module, for any modulus
    The CVE was reported in http://www.openwall.com/lists/oss-security/2016/01/05/3
    So if the RSA module wasn't updated after that, you can forge the signature!
    https://blog.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/
    """
    HASH_ASN1 = {
        'MD5': b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
        'SHA-1': b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
        'SHA-256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
        'SHA-384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
        'SHA-512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40'
    }
    # we need to forge 00 01 XX XX XX ... XX XX 00 HASH_ASN1[hashtype] HASH
    # where the XX's make the whole thing same size as modulus

    # MAKE SUFFIX
    #print(msgHashed)
    #Its 10 0's because the first two 0's of the ASN.1 isn't getting printed with bin()
    targetSuffix = '0000000000' + bin(int(binascii.hexlify(HASH_ASN1[hashtype]),16))[2:] + bin(msgHashed)[2:]
    if(int(targetSuffix,2)%2 == 0):
        if(int(targetSuffix,2)%8 != 0):
            print("No solution for this hash!")
            return -1
    # print(targetSuffix)
    # print(hex(int(targetSuffix,2)))
    # s = our forgery
    # c = s^3
    # tgt = targetSuffix
    # key here is that nth bit, counting from LSB, only affects nth bit OR later in c

    # s starts out as bytes until first 1 in tgt
    s = targetSuffix[targetSuffix.rfind('1'):]
    c = sToC(s)

    initLenS = len(s)
    for index in range(initLenS,len(targetSuffix)):
        if(c[len(c)-index-1]==targetSuffix[len(targetSuffix)-index-1]):
            s = '0' + s
        else:
            s = '1' + s
        c = sToC(s)

    # SUFFIX MADE!

    assert(c[-len(targetSuffix):]==targetSuffix)
    if(len(c) > modulusSize):
        print("e is too big for this hash type. Try a smaller hash type.")
        return -2

    suffix ='00'+hex(int(s,2))[2:]

    # print("suffix is %s" % hex(int(s,2)))
    # print("suffix is %s" % hex(int(c,2)))

    valid = False
    import gmpy
    while(valid == False):
        valid = True
        # Generate prefix
        prefix = format(0,'08b') + format(1,'08b')
        prefix += ''.join([format(random.randint(1,256),'08b')]*((modulusSize-len(prefix))//8))
        assert len(prefix) == modulusSize

        cRoot = gmpy.root(int(prefix,2),3)
        if(cRoot[1]==1):
            #Its a perfect cubed root! How unlikely :)
            cRoot = int(cRoot[0].digits())
        else:
            cRoot = int(cRoot[0].digits())

        prefix = hex(cRoot)[2:]
        final = prefix[:-len(suffix)] + suffix

        # print(final)
        # Message that is forged when cubed:
        # ('0'+hex(int(final,16)**3)[2:])
        finalcubed = ('0'+hex(int(final,16)**3)[2:])
        finalcubedbytes = chunks(finalcubed[:-len(suffix)],2)
        # print(finalcubed)

        for element in finalcubedbytes:
            if(element=='00'):
                valid = False
                print("NEXT ITERATION")
    return int(final,16)

def sToC(s,e=3):
    s = int(s,2)
    if(s==1):
        return '00001'
    return bin(s**e)[2:]

def chunks(l, n):
    n = max(1, n)
    return (l[i:i+n] for i in range(0, len(l), n))

def testFunction():
    # msg = "right below"
    # Hash is hashed version of msg.
    print(hex(python_rsa_bleichenbacher('SHA-256',int('b24fbe5fba106419e028be32dd049736d797815f6a6f5370579437784c51eb9f',16),2048)))
    # Check against: nc challenge.uiuc.tf 11345
    # If it is still up

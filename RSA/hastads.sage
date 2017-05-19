def hastads(cArray,nArray,e=3):
    """
    Performs Hastads attack on raw RSA with no padding.
    cArray = Ciphertext Array
    nArray = Modulus Array
    e = public exponent
    """

    if(len(cArray)==len(nArray)==e):
        for i in range(e):
            cArray[i] = Integer(cArray[i])
            nArray[i] = Integer(nArray[i])
        M = crt(cArray,nArray)
        return(Integer(M).nth_root(e,truncate_mode=1))
    else:
        print("CiphertextArray, ModulusArray, need to be of the same length, and the same size as the public exponent")


def linearPaddingHastads(cArray,nArray,aArray,bArray,e=3,eps=1/8):
    """
    Performs Hastads attack on raw RSA with no padding.
    This is for RSA encryptions of the form: cArray[i] = pow(aArray[i]*msg + bArray[i],e,nArray[i])
    Where they are all encryptions of the same message.
    cArray = Ciphertext Array
    nArray = Modulus Array
    aArray = Array of 'slopes' for the linear padding
    bArray = Array of 'y-intercepts' for the linear padding
    e = public exponent
    """
    if(len(cArray) == len(nArray) == len(aArray) == len(bArray) == e):
        for i in range(e):
            cArray[i] = Integer(cArray[i])
            nArray[i] = Integer(nArray[i])
            aArray[i] = Integer(aArray[i])
            bArray[i] = Integer(bArray[i])
        TArray = [-1]*e
        for i in range(e):
            arrayToCRT = [0]*e
            arrayToCRT[i] = 1
            TArray[i] = crt(arrayToCRT,nArray)
        P.<x> = PolynomialRing(Zmod(prod(nArray)))
        gArray = [-1]*e
        for i in range(e):
            gArray[i] = TArray[i]*(pow(aArray[i]*x + bArray[i],e) - cArray[i])
        g = sum(gArray)
        g = g.monic()
        # Use Sage's inbuilt coppersmith method
        roots = g.small_roots(epsilon=eps)
        if(len(roots)== 0):
            print("No Solutions found")
            return -1
        return roots[0]

    else:
        print("CiphertextArray, ModulusArray, and the linear padding arrays need to be of the same length," +
         "and the same size as the public exponent")

def testLinearPadding():
    from Crypto.PublicKey import RSA
    import random
    import binascii
    flag = b"flag{Th15_1337_Msg_is_a_secret}"
    flag = int(binascii.hexlify(flag),16)
    e = 3
    nArr = [-1]*e
    cArr = [-1]*e
    aArr = [-1]*e
    bArr = [-1]*e
    randUpperBound = pow(2,500)
    for i in range(e):
        key = RSA.generate(2048)
        nArr[i] = key.n
        aArr[i] = random.randint(1,randUpperBound)
        bArr[i] = random.randint(1,randUpperBound)
        cArr[i] = pow(flag*aArr[i]+bArr[i],e,key.n)
    msg = linearPaddingHastads(cArr,nArr,aArr,bArr,e=e,eps=1/8)
    if(msg==flag):
        print("Hastad's solver with linear padding is working! We got message: ")
    msg = hex(int(msg))[2:]
    if(msg[-1]=='L'):
        msg = msg[:-1]
    if(len(msg)%2 == 1):
        msg = '0' + msg
    print(msg)
    print(binascii.unhexlify(msg))
    if(flag==binascii.unhexlify(msg)):
        return True

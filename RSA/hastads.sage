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


def linearPaddingHastads(cArray,nArray,aArray,bArray,e=3):
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
            arrayToCRT = [-1]*e
            for j in range(e):
                if(j==i):
                    arrayToCRT[j] = 1
                else:
                    arrayToCRT[j] = 0
            TArray[i] = crt(arrayToCRT,nArray)
        P.<x> = PolynomialRing(Zmod(prod(nArray)))
        gArray = [-1]*e
        for i in range(e):
            gArray[i] = TArray[i]*pow(aArray[i]*x + bArray[i],e)
        g = sum(gArray)
        g.monic()
        # Use Sage's inbuilt coppersmith method
        return g.small_roots()

    else:
        print("CiphertextArray, ModulusArray, and the linear padding arrays need to be of the same length," +
         "and the same size as the public exponent")

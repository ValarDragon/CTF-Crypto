from fractions import gcd
from Crypto.PublicKey import RSA
import requests
import re
import signal
import wienerAttack
import datetime
# Note this file is Linux only because of usage of signal.

# TODO Add Sieve improvement to Fermat Attack
# https://en.wikipedia.org/wiki/Fermat's_factorization_method
class RSATool:
    """
    RSA Factorization Utility written by Valar_Dragon for use in CTF's.
    It is meant for factorizing large modulii
    Currently it checks Factor DB, performs the Wiener Attack, fermat attack, and GCD between multiple keys.
    """
    def __init__(self):
        #Eventually put logging here@
        #this is the number to be added to x^2 in pollards rho.
        self.pollardRhoConstant1 = 1
        #this is the number to be multiplied to x^2 in pollards rho.
        self.pollardRhoConstant2 = 1
        self.keyNotFound = "key not found"


    def factorModulus(self,pubKey="pubkey",e="e",n="n",outFileName=""):
        if(type(pubKey)==type("pubkey")):
            self.e = e
            self.modulus = n
        else:
            self.e = pubKey.e
            self.modulus = pubKey.n
        self.outFileName = outFileName
        self.p = -1
        self.q = -1

        print("[*] Checking Factor DB...")
        self.checkFactorDB()
        if(self.p != -1 and self.q != -1):
            print("[*] Factors are: %s and %s" % (self.p,self.q))
            return self.generatePrivKey()
        print("[x] Factor DB did not have the modulus")

        print("[*] Trying Wiener Attack...")
        if(len(str(self.e))*3 > len(str(self.modulus))):
            print("[*] Wiener Attack is likely to be succesful, increasing its timeout to 8 minutes")
            self.wienerAttack(wienerTimeout=8*60)
        else:
            self.wienerAttack()
        if(self.p != -1 and self.q != -1):
            print("[*] Wiener Attack Successful!!")
            print("[*] Factors are: %s and %s" % (self.p,self.q))
            return self.generatePrivKey()
        print("[x] Wiener Attack Failed")

        print("[*] Trying Sieved Fermat Attack...")
        self.sieveFermatAttack()
        if(self.p != -1 and self.q != -1):
            print("[*] Sieved Fermat Attack Successful!!")
            print("[*] Factors are: %s and %s" % (self.p,self.q))
            return self.generatePrivKey()

        print("[*] Trying Small Primes Factorization...")
        self.smallPrimes()
        if(self.p != -1 and self.q != -1):
            print("[*] Small Primes Factorization Successful!!")
            print("[*] Factors are: %s and %s" % (self.p,self.q))
            return self.generatePrivKey()
        print("[x] Small Primes Factorization Failed")

        print("[*] Trying Pollards P-1 Attack...")
        self.pollardPminus1()
        if(self.p != -1 and self.q != -1):
            print("[*] Pollards P-1 Factorization Successful!!")
            print("[*] Factors are: %s and %s" % (self.p,self.q))
            return self.generatePrivKey()

        return self.keyNotFound

    def factorModulii(self,pubkeys,outFileNameFormat="privkey-%s.pem"):
        success = [-1]*len(pubkeys)
        privkeys = [-1] * len(pubkeys)
        print("[*] Trying multi-key attacks")
        print("[*] Searching for common factors (GCD Attack)")
        for i in range(len(pubkeys)):
            for j in range(i):
                if(success[i]==True and True==success[j]):
                    continue
                greatestCommonDivisor = gcd(pubkeys[i].n,pubkeys[j].n)
                if(greatestCommonDivisor != 1):
                    print("[*] Common Factor Found between key-%s and key-%s!!!"
                        % (i,j))
                    print("[*] Generating respective privatekeys")
                    for k in [i,j]:
                        success[k]=True
                        privkeys[k] = (self.generatePrivKey(modulus=pubkeys[k].n,
                            pubexp=pubkeys[k].e,p=greatestCommonDivisor,
                            q=pubkeys[k].n//greatestCommonDivisor,
                            outFileName=outFileNameFormat%k))
        for i in range(len(pubkeys)):
            if(success[i]==True):
                print("Key #%s already factored!"%i)
                continue
            print("Factoring key #%s"%i)
            privkey = self.factorModulus(pubkeys[i],outFileName=outFileNameFormat%i)
            if(type(privkey) == type(self.keyNotFound)):
                success[i]==False
            else:
                privkeys[i] = (privkey)
                success[i]==True
        return privkeys


    #----------------BEGIN FACTOR DB SECTION------------------#

    def checkFactorDB(self, n="n"):
        """See if the modulus is already factored on factordb.com,
         and if so get the factors"""
        if(n=="n"): n = self.modulus
        # Factordb gives id's of numbers, which act as links for full number
        # follow the id's and get the actual numbers
        r = requests.get('http://www.factordb.com/index.php?query=%i' % self.modulus)
        regex = re.compile("index\.php\?id\=([0-9]+)", re.IGNORECASE)
        ids = regex.findall(r.text)
        # These give you ID's to the actual number
        p_id = ids[1]
        q_id = ids[2]
        # follow ID's
        regex = re.compile("value=\"([0-9]+)\"", re.IGNORECASE)
        r_1 = requests.get('http://www.factordb.com/index.php?id=%s' % p_id)
        r_2 = requests.get('http://www.factordb.com/index.php?id=%s' % q_id)
        # Get numbers
        self.p = int(regex.findall(r_1.text)[0])
        self.q = int(regex.findall(r_2.text)[0])
        if(self.p == self.q == self.modulus):
            self.p = -1
            self.q = -1



    #------------------END FACTOR DB SECTION------------------#
    #---------------BEGIN WIENER ATTACK SECTION---------------#
    #This comes from  https://github.com/sourcekris/RsaCtfTool/blob/master/wiener_attack.py
    def wienerAttack(self,n="n",e="e",wienerTimeout=3*60):
        if(n=="n"): n = self.modulus
        if(e=="e"): e = self.e
        try:
            with timeout(seconds=wienerTimeout):
                wiener = wienerAttack.WienerAttack(n, e)
                if wiener.p is not None and wiener.q is not None:
                    self.p = wiener.p
                    self.q = wiener.q
        except TimeoutError:
            print("[x] Wiener Attack went over %s seconds "% wienerTimeout)


    #----------------END WIENER ATTACK SECTION----------------#
    #-----------BEGIN Fermat Factorization SECTION------------#

    # Maybe make this take a bigger lastDig?
    def isLastDigitPossibleSquare(self,x):
        if(x < 0):
            return False
        lastDig = x & 0xF
        if(lastDig > 9):
            return False
        if(lastDig < 2):
            return True
        if(lastDig == 4 or lastDig == 5 or lastDig == 9):
            return True
        return False

    # https://en.wikipedia.org/wiki/Fermat's_factorization_method
    # Fermat factorization method written by me, inspired from wikipedia :D
    # Limit is the number of a's to try.
    def fermatAttack(self,n="n",limit=100,fermatTimeout=3*60):
        if(n=="n"): n = self.modulus
        try:
            with timeout(seconds=fermatTimeout):
                a = self.floorSqrt(n)+1
                b2 = a*a - n
                for i in range(limit):
                    if(self.isLastDigitPossibleSquare(b2)):
                        b = self.floorSqrt(b2)
                        if(b**2 == a*a-n):
                            #We found the factors!
                            self.p = a+b
                            self.q = a-b
                            return
                    a = a+1
                    b2 = a*a-n
                if(i==limit-1):
                    print("[x] Fermat Iteration Limit Exceeded")
        except TimeoutError:
            print("[x] Fermat Timeout Exceeded")

    def genSquaresModSieve(self,sieve):
        squaresModSieve = {}
        #Range not starting from 0, because we have already checked that
        # N % sieve != 0
        # Use property that (a-x)^2 mod a = x^2 mod a
        if(sieve%2 == 0):
            sieve2 = sieve // 2
            for num in range(1,sieve2+1):
                mod = pow(num,2,sieve)
                if mod not in squaresModSieve:
                    squaresModSieve[mod] = [num]
                else:
                    squaresModSieve[mod].append(num)
                if(num != sieve2):
                    squaresModSieve[mod].append(sieve-num)
            return squaresModSieve
        else:
            # There is a duplication issue using the above halving of the sieve.
            # and I don't want to add a delay by doing a search for duplicate values
            for num in range(1,sieve):
                mod = pow(num,2,sieve)
                if mod not in squaresModSieve:
                    squaresModSieve[mod] = [num]
                else:
                    squaresModSieve[mod].append(num)
            return squaresModSieve

    # Create an array of possible a values for this N and sieveModulus
    # What we're doing is using that only a few numbers can be squares mod Sieve,
    # you use the idea that a^2 mod x, can only be a few different values.
    # b^2 = a^2 - N, so taking everything mod x, b^2 must also be one of those few different values
    # So the candidateA, are values of a, which when squared and subtracted by N, are still a number
    # that COULD potentially be a square mod x. This lowers our brute space in the Fermat Attack!
    def getCandidateA(self,sieveModulus,N="RSA modulus",secondIter=False):
        nModSieve = N % sieveModulus
        squaresModSieve = self.genSquaresModSieve(sieveModulus)
        candidateA = []

        # potential a values:
        for mod in squaresModSieve:
            if(((mod - nModSieve) % sieveModulus) in squaresModSieve):
                for x in squaresModSieve[mod]:
                    candidateA.append(x)

        # any number thats a solution mod x, must also be a solution mod 2x
        # and vice versa. Depending on N and the sieve used, it can save many modulii
        # from being checked. Un comment print statement to see effect.
        if(not secondIter):
            if(sieveModulus % 2 == 0):
                candidateA2 = self.getCandidateA(sieveModulus*2, N=N, secondIter = True)
                candidateAFinal = []
                for i in candidateA:
                    if(i in candidateA2):
                        candidateAFinal.append(i)
                # print("%s numbers per modular ring are saved" % (len(candidateA) - len(candidateAFinal)))
                return candidateAFinal
        return candidateA


    # https://en.wikipedia.org/wiki/Fermat's_factorization_method#Sieve_improvement
    # This code is based upon the sieve improvement presented there.
    # Limit is the number of a's to try.
    def sieveFermatAttack(self,N="RSA modulus",sieveModulus=4500,limit=1000,fermatTimeout=3*60):
        if(N=="RSA modulus"): N = self.modulus
        try:
            with timeout(seconds=fermatTimeout):

                # ASSUME THAT N is not divisible by anything in sieveModulus
                # confirm via small primes first.
                #This lets me remove 0 from genSquaresModSieve, thus boosting times
                # GCD = gcd(sieveModulus,N)
                # if(GCD != 1):
                #     self.p = GCD
                #     self.q = N // GCD
                #     return

                candidateA = self.getCandidateA(sieveModulus,N)
                # print(candidateA)
                # Redefine limit accordingly.
                limit = limit // len(candidateA)
                print("[*] %s %% faster than standard Fermat Factorization" % (100-100*len(candidateA)/sieveModulus))
                a = self.floorSqrt(N)+1
                a = a - (a%sieveModulus)
                b2 = a*a - N


                for i in range(limit):
                    for aModSieve in candidateA:
                        aPlusMod = a + aModSieve
                        b2 = aPlusMod*aPlusMod-N
                        if(b2 < 0):
                            continue
                        if(self.isLastDigitPossibleSquare(b2)):
                            b = self.floorSqrt(b2)
                            if(pow(b,2) == b2):
                                #We found the factors!
                                self.p = aPlusMod+b
                                self.q = aPlusMod-b
                                return
                    a = a+sieveModulus
                if(i==limit-1):
                    print("[x] Sieved Fermat Iteration Limit Exceeded")

        except TimeoutError:
            print("[x] Sieved Fermat Timeout Exceeded")

    # Brute forces which SieveModulus has the least amount of candidates per sieveMod
    # I reccomend using startVal > 10, lower than that, I don't really trust the result

    def bruteBestSieveModulus(self,startVal,endVal,N="RSA modulus"):
        if(N=="RSA modulus"): N = self.modulus
        # index 0 = % speed up, index 1 = what the SieveMod is
        bestSpeedUp = [-1,-1]
        for sieveModulus in range(startVal,endVal):
            candidateA = self.getCandidateA(sieveModulus,N)
            speedUp = 1-len(candidateA)/sieveModulus
            if(speedUp > bestSpeedUp[0]):
                bestSpeedUp = [speedUp,sieveModulus]
        return bestSpeedUp[1]

    #------------END Fermat Factorization SECTION-------------#
    #----------------BEGIN SMALL PRIME SECTION----------------#
    def smallPrimes(self,n="n",upperlimit=1000000):
        if(n=="n"): n = self.modulus
        from sympy import sieve
        for i in sieve.primerange(1,upperlimit):
            if(n % i == 0):
                self.p = i
                self.q = n // i
                return

    #-----------------END SMALL PRIME SECTION-----------------#
    #----------------BEGIN POLLARDS P-1 SECTION---------------#

    #Pollard P minus 1 factoring, using the algorithm as described by
    # https://math.berkeley.edu/~sagrawal/su14_math55/notes_pollard.pdf
    # Then I further modified it by using the standard "B" as the limit, and only
    # taking a to the power of a prime. Then from looking at wikipedia and such,
    # I took the gcd out of the loop, and put it at the end.
    # TODO Update this to official wikipedia definition, once I find an explanation of
    # Wikipedia definition. (I.e. Why it works)
    def pollardPminus1(self,N="modulus",a=7,B=2**16,pMinus1Timeout=3*60):
        if(N=="modulus"): N = self.modulus
        from sympy import sieve
        try:
            with timeout(seconds=pMinus1Timeout):
                brokeEarly = False
                for x in sieve.primerange(1, B):
                    tmp = 1
                    while tmp < B:
                        a = pow(a, x, N)
                        tmp *= x
                d = gcd(a-1,N)
                if(d==N):
                    #try next a value
                    print('[x] Unlucky choice of a, try restarting Pollards P-1 with a different a')
                    brokeEarly = True
                    return
                elif(d>1):
                    #Success!
                    self.p = d
                    self.q = N//d
                    return
                if(brokeEarly == False):
                    print("[x] Pollards P-1 did not find the factors with B=%s"% B)
        except TimeoutError:
            print("[x] Pollard P-1 Timeout Exceeded")


    #-----------------END POLLADS P-1 SECTION-----------------#
    #---------------BEGIN POLLARDS RHO SECTION----------------#
    def pollardf(self,x):
        return (self.pollardRhoConstant2*x*x + self.pollardRhoConstant1) % self.modulus

    def pollardsRho(self,n="modulus",rhoTimeout=5*60):
        if(n=="modulus"): n = self.modulus
        """
        Pollard's Rho method for factoring numbers.
        Explanation I based this off of:
        https://www.csh.rit.edu/~pat/math/quickies/rho/#algorithm
        This is apparently not the standard definition, and doesn't work well.
        """
        xValues = [1]
        i = 2

        with timeout(seconds=rhoTimeout):
            while(True):
                if(i % 2 == 0):
                    #if(i%100000==0):
                        #print("on iteration %s " % i )
                    #Calculate GCD(n, x_k - x_(k/2)), to conserve memory I'm popping x_k/2
                    x_k = self.pollardf(i)
                    xValues.append(x_k)
                    x_k2 = xValues.pop(0)
                    #if x_k2 >= x_k, their difference is negative and thus we can't do the GCD
                    if(x_k2 < x_k):
                        commonDivisor = gcd(n,x_k - x_k2)
                        if(commonDivisor > 1):
                            print("[*] Pollards Rho completed in %s iterations!" % i)
                            #print("Factors: " + str(commonDivisor) + ", " + str(n / commonDivisor))
                            assert commonDivisor * (n // commonDivisor) == n

                            return (commonDivisor, n // commonDivisor)
                else:
                    #Just append new x value
                    xValues.append(self.pollardf(i))
                i+=1

    #-----------------END POLLADS RHO SECTION-----------------#
    #---------------BEGIN COMMON MODULUS ATTACK---------------#\
    def commonModulusPubExpSamePlainText(self,e1,e2,c1,c2,n="n"):
        """
            Solves for message if you have two ciphertexts of the same message
            encrypted with different public exponents and same modulus.
            Source: https://crypto.stackexchange.com/questions/16283/how-to-use-common-modulus-attack
        """
        if(n=="n"): n = self.modulus
        GCD, s1, s2 = self.extended_gcd(e1, e2)
        assert GCD == 1
        assert s1*e1 + s2*e2 == 1
        message = 1
        if(s1 < 0):
            inv = self.modinv(c1,n)
            message = message*pow(inv,-1*s1,n) % n
            message = message*pow(c2,s2,n) %n
        elif(s2 < 0):
            inv = self.modinv(c2,n)
            message = message*pow(inv,-1*s2,n) % n
            message = message*pow(c1,s1,n) %n
        else:
            message = pow(c1,s1,n)*pow(c2,s2,n) % n
        return message
    #----------------END COMMON MODULUS ATTACK----------------#
    #----------BEGIN INVALID PUBLIC EXPONENT SECTION----------#

    def invalidPubExponent(self,c,p="p",q="q",e="e"):
        """Recovers some bytes of ciphertext if n is factored, but e was invalid.
        (Like e=100) The vast majority of bytes are however lost, as we are taking the
        GCD(e, totient(N))th root of the Ciphertext. Therefore only the most significant
        bits of the ciphertext may be recovered.
        Returns plaintext, since a key can't be formed from a non-integer exponent"""
        # Explanation of why this works: There exists no modinv if GCD(e,Totient(N)) != 1
        # but let x be e/GCD
        # then there is a modular inverse of x to totient n
        # c = m^(GCDx) mod n
        # c^(x^-1) = m^GCD mod n, where x^-1 denotes modinv(x,totientN)
        # Now if we take the GCD-th root
        # c^(x^-1)^(1/GCD) = m mod n, except that roots aren't an operation defined on modular rings
        # They are defined on finite fields in some circumstances, but this is not a finite field.
        # Therefore we have only recovered a few of the most significant bits of c.
        if(p=="p"): p = self.p
        if(p=="q"): q = self.q
        totientN = (p-1)*(q-1)
        n = p*q
        if(e=="e"): e = self.e
        GCD = gcd(e,totientN)
        if(GCD == 1):
            return "[X] This method only applies for invalid Public Exponents."
        d = self.modinv(e//GCD,totientN)
        c = pow(c,d,n)
        import sympy
        plaintext = sympy.root(c,GCD)
        return plaintext

    #-----------END INVALID PUBLIC EXPONENT SECTION-----------#
    #-----------BEGIN PARTIAL KEY RECOVERY SECTION------------#
    # TODO Implement Coppersmith, and get a quarter d partial key recovery attack

    def halfdPartialKeyRecoveryAttack(self,d0,d0BitSize,nBitSize="nBitSize",n="n",e="e", outFileName="None"):
        """
            Recovers full private key given more than half of the private key. Links:
            http://www.ijser.org/researchpaper/Attack_on_RSA_Cryptosystem.pdf
            http://honors.cs.umd.edu/reports/lowexprsa.pdf
        """
        if(n=="n"): n = self.modulus
        if(nBitSize == "nBitSize"):
            import sympy as sp
            nBitSize = int(sp.floor(sp.log(n)/sp.log(2)) + 1)
        if(e=="e"): e = self.e
        test = pow(3, e, n)
        test2 = pow(5, e, n)
        if(d0BitSize < nBitSize//2):
            return "Not enough bits of d0"
        # The idea is that ed - k(N-p-q+1)=1 by definitions (1)
        # d < totient(N) since its modInv(e,Totient(n)), so k can't be bigger than e
        # Therefore k is on range(1,e)
        # But we don't have totient(N), we have N, so its only an approximation
        # Proofs are in the links, but if you switch totientN with just N in the above,
        # and set d' = (k*N + 1)/e ,
        # the maximum error in d' is 3*sqrt(nBitSize) bits
        # Thats less than d/2, so we can just replace the least significant bits with d0
        # and get plaintext
        for k in range(1,e):
            # This is guaranteed to be accurate to nBitSize^(1/3),
            # so we replace last bits with d
            d = ((k * n + 1) // e)
            # Chop of last d0 bits of d, and put d0 there.
            d >>= d0BitSize
            d <<= d0BitSize
            d |= d0
            # This condition must be true from modulo def. (1) And avoids computing many modpows
            if((e * d) % k == 1):
                # Were testing that d is valid by decoding two test messages
                if pow(test, d, n) == 3:
                    if pow(test2, d, n) == 5:
                        # From (1)
                        totientN = (e*d - 1) // k
                        #totient(N) = (p-1)(q-1) = n - p - q + 1
                        # p^2 - p^2 - N + N = 0
                        # p^2 - p^2 - pq + N = 0
                        # p^2 + (-p -q)p + N = 0
                        # p^2 + (totient(N) -n -1) + N = 0
                        # Solving this quadratic for variable p:
                        b = totientN - n - 1
                        discriminant = b*b - 4*n
                        #make sure discriminant is perfect square
                        root = self.floorSqrt(discriminant)
                        if(root*root != discriminant):
                            continue
                        p = (-b + root) // 2
                        q = n // p
                        self.p = p
                        self.q = q
                        #print("[*] Factors are: %s and %s" % (self.p,self.q))
                        return self.generatePrivKey(modulus=n,pubexp=e,outFileName=outFileName)


    def dpPartialKeyRecoveryAttack(self,dp,n="n",e="e", outFileName="None"):
        """
            Recovers full private key given d_p for CRT version of RSA. Links:
            https://www.iacr.org/archive/crypto2003/27290027/27290027.pdf
        """
        if(n=="n"): n = self.modulus
        if(e=="e"): e = self.e

        for k in range(1,e):
            if((e * dp) % k == 1):
                p = (e * dp - 1 + k) // k
                if(n%p==0):
                    q = n // p
                    self.p = p
                    self.q = q

                    return self.generatePrivKey(modulus=n,pubexp=e,outFileName=outFileName)
    #--------------END PARTIAL KEY RECOVERY SECTION---------------#
    #---------------BEGIN SHARED ALGORITHM SECTION----------------#

    #moduliiValueDictionary is a dictionary with key = modulus, value = array of possible values
    def chineseRemainderTheorem(self,moduliiValueDictionary):
        # Now we have to iterate through every combination of elements in each array
        # We can be slightly inefficient, and just keep CRT'ing 2 arrays at a time
        # one array being new array, other array being prevIteration

        # CRT first two arrays
        keys = list(moduliiValueDictionary.keys())
        curCRTCandidateA = []
        M = keys[0]*keys[1]

        # M // sieveModulus[0] = sieveModulus[1]

        b0 = self.modinv(keys[1],keys[0])
        b1 = self.modinv(keys[0],keys[1])

        for element0 in moduliiValueDictionary[keys[0]]:
            ab0 = element0*b0* keys[1]
            for element1 in moduliiValueDictionary[keys[1]]:
                ab1 = element1*b1 * keys[0]
                curCRTCandidateA.append((ab0 + ab1) % M)

        del moduliiValueDictionary[keys[0]]
        del keys[0]
        del moduliiValueDictionary[keys[0]]
        del keys[0]
        oldCRTCandidateA = curCRTCandidateA

        while(len(keys) > 0):
            oldCRTModulus = M
            curCRTCandidateA = []
            M = M * keys[0]

            b0 = self.modinv(keys[0] ,oldCRTModulus)
            b1 = self.modinv(oldCRTModulus,keys[0])

            for element0 in oldCRTCandidateA:
                ab0 = element0*b0*keys[0]
                for element1 in moduliiValueDictionary[keys[0]]:
                    ab1 = element1*b1*oldCRTModulus
                    curCRTCandidateA.append((ab0 + ab1) % M)

            del keys[0]

        return curCRTCandidateA,M

    def floorSqrt(self,n):
        x = n
        y = (x + 1) // 2
        while y < x:
            x = y
            y = (x + n // x) // 2
        return x

    def extended_gcd(self,aa, bb):
        """Extended Euclidean Algorithm,
        from https://rosettacode.org/wiki/Modular_inverse#Python
        """
        lastremainder, remainder = abs(aa), abs(bb)
        x, lastx, y, lasty = 0, 1, 1, 0
        while remainder:
            lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
            x, lastx = lastx - quotient*x, x
            y, lasty = lasty - quotient*y, y
        return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

    def modinv(self,a, m):
        """Modular Multiplicative Inverse,
        from https://rosettacode.org/wiki/Modular_inverse#Python
        """
        g, x, y = self.extended_gcd(a, m)
        if g != 1:
            raise ValueError
        return x % m

    def generatePrivKey(self, modulus="modulus",pubexp="e",p="p",q="q",outFileName="None"):
        if(modulus=="modulus"): modulus = self.modulus
        if(p=="p"): p = self.p
        if(pubexp=="e"): pubexp = self.e
        if(q=="q"): q = self.q
        if(outFileName==""): outFileName = self.outFileName
        if(outFileName==""): outFileName = "RSA_PrivKey_%s" % str(datetime.datetime.now())
        totn = (p-1)*(q-1)
        privexp = self.modinv(pubexp,totn)
        assert p*q == modulus
        #Wieners attack returns "Integers" that throw type errors for not being "ints"
        #casting fixes this. This is likely due to use of sympy
        privKey = RSA.construct((modulus,pubexp,int(privexp),int(p),int(q)))
        #Write to File
        if(outFileName != "None"):
            open(outFileName,'bw+').write(privKey.exportKey())
            print("Wrote private key to file %s " % outFileName)
        return privKey

    def generatePubKey(self, modulus="modulus",pubexp="e",outFileName="None"):
        if(modulus=="modulus"): modulus = self.modulus
        if(pubexp=="e"): pubexp = self.e
        if(outFileName==""): outFileName = self.outFileName
        if(outFileName==""): outFileName = "RSA_PubKey_%s" % str(datetime.datetime.now())

        pubKey = RSA.construct((modulus,pubexp))
        #Write to File
        if(outFileName != "None"):
            open(outFileName,'bw+').write(privKey.exportKey())
            print("Wrote public key to file %s " % outFileName)
        return pubKey
    #----------------END SHARED ALGORITHM SECTION -----------------#

class timeout:
    def __init__(self, seconds=1, error_message='[*] Timeout'):
        self.seconds = seconds
        self.error_message = error_message
    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)
    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)
    def __exit__(self, type, value, traceback):
        signal.alarm(0)

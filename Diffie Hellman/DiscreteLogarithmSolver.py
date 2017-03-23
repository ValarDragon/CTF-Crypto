class DiscreteLogarithmSolver:
    def babyStepGiantStep(self, g,b,p,m="m"):
        """
        Baby Step Giant Step algorithm from https://en.wikipedia.org/wiki/Baby-step_giant-step
        Input: A cyclic group G of order n, having a generator g and an element β.
        order n = p, as is standard for DH
        Output: A value x satisfying g^x = β mod p

        This is essentially a space time trade-off attack. The amount of space needed can be quite large for not that large p.
        ( > 8 gb) hence the input() statement.
        """
        if(m=="m"):
            m = self.floorSqrt(p) + 1
        if(m > 50000000):
            cont = input("m is large (%s), this may eat up all your available RAM. Type 'Y' to continue\n" % m).lower()
            if(cont != 'y' and cont != 'yes'):
                return -2
        gInverse = self.modinv(pow(g,m,p),p)
        hashtable = {}
        # The current power, using this instead of doing a
        # more expensive modpow every time
        cur = 1
        hashtable[1] = 0
        for j in range(1,m):
            cur = (cur*g)%p
            hashtable[cur] = j
        #print('finished beggining')
        gamma = b
        for i in range(m):
            if(gamma in hashtable):
                solution =  i*m + hashtable[gamma]
                #open('solution','w+').write(str(solution))
                return solution
            else:
                gamma = (gamma * gInverse) %p
                if(gamma==b):
                    return -1
                    #return "Looped at %s :( " % i
        return -1

    #----------------SHARED ALGORITHMS SECTION-----------------------#
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

    def floorSqrt(self,n):
        x = n
        y = (x + 1) // 2
        while y < x:
            x = y
            y = (x + n // x) // 2
        return x

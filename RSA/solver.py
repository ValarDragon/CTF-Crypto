from Crypto.PublicKey import RSA
import Factorizer
import os

keys =[]

def loadPEMs():
    for i in range(10):
        key = RSA.importKey(open('given/key-%s.pem' % i).read())
        keys.append(key)

def main():
    if not os.path.exists('privkeys'):
        os.makedirs('privkeys')
    fact = Factorizer.Factorizer()
    loadPEMs()
    fact.factorModulii(keys,'privkeys/privkey-%s.pem')

main()

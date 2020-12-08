import Crypto.Util.number
# pip3 install pycryptodome
import sys

def fastpow(x, y, p):
    res = 1;
    x = x % p
    if x == 0:
        return 0
    while y > 0:
        if (y & 1) == 1:
            res = (res * x) % p
        y = y >> 1  # y = y//2
        x = (x * x) % p
    return res

class RSA:
    def __init__(self, bits=112, DEBUG=False):
        self.p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
        self.q = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
        self.n = self.p*self.q
        self.phi = (self.p-1)*(self.q-1)
        self.e = 65537
        self.d = Crypto.Util.number.inverse(self.e, self.phi)

        if DEBUG:
            print("p:   %d\nq:   %d\nn:   %d\nphi: %d\ne:   %d\nd:   %d\nbit: %d\n" % (
                self.p, self.q, self.n, self.phi, self.e, self.d, bits
            ))

    def encrypt(self, message):
        sz = len(message)
        cipher = [0]*sz
        for i in range(sz):
            ascii = ord(message[i]) # Ascii code of message[i]
            cipher[i] = fastpow(ascii, self.e, self.n)
            # ci = (mi**e) % n
        return cipher
    
    def decript(self, cipher) :
        sz = len(cipher)
        message = ""
        for i in range(sz):
            ascii = fastpow(cipher[i], self.d, self.n)
            # mi = (ci**d) % n
            message += chr(ascii)
        return message
    

if __name__ == '__main__':
    rsa = RSA(DEBUG=True)
    text = "Message to encrypt with RSA"
    cipher = rsa.encrypt(text)
    print("Cipher:", cipher, "\n\n")
    decripted_message = rsa.decript(cipher)
    print("Decripted Message:", decripted_message)


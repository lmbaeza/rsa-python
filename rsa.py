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
    def __init__(self, bits=1024, DEBUG=False):
        self.p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
        self.q = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
        self.n = self.p*self.q
        self.phi = (self.p-1)*(self.q-1)
        self.e = 65537
        self.d = Crypto.Util.number.inverse(self.e, self.phi)
        self.bits = bits
        self.DEBUG = DEBUG

        if DEBUG:
            print("p:   %d\nq:   %d\nn:   %d\nphi: %d\ne:   %d\nd:   %d\nbit: %d\n" % (
                self.p, self.q, self.n, self.phi, self.e, self.d, bits
            ))

    def encrypt(self, message):
        m = int(self.text_to_hex(message), 16)
        cipher = fastpow(m, self.e, self.n)
        # ci = (mi**e) % n
        return hex(cipher)[2:]
    
    def decript(self, cipher) :
        ci = int(cipher, 16)
        m = fastpow(ci, self.d, self.n)
        # ci = (mi**e) % n
        return self.hex_to_text(hex(m)[2:])

    def text_to_hex(self, text):
        cipher_hex = ""
        for ch in text:
            number = hex(ord(ch))[2:]
            cipher_hex += number
        return cipher_hex

    def hex_to_text(self, cipher_hex):
        cipher_list = ""
        for i in range(0, len(cipher_hex), 2):
            cipher_list += chr(int(cipher_hex[i: i+2], 16))
        return cipher_list
    

if __name__ == '__main__':
    rsa = RSA(DEBUG=True)
    text = "Message to encrypt with RSA"
    cipher = rsa.encrypt(text)
    print("Cipher:", cipher, "\n")
    decripted_message = rsa.decript(cipher)
    print("Decripted Message:", decripted_message)

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
        self.bits = bits
        self.DEBUG = DEBUG

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
        # print(cipher)
        return self.list_to_hex(cipher)
    
    def decript(self, cipher) :
        cipher = self.hex_to_list(cipher)
        sz = len(cipher)
        message = ""
        for i in range(sz):
            ascii = fastpow(cipher[i], self.d, self.n)
            # mi = (ci**d) % n
            message += chr(ascii)
        return message

    def list_to_hex(self, cipher):
        cipher_hex = ""
        for value in cipher:
            number = hex(value)[2:]
            diff = self.bits//2 - len(number)
            number = "0"*diff + number
            cipher_hex += number
        return cipher_hex

    def hex_to_list(self, cipher_hex):
        cipher_list = []
        for i in range(0, len(cipher_hex), self.bits//2):
            cipher_list.append(int(cipher_hex[i: i+self.bits//2], 16))
        return cipher_list
    

if __name__ == '__main__':
    rsa = RSA(DEBUG=True)
    text = "Message to encrypt with RSA"
    cipher = rsa.encrypt(text)
    print("Cipher:", cipher, "\n\n")
    decripted_message = rsa.decript(cipher)
    print("Decripted Message:", decripted_message)

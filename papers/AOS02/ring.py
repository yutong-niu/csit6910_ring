import Crypto.PublicKey.RSA
import os
import hashlib
import random

class AOSRing:

    def __init__(self, k, L = 1024):
        self.k = k
        self.vk_serialize()
        self.q = 1 << (L - 1)
        self.l = L
        self.n = len(k)

    def vk_serialize(self):
        self.L = b''
        for key in self.k:
            if isinstance(key, Crypto.PublicKey.RSA.RsaKey):
                self.L += key.publickey().export_key('DER')

    @staticmethod
    def F(s, k):
        return pow(s, k.e, k.n)
    
    @staticmethod
    def I(c, k):
        return pow(c, k.d, k.n)
    
    def H(self, m, e):
        h = hashlib.sha1(self.L)
        h.update(m.encode('utf-8'))
        h.update(e.to_bytes(self.l, 'big'))
        return int(h.hexdigest(),16)
    
    def sign(self, m, z):
        e = [None] * self.n
        c = [None] * self.n
        s = [None] * self.n
        
        ## Initialization
        if isinstance(self.k[z], Crypto.PublicKey.RSA.RsaKey):
            e[z] = random.randint(0, self.q)
        else:
            raise RuntimeError
        c[(z+1) % self.n] = self.H(m, e[z])

        ## Forward sequence
        first_range = list(range(z + 1, self.n))
        second_range = list(range(z))
        whole_range = first_range + second_range

        for i in whole_range:
            s[i] = random.randint(0, self.q)
            if isinstance(self.k[i], Crypto.PublicKey.RSA.RsaKey):
                e[i] = c[i] + self.F(s[i], self.k[i])
            else:
                raise RuntimeError
            c[(i+1) % self.n] = self.H(m, e[i])
        
        ## Forming the ring
        if isinstance(self.k[z], Crypto.PublicKey.RSA.RsaKey):
            s[z] = self.I(e[z] - c[z], self.k[z])
        else:
            raise RuntimeError

        return [c[0]] + s

    def verify(self, m, sig):
        e = [None] * self.n
        c = [None] * self.n
        c[0] = sig[0]
        s = sig[1:]
        for i in range(self.n):
            if isinstance(self.k[i], Crypto.PublicKey.RSA.RsaKey):
                e[i] = c[i] + self.F(s[i], self.k[i])
            if i != self.n - 1:
                c[i + 1] = self.H(m, e[i])
        return c[0] == self.H(m, e[self.n - 1])

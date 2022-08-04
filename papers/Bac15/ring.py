import hashlib
import random

from ecc import (
    PrivateKey as EccKey,
    S256Point as EccPubKey,
    G as EccGenerator,
    N as EccOrder,
)

class Bac_LSAG:

    def __init__(self, k):
        self.k = k
        self.n = len(k)
        self.vk_serialize()
    
    def vk_serialize(self):
        self.L = b''
        for key in self.k:
            if not isinstance(key, EccKey):
                raise TypeError('Only ECC key is allowed')
            self.L += key.point.sec()
    
    @staticmethod
    def H_p(point):
        hashed_p = hashlib.sha1(point.sec())
        return (int(hashed_p.hexdigest(), 16) % EccOrder) * EccGenerator

    @staticmethod
    def H(l):
        h = hashlib.sha1()
        for item in l:
            if isinstance(item, str):
                h.update(item.encode('utf-8'))
            elif isinstance(item, EccPubKey):
                h.update(item.sec())
            elif isinstance(item, int):
                h.update(item.to_bytes((item.bit_length() + 7) // 8, 'big'))
            elif isinstance(item, bytes):
                h.update(item)
            else:
                raise TypeError('Wrong type to hash')
        return int(h.hexdigest(), 16)

    def sign(self, m, z):
        I = self.k[z].secret * self.H_p(self.k[z].point)
        L = [None] * self.n
        R = [None] * self.n
        c = [None] * self.n
        s = [random.randint(0, EccOrder) if i !=z else None for i in range(self.n)]
        _alpha = random.randint(0, EccOrder)

        L[z] = _alpha * EccGenerator
        R[z] = _alpha * self.H_p(self.k[z].point)
        c[(z+1) % self.n] = self.H([m, L[z], R[z]])

        first_range = list(range(z + 1, self.n))
        second_range = list(range(z))
        whole_range = first_range + second_range

        for i in whole_range:
            L[i] = s[i] * EccGenerator + c[i] * self.k[i].point
            R[i] = s[i] * self.H_p(self.k[i].point) + c[i] * I
            c[(i+1) % self.n] = self.H([m, L[i], R[i]])
        
        s[z] = (_alpha - c[z] * self.k[z].secret) % EccOrder

        return [I] + [c[0]]+ s
    
    def verify(self, m, sig):
        I = sig[0]
        c0 = sig[1]
        s = sig[2:]
        c = [None] * (self.n + 1)
        L = [None] * self.n
        R = [None] * self.n

        c[0] = c0

        for i in range(self.n):
            L[i] = s[i] * EccGenerator + c[i] * self.k[i].point
            R[i] = s[i] * self.H_p(self.k[i].point) + c[i] *I
            c[i+1] = self.H([m, L[i], R[i]])

        return c[0] == c[self.n]
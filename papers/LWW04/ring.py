import hashlib
import random
from typing import Type

from ecc import (
    PrivateKey as EccKey,
    S256Point as EccPubKey,
    G as EccGenerator,
    N as EccOrder,
)

class LSAG:

    def __init__(self, k):
        self.k = k
        self.n = len(k)
        self.vk_serialize()
        self.H2()
    
    def vk_serialize(self):
        self.L = b''
        for key in self.k:
            if not isinstance(key, EccKey):
                raise TypeError('Only ECC key is allowed')
            self.L += key.point.sec()
    
    def H2(self):
        hashed_L = hashlib.sha1(self.L)
        self.h = (int(hashed_L.hexdigest(), 16) % EccOrder) * EccGenerator

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
        c = [None] * self.n
        s = [None] * self.n
        y = self.k[z].secret * self.h
        u = random.randint(0, EccOrder)

        c[(z+1) % self.n] = self.H([
            self.L,
            y,
            m,
            u * EccGenerator,
            u * self.h
        ])

        first_range = list(range(z + 1, self.n))
        second_range = list(range(z))
        whole_range = first_range + second_range

        for i in whole_range:
            s[i] = random.randint(0, EccOrder)
            c[(i + 1) % self.n] = self.H([
                self.L,
                y,
                m,
                s[i] * EccGenerator + c[i] * self.k[i].point,
                s[i] * self.h + c[i] * y,
            ])
        s[z] = (u - self.k[z].secret*c[z]) % EccOrder

        return [c[0]] + s + [y]
    
    def verify(self, m, sig):
        c0 = sig[0]
        s = sig[1:-1]
        c = [None] * (self.n + 1)
        c[0] = c0
        y = sig[-1]

        for i in range(self.n):
            c[i+1] = self.H([
                self.L,
                y,
                m,
                s[i] * EccGenerator + c[i] * self.k[i].point,
                s[i] * self.h + c[i] * y,
            ])
        return c0 == c[self.n]

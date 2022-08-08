import hashlib
import random

from ecc import (
    PrivateKey as EccKey,
    S256Point as EccPubKey,
    G as EccGenerator,
    N as EccOrder,
)

class MLSAG:

    def __init__(self, k):
        self.k = k
        self.n = len(k)
        self.m = len(k[0])
    
    @staticmethod
    def H_p(point):
        hashed_p = hashlib.sha256(point.sec())
        return (int(hashed_p.hexdigest(), 16) % EccOrder) * EccGenerator

    @staticmethod
    def H(l):
        h = hashlib.sha256()
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

    def sign(self, m, z, sk):
        if len(sk) != self.m:
            raise TypeError("wrong private key array size")
        I = [None] * self.m
        for j in range(self.m):
            I[j] = sk[j] * self.H_p(self.k[z][j])
        s = [ [ None for j in range(self.m) ] for i in range(self.n) ]
        L = [ [ None for j in range(self.m) ] for i in range(self.n) ]
        R = [ [ None for j in range(self.m) ] for i in range(self.n) ]
        c = [None] * self.n
        _alpha = [random.randint(0, EccOrder) for j in range(self.m)]
        for i in range(self.n):
            for j in range(self.m):
                if i == z:
                    continue
                s[i][j] = random.randint(0, EccOrder)

        for j in range(self.m):
            L[z][j] = _alpha[j] * EccGenerator
            R[z][j] = _alpha[j] * self.H_p(self.k[z][j])
            
        hashin = [m]
        for j in range(self.m):
            hashin.append(L[z][j])
            hashin.append(R[z][j])
        c[(z+1) % self.n] = self.H(hashin)

        first_range = list(range(z + 1, self.n))
        second_range = list(range(z))
        whole_range = first_range + second_range

        for i in whole_range:
            hashin = [m]
            for j in range(self.m):
                L[i][j] = s[i][j] * EccGenerator + c[i] * self.k[i][j]
                R[i][j] = s[i][j] * self.H_p(self.k[i][j]) + c[i] * I[j]
                hashin.append(L[i][j])
                hashin.append(R[i][j])
            c[(i+1) % self.n] = self.H(hashin)
        
        for j in range(self.m):
            s[z][j] = (_alpha[j] - c[z] * sk[j]) % EccOrder

        return I + [c[0]] + s
    
    def verify(self, m, sig):
        I = sig[0:self.m]
        c0 = sig[self.m]
        s = sig[self.m+1:]
        c = [None] * (self.n + 1)
        L = [ [ None for j in range(self.m) ] for i in range(self.n) ]
        R = [ [ None for j in range(self.m) ] for i in range(self.n) ]

        c[0] = c0

        for i in range(self.n):
            hashin = [m]
            for j in range(self.m):
                L[i][j] = s[i][j] * EccGenerator + c[i] * self.k[i][j]
                R[i][j] = s[i][j] * self.H_p(self.k[i][j]) + c[i] * I[j]
                hashin.append(L[i][j])
                hashin.append(R[i][j])
            c[i+1] = self.H(hashin)

        return c[0] == c[self.n]
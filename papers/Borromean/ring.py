import hashlib
import random

from ecc import (
    PrivateKey as EccKey,
    S256Point as EccPubKey,
    G as EccGenerator,
    N as EccOrder,
)

class BorromeanRing:

    def __init__(self, rings):
        self.rings = rings
        self.n = len(rings)
        self.vk_serialize()
    
    def vk_serialize(self):
        self.L = b''
        for ring in self.rings:
            for key in ring:
                if not isinstance(key, EccKey):
                    raise TypeError('Only ECC key is allowed')
                self.L += key.point.sec()
    
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

    def sign(self, m, i_sk):
        if len(i_sk) != self.n:
            raise ValueError('No. of sk not correct')

        M = self.H([m, self.L])
        k = [None] * self.n
        e = [[None] * len(self.rings[i]) for i in range(self.n)]
        s = [[None] * len(self.rings[i]) for i in range(self.n)]

        hashin = []

        for i in range(self.n):
            k[i] = random.randint(0, EccOrder)
            m_i = len(self.rings[i])
            j_i = i_sk[i]
            e[i][j_i+1] = self.H([M, k[i] * EccGenerator, i, j_i])
            for j in range(j_i+1, m_i-1):
                s[i][j] = random.randint(0, EccOrder)
                e[i][j+1] = self.H([
                    M,
                    s[i][j] * EccGenerator - e[i][j] * self.rings[i][j].point,
                    i,
                    j,
                ])
            s[i][m_i - 1] = random.randint(0, EccOrder)

            hashin.append(s[i][m_i - 1] * EccGenerator - e[i][m_i - 1] * self.rings[i][m_i - 1].point)
        e0 = self.H(hashin)
        
        for i in range(self.n):
            j_i = i_sk[i]
            e[i][0] = e0
            for j in range(j_i):
                s[i][j] = random.randint(0, EccOrder)
                e[i][j+1] = self.H([
                    M,
                    s[i][j] * EccGenerator - e[i][j] * self.rings[i][j].point,
                    i,
                    j,
                ])
            s[i][j_i] = k[i] + self.rings[i][j_i].secret * e[i][j_i]
        
        return [e0, s]
    
    def verify(self, m, sig):
        M = self.H([m, self.L])
        e = [[None] * (len(self.rings[i])+1) for i in range(self.n)]
        R = [[None] * (len(self.rings[i])+1) for i in range(self.n)]
        e0 = sig[0]
        s = sig[1]
        for i in range(self.n):
            e[i][0] = e0

        for i in range(self.n):
            for j in range(len(self.rings[i])):
                R[i][j + 1] = s[i][j] * EccGenerator - e[i][j] * self.rings[i][j].point
                e[i][j + 1] = self.H([M, R[i][j + 1], i, j])

        hashin = []
        for i in range(self.n):
            m_i = len(self.rings[i])
            hashin.append(R[i][m_i])
        calculated_e0 = self.H(hashin)

        return calculated_e0 == e0




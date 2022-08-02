import hashlib
import random

import functools


class Ring:
    """RSA implementation."""
    def __init__(self, k, L: int = 1024) -> None:
        self.k = k
        self.l = L
        self.n = len(k)
        self.q = 1 << (L - 1)

    def sign_message(self, m: str, z: int):
        self._permut(m)
        s = [None] * self.n
        u = random.randint(0, self.q)
        c = v = self._E(u)

        first_range = list(range(z + 1, self.n))
        second_range = list(range(z))
        whole_range = first_range + second_range

        for i in whole_range:
            s[i] = random.randint(0, self.q)
            e = self._g(s[i], self.k[i].e, self.k[i].n)
            v = self._E(v ^ e)
            if (i + 1) % self.n == 0:
                c = v

        s[z] = self._g(v ^ u, self.k[z].d, self.k[z].n)
        return [c] + s

    def verify_message(self, m: str, X) -> bool:
        self._permut(m)

        def _f(i):
            return self._g(X[i + 1], self.k[i].e, self.k[i].n)

        y = map(_f, range(len(X) - 1))
        y = list(y)

        def _g(x, i):
            return self._E(x ^ y[i])
        r = functools.reduce(_g, range(self.n), X[0])
        return r == X[0]

    def _permut(self, m):
        msg = m.encode("utf-8")
        self.p = int(hashlib.sha1(msg).hexdigest(), 16)

    def _E(self, x):
        msg = f"{x}{self.p}".encode("utf-8")
        return int(hashlib.sha1(msg).hexdigest(), 16)

    def _g(self, x, e ,n):
        q, r = divmod(x, n)
        if((q + 1) * n) <= ((1 << self.l) - 1):
            result = q * n + pow(r, e, n)
        else:
            result = x
        return result
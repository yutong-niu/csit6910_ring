from io import BytesIO
from ffe import FieldElement
from pt import Point
from helper import hash160, encode_base58_checksum

import hashlib
import hmac

# a and b of the curve
A = 0
B = 7
# the prime of the finite field
P = 2**256 - 2**32 - 977
# the order of the group
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

class S256Field(FieldElement):
    """
    FieldElement specific to secp256k1 curve
    """

    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    def __repr__(self):
        # display a 256-bit number by filling 64 characters
        return '{:x}'.format(self.num).zfill(64)

    def sqrt(self):
        return self**((P + 1) // 4)

class S256Point(Point):
    """
    Point on the secp256k1 curve
    """

    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)  # point at infinity

    def __repr__(self):
        if self.x is None:
            return 'S256Point(infinity)'
        else:
            return 'S256Point({}, {})'.format(self.x, self.y)

    def __rmul__(self, coefficient):
        coef = coefficient % N  # nG = 0
        return super().__rmul__(coef)

    def verify(self, z, sig):
        s_inv = pow(sig.s, N - 2, N)  # 1/s calculated using Fermat's little theorem
        u = z * s_inv % N  # u = z / s
        v = sig.r * s_inv % N  # v = r / s
        total = u * G + v * self  # uG + vP should be R
        return total.x.num == sig.r  # check that x coordinate is r
    
    def sec(self, compressed=True):
        '''returns the binary version of the SEC format'''
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') + \
                self.y.num.to_bytes(32, 'big')
    
    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    def address(self, compressed=True, testnet=False):
        '''Returns the address string'''
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + h160)
    
    @classmethod
    def parse(self, sec_bin):
        '''returns a Point object from a SEC binary (not hex)'''
        if sec_bin[0] == 4:  # uncompressed SEC format
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(x=x, y=y)
        is_even = sec_bin[0] == 2  # evenness of y coord
        x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
        # right side of the equation y^2 = x^3 + 7
        alpha = x**3 + S256Field(B)
        # solve for left side
        beta = alpha.sqrt()  # y
        if beta.num % 2 == 0:  # y is even
            even_beta = beta
            odd_beta = S256Field(P - beta.num)
        else:
            even_beta = S256Field(P - beta.num)
            odd_beta = beta
        if is_even:
            return S256Point(x, even_beta)
        else:
            return S256Point(x, odd_beta)

G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

class Signature:
    """
    Signature
    """

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return 'Signature({:x},{:x})'.format(self.r, self.s)
    
    def der(self):
        rbin = self.r.to_bytes(32, byteorder='big')
        # remove all null bytes at the beginning
        rbin = rbin.lstrip(b'\x00')
        # if rbin has a high bit, add a \x00
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin
        result = bytes([2, len(rbin)]) + rbin
        sbin = self.s.to_bytes(32, byteorder='big')
        # remove all null bytes at the beginning
        sbin = sbin.lstrip(b'\x00')
        # if sbin has a high bit, add a \x00
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result
    
    @classmethod
    def parse(cls, signature_bin):
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise SyntaxError("Bad Signature")
        length = s.read(1)[0]
        if length + 2 != len(signature_bin):
            raise SyntaxError("Bad Signature Length")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        rlength = s.read(1)[0]
        r = int.from_bytes(s.read(rlength), 'big')
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        slength = s.read(1)[0]
        s = int.from_bytes(s.read(slength), 'big')
        if len(signature_bin) != 6 + rlength + slength:
            raise SyntaxError("Signature too long")
        return cls(r, s)

class PrivateKey:
    """
    Private Key
    """

    def __init__(self, secret):
        self.secret = secret
        self.point = secret * G  # public key

    def hex(self):
        return '{:x}'.format(self.secret).zfill(64)

    def sign(self, z):
        k = self.deterministic_k(z)  # using the deterministic k instead of a random one
        r = (k * G).x.num  # r = x-coord of kG
        k_inv = pow(k, N - 2, N)  # 1/k calculated by Fermat's little theorem
        s = (z + r * self.secret) * k_inv % N  # s = (z + re) / k
        if s > N / 2:
            s = N - s
        return Signature(r, s)

    def deterministic_k(self, z):
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate  # return suitable candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()
    
    def wif(self, compressed=True, testnet=False):
        secret_bytes = self.secret.to_bytes(32, 'big')
        if testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'
        if compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        return encode_base58_checksum(prefix + secret_bytes + suffix)
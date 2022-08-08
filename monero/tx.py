import random
from address import UserKeys
from ecc import (
    PrivateKey as EccKey,
    S256Point as EccPoint,
    G as EccGenerator,
    N as EccOrder,
)

from helper import (
    int_to_little_endian,
    little_endian_to_int,
)

H_n = UserKeys.H_n

H = 8 * EccKey(H_n([EccGenerator])).point

"""
helper function
"""
def first_eight_bytes(x):
    return int(format(x, 'x')[:16], 16)
    
class Commit(EccPoint):
    def __init__(self, y, b):
        p = y * EccGenerator + b * H
        super().__init__(p.x, p.y)
    
    def __sub__(self, other):
        return EccPoint.parse(self.sec()) - EccPoint.parse(other.sec())

    @classmethod
    def generate(cls, K_v, b, r, t=0):
        y = H_n(["commitment_mask", H_n([r * K_v, t])])
        amount = first_eight_bytes(H_n(["amount", H_n([r * K_v, t])])) ^ first_eight_bytes(b)

        return (cls(y, b), amount)
    
    def resolve(self, txPubKey, amount, k_v, t=0):
        return first_eight_bytes(amount) ^ \
            first_eight_bytes(H_n(["amount", H_n([k_v * txPubKey, t])]))
    
    def newCommit(self, txPubKey, amount, k_v, t, new_y=None):
        b = self.resolve(txPubKey, amount, k_v, t)
        y = H_n(["commitment_mask", H_n([k_v * txPubKey, t])])
        if new_y is None:
            new_y = random.randint(1, EccOrder)

        return self.__class__(new_y, b)

class TxIn:
    """
    Transaction Input

    1. ring (list of one-time address from previous output)
    2. pseudo output commitment (sum of which equals to sum of output commitments)
    3. key image (part of ring sig)
    4. signature (ring signature)
    """
    pass

class TxOut:
    """
    Transaction output
    4 field for each output:
    1. oneTimeAddr
    2. txPubKey (r * G)
    3. amount (used to calculate actual amount b)
    4. commit (amount hidden by commit mask)
    """

    def __init__(self, oneTimeAddr, txPubKey, amount, commit):
        self.oneTimeAddr = oneTimeAddr
        self.txPubKey = txPubKey
        self.amount = amount
        self.commit = commit
    
    def __eq__(self, other):
        return (
            self.oneTimeAddr == other.oneTimeAddr and
            self.txPubKey == other.txPubKey and
            self.amount == other.amount and
            self.commit == other.commit
        )
    @classmethod
    def generate(cls, b, pubKeyPair, t=0, r=None, sub=False):
        if r is None:
            r = random.randint(1, EccOrder)
        if t == 0:
            (txPubKey, oneTimeAddr) = UserKeys.generateOneTimeAddr(
                pubKeyPair=pubKeyPair,
                r = r,
                sub=sub,
            )
        else:
            (txPubKey, oneTimeAddr) = UserKeys.generateOneTimeAddrMultiOut(
                pubKeyPair=pubKeyPair,
                t = t,
                r = r,
                sub=sub,
            )
        (commit, amount) = Commit.generate(
            K_v = pubKeyPair[0],
            b = b,
            r = r,
            t = t,
        )
        return cls(oneTimeAddr, txPubKey, amount, commit)
    

    @classmethod
    def parse(cls, s):
        # Takes a byte stream and parses the tx_output
        # and return a TxOut Object
        oneTimeAddress = EccPoint.parse(s.read(33))
        txPubKey = EccPoint.parse(s.read(33))
        commit = EccPoint.parse(s.read(33))
        amount = little_endian_to_int(s.read(8))

        return cls(oneTimeAddress, txPubKey, amount, commit)

    def serialize(self):
        # returns the byte serialization of the transaction output
        # the result will be static 107 bytes
        # 33 + 33 + 33 + 8
        result = self.oneTimeAddr.sec()
        result += self.txPubKey.sec()
        result += self.commit.sec()
        result += int_to_little_endian(self.amount, 8)
        return result

    
    def revealCommitMask(self, k_v, t):
        return H_n(["commitment_mask", H_n([k_v * self.txPubKey, t])])
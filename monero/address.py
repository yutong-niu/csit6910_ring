import random
import hashlib

from ecc import (
    PrivateKey as EccKeyPair,
    S256Point as EccPubKey,
    G as EccGenerator,
    N as EccOrder,
)

H_n = hashlib.sha256

class UserKeys:
    """
    Users have two sets of private/public keys
    (k_v, K_v) and (k_s, K_s)
    view key and spend key
    view key: determine if their address owns an output
    spend key: spend that output / check if spent
    """

    def __init__(self, secret1, secret2):
        # view key
        self.view = EccKeyPair(secret1)
        # spend key
        self.spend = EccKeyPair(secret2)
    
    @staticmethod
    def H_n(l):
        # hash function using sha256
        # take str, pubkey, int, bytes as inputs
        # or a list of combination above
        if not isinstance(l, list):
            l = [l]
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
    
    @classmethod
    def generate(cls):
        # generate a random user address
        secret1 = random.randint(1, EccOrder)
        secret2 = random.randint(1, EccOrder)
        return cls(secret1, secret2)
    
    def getPubKey(self):
        # pub key getter
        return (self.view.point, self.spend.point)

    @classmethod
    def generateOneTimeAddr(cls, pubKeyPair):
        # generate one time address
        # taking pubkey pair as input
        # output: transactino pubkey and one-time address
        (K_v, K_s) = pubKeyPair
        # generate random number
        r = random.randint(1, EccOrder)
        # K = H(r * K_v) * G + K_s
        K = cls.H_n(r * K_v) * EccGenerator + K_s

        # (tx pubkey, one-time address)
        return (r * EccGenerator, K)
    

    def ownsOneTimeAddr(self, oneTimeAddr):
        # txPubKey = r * G
        (txPubKey, oneTimePubKey) = oneTimeAddr
        # k_v * r * G = r * K_v
        hashin = self.view.secret * txPubKey
        # K_s' = K - H(r*K_v)G
        K_s = oneTimePubKey - self.H_n(hashin) * EccGenerator
        # check if K_s' == K_s
        return K_s == self.spend.point
        

    def generateOneTimeSecret(self, oneTimeAddr):
        # txPubKey = r * G
        (txPubKey, oneTimePubKey) = oneTimeAddr
        # k_v * r * G = r * K_v
        hashin = self.view.secret * txPubKey
        # k = H(r * K_v) + k_s
        return (self.H_n(hashin) + self.spend.secret) % EccOrder

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

    def __init__(self, secret1, secret2, sub=False):
        # view key
        self.view = EccKeyPair(secret1)
        # spend key
        self.spend = EccKeyPair(secret2)
        # if key is subaddress
        self.sub = sub
        # list of sub spend keys
        # for sub-address, this will be empty list forever
        self.subSpendKeys = []
    
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
    
    def generateSub(self, i):
        if self.sub:
            raise RuntimeError("sub address cannot call generate sub")
        k_v = self.view.secret * (self.spend.secret + self.H_n(["SubAddr", self.view.secret, i]))
        k_s = self.spend.secret + self.H_n(["SubAddr", self.view.secret, i])
        # expand subSpendKeys to include the new generate
        if len(self.subSpendKeys) > i:
            self.subSpendKeys[i] = k_s * EccGenerator
        else:
            list_cp = self.subSpendKeys.copy()
            self.subSpendKeys = [None] * (i + 1)
            for j in range(len(list_cp)):
                self.subSpendKeys[j] = list_cp[j]
            self.subSpendKeys[i] = k_s * EccGenerator


        return self.__class__(k_v, k_s, sub=True)
    
    def getPubKey(self):
        # pub key getter
        return (self.view.point, self.spend.point, self.sub)

    @classmethod
    def generateOneTimeAddr(cls, pubKeyPair, sub=False):
        # generate one time address
        # taking pubkey pair as input
        # output: tx pubkey and one-time address
        if len(pubKeyPair) == 2:
            (K_v, K_s) = pubKeyPair
        elif len(pubKeyPair) == 3 and isinstance(pubKeyPair[2], bool):
            (K_v, K_s, sub) = pubKeyPair
        else:
            raise TypeError("pubKeyPair has invalid len")
        # generate random number
        r = random.randint(1, EccOrder)
        # K = H(r * K_v) * G + K_s
        K = cls.H_n(r * K_v) * EccGenerator + K_s

        # (tx pubkey, one-time address)
        if sub:
            return (r * K_s, K)
        else:
            return (r * EccGenerator, K)


    @classmethod
    def generateOneTimeAddrMultiOut(cls, pubKeyPairs):
        # generate one time address
        # . for multiple tx outputs
        # taking list of pubkey pairs as input
        # output: list of
        # .       (tx pubkey, one-time addr, tx index)
        # tx pubkey = r * G
        r = random.randint(1, EccOrder)

        p = len(pubKeyPairs)
        oneTimeAddresses = []
        for t in range(p):
            if len(pubKeyPairs[t]) == 2:
                (K_v, K_s) = pubKeyPairs
                sub = False
            elif len(pubKeyPairs[t]) == 3:
                (K_v, K_s, sub) = pubKeyPairs[t]
            else:
                raise TypeError("pubKeyPair has invalid len")
            # K = H(r*K_v, t)G + K_s
            K = cls.H_n([r * K_v, t]) * EccGenerator + K_s
            # (tx pubkey, one-time addr, tx index)
            if sub:
                oneTimeAddresses.append((r * K_s, K, t))
            else:
                oneTimeAddresses.append((r * EccGenerator, K, t))
        
        return oneTimeAddresses
   

    def ownsOneTimeAddr(self, oneTimeAddr, subSpendKeys = []):
        if self.sub:
            raise RuntimeError("sub address cannot check one-time address ownership")
        if len(subSpendKeys) == 0:
            subSpendKeys = self.subSpendKeys
        # check if the address owns the one-time addr
        if len(oneTimeAddr) == 2:
            # txPubKey = r * G
            (txPubKey, oneTimePubKey) = oneTimeAddr
            # k_v * r * G = r * K_v
            hashin = self.view.secret * txPubKey
            # K_s' = K - H(r*K_v)G
            K_s = oneTimePubKey - self.H_n(hashin) * EccGenerator
            # check if K_s' == K_s or K_s in subsSpendKeys
            return K_s == self.spend.point or K_s in subSpendKeys
        elif len(oneTimeAddr) == 3:
            # one-time address for multiple outputs
            # t: output index
            (txPubKey, oneTimePubKey, t) = oneTimeAddr
            # k_v * r * G = r * K_v
            hashin = self.view.secret * txPubKey
            # K_s' = K - H(r*K_v, t)G
            K_s = oneTimePubKey - self.H_n([hashin, t]) * EccGenerator
            # check if K_s' == K_s or K_s in subSpendKeys
            return K_s == self.spend.point or K_s in subSpendKeys
        else:
            raise TypeError("Wrong one-time address len")
        

    def generateOneTimeSecret(self, oneTimeAddr, subSpendKeys = []):
        # generate one-time secret from one-time addr
        if self.sub:
            raise RuntimeError("sub address cannot generate one-time secret")
        if not self.ownsOneTimeAddr(oneTimeAddr, subSpendKeys=subSpendKeys):
            raise RuntimeError("OneTimeAddress not owned by this addr")
        if len(subSpendKeys) == 0:
            subSpendKeys = self.subSpendKeys
        if len(oneTimeAddr) == 2:
            # txPubKey = r * G
            (txPubKey, oneTimePubKey) = oneTimeAddr
            # k_v * r * G = r * K_v
            hashin = self.view.secret * txPubKey
            # K_s' = K - H(r*K_v, t)G
            K_s = oneTimePubKey - self.H_n(hashin) * EccGenerator
            if K_s == self.spend.point:
                # k = H(r * K_v) + k_s
                return (self.H_n(hashin) + self.spend.secret) % EccOrder
            elif K_s in subSpendKeys:
                index = subSpendKeys.index(K_s)
                k_s = self.generateSub(index).spend.secret
                return (self.H_n(hashin) + k_s) % EccOrder
            else:
                raise RuntimeError("OneTimeAddress not owned by this addr")
        elif len(oneTimeAddr) == 3:
            # one-time address for multiple outputs
            # t: output index
            (txPubKey, oneTimePubKey, t) = oneTimeAddr
            # k_v * r * G = r * K_v
            hashin = self.view.secret * txPubKey
            # K_s' = K - H(r*K_v, t)G
            K_s = oneTimePubKey - self.H_n([hashin, t]) * EccGenerator
            if K_s == self.spend.point:
                # k = H(r * K_v, t) + k_s
                return (self.H_n([hashin, t]) + self.spend.secret) % EccOrder
            elif K_s in subSpendKeys:
                index = subSpendKeys.index(K_s)
                k_s = self.generateSub(index).spend.secret
                return (self.H_n([hashin, t]) + k_s) % EccOrder
            else:
                raise RuntimeError("OneTimeAddress not owned by this addr")
        else:
            raise TypeError("Wrong one-time address len")
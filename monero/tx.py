import random
from io import BytesIO
from ring import MLSAG
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

RING_SIZE = 6
MINER_REWARD = 100

"""
helper function
"""
def first_eight_bytes(x):
    return int(format(x, 'x')[:16], 16)

def searchOneTimeAddr(oneTimeAddr):
    raise RuntimeError("To be substitued")

def searchOneTimeAddrIndex(oneTimeAddr):
    raise RuntimeError("To be substitued")

def selectOneTimeAddr():
    raise RuntimeError("To be substitued")


class Commit(EccPoint):
    def __init__(self, y, b):
        p = y * EccGenerator + b * H
        return super().__init__(p.x, p.y)
    
    def __eq__(self, other):
        return EccPoint.parse(self.sec()) == EccPoint.parse(other.sec())
    
    def __sub__(self, other):
        return EccPoint.parse(self.sec()) - EccPoint.parse(other.sec())

    @classmethod
    def generate(cls, K_v, b, r, t=0):
        y = H_n(["commitment_mask", H_n([r * K_v, t])])
        amount = first_eight_bytes(H_n(["amount", H_n([r * K_v, t])])) ^ first_eight_bytes(b)

        return (cls(y, b), amount)
    
    @staticmethod
    def resolve(txPubKey, amount, k_v, t=0):
        return first_eight_bytes(amount) ^ \
            first_eight_bytes(H_n(["amount", H_n([k_v * txPubKey, t])]))
    
    def newCommit(self, txPubKey, amount, k_v, t, new_y=None):
        b = Commit.resolve(txPubKey, amount, k_v, t)
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

    def __init__(self, ring, pseudoOut, keyImage, sig):
        # ring has the size 6 * 2
        self.ring = ring
        self.pseudoOut = pseudoOut
        self.keyImage = keyImage
        # (I + c0 + s)
        # I has size 2
        # c0 is a hash256 int
        # s has size 6 * 2
        self.sig = sig
    
    def __eq__(self, other):
        result = True
        for i in range(RING_SIZE):
            for j in range(2):
                if not self.ring[i][j] == other.ring[i][j]:
                    result = False

        if not self.pseudoOut == other.pseudoOut:
            result = False
        if not self.keyImage == other.keyImage:
            result = False
        if not self.sig == other.sig:
            result = False
        return result
    
    @classmethod
    def generateUnsigned(cls, oneTimeAddr, user, t=0, pseudoMask=None):
        prevOut = searchOneTimeAddr(oneTimeAddr)
        if not user.ownsOneTimeAddr((prevOut.txPubKey, prevOut.oneTimeAddr, t)):
            raise RuntimeError("user does NOT own prevOut")
        
        # calculate pseudo out commit
        if pseudoMask is None:
            pseudoMask = random.randint(1, EccOrder)
        if prevOut.commit == Commit(1, prevOut.amount):
            # miner tx output
            b = prevOut.amount
            t = 0
        else:
            # normal tx output
            b = Commit.resolve(
                txPubKey = prevOut.txPubKey,
                amount = prevOut.amount,
                k_v = user.view.secret,
                t = t,
            )
        pseudoOut = pseudoMask * EccGenerator + b * H

        # construct ring
        ring = [None] * RING_SIZE
        _pi = random.randint(0, RING_SIZE - 1)
        ring[_pi] = [oneTimeAddr, prevOut.commit - pseudoOut]
        for i in range(len(ring)):
            while ring[i] is None:
                randomOneTimeAddr = selectOneTimeAddr()
                if randomOneTimeAddr not in [_[0] for _ in ring if _ is not None]:
                    randomOut = searchOneTimeAddr(randomOneTimeAddr)
                    ring[i] = [randomOneTimeAddr, randomOut.commit - pseudoOut]
        
        # skip sig since the input is unsigned
        sig = None 

        # add key Image
        keyImage = user.generateOneTimeSecret((prevOut.txPubKey, oneTimeAddr, t)) * \
            MLSAG.H_p(oneTimeAddr)

        return cls(ring, pseudoOut, keyImage, sig)
    
    @classmethod
    def parse_unsigned(cls, s):
        ring = [[None for i in range(2)] for j in range(RING_SIZE)]
        for i in range(RING_SIZE):
            for j in range(2):
                ring[i][j] = EccPoint.parse(s.read(33))
        pseudoOut = EccPoint.parse(s.read(33))
        keyImage = EccPoint.parse(s.read(33))

        return cls(ring=ring, pseudoOut=pseudoOut, keyImage=keyImage, sig=None)
    
    @classmethod
    def parse(cls, stream):
        unsigned = cls.parse_unsigned(BytesIO(stream.read(462)))
        I = [None] * 2
        for i in range(2):
            I[i] = EccPoint.parse(stream.read(33))
        c0 = little_endian_to_int(stream.read(32))
        s = [[None for i in range(2)] for j in range(RING_SIZE)]
        for i in range(RING_SIZE):
            for j in range(2):
                s[i][j] = little_endian_to_int(stream.read(32))
        unsigned.sig = I + [c0] + s 

        return unsigned

    
    def serialize_unsigned(self):
        # returns serialization without sig
        # includes only ring, pseuodoOut, keyImage
        # ring has size 6 * 2; each is a one-time address(EccPoint)
        #   size: 6 * 2 * 33bytes
        # pseudoOut is a EccPoint
        #   size: 33 bytes
        # keyImage is a EccPoint
        #   size: 33 bytes
        # In total: 33 bytes * 14 = 462 bytes
        result = b''
        for i in range(RING_SIZE):
            for j in range(2):
                result += self.ring[i][j].sec()
        result += self.pseudoOut.sec()
        result += self.keyImage.sec()

        return result
    
    def serialize(self):
        # serialized unsigned: 462 bytes
        # sig:
        #   (I + c0 + s)
        #   I has size 2 * 33 bytes
        #   c0 is a hash256 int: 256 / 8 = 32 bytes
        #   s has size 6 * 2, each has 32 bytes
        #   sig total = 2 * 33 + 32 + 12 * 32 = 482 bytes
        # Total: 462 bytes + 482 bytes = 944 bytes
        result = self.serialize_unsigned()
        I = self.sig[0:2]
        c0 = self.sig[2]
        s = self.sig[3:]
        for i in range(2):
            result += I[i].sec()
        result += int_to_little_endian(c0, 32)
        for i in range(RING_SIZE):
            for j in range(2):
                result += int_to_little_endian(s[i][j], 32)
        
        return result


    def sign(self, oneTimeAddr, user, m, pseudoMask, t=0):
        if self.sig is not None:
            raise RuntimeError("cannot re-sign TxIn")
        prevOut = searchOneTimeAddr(oneTimeAddr)
        if not user.ownsOneTimeAddr((prevOut.txPubKey, prevOut.oneTimeAddr, t)):
            raise RuntimeError("user does NOT own prevOut")
        if prevOut.commit == Commit(1, prevOut.amount):
            # miner tx output
            prevMask = 1
            t = 0
        else:
            prevMask = H_n(["commitment_mask", H_n([user.view.secret * prevOut.txPubKey, t])])
        secrets = [user.generateOneTimeSecret((prevOut.txPubKey, oneTimeAddr, t)), (prevMask - pseudoMask) % EccOrder]

        _pi = [_[0] for _ in self.ring].index(oneTimeAddr)

        self.sig = MLSAG(self.ring).sign(m, _pi, secrets)
    
    def verify(self, m):
        if self.sig is None:
            raise RuntimeError("cannot verify unsigned TxIn")
        return MLSAG(self.ring).verify(m, self.sig)

        

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
    


class Tx:

    """
    Transaction class:
    4 fields
    1. type: 0 (miner transaction), 1 (normal transaction)
    2. tx_ins: a list of TxIn object
    3. tx_outs: a list of TxOut object
    4. fee: clear text
    """
    def __init__(self, type, tx_ins, tx_outs, fee):
        if type == 0 and len(tx_ins) != 0:
            raise ValueError("miner transaction cannot have tx_ins")
        self.type = type
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.fee = fee
    
    def __eq__(self, other):
        if self.type != other.type:
            return False
        if self.fee != other.fee:
            return False
        in_len = len(self.tx_ins)
        if in_len != len(other.tx_ins):
            return False
        for i in range(in_len):
            if self.tx_ins[i] != other.tx_ins[i]:
                return False
        out_len = len(self.tx_outs)
        if out_len != len(other.tx_outs):
            return False
        for i in range(out_len):
            if self.tx_outs[i] != other.tx_outs[i]:
                return False
        return True


    @classmethod
    def generate(cls, user, oneTimeAddresses, outs):
        # inputs:
        #   user: UserKeys object
        #   oneTimeAddresses: a list of oneTimeAddress
        #   outs: a list of (pubKey, amount) tuple
        r = random.randint(1, EccOrder)
        
        type = 1

        # generate tx outputs
        tx_outs = []
        tx_out_amounts = []
        sum_y = 0
        for t in range(len(outs)):
            (pubKey, b) = outs[t]
            if b < 0 or b > 0xffffffffffffffff:
                raise RuntimeError("invalid amount for TxOut")
            tx_out_amounts.append(b)
            tx_outs.append(
                TxOut.generate(
                    b = b,
                    pubKeyPair=pubKey,
                    t=t,
                    r = r,
                )
            )
            sum_y += H_n(["commitment_mask", H_n([r * pubKey[0], t])])
        
        # generate unsigned tx inputs
        tx_ins = []
        tx_in_amounts = []
        pseudoMasks = []
        for i in range(len(oneTimeAddresses)):
            oneTimeAddr = oneTimeAddresses[i]
            t = searchOneTimeAddrIndex(oneTimeAddr)
            if i == len(oneTimeAddresses) - 1:
                if not len(pseudoMasks) == len(oneTimeAddresses) - 1:
                    raise ValueError("Incorrect No. of pseudoMasks")
                pseudoMask = (sum_y - sum(pseudoMasks)) % EccOrder
            else:
                pseudoMask = random.randint(1, EccOrder)
            pseudoMasks.append(pseudoMask)
            tx_in = TxIn.generateUnsigned(
                    oneTimeAddr=oneTimeAddr,
                    user = user,
                    t = t,
                    pseudoMask=pseudoMask,
            )
            prevOut = searchOneTimeAddr(oneTimeAddr)
            if prevOut.commit == Commit(1, prevOut.amount):
                b = prevOut.amount
                t = 0
            else:
                b = Commit.resolve(
                    txPubKey = prevOut.txPubKey,
                    amount = prevOut.amount,
                    k_v = user.view.secret,
                    t = searchOneTimeAddrIndex(oneTimeAddr),
                )
            tx_in_amounts.append(b)
            tx_ins.append(tx_in)
        fee = sum(tx_in_amounts) - sum(tx_out_amounts)
        if fee < 0 or fee > 0xffffffffffffffff:
            raise ValueError("Incorrect fee amount")

        # unsigned tx
        tx = cls(
            type = type,
            tx_ins = tx_ins,
            tx_outs = tx_outs,
            fee = fee,
        )
        m = tx.serialize_unsigned()

        # sign each tx in
        for i in range(len(tx.tx_ins)):
            tx.tx_ins[i].sign(
                oneTimeAddr=oneTimeAddresses[i],
                user = user,
                m = m,
                pseudoMask=pseudoMasks[i],
                t = searchOneTimeAddrIndex(oneTimeAddresses[i]),
            )
            if not tx.tx_ins[i].verify(m):
                raise RuntimeError("sig verification failed")

        return tx
    
    @classmethod
    def generateMiner(cls, pubKeyPair, fee):
        reward = MINER_REWARD
        if reward < 0 or reward > 0xffffffffffffffff:
            raise ValueError("Invalid miner reward value")
        if fee < 0 or fee > 0xffffffffffffffff:
            raise ValueError("Invalid fee reward value")
        amount = reward + fee
        if amount < 0 or amount > 0xffffffffffffffff:
            raise ValueError("Invalid amount value")
        
        tx_out = TxOut.generate(
            pubKeyPair=pubKeyPair,
            b = 0,
        )
        tx_out.amount = amount
        tx_out.commit = Commit(1, amount)
        tx_outs = [tx_out]

        tx_ins = []
        type = 0
        fee = 0

        return cls(type, tx_ins, tx_outs, fee)
    

    def getKeyImages(self):
        images = []
        for tx_in in self.tx_ins:
            images.append(tx_in.keyImage)
        return images

    def verify(self):
        if self.type == 1:
            m = self.serialize_unsigned()
            for tx_in in self.tx_ins:
                # verify sig
                if not tx_in.verify(m):
                    return False
            # verify amount
            commit_sum = 0 * EccGenerator
            for i in self.tx_ins:
                commit_sum += i.pseudoOut
            # duplicate keyImages
            images = self.getKeyImages()
            if len(set(images)) != len(self.tx_ins):
                return False
            for o in self.tx_outs:
                commit_sum -= o.commit
            if not commit_sum == self.fee * H:
                return False
            return True
        elif self.type == 0:
            return self.fee == 0 and len(self.tx_ins) == 0 and len(self.tx_outs) == 1 \
                and self.tx_outs[0].commit == Commit(1, self.tx_outs[0].amount)
        else:
            raise TypeError("Invalid tx type")
        
        
    def serialize_unsigned(self):
        # serialize unsigned transaction for signature
        result = b''
        result += int_to_little_endian(self.type, 1)
        result += int_to_little_endian(self.fee, 8)
        for tx_in in self.tx_ins:
            result += tx_in.serialize_unsigned()
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        return H_n([result])
    
    def serialize(self):
        result = b''
        # 1 byte for type (0 or 1)
        result += int_to_little_endian(self.type, 1)
        # 8 bytes for tx fee
        result += int_to_little_endian(self.fee, 8)
        # 1 byte for input len
        in_len = len(self.tx_ins)
        if in_len < 0 or in_len > 0xff:
            raise ValueError("Invalid input len")
        result += int_to_little_endian(in_len, 1)
        for i in range(in_len):
            # each input has len 944 bytes
            result += self.tx_ins[i].serialize()
        out_len = len(self.tx_outs)
        if out_len < 0 or out_len > 0xff:
            raise ValueError("Invalid output len")
        result += int_to_little_endian(out_len, 1)
        for i in range(out_len):
            # each output has len 107 bytes
            result += self.tx_outs[i].serialize()

        total_len = 1 + 8 + 1 + in_len * 944 + 1 + out_len * 107
        if len(result) != total_len:
            raise ValueError("error when serializing tx")
        
        return result

    @classmethod
    def parse(cls, s):
        # 1 byte for type (0 or 1)
        type = little_endian_to_int(s.read(1))
        if type != 0 and type != 1:
            raise ValueError("Tx type can only be 0 or 1")
        # 8 bytes for tx fee
        fee = little_endian_to_int(s.read(8))

        in_len = little_endian_to_int(s.read(1))
        tx_ins = []
        if type == 0 and in_len != 0:
            raise ValueError("Miner Tx cannot have non-zero inputs")
        for i in range(in_len):
            tx_ins.append(TxIn.parse(BytesIO(s.read(944))))
        
        out_len = little_endian_to_int(s.read(1))
        tx_outs = []
        if type == 0 and out_len != 1:
            raise ValueError("Miner Tx can only have 1 output")
        for i in range(out_len):
            tx_outs.append(TxOut.parse(BytesIO(s.read(107))))
        
        return cls(
            type = type,
            tx_ins = tx_ins,
            tx_outs = tx_outs,
            fee = fee,
        )
    

    def id(self):
        return int_to_little_endian(self.hash(), 32)
    
    def hash(self):
        return H_n(self.serialize())
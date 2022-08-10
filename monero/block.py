import hashlib
from io import BytesIO
from tx import Tx, MINER_REWARD
from datetime import datetime
from helper import (
    little_endian_to_int,
    int_to_little_endian,
    encode_varint,
    read_varint,
)

# Fix difficulty
TARGET = '0000'

class Block:

    def __init__(self, prev, txs=[], miner=None, timestamp=int(datetime.timestamp(datetime.now())), nonce=None):
        # previous block hash (should start with '0000')
        # hash256 (32 bytes)
        # hexdigest, as string
        self.prev_block = prev
        # 4 bytes int
        self.timestamp = timestamp
        # 4 bytes int
        self.nonce = nonce
        # miner tx (118 bytes)
        self.miner = miner
        # list of tx object
        self.txs = txs
    
    def __eq__(self, other):
        if self.prev_block != other.prev_block:
            return False
        if self.timestamp != other.timestamp:
            return False
        if self.nonce != other.nonce:
            return False
        if self.miner != other.miner:
            return False
        tx_len = len(self.txs)
        if len(other.txs) != tx_len:
            return False
        for i in range(tx_len):
            if self.txs[i] != other.txs[i]:
                return False
        return True
    
    @classmethod
    def parse(cls, s):
        # prev_block as bytes (32 bytes)
        # convert it to int
        prev_block = little_endian_to_int(s.read(32))
        prev_block = format(prev_block, 'x')
        prev_block = '0' * (32 - len(prev_block)) + prev_block

        timestamp = little_endian_to_int(s.read(4))
        nonce = little_endian_to_int(s.read(4))
        miner = Tx.parse(BytesIO(s.read(118)))

        txs = []
        len_tx = read_varint(s)
        for i in range(len_tx):
            tx_len = read_varint(s)
            tx = Tx.parse(BytesIO(s.read(tx_len)))
            txs.append(tx)
        
        return cls(prev=prev_block, timestamp=timestamp, nonce=nonce, miner=miner, txs=txs)


    def serialize(self):
        result = b''
        result += int_to_little_endian(int(self.prev_block, 16), 32)
        result += int_to_little_endian(self.timestamp, 4)
        result += int_to_little_endian(self.nonce, 4)
        result += Tx.serialize(self.miner)
        len_tx = len(self.txs)
        result += encode_varint(len_tx)
        for i in range(len_tx):
            tx_serialized = self.txs[i].serialize()
            tx_len = len(tx_serialized)
            result += encode_varint(tx_len)
            result += tx_serialized
        return result


    def createMiner(self, pubKeyPair):
        fee_total = 0
        for tx in self.txs:
            fee_total += tx.fee
        self.miner = Tx.generateMiner(pubKeyPair=pubKeyPair, fee=fee_total)

    
    def hash(self):
        return hashlib.sha256(self.serialize()).hexdigest()

    def pow(self):
        for n in range(0, 0xffffffff + 1):
            self.nonce = n
            if self.hash().startswith(TARGET):
                break
        else:
            raise RuntimeError("Failed to mine the block")
    

    def getKeyImages(self):
        images = []
        for tx in self.txs:
            images += tx.getKeyImages()
        return images

    
    def verify(self):
        if not self.prev_block.startswith(TARGET):
            return False
        if not self.hash().startswith(TARGET):
            return False
        if not self.miner.verify():
            return False
        minerAmount = self.miner.tx_outs[0].amount
        for tx in self.txs:
            if not tx.verify():
                return False
            minerAmount -= tx.fee
        if minerAmount != MINER_REWARD:
            return False
        images = self.getKeyImages()
        if len(images) != len(set(images)):
            return False

        return True
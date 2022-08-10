import os
import random
import inspect

from io import BytesIO
from re import L
from address import UserKeys
from block import Block
from tx import Tx
from helper import (
    read_varint,
    encode_varint,
)


currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))

class Chain:

    def __init__(self, name, blocks=[], txs=[]):
        self.name = name
        self.blocks = blocks
        self.txs = txs
    

    def __eq__(self, other):
        if self.name != other.name:
            return False
        len_b = len(self.blocks)
        if len_b != len(other.blocks):
            return False
        len_t = len(self.txs)
        if len_t != len(other.txs):
            return False
        for i in range(len_b):
            if self.blocks[i] != other.blocks[i]:
                return False
        for i in range(len_t):
            if self.txs[i] != other.txs[i]:
                return False
        return True


    @classmethod
    def genesis(cls, name):
        prev_block = '0' * 64
        blocks = []
        for i in range(10):
            receiver = UserKeys.generate().getPubKey()
            block = Block(prev=prev_block)
            block.createMiner(receiver)
            block.pow()
            if not block.verify():
                raise RuntimeError("Failed to create genesis block")
            blocks.append(block)
            prev_block = block.hash()
        return cls(name=name, blocks=blocks)


    def serializeBlocks(self):
        result = b''
        len_blocks = len(self.blocks)
        result += encode_varint(len_blocks)

        for block in self.blocks:
            s = block.serialize()
            s_len = len(s)
            result += encode_varint(s_len)
            result += s
        return result
    

    def serializeTxs(self):
        result = b''
        len_txs = len(self.txs)
        result += encode_varint(len_txs)

        for tx in self.txs:
            s = tx.serialize()
            s_len = len(s)
            result += encode_varint(s_len)
            result += s
        return result
    

    @classmethod
    def parseBlocks(cls, s):
        blocks = []

        len_blocks = read_varint(s)
        for i in range(len_blocks):
            s_len = read_varint(s)
            blocks.append(Block.parse(BytesIO(s.read(s_len))))
        
        return blocks


    @classmethod
    def parseTxs(cls, s):
        txs = []

        len_tx = read_varint(s)
        for i in range(len_tx):
            s_len = read_varint(s)
            txs.append(Tx.parse(BytesIO(s.read(s_len))))
        
        return txs

    def getBlockDataFile(self):
        return os.path.join(currentdir, 'data', self.name, 'chain.dat')
    
    def getTxDataFile(self):
        return os.path.join(currentdir, 'data', self.name, 'tx.dat')
    

    def dumpBlockData(self):
        with open(self.getBlockDataFile(), 'wb') as f:
            f.write(self.serializeBlocks())

    def dumpTxData(self):
        with open(self.getTxDataFile(), 'wb') as f:
            f.write(self.serializeTxs())

    def loadBlockData(self):
        with open(self.getBlockDataFile(), 'rb') as f:
            self.blocks = self.parseBlocks(BytesIO(f.read()))

    def loadTxData(self):
        with open(self.getTxDataFile(), 'rb') as f:
            self.txs = self.parseTxs(BytesIO(f.read()))
    

    def searchOneTimeAddr(self, oneTimeAddr):
        for b in self.blocks:
            if oneTimeAddr == b.miner.tx_outs[0].oneTimeAddr:
                return b.miner.tx_outs[0]
            for tx in b.txs:
                for index in range(len(tx.tx_outs)):
                    if tx.tx_outs[index].oneTimeAddr == oneTimeAddr:
                        return tx.tx_outs[index]
        return None
    
    def searchOneTimeAddrIndex(self, oneTimeAddr):
        for b in self.blocks:
            if oneTimeAddr == b.miner.tx_outs[0].oneTimeAddr:
                return 0
            for tx in b.txs:
                for index in range(len(tx.tx_outs)):
                    if tx.tx_outs[index].oneTimeAddr == oneTimeAddr:
                        return index
        return None

    def selectOneTimeAddr(self):
        b = random.randint(0, len(self.blocks) - 1)
        l = random.randint(0, len(self.blocks[b].txs))
        if l == len(self.blocks[b].txs):
            tx = self.blocks[b].miner
        else:
            tx = self.blocks[b].txs[l]
        i = random.randint(0, len(tx.tx_outs) - 1)
        return tx.tx_outs[i].oneTimeAddr


    def getKeyImages(self):
        images = []
        for b in self.blocks:
            images += b.getKeyImages()
        return images
    
    def verifyBlocks(self):
        # verify blocks
        if self.blocks[0].prev_block != '0' * 64:
            return False
        for b in self.blocks:
            if not b.verify():
                return False
        # verify key images
        images = self.getKeyImages()
        if len(set(images)) != len(images):
            return False
        return True
    
    def verifyTxs(self):
        images = self.getKeyImages()
        for tx in self.txs:
            if not tx.verify():
                return False
            for i in tx.getKeyImages():
                if i in images:
                    return False
        return True
    
    def mine(self, pubKeyPair):
        if not self.verifyBlocks():
            raise RuntimeError("Cannot mine on invalid chain")
        txs = []
        # at most 5 tx per block
        while len(txs) < 5 and len(self.txs) > 0:
            to_be_added = self.txs.pop()
            if not to_be_added.verify():
                raise RuntimeError("Cannot mine with invalid tx")
            txs.append(to_be_added)
        
        # mined block
        block = Block(prev=self.blocks[-1].hash(), txs = txs)
        block.createMiner(pubKeyPair=pubKeyPair)
        block.pow()
        if not block.verify():
            raise RuntimeError("Mined block does not pass verification")
        
        # double spending check
        images = self.getKeyImages()
        for i in block.getKeyImages():
            if i in images:
                raise RuntimeError("Discovered double spending")
        
        self.blocks.append(block)

        self.dumpBlockData()
        self.dumpTxData()
        

    def replace(self, blocks):
        longer = self.__class__(name = self.name, blocks = blocks)
        if not longer.verifyBlocks():
            raise RuntimeError("Invalid chain received")
        if (not self.verifyBlocks()) or (len(blocks) > len(self.blocks)):
            self.blocks = blocks
        

        # cleanup tx
        images = self.getKeyImages()
        for tx in self.txs:
            if not tx.verify():
                self.txs.remove(tx)            
            for i in tx.getKeyImages():
                if i in images:
                    self.txs.remove(tx)
                    break
        self.dumpBlockData()
        self.dumpTxData()


    def add_tx(self, tx):
        if not tx.verify():
            raise RuntimeError("Invalid tx to be added")
        images = self.getKeyImages()
        for i in tx.getKeyImages():
            if i in images:
                raise RuntimeError("Discovered double spending")
        self.txs.append(tx)
        self.dumpTxData()
    

    def replace_tx(self, txs):
        images = self.getKeyImages()
        for tx in txs:
            try:
                if not tx.verify():
                    raise RuntimeError("Invalid tx to be added")
                for i in tx.getKeyImages():
                    if i in images:
                        raise RuntimeError("Discovered double spending")
                if tx not in self.txs:
                    self.txs.append(tx)
            except:
                continue
        self.dumpTxData()
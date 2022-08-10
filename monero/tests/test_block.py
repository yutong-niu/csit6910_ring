import setup
import tx

from io import BytesIO
from unittest import TestCase
from block import Block
from tx import *
from address import UserKeys

class BlockTest(TestCase):

    def test_emptyBlock(self):
        prev_block = '0' * 64
        user = UserKeys.generate()
        block = Block(prev=prev_block)        
        block.createMiner(user.getPubKey())
        block.pow()
        self.assertTrue(block.verify())
        serialized = block.serialize()
        parsed = Block.parse(BytesIO(serialized))
        self.assertTrue(block == parsed)
    
    def test_normalBlock(self):
        prev_block = '0' * 64
        user = UserKeys.generate()
        outs = []
        ts = []
        oneTimeAddresses = []

        for i in range(10):
            r = random.randint(1, EccOrder)
            t = random.randint(0, 4)
            b = 100
            out = TxOut.generate(
                b = b,
                pubKeyPair=user.getPubKey(),
                r = r,
                t = t,
            )
            outs.append(out)
            oneTimeAddresses.append(out.oneTimeAddr)
            ts.append(t)

        def searchOneTimeAddr(oneTimeAddress):
            i = oneTimeAddresses.index(oneTimeAddress)
            return outs[i]
        
        def selectOneTimeAddr():
            return outs[random.randint(0, 9)].oneTimeAddr
        
        def searchOneTimeAddrIndex(oneTimeAddr):
            return ts[oneTimeAddresses.index(oneTimeAddr)]
        
        tx.searchOneTimeAddr = searchOneTimeAddr
        tx.selectOneTimeAddr = selectOneTimeAddr
        tx.searchOneTimeAddrIndex = searchOneTimeAddrIndex
        
        receiver = UserKeys.generate().getPubKey()

        tx1 = Tx.generate(
            user = user,
            oneTimeAddresses=[
                oneTimeAddresses[0]
            ],
            outs = [
                (receiver, 100)
            ]
        )

        tx2 = Tx.generate(
            user = user,
            oneTimeAddresses=[
                oneTimeAddresses[1],
                oneTimeAddresses[2],
            ],
            outs = [
                (receiver, 100)
            ]
        )

        block = Block(prev=prev_block, txs = [tx1, tx2])
        block.createMiner(user.getPubKey())
        block.pow()
        self.assertTrue(block.verify())
        serialized = block.serialize()
        parsed = Block.parse(BytesIO(serialized))
        self.assertTrue(block == parsed)


    def test_doubleSpend(self):
        prev_block = '0' * 32
        user = UserKeys.generate()
        outs = []
        ts = []
        oneTimeAddresses = []

        for i in range(10):
            r = random.randint(1, EccOrder)
            t = random.randint(0, 4)
            b = 100
            out = TxOut.generate(
                b = b,
                pubKeyPair=user.getPubKey(),
                r = r,
                t = t,
            )
            outs.append(out)
            oneTimeAddresses.append(out.oneTimeAddr)
            ts.append(t)

        def searchOneTimeAddr(oneTimeAddress):
            i = oneTimeAddresses.index(oneTimeAddress)
            return outs[i]
        
        def selectOneTimeAddr():
            return outs[random.randint(0, 9)].oneTimeAddr
        
        def searchOneTimeAddrIndex(oneTimeAddr):
            return ts[oneTimeAddresses.index(oneTimeAddr)]
        

        tx.searchOneTimeAddr = searchOneTimeAddr
        tx.selectOneTimeAddr = selectOneTimeAddr
        tx.searchOneTimeAddrIndex = searchOneTimeAddrIndex
        
        receiver = UserKeys.generate().getPubKey()

        tx1 = Tx.generate(
            user = user,
            oneTimeAddresses=[
                oneTimeAddresses[0],
                oneTimeAddresses[1],
            ],
            outs = [
                (receiver, 100)
            ]
        )

        tx2 = Tx.generate(
            user = user,
            oneTimeAddresses=[
                oneTimeAddresses[1],
                oneTimeAddresses[2],
            ],
            outs = [
                (receiver, 100)
            ]
        )

        block = Block(prev=prev_block, txs = [tx1, tx2])
        block.createMiner(user.getPubKey())
        block.pow()
        self.assertFalse(block.verify())

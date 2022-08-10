import setup

import tx
from unittest import TestCase
from chain import *

class ChainTest(TestCase):

    def test_genesis(self):
        chain = Chain.genesis('ring')
        b = [b for b in chain.blocks]

        #chain.txs.append()
        chain.dumpBlockData()
        chain.loadBlockData()
        for i in range(len(chain.blocks)):
            self.assertTrue(b[i] == chain.blocks[i])
        
    def test_mining(self):
        chain = Chain.genesis('ring')

        user = UserKeys.generate().getPubKey()
        chain.mine(pubKeyPair=user)
        self.assertTrue(chain.verifyBlocks())
        self.assertTrue(len(chain.blocks) == 11)
        self.assertTrue(len(chain.txs) == 0)
        self.assertTrue(len(chain.blocks[-1].txs) == 0)
    
    def test_help_functions(self):
        chain = Chain.genesis('ring')

        alice = UserKeys.generate()
        chain.mine(pubKeyPair=alice.getPubKey())

        oneTimeAddr = chain.blocks[-1].miner.tx_outs[0].oneTimeAddr

        def searchOneTimeAddr(oneTimeAddr):
            return chain.searchOneTimeAddr(oneTimeAddr)
        def searchOneTimeAddrIndex(oneTimeAddr):
            return chain.searchOneTimeAddrIndex(oneTimeAddr)
        def selectOneTimeAddr():
            return chain.selectOneTimeAddr()
        
        tx.searchOneTimeAddr = searchOneTimeAddr
        tx.searchOneTimeAddrIndex = searchOneTimeAddrIndex
        tx.selectOneTimeAddr = selectOneTimeAddr

        self.assertTrue(searchOneTimeAddr(oneTimeAddr=oneTimeAddr) == \
            chain.blocks[-1].miner.tx_outs[0])
        self.assertTrue(searchOneTimeAddrIndex(oneTimeAddr=oneTimeAddr) == 0)
        for i in range(10):
            self.assertTrue(searchOneTimeAddr(selectOneTimeAddr()) is not None)
            self.assertTrue(searchOneTimeAddrIndex(selectOneTimeAddr()) is not None)
    
    def test_addTx(self):
        chain = Chain.genesis('ring')
        alice = UserKeys.generate()
        chain.mine(pubKeyPair=alice.getPubKey())
        chain.mine(pubKeyPair=alice.getPubKey())


        def searchOneTimeAddr(oneTimeAddr):
            return chain.searchOneTimeAddr(oneTimeAddr)
        def searchOneTimeAddrIndex(oneTimeAddr):
            return chain.searchOneTimeAddrIndex(oneTimeAddr)
        def selectOneTimeAddr():
            return chain.selectOneTimeAddr()
        
        tx.searchOneTimeAddr = searchOneTimeAddr
        tx.searchOneTimeAddrIndex = searchOneTimeAddrIndex
        tx.selectOneTimeAddr = selectOneTimeAddr

        bob = UserKeys.generate()
        t = Tx.generate(
            user = alice,
            oneTimeAddresses=[
                chain.blocks[-1].miner.tx_outs[0].oneTimeAddr,
            ],
            # fee = 10
            outs = [
                (bob.getPubKey(), 90)
            ]
        )
        self.assertTrue(len(chain.blocks) == 12)
        chain.add_tx(t)
        self.assertTrue(chain.verifyTxs())
        self.assertTrue(t.fee == 10)

        t2 = Tx.generate(
            user = alice,
            oneTimeAddresses=[
                chain.blocks[-2].miner.tx_outs[0].oneTimeAddr,
            ],
            # fee = 20
            outs = [
                (bob.getPubKey(), 80)
            ]
        )
        chain.add_tx(t2)
        self.assertTrue(chain.verifyTxs())
        self.assertTrue(t2.fee == 20)

        txs = []
        txs.append(chain.txs.pop())
        txs.append(chain.txs.pop())

        self.assertTrue(len(chain.txs) == 0)
        chain.loadTxData()
        self.assertTrue(len(chain.txs) == 2)

        serialized_txs = chain.serializeTxs()
        txs = Chain.parseTxs(BytesIO(serialized_txs))
        chain.txs = []
        self.assertTrue(len(chain.txs) == 0)
        chain.replace_tx(txs)
        self.assertTrue(len(chain.txs) == 2)

        self.assertTrue(txs[0] in chain.txs)
        self.assertTrue(txs[1] in chain.txs)

        self.assertTrue(len(chain.txs) == 2)
        chain.mine(bob.getPubKey())
        self.assertTrue(len(chain.txs) == 0)
        self.assertTrue(chain.blocks[-1].miner.tx_outs[0].amount == 130)
        self.assertTrue(len(chain.blocks[-1].txs) == 2)

        serialized_blocks = chain.serializeBlocks()
        chain = Chain.genesis('ring')
        self.assertTrue(len(chain.blocks) == 10)
        chain.replace(Chain.parseBlocks(BytesIO(serialized_blocks)))
        self.assertTrue(len(chain.blocks) == 13)
        self.assertTrue(chain.blocks[-1].miner.tx_outs[0].amount == 130)
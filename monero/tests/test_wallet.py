import setup

import tx
from unittest import TestCase
from wallet import *
from chain import Chain

class WalletTest(TestCase):

    def test_address(self):
        w = Wallet.me()
        addr = w.address()
        pubKey = Wallet.parseAddress(addr)
        self.assertTrue(pubKey == w.key.getPubKey())
    

    def test_send(self):

        def searchOneTimeAddr(oneTimeAddr):
            return chain.searchOneTimeAddr(oneTimeAddr)
        def searchOneTimeAddrIndex(oneTimeAddr):
            return chain.searchOneTimeAddrIndex(oneTimeAddr)
        def selectOneTimeAddr():
            return chain.selectOneTimeAddr()
        
        tx.searchOneTimeAddr = searchOneTimeAddr
        tx.searchOneTimeAddrIndex = searchOneTimeAddrIndex
        tx.selectOneTimeAddr = selectOneTimeAddr

        w = Wallet.me()

        chain = Chain.genesis('ring')

        self.assertTrue(w.amount(chain) == 0)
        w.mine(chain)
        self.assertTrue(w.amount(chain) == 100)

        bob = Wallet(UserKeys.generate())
        w.send(addr = bob.address(), chain = chain, amount = 15, fee = 5)
        self.assertTrue(w.amount(chain) == 0)
        self.assertTrue(bob.amount(chain) == 0)
        self.assertTrue(len(chain.txs) == 1)

        w.mine(chain)
        self.assertTrue(len(chain.txs) == 0)
        self.assertTrue(w.amount(chain) == 185)
        self.assertTrue(bob.amount(chain) == 15)
        bob.send(addr = w.address(), chain=chain, amount= 2, fee = 3)
        self.assertTrue(bob.amount(chain) == 0)
        w.mine(chain)
        self.assertTrue(bob.amount(chain) == 10)
        self.assertTrue(w.amount(chain) == 290)



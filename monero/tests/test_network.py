import setup
import os
import network
import tx

from io import BytesIO
from unittest import TestCase
from network import Network, currentdir,CHAIN_NAME
from wallet import Wallet
from address import UserKeys


class NetworkTest(TestCase):
    def setUp(self):
        nodes_path = os.path.join(currentdir, 'data', CHAIN_NAME, 'node.dat')
        if os.path.isfile(nodes_path):
            os.remove(nodes_path)
        chain_path = os.path.join(currentdir, 'data', CHAIN_NAME, 'chain.dat')
        if os.path.isfile(chain_path):
            os.remove(chain_path)
        tx_path = os.path.join(currentdir, 'data', CHAIN_NAME, 'tx.dat')
        if os.path.isfile(tx_path):
            os.remove(tx_path)

        self.node = Network()

        def searchOneTimeAddr(oneTimeAddr):
            return self.node.chain.searchOneTimeAddr(oneTimeAddr)

        def searchOneTimeAddrIndex(oneTimeAddr):
            return self.node.chain.searchOneTimeAddrIndex(oneTimeAddr)

        def selectOneTimeAddr():
            return self.node.chain.selectOneTimeAddr()

        tx.searchOneTimeAddr = searchOneTimeAddr
        tx.searchOneTimeAddrIndex = searchOneTimeAddrIndex
        tx.selectOneTimeAddr = selectOneTimeAddr

        network.validate_port = lambda *_: True

    
    def test_nodes(self):
        self.assertTrue(len(self.node.chain.blocks) == 10)

        self.assertTrue(len(self.node.nodes) == 0)
        self.node.registerNodes("192.168.0.3")
        self.assertTrue(len(self.node.nodes) == 1)
        self.node.loadNodes()
        self.assertTrue(len(self.node.nodes) == 1)
        self.node.registerNodes(["192.168.0.4", "192.168.0.5"])
        self.assertTrue(len(self.node.nodes) == 3)
        self.node.loadNodes()
        self.assertTrue(len(self.node.nodes) == 3)
        self.node.registerNodes("192.168.0.5")
        self.assertTrue(len(self.node.nodes) == 3)
        self.node.loadNodes()
        self.assertTrue(len(self.node.nodes) == 3)
        self.node.unregisterNode("192.168.0.5")
        self.assertTrue(len(self.node.nodes) == 2)
        self.node.loadNodes()
        self.assertTrue(len(self.node.nodes) == 2)
    
    def test_wallet(self):
        address = self.node.address()
        self.assertTrue(self.node.balance() == 0)
        self.node.mine()
        self.assertTrue(self.node.balance() == 100)
        self.node.transfer(address, 90, 5)
        self.assertTrue(self.node.balance() == 0)
        self.node.mine()
        self.assertTrue(self.node.balance() == 200)
    
        # chain when me owns 200, bob owns 0
        bob = Wallet(UserKeys.generate())
        bobNode = Network()
        bobNode.wallet = bob
        self.assertTrue(self.node.balance() == 200)
        self.assertTrue(bobNode.balance() == 0)

        # me send bob 100 and me mine
        self.node.transfer(address=bobNode.address(), amount = 100, fee = 10)
        self.assertTrue(len(self.node.chain.blocks) == 12)
        self.assertTrue(len(bobNode.chain.blocks) == 12)
        
        self.assertTrue(len(self.node.chain.txs) == 1)
        self.assertTrue(len(bobNode.chain.txs) == 0)

        b = self.node.getTxInBytes()
        bobNode.replaceTxInBytes(BytesIO(b))

        self.assertTrue(len(self.node.chain.txs) == 1)
        self.assertTrue(len(bobNode.chain.txs) == 1)
       

        self.node.mine()
        self.assertTrue(len(self.node.chain.blocks) == 13)
        self.assertTrue(len(bobNode.chain.blocks) == 12)
        self.assertTrue(len(self.node.chain.txs) == 0)
        self.assertTrue(len(bobNode.chain.txs) == 1)
        self.assertTrue(self.node.balance() == 200)
        self.assertTrue(bobNode.balance() == 0)

        b = self.node.getChainInBytes()
        bobNode.replaceChainInBytes(BytesIO(b))
        self.assertTrue(bobNode.balance() == 100)
        self.assertTrue(len(bobNode.chain.txs) == 0)


        

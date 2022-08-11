from atexit import register
import os
import re
import socket

from wallet import Wallet
from chain import Chain, currentdir

CHAIN_PORT = 6707
CHAIN_NAME = 'ring'

"""helper function"""
def validate_ip(ip):
    return re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",ip)

def validate_port(ip, port=CHAIN_PORT):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.settimeout(5)
   try:
      s.connect((ip, int(port)))
      s.shutdown(2)
      return True
   except:
      return False

class Network:
    def __init__(self):
        self.wallet = Wallet.me()
        # chain read from dat file
        self.chain = Chain(name=CHAIN_NAME)
        try:
            self.chain.loadBlockData()
        except:
            filePath = self.chain.getBlockDataFile()
            os.makedirs(os.path.dirname(filePath), exist_ok=True)
        try:
            self.chain.loadTxData()
        except:
            filePath = self.chain.getTxDataFile()
            os.makedirs(os.path.dirname(filePath), exist_ok=True)
        
        if len(self.chain.blocks) == 0 and len(self.chain.txs) == 0:
            self.chain = Chain.genesis(name=CHAIN_NAME)
            self.chain.dumpBlockData()
        
        self.loadNodes()
    

    """
    methods managing node
    """
    def loadNodes(self):
        nodes_path = os.path.join(currentdir, 'data', CHAIN_NAME, 'node.dat')
        try:
            nodes = []
            with open(nodes_path, 'r') as f:
                for ip in f:
                    ip = ip.strip()
                    if validate_ip(ip):
                        nodes.append(ip)
        except:
            os.makedirs(os.path.dirname(nodes_path), exist_ok=True)
            nodes = []
        self.nodes = set(nodes)
    

    # automated in register and discard
    def dumpNodes(self):
        nodes_path = os.path.join(currentdir, 'data', CHAIN_NAME, 'node.dat')
        with open(nodes_path, 'w+') as f:
            for ip in self.nodes:
                f.write(ip)
                f.write('\n')

    # internal helper function
    def registerNode(self, ip):
        if not validate_ip(ip):
            raise ValueError("Invalid IP address")
        
        if not validate_port(ip):
            raise RuntimeError("Port not open or IP not reachable")

        self.nodes.add(ip.strip())
    
    # Called by /registerNode
    def registerNodes(self, ip):
        if isinstance(ip, str):
            self.registerNode(ip)
        elif isinstance(ip, list):
            for i in ip:
                try:
                    self.registerNode(i)
                except:
                    continue
        self.dumpNodes()
    
    # automated in /connect
    def unregisterNode(self, ip):
        self.nodes.discard(ip)
        self.dumpNodes()
            
    # Called by /node
    def node(self):
        return list(self.nodes)

    """
    methods managing wallet
    """
    # Called by /address
    def address(self):
        return self.wallet.address()
    
    # Called by /balance
    def balance(self):
        return self.wallet.amount(self.chain)
    
    # Called by /mine
    def mine(self):
        self.wallet.mine(self.chain)
    
    # Called by /transfer
    def transfer(self, address, amount, fee):
        self.wallet.send(
            addr = address,
            chain = self.chain,
            amount = amount,
            fee = fee
        )

    """
    methods managing chain
    """

    # Called by /chain
    def getChainInBytes(self):
        return self.chain.serializeBlocks()
    
    # Called by /tx
    def getTxInBytes(self):
        return self.chain.serializeTxs()
    
    # automated in /connect
    # s <- Bytes stream
    def replaceChainInBytes(self, s):
        blocks = Chain.parseBlocks(s)
        self.chain.replace(blocks)
    
    # automated in /connect
    # s <- Bytes stream
    def replaceTxInBytes(self, s):
        txs = Chain.parseTxs(s)
        self.chain.replace_tx(txs)
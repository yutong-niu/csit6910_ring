from network import Network
import tx

node = Network()

def searchOneTimeAddr(oneTimeAddr):
    return node.chain.searchOneTimeAddr(oneTimeAddr)

def searchOneTimeAddrIndex(oneTimeAddr):
    return node.chain.searchOneTimeAddrIndex(oneTimeAddr)

def selectOneTimeAddr():
    return node.chain.selectOneTimeAddr()

tx.searchOneTimeAddr = searchOneTimeAddr
tx.searchOneTimeAddrIndex = searchOneTimeAddrIndex
tx.selectOneTimeAddr = selectOneTimeAddr
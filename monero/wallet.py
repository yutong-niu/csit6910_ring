import os
import inspect
from tkinter import W

from tx import Tx, Commit
from ecc import S256Point as EccPoint
from ring import MLSAG
from address import UserKeys


currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))

SECRET_PATH = os.path.join(currentdir, 'secret')
VIEW_SECRET_PATH = os.path.join(SECRET_PATH, 'view')
SPEND_SECRET_PATH = os.path.join(SECRET_PATH, 'spend')

class Wallet:
    def __init__(self, key):
        self.key = key
    
    @classmethod
    def me(cls):
        # check if user secret already exists
        if os.path.exists(VIEW_SECRET_PATH) and \
            os.path.exists(SPEND_SECRET_PATH):
                with open(VIEW_SECRET_PATH, 'r') as f:
                    k_v = f.read()
                k_v = int(k_v, 16)
                with open(SPEND_SECRET_PATH, 'r') as f:
                    k_s = f.read()
                k_s = int(k_s, 16)
                return cls(UserKeys(k_v, k_s))
        else:
        # create secret if not exist
            os.makedirs(os.path.dirname(VIEW_SECRET_PATH), exist_ok=True)
            key = UserKeys.generate()
            with open(VIEW_SECRET_PATH, 'w+') as f:
                f.write(format(key.view.secret, 'x'))
            with open(SPEND_SECRET_PATH, 'w+') as f:
                f.write(format(key.spend.secret, 'x'))
            return cls(key)

    def scan_chain(self, chain):
        # get oneTimeAddr, amount belonged to the wallet
        result = []

        for block in chain.blocks:
            minerOut = block.miner.tx_outs[0]
            if self.key.ownsOneTimeAddr((minerOut.txPubKey, minerOut.oneTimeAddr)):
                oneTimeAddr = minerOut.oneTimeAddr
                amount = minerOut.amount
                keyImage = self.key.generateOneTimeSecret((minerOut.txPubKey, oneTimeAddr, 0)) * \
                    MLSAG.H_p(oneTimeAddr)
                result.append((oneTimeAddr, amount, keyImage))
            for tx in block.txs:
                for t in range(len(tx.tx_outs)):
                    out = tx.tx_outs[t]
                    if self.key.ownsOneTimeAddr((out.txPubKey, out.oneTimeAddr, t)):
                        amount = Commit.resolve(out.txPubKey, out.amount, self.key.view.secret, t)
                        keyImage = self.key.generateOneTimeSecret((out.txPubKey, out.oneTimeAddr, t)) * \
                            MLSAG.H_p(out.oneTimeAddr)
                        result.append((out.oneTimeAddr, amount, keyImage))
        
        images = chain.getKeyImages()
        for tx in chain.txs:
            images += tx.getKeyImages()
        
        return [x for x in result if x[2] not in images]
            
    def address(self):
        (K_v, K_s, sub) = self.key.getPubKey()
        return K_v.sec().hex() + K_s.sec().hex()

    @staticmethod
    def parseAddress(address):
        if not isinstance(address, str):
            raise TypeError("Wrong address type: only string supported")
        if not len(address) == 132:
            raise ValueError("Wrong address length: must be str of 132")
        K_v = address[0: len(address) // 2]
        K_v = EccPoint.parse(bytes.fromhex(K_v))
        K_s = address[len(address) // 2:]
        K_s = EccPoint.parse(bytes.fromhex(K_s))
        sub = False

        return (K_v, K_s, sub)
    
    def amount(self, chain, unspent=None):
        if unspent is None:
            unspent = self.scan_chain(chain)
        return sum([u[1] for u in unspent])
    
    def mine(self, chain):
        chain.mine(pubKeyPair=self.key.getPubKey())
    
    def send(self, addr, chain, amount, fee):
        unspent = self.scan_chain(chain)
        balance = self.amount(chain, unspent=unspent)
        if amount < 0 or amount > 0xffffffffffffffff:
            raise ValueError("Invalid tx amount")
        if balance < amount + fee:
            raise ValueError("Balance not enough")
        pubKey = self.parseAddress(addr)
        ins = []
        out_amount = 0
        for i in unspent:
            ins.append(i[0])
            out_amount += i[1]
            if out_amount >= amount + fee:
                break
        change = out_amount - amount - fee
        t = Tx.generate(
            user = self.key,
            oneTimeAddresses=ins,
            outs = [
                (pubKey, amount),
                (self.key.getPubKey(), change)
            ]
        )
        if t.verify():
            chain.add_tx(t)
        else:
            raise RuntimeError("Tx verification failed during creation")
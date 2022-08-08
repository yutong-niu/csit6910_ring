import time
import setup
import random
from unittest import TestCase
import tx
from tx import *
from address import UserKeys
from io import BytesIO

class TxTest(TestCase):

    def test_commit(self):
        user = UserKeys.generate()
        r = random.randint(1, EccOrder)
        (K_v, K_s, sub) = user.getPubKey()
        (txPubKey, oneTimeAddr) = UserKeys.generateOneTimeAddr(user.getPubKey(), r=r)
        t = random.randint(0, 10)
        b = random.randint(0, 0xffffffffffffffff)
        new_y = random.randint(0, EccOrder)
        (commit, amount) = Commit.generate(K_v, b, r, t)

        self.assertTrue(commit.resolve(txPubKey, amount, user.view.secret, t) == b)

        new = commit.newCommit(txPubKey, amount, user.view.secret, t, new_y=new_y)
        old_y = H_n(["commitment_mask", H_n([r * K_v, t])])
        delta_y = old_y - new_y
        delta_commit = commit - new
        self.assertTrue(delta_y * EccGenerator == delta_commit)
    
    def test_TxOut(self):
        user = UserKeys.generate()
        r = random.randint(1, EccOrder)
        b = random.randint(0, 0xffffffffffffffff)
        t = random.randint(0, 10)
        out1 = TxOut.generate(
            b = b,
            pubKeyPair=user.getPubKey(),
            r = r,
        ) 

        out2 = TxOut.generate(
            b = b,
            pubKeyPair=user.getPubKey(),
            r = r,
            t = t,
        )

        self.assertTrue(user.ownsOneTimeAddr((out1.txPubKey, out1.oneTimeAddr)))
        self.assertTrue(user.ownsOneTimeAddr((out2.txPubKey, out2.oneTimeAddr, t)))

        b1 = out1.commit.resolve(out1.txPubKey, out1.amount, user.view.secret, 0)
        self.assertTrue(b1 == b)
        b2 = out2.commit.resolve(out2.txPubKey, out2.amount, user.view.secret, t)
        self.assertTrue(b2 == b)

        y1 = out1.revealCommitMask(user.view.secret, 0)
        y2 = out2.revealCommitMask(user.view.secret, t)
        
        self.assertTrue(out1.commit == y1 * EccGenerator + b * H)
        self.assertTrue(out2.commit == y2 * EccGenerator + b * H)

        out1_serialized = out1.serialize()
        out1_parsed = TxOut.parse(BytesIO(out1_serialized))
        self.assertTrue(out1 == out1_parsed)
        out2_serialized = out2.serialize()
        out2_parsed = TxOut.parse(BytesIO(out2_serialized))
        self.assertTrue(out2 == out2_parsed)
    
    def test_TxIn(self):
        user = UserKeys.generate()
        outs =[]
        ts = []
        oneTimeAddresses = []
        for i in range(10):
            r = random.randint(1, EccOrder)
            t = random.randint(0, 4)
            b = random.randint(0, 0xffffffffffffffff)
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

        tx.searchOneTimeAddr = searchOneTimeAddr
        tx.selectOneTimeAddr = selectOneTimeAddr

        inAddress = selectOneTimeAddr()

        t = ts[oneTimeAddresses.index(inAddress)]
        pseudoMask = random.randint(1, EccOrder)
        tx_in = TxIn.generateUnsigned(
            oneTimeAddr=inAddress,
            user = user,
            t = t,
            pseudoMask = pseudoMask,
        )
        unsigned_serialized = tx_in.serialize_unsigned()
        self.assertTrue(len(unsigned_serialized) == 462)
        tx_in_parsed = TxIn.parse_unsigned(BytesIO(unsigned_serialized))
        self.assertTrue(tx_in == tx_in_parsed)


        m = "hello"
        tx_in.sign(inAddress, user, "hello", pseudoMask, t=t)
        self.assertTrue(tx_in.verify(m))

       
        serialized = tx_in.serialize()
        self.assertTrue(len(serialized) == 944)
        tx_in_parsed = TxIn.parse(BytesIO(serialized))
        self.assertTrue(tx_in == tx_in_parsed)
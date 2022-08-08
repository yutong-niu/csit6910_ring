import time
import setup
import random
from unittest import TestCase
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
import time
import setup
import random
from unittest import TestCase
import tx
from tx import *
from address import UserKeys
from io import BytesIO

class TxTest(TestCase):

    """
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
        """

    def test_Tx(self):
        user = UserKeys.generate()
        outs = []
        ts = []
        oneTimeAddresses = []
        consumedImages = []
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
        
        def verifyKeyImage(keyImage):
            return keyImage not in consumedImages

        tx.searchOneTimeAddr = searchOneTimeAddr
        tx.selectOneTimeAddr = selectOneTimeAddr
        tx.searchOneTimeAddrIndex = searchOneTimeAddrIndex
        tx.verifyKeyImage = verifyKeyImage

        # test 1 input 1 output with no fee
        receiver = UserKeys.generate().getPubKey()
        
        input = random.randint(0, 9)
        one_input_one_output_tx = Tx.generate(
            user = user,
            oneTimeAddresses=[
                oneTimeAddresses[input]
            ],
            outs = [
                (receiver, 100)
            ]
        )

        self.assertTrue(one_input_one_output_tx.verify())
        self.assertTrue(one_input_one_output_tx.fee == 0)

        # prevent double spending
        for i in one_input_one_output_tx.tx_ins:
            consumedImages.append(i.keyImage)
        

        receiver2 = UserKeys.generate().getPubKey()
        one_input_one_output_double_spend = Tx.generate(
            user = user,
            oneTimeAddresses=[
                oneTimeAddresses[input]
            ],
            outs = [
                ((receiver2[0], receiver2[1]), 100)
            ]
        )

        self.assertFalse(one_input_one_output_double_spend.verify())
        self.assertTrue(one_input_one_output_double_spend.fee == 0)

        
        # fee calculation
        consumedImages = []
        fee_cal = Tx.generate(
            user = user,
            oneTimeAddresses=[
                oneTimeAddresses[input]
            ],
            outs = [
                (receiver2, 90)
            ]
        )        
        self.assertTrue(fee_cal.verify())
        self.assertTrue(fee_cal.fee == 10)

        # one input 2 output
        one_input_two_output_tx = Tx.generate(
            user = user,
            oneTimeAddresses=[
                oneTimeAddresses[input]

            ],
            outs = [
                (receiver, 10),
                (receiver2, 90)
            ]
        )

        self.assertTrue(one_input_two_output_tx.verify())
        self.assertTrue(one_input_two_output_tx.fee == 0)

        # two input one output
        two_input_one_output_tx = Tx.generate(
            user = user,
            oneTimeAddresses=[
                oneTimeAddresses[input],
                oneTimeAddresses[input + 1]
            ],
            outs = [
                (receiver, 198)
            ]
        )
        self.assertTrue(two_input_one_output_tx.verify())
        self.assertTrue(two_input_one_output_tx.fee == 2)

        # two input two output
        two_input_two_output_tx = Tx.generate(
            user = user,
            oneTimeAddresses=[
                oneTimeAddresses[input],
                oneTimeAddresses[input + 1]
            ],
            outs = [
                (receiver, 90),
                (receiver2, 80)
            ]
        )

        self.assertTrue(two_input_two_output_tx.verify())
        self.assertTrue(two_input_two_output_tx.fee == 30)

        # ten input one output
        ten_input_one_output_tx = Tx.generate(
            user = user,
            oneTimeAddresses=oneTimeAddresses,
            outs = [
                (receiver, 999)
            ]
        )

        self.assertTrue(ten_input_one_output_tx.verify())
        self.assertTrue(ten_input_one_output_tx.fee == 1)

        # key image part fail
        consumedImages.append(ten_input_one_output_tx.tx_ins[0].keyImage)
        consumedImages.append(ten_input_one_output_tx.tx_ins[1].keyImage)

        ten_input_one_output_tx = Tx.generate(
            user = user,
            oneTimeAddresses=oneTimeAddresses,
            outs = [
                (receiver, 998)
            ]
        )

        self.assertFalse(ten_input_one_output_tx.verify())
        self.assertTrue(ten_input_one_output_tx.fee == 2)

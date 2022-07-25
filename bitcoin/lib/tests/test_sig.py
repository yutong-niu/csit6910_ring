import setup
from unittest import TestCase
from ecc import Signature
from random import randint

class SignatureTest(TestCase):

    def test_der(self):
        testcases = (
            (1, 2),
            (randint(0, 2**256), randint(0, 2**255)),
            (randint(0, 2**256), randint(0, 2**255)),
        )
        for r, s in testcases:
            sig = Signature(r, s)
            der = sig.der()
            sig2 = Signature.parse(der)
            self.assertEqual(sig2.r, r)
            self.assertEqual(sig2.s, s)
import os
import sys
import inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

from unittest import TestCase
from ring import *

class RingTest(TestCase):
    def test_LSAG_verification(self):
        size = 4
        msg1, msg2 = "hello", "world"

        def _rn(_):
            return EccKey(random.randint(0, EccOrder))
        
        key = map(_rn, range(size))
        key = list(key)

        ring = Bac_LSAG(key)

        for i in range(size):
            signature_1 = ring.sign(msg1, i)
            signature_2 = ring.sign(msg2, i)
            signature_3 = ring.sign(msg1, (i+1) % size)
            self.assertTrue(ring.verify(msg1, signature_1))
            self.assertTrue(ring.verify(msg2, signature_2))
            self.assertFalse(ring.verify(msg1, signature_2))
            self.assertTrue(signature_1[0] == signature_2[0])
            self.assertFalse(signature_1[0] == signature_3[0])
            self.assertFalse(signature_2[0] == signature_3[0])
    
    def test_LSAG_linkability(self):
        size = 4
        msg1, msg2 = "hello", "world"

        def _rn(_):
            return EccKey(random.randint(0, EccOrder))
        
        key = map(_rn, range(size))
        key = list(key)

        ring = Bac_LSAG(key)

        for i in range(size):
            signature_1 = ring.sign(msg1, i)
            signature_2 = ring.sign(msg2, i)
            signature_3 = ring.sign(msg1, (i+1) % size)
            signature_4 = ring.sign(msg2, (i+1) % size)
            self.assertTrue(ring.verify(msg1, signature_1))
            self.assertFalse(ring.verify(msg1, signature_2))
            self.assertTrue(ring.verify(msg2, signature_2))
            self.assertFalse(ring.verify(msg2, signature_1))
            self.assertTrue(signature_1[0] == signature_2[0])
            self.assertTrue(signature_3[0] == signature_4[0])
            self.assertFalse(signature_1[0] == signature_3[0])
            self.assertFalse(signature_2[0] == signature_3[0])
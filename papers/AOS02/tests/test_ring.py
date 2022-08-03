import os
import sys
import inspect
import Crypto.PublicKey.RSA

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

from unittest import TestCase
from ring import *

class RingTest(TestCase):
    def test_rsa(self):
        size = 4
        msg1, msg2 = "hello", "world!"
        
        def _rn(_):
            return Crypto.PublicKey.RSA.generate(1024, os.urandom)

        key = map(_rn, range(size))
        key = list(key)

        ring = AOSRing(key)

        for i in range(size):
            signature_1 = ring.sign(msg1, i)
            signature_2 = ring.sign(msg2, i)
            self.assertTrue(ring.verify(msg1, signature_1))
            self.assertTrue(ring.verify(msg2, signature_2))
            self.assertFalse(ring.verify(msg1, signature_2))
    
    def test_ecc(self):
        size = 4
        msg1, msg2 = "hello", "world!"

        def _rn(_):
            return EccKey(random.randint(0, EccOrder))
        
        key = map(_rn, range(size))
        key = list(key)

        ring = AOSRing(key)

        for i in range(size):
            signature_1 = ring.sign(msg1, i)
            signature_2 = ring.sign(msg2, i)
            self.assertTrue(ring.verify(msg1, signature_1))
            self.assertTrue(ring.verify(msg2, signature_2))
            self.assertFalse(ring.verify(msg1, signature_2))
    
    def test_mix(self):
        size = 8
        msg1, msg2 = "hello", "world"

        def _rn(_):
            if bool(random.getrandbits(1)):
                return Crypto.PublicKey.RSA.generate(1024, os.urandom)
            else:
                return EccKey(random.randint(0, EccOrder))
        
        key = map(_rn, range(size))
        key = list(key)

        ring = AOSRing(key)

        for i in range(size):
            signature_1 = ring.sign(msg1, i)
            signature_2 = ring.sign(msg2, i)
            self.assertTrue(ring.verify(msg1, signature_1))
            self.assertTrue(ring.verify(msg2, signature_2))
            self.assertFalse(ring.verify(msg1, signature_2))
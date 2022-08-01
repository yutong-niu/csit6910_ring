import os
import sys
import inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

from unittest import TestCase
from ring import *

class RingTest(TestCase):

    def test_ring(self):
        size = 4
        msg1, msg2 = "hello", "world!"
        
        
        def _rn(_):
            return Crypto.PublicKey.RSA.generate(1024, os.urandom)
        
        
        key = map(_rn, range(size))
        key = list(key)
        
        r = Ring(key)
        
        for i in range(size):
            signature_1 = r.sign_message(msg1, i)
            signature_2 = r.sign_message(msg2, i)
            self.assertTrue(r.verify_message(msg1, signature_1))
            self.assertTrue(r.verify_message(msg2, signature_2))
            self.assertFalse(r.verify_message(msg1, signature_2))
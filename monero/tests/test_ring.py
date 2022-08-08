import os
import sys
import inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

from unittest import TestCase
from ring import *

class RingTest(TestCase):
    def test_MLSAG_verification(self):
        size = 4
        vector_size = 5
        msg1, msg2 = "hello", "world"

        def _rn(_):
            return EccKey(random.randint(0, EccOrder))
        
        
        key = []
        for i in range(size):
            key_vector = list(map(_rn, range(vector_size)))
            key.append(key_vector)

        keyPub = [[key[i][j].point for j in range(len(key[i]))] for i in range(len(key))]
        ring = MLSAG(keyPub)

        for i in range(size):
            signature_1 = ring.sign(msg1, i, [k.secret for k in key[i]])
            signature_2 = ring.sign(msg2, i, [k.secret for k in key[i]])
            self.assertTrue(ring.verify(msg1, signature_1))
            self.assertTrue(ring.verify(msg2, signature_2))
            self.assertFalse(ring.verify(msg1, signature_2))
    
    def test_MLSAG_linkability(self):

        size = 4
        vector_size = 5
        msg1, msg2 = "hello", "world"

        def _rn(_):
            return EccKey(random.randint(0, EccOrder))
        
        
        key = []
        for i in range(size):
            key_vector = list(map(_rn, range(vector_size)))
            key.append(key_vector)

        keyPub = [[key[i][j].point for j in range(len(key[i]))] for i in range(len(key))]
        ring = MLSAG(keyPub)

        images = []

        signature_1 = ring.sign(msg1, 0, [k.secret for k in key[0]])
        images += signature_1[:vector_size]
        signature_2 = ring.sign(msg2, 0, [k.secret for k in key[0]])
        signature_3 = ring.sign(msg1, 1, [k.secret for k in key[1]])
        images += signature_3[:vector_size]
        signature_4 = ring.sign(msg2, 1, [k.secret for k in key[1]])
        self.assertTrue(ring.verify(msg1, signature_1))
        self.assertTrue(ring.verify(msg2, signature_2))
        self.assertFalse(ring.verify(msg1, signature_2))

        self.assertTrue(set(signature_2[:vector_size]) <= set(images))
        self.assertTrue(set(signature_4[:vector_size]) <= set(images))
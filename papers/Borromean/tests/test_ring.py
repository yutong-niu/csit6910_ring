import os
import sys
import inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

from unittest import TestCase
from ring import *

class RingTest(TestCase):
    def test_borromean(self):
        msg1, msg2 = "hello", "world!"
        for ring_count in range(2, 6):
            for ring_length in range(2, 6):
                keys = []
                for _ in range(ring_count):
                    keys.append([EccKey(random.randint(0, EccOrder)) for _ in range(ring_length)])

                ring = BorromeanRing(keys)

                k  = []
                for _ in range(ring_count):
                    k.append(random.randint(0, ring_length-1))
                sig1 = ring.sign(msg1, k)
                sig2 = ring.sign(msg2, k)
                self.assertTrue(ring.verify(msg1, sig1))
                self.assertTrue(ring.verify(msg2, sig2))
                self.assertFalse(ring.verify(msg1, sig2))


import setup
import hashlib
from address import *
from unittest import TestCase

class UserKeysTest(TestCase):

    def test_generate(self):
        user = UserKeys.generate()
        self.assertTrue(isinstance(user, UserKeys))
        self.assertTrue(isinstance(user.spend, EccKeyPair))
        self.assertTrue(user.spend.secret != user.view.secret)
        self.assertTrue(user.spend.point == user.spend.secret * EccGenerator)
        self.assertTrue(user.view.point == user.view.secret * EccGenerator)
    
    def test_view(self):
        user = UserKeys.generate()
        self.assertTrue(isinstance(user.view, EccKeyPair))
        msg = "hello"
        hashed_msg = int(hashlib.sha1(msg.encode('utf-8')).hexdigest(), 16)
        sig = user.view.sign(hashed_msg)
        self.assertTrue(user.view.point.verify(hashed_msg, sig))

    def test_spend(self):
        user = UserKeys.generate()
        self.assertTrue(isinstance(user.spend, EccKeyPair))
        msg = "hello"
        hashed_msg = int(hashlib.sha256(msg.encode('utf-8')).hexdigest(), 16)
        sig = user.spend.sign(hashed_msg)
        self.assertTrue(user.spend.point.verify(hashed_msg, sig))        
    
    def test_pubKey(self):
        user = UserKeys.generate()
        pubkey = user.getPubKey()
        self.assertTrue(len(pubkey) == 2)
        self.assertTrue(isinstance(pubkey, tuple))
        self.assertTrue(isinstance(pubkey[0], EccPubKey))
        self.assertTrue(isinstance(pubkey[1], EccPubKey))
    
    def test_oneTimeAddr(self):
        user1 = UserKeys.generate()
        user2 = UserKeys.generate()

        oneTimeAddr1 = UserKeys.generateOneTimeAddr(user1.getPubKey())
        oneTimeAddr2 = UserKeys.generateOneTimeAddr(user2.getPubKey())

        self.assertTrue(user1.ownsOneTimeAddr(oneTimeAddr1))
        self.assertTrue(user2.ownsOneTimeAddr(oneTimeAddr2))
        self.assertFalse(user1.ownsOneTimeAddr(oneTimeAddr2))
        self.assertFalse(user2.ownsOneTimeAddr(oneTimeAddr1))

        oneTimeSecret1 = user1.generateOneTimeSecret(oneTimeAddr1)
        oneTimeSecret2 = user2.generateOneTimeSecret(oneTimeAddr2)

        for (s, p) in [
            (
                oneTimeSecret1,
                oneTimeAddr1[1]
            ),
            (
                oneTimeSecret2,
                oneTimeAddr2[1]
            )
        ]:
            msg = "hello"
            hashed_msg = int(hashlib.sha256(msg.encode('utf-8')).hexdigest(), 16)

            sig = EccKeyPair(s).sign(hashed_msg)

            self.assertTrue(p.verify(hashed_msg, sig))        
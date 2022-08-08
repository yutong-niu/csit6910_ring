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
        self.assertTrue(len(pubkey) == 3)
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
    
    def test_multiOneTimeAddrMultiOut(self):
        size = 4
        users = []
        for i in range(size):
            users.append(UserKeys.generate())

        pubKeys = [user.getPubKey() for user in users]

        oneTimeAddresses = UserKeys.generateMultiOneTimeAddrMultiOut(pubKeys)

        for i in range(size): 
            self.assertTrue(users[i].ownsOneTimeAddr(oneTimeAddresses[i]))

            secret = users[i].generateOneTimeSecret(oneTimeAddresses[i])

            msg = "hello"
            hashed_msg = int(hashlib.sha256(msg.encode('utf-8')).hexdigest(), 16)

            sig = EccKeyPair(secret).sign(hashed_msg)
            self.assertTrue(oneTimeAddresses[i][1].verify(hashed_msg, sig))
    
    def test_subAddrOneTimeAddr(self):
        size = 10
        user = UserKeys.generate()
        subSpendKeys = []
        oneTimeAddresses = []
        for i in range(size):
            subKey = user.generateSub(i)
            oneTimeAddr = subKey.generateOneTimeAddr(subKey.getPubKey())
            subSpendKeys.append(subKey.spend.point)
            oneTimeAddresses.append(oneTimeAddr)
        
        for oneTimeAddr in oneTimeAddresses:
            self.assertTrue(user.ownsOneTimeAddr(oneTimeAddr, subSpendKeys=subSpendKeys))
        
        for i in range(size):
            secret = user.generateOneTimeSecret(oneTimeAddresses[i], subSpendKeys=subSpendKeys)
            self.assertTrue(secret * EccGenerator == oneTimeAddresses[i][1])
    
    def test_subAddrOneTimeAddrMultiOut(self):
        size = 4
        user = UserKeys.generate()
        subSpendKeys = []
        subKeys = []
        for i in range(size):
            subkey = user.generateSub(i)
            subKeys.append(subkey)
            subSpendKeys.append(subkey.spend.point)
            
        oneTimeAddresses = UserKeys.generateMultiOneTimeAddrMultiOut([k.getPubKey() for k in subKeys])
        self.assertTrue(len(oneTimeAddresses) == size)
        for i in range(size):
            self.assertTrue(user.ownsOneTimeAddr(oneTimeAddresses[i]))
            secret = user.generateOneTimeSecret(oneTimeAddresses[i]) 
            self.assertTrue(secret * EccGenerator == oneTimeAddresses[i][1])
        self.assertTrue(len(user.subSpendKeys) == 4)
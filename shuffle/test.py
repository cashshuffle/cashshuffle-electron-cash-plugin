import unittest
# import logging
import random
from .client import protocolThread
from .commutator_thread import (ChannelWithPrint, Channel)
from .coin import Coin
import ecdsa
from electroncash.bitcoin import (regenerate_key, deserialize_privkey, EC_KEY, generator_secp256k1,
                                  number_to_string ,public_key_to_p2pkh)

class testNetwork(object):
    "simple class for emulating the network. You can make your own utxo pool for test"
    def __init__(self):
        self.coins = {}

    def add_coin(self, address, value, height = 0, tx_pos = 0, tx_hash = ''):
        if not self.coins.get(address):
            self.coins[address] = []
        self.coins[address].append({ "height" : height, "value": value , "tx_pos": tx_pos , "tx_hash" :tx_hash})

    def synchronous_get(self, command):
        bc_command, addresses = command
        if bc_command == 'blockchain.address.listunspent':
            if len(addresses)>0:
                return self.coins.get(addresses[0],[])
        else:
            return []

class testThread(protocolThread):
    def __init__(self, host, port, network, amount, fee, sk, pubk, addr_new, change, logger = None, ssl = False):
        protocolThread.__init__(self, host, port, network, amount, fee, sk, pubk, addr_new, change, logger = logger, ssl = False)

    @classmethod
    def from_private_key(cls, priv_key, host, port, network, amount, fee, addr_new, change):
        address, secret, compressed = deserialize_privkey(priv_key)
        sk = regenerate_key(secret)
        pubk = sk.get_public_key(compressed)
        return cls(host, port, network, amount, fee, sk, pubk, addr_new, change)

    @classmethod
    def from_sk(cls, sk, host, port, network, amount, fee, addr_new, change, compressed = True, logger = None):
        pubk = sk.get_public_key(compressed)
        return cls(host, port, network, amount, fee, sk, pubk, addr_new, change, logger = logger)

class random_sk(EC_KEY):

    def __init__(self):
        G = generator_secp256k1
        _r  = G.order()
        pvk = ecdsa.util.randrange( pow(2,256) ) %_r
        eck = EC_KEY.__init__(self, number_to_string(pvk,_r))

class Test_protocol(unittest.TestCase):

    def setUp(self):
        self.HOST = 'localhost'
        self.PORT = 33333
        self.fee = 1000
        self.amount = 10000
        self.network = testNetwork()
        self.logger = Channel()

    def get_random_address(self):
        return public_key_to_p2pkh(bytes.fromhex(random_sk().get_public_key()))

    def test_correct_protocol(self):
        players_count = 3
        # generate random keys
        sks = [random_sk() for sk in range(players_count)]
        for sk in sks:
            pubk = sk.get_public_key()
            addr = public_key_to_p2pkh(bytes.fromhex(pubk))
            # add coins to pseudonetwork with sufficient ammount
            self.network.add_coin(addr , self.amount + random.randint(1001 , 5000))
        # make threads
        protocolThreads = [testThread.from_sk(sk, self.HOST, self.PORT, self.network, self.amount, self.fee, self.get_random_address(), self.get_random_address(), logger = self.logger) for sk in sks]
        for pThread in protocolThreads:
            pThread.start()
        done = False
        completed = 0
        while not done:
            message = self.logger.get()
            print(message)
            if message[-17:] == "complete protocol":
                completed += 1
                if completed == players_count:
                    done = True
            if message[:5] == 'Blame':
                done = True
        self.assertEqual(completed, players_count)        

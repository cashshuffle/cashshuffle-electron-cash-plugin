import unittest
import configparser
import subprocess
import os
import random
from electroncash_plugins.shuffle.client import protocolThread
from electroncash_plugins.shuffle.commutator_thread import (ChannelWithPrint, Channel)
from electroncash_plugins.shuffle.coin import Coin
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
            if len(addresses) > 0:
                return self.coins.get(addresses[0],[])
        else:
            return []

class testThread(protocolThread):
    def __init__(self, host, port, network, amount, fee, sk, pubk, addr_new, change, logger = None, ssl = False):
        # protocolThread.__init__(self, host, port, network, amount, fee, sk, pubk, addr_new, change, logger = logger, ssl = False)
        super(testThread, self).__init__(host, port, network, amount, fee, sk, pubk, addr_new, change, logger = logger, ssl = False)

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

class TestProtocolCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestProtocolCase,self).__init__(*args, **kwargs)
        config = configparser.ConfigParser()
        config.read_file(open('plugins/shuffle/tests/config.ini'))
        self.HOST = config["CashShuffle"]["address"]
        self.PORT = int(config["CashShuffle"]["port"])
        self.fee = int(config["Clients"]["fee"])
        self.amount = int(config["Clients"]["amount"])
        self.number_of_players = int(config["CashShuffle"]["pool_size"])
        self.server_degug = " -d " if {"True":True, "False":False}.get(config["CashShuffle"]["enable_debug"], False) else " "
        self.args = self.server_degug + " -s "+ str(self.number_of_players) + " -p " + str(self.PORT)
        self.casshuffle_path = "/home/yurkazaytsev/work/src/github.com/cashshuffle/cashshuffle/cashshuffle"

    def setUp(self):
        self.network = testNetwork()
        self.logger = ChannelWithPrint()
        self.server = subprocess.Popen("exec " + self.casshuffle_path + self.args, shell = True, preexec_fn=os.setsid)


    def tearDown(self):
        self.server.kill()

    def get_random_address(self):
        return public_key_to_p2pkh(bytes.fromhex(random_sk().get_public_key()))

    def make_clients_threads(self, number_of_clients = None, with_print = False):
        if not number_of_clients:
            number_of_clients = self.number_of_players
        # generate random keys
        players = [{"sk": random_sk(), "channel":ChannelWithPrint() if with_print else Channel()}  for sk in range(number_of_clients)]
        # loggers = [Channel() for _ in range(self.number_of_players)]
        for player in players:
            pubk = player["sk"].get_public_key()
            addr = public_key_to_p2pkh(bytes.fromhex(pubk))
            # add coins to pseudonetwork with sufficient ammount
            self.network.add_coin(addr , self.amount + random.randint(self.amount + 1 , self.amount + self.fee + 1000))

        # make threads
        protocolThreads = [testThread.from_sk(player["sk"], self.HOST, self.PORT, self.network, self.amount, self.fee, self.get_random_address(), self.get_random_address(), logger = player['channel']) for player in players]
        return protocolThreads

    def start_protocols(self, protocolThreads):
        for pThread in protocolThreads:
            pThread.start()

    def stop_protocols(self, protocolThreads):
        for pThread in protocolThreads:
            pThread.join()

    def is_round_live(sefl, pThread):
        return pThread.executionThread.is_alive() if pThread.executionThread else None

    def get_last_logger_message(self, pThread, debug = False):
        message = None
        while not pThread.logger.empty():
            message = pThread.logger.get()
            if debug:
                print(message)
        return message

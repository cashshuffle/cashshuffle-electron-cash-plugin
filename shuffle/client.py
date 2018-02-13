import sys
import time
from .coin import Coin
from .crypto import Crypto
from .messages import Messages
from .commutator_thread import Commutator
from .commutator_thread import Channel
from .commutator_thread import ChannelWithPrint
from .phase import Phase
import socket
import threading
from .coin_shuffle import Round
from ecdsa.util import number_to_string
import ecdsa
from electroncash.bitcoin import (
    generator_secp256k1, point_to_ser, public_key_to_p2pkh, EC_KEY,
    bip32_root, bip32_public_derivation, bip32_private_derivation, pw_encode,
    pw_decode, Hash, public_key_from_private_key, address_from_private_key,
    is_private_key, xpub_from_xprv, is_new_seed, is_old_seed,
    var_int, op_push, msg_magic)

class protocolThread(threading.Thread):
    """
    This class emulate thread with protocol run
    """
    def __init__(self, host, port, network, amount, fee, sk, pubk, addr_new, change, logger = None, ssl = False):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.messages = Messages()
        self.income = Channel()
        self.outcome = Channel()
        if not logger:
            self.logger = ChannelWithPrint()
        else:
            self.logger = logger
        self.commutator = Commutator(self.income, self.outcome, ssl = ssl)
        self.vk = pubk
        self.session = None
        self.number = None
        self.number_of_players = None
        self.players = {}
        self.amount = amount
        self.fee = fee
        self.sk = sk
        self.addr_new = addr_new
        self.change = change
        self.deamon = True
        self.protocol = None
        self.network = network
        self.tx = None
        self.executionThread = None
        self.done = threading.Event()

    def not_time_to_die(f):
        def wrapper(self):
            if not self.done.is_set():
                f(self)
            else:
                pass

        return wrapper

    @not_time_to_die
    def register_on_the_pool(self):
        self.messages.make_greeting(self.vk, int(self.amount))
        msg = self.messages.packets.SerializeToString()
        self.income.send(msg)
        req = self.outcome.recv()
        self.messages.packets.ParseFromString(req)
        self.session = self.messages.packets.packet[-1].packet.session
        self.number = self.messages.packets.packet[-1].packet.number
        if self.session != '':
            self.logger.send("Player "  + str(self.number)+" get session number.\n")

    @not_time_to_die
    def wait_for_announcment(self):
        while self.number_of_players is None:
            req = self.outcome.get()
            if self.done.is_set():
                break
            if req is None:
                time.sleep(0.1)
                continue
            try:
                self.messages.packets.ParseFromString(req)
            except:
                continue
            if self.messages.get_phase() == 1:
                self.number_of_players = self.messages.get_number()
                break
            else:
                self.logger.send("Player " + str(self.messages.get_number()) + " joined the pool!")

    @not_time_to_die
    def share_the_key(self):
        self.logger.send("Player " + str(self.number) + " is about to share verification key with " + str(self.number_of_players) +" players.\n")
        #Share the keys
        self.messages.clear_packets()
        self.messages.packets.packet.add()
        self.messages.packets.packet[-1].packet.from_key.key = self.vk
        self.messages.packets.packet[-1].packet.session = self.session
        self.messages.packets.packet[-1].packet.number = self.number
        shared_key_message = self.messages.packets.SerializeToString()
        self.income.send(shared_key_message)

    @not_time_to_die
    def gather_the_keys(self):
        messages = b''
        for i in range(self.number_of_players):
            messages += self.outcome.recv()
        self.messages.packets.ParseFromString(messages)
        self.players = {packet.packet.number:str(packet.packet.from_key.key) for packet in self.messages.packets.packet}
        if self.players:
            self.logger.send('Player ' +str(self.number)+ " get " + str(len(self.players))+".\n")

    @not_time_to_die
    def start_protocol(self):
        coin = Coin(self.network)
        crypto = Crypto()
        self.messages.clear_packets()
        begin_phase = Phase('Announcement')
        # Make Round
        self.protocol = Round(
            coin,
            crypto,
            self.messages,
            self.outcome,
            self.income,
            self.logger,
            self.session,
            begin_phase,
            self.amount ,
            self.fee,
            self.sk,
            self.vk,
            self.players,
            self.addr_new,
            self.change)
        # self.executionThread = threading.Thread(target = self.protocol.protocol_definition)
        self.executionThread = threading.Thread(target = self.protocol.protocol_loop)
        self.executionThread.start()
        self.done.wait()
        self.executionThread.join()


    def run(self):
        try:
            self.commutator.connect(self.host, self.port)
            self.commutator.start()
        except:
            self.logger.send("Error: cannot connect to server")
        try:
            self.register_on_the_pool()
        except:
            self.logger.send("Error: cannot register on the pool")
        try:
            self.wait_for_announcment()
        except:
            self.logger.send("Error: cannot complete the pool")
        try:
            self.share_the_key()
        except:
            self.logger.send("Error: cannot share the keys")
        try:
            self.gather_the_keys()
        except:
            self.logger.send("Error: cannot gather the keys")
        self.start_protocol()
        if self.commutator.is_alive():
            self.commutator.join()

    def stop(self):
        if self.executionThread:
            self.protocol.done = True
        self.done.set()
        self.outcome.send(None)


    def join(self, timeout = None):
        self.stop()
        threading.Thread.join(self, timeout)

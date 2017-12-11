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
# from electroncash.bitcoin import (generator_secp256k1, point_to_ser, EC_KEY)
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
        self.commutator.connect(host, port)
        self.network = network
        self.tx = None
        self.executionThread = None
        self.protocol = None
        self.time_to_die = False

    def run(self):
        self.commutator.start()
        self.messages.make_greeting(self.vk, int(self.amount))
        msg = self.messages.packets.SerializeToString()
        self.income.send(msg)
        req = self.outcome.recv()
        self.messages.packets.ParseFromString(req)
        self.session = self.messages.packets.packet[-1].packet.session
        self.number = self.messages.packets.packet[-1].packet.number
        if self.session != '':
             self.logger.send("Player "  + str(self.number)+" get session number.\n")
        # # Here is when announcment should begin
        req = self.outcome.recv()
        self.messages.packets.ParseFromString(req)
        phase = self.messages.get_phase()
        number = self.messages.get_number()
        if phase == 1 and number > 0:
            self.logger.send("Player " + str(self.number) + " is about to share verification key with " + str(number) +" players.\n")
            self.number_of_players = number
            #Share the keys
            self.messages.clear_packets()
            self.messages.packets.packet.add()
            self.messages.packets.packet[-1].packet.from_key.key = self.vk
            self.messages.packets.packet[-1].packet.session = self.session
            self.messages.packets.packet[-1].packet.number = self.number
            shared_key_message = self.messages.packets.SerializeToString()
            self.income.send(shared_key_message)
            messages = b''
            for i in range(number):
                messages += self.outcome.recv()
            self.messages.packets.ParseFromString(messages)
            self.players = {packet.packet.number:str(packet.packet.from_key.key) for packet in self.messages.packets.packet}
        if self.players:
            self.logger.send('Player ' +str(self.number)+ " get " + str(len(self.players))+".\n")
        #
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
        self.executionThread = threading.Thread(target = self.protocol.protocol_definition)
        self.executionThread.start()
        while not self.protocol.done and not self.time_to_die and self.executionThread.is_alive():
            time.sleep(0.1)
        self.commutator.join()

    def join(self, timeout = None):
        if self.executionThread:
            self.time_to_die = True
            time.sleep(0.2)
        self.commutator.join()
        threading.Thread.join(self, timeout)

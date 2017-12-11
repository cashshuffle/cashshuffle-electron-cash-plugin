from . import message_pb2 as message_factory
from random import shuffle

class Messages(object):

    def __init__(self):
        self.packets = message_factory.Packets()
        self.phases = {
            'Announcement':message_factory.ANNOUNCEMENT, # Everone generates new encryption keys and distributes them to one another.
            'Shuffling':message_factory.SHUFFLE, # In turn, each of the players adds his own new address and reshufles the result.
            'BroadcastOutput':message_factory.BROADCAST, # The final output order is broadcast to everyone.
            'EquivocationCheck':message_factory.EQUIVOCATION_CHECK, # Check that everyone has the same set of inputs.
            'VerificationAndSubmission':message_factory.VERIFICATION_AND_SUBMISSION, # Generate transaction, distribute signatures, and send it off.
            'Signing':message_factory.SIGNING,
            'Blame':message_factory.BLAME, # Someone has attempted to cheat.
            }

    def make_greeting(self, vk, amount):
        packet = self.packets.packet.add()
        packet.packet.from_key.key = vk
        packet.packet.registration.amount = amount

    def form_last_packet(self, eck, session, number, vk_from , vk_to, phase):
        packet = self.packets.packet[-1]
        packet.packet.session = session
        packet.packet.number = int(number)
        packet.packet.phase = self.phases.get(phase)
        packet.packet.from_key.key = vk_from
        if vk_to:
            packet.packet.to_key.key = vk_to
        else:
            packet.packet.ClearField('to_key')
        msg = packet.packet.SerializeToString()
        packet.signature.signature = eck.sign_message(msg,True)

    def form_all_packets(self, eck, session, number, vk_from, vk_to, phase):
        for packet in self.packets.packet:
            packet.packet.session = session
            packet.packet.phase = self.phases.get(phase)
            packet.packet.number = int(number)
            packet.packet.session = session
            packet.packet.number = int(number)
            packet.packet.from_key.key = vk_from
            if vk_to :
                 packet.packet.to_key.key = vk_to
            else:
                packet.packet.ClearField('to_key')
            msg = packet.packet.SerializeToString()
            packet.signature.signature = eck.sign_message(msg,True)

    def general_blame(self, reason,  accused):
        """
        accused is a veryfikation key! of player who accused the Blame
        reason is a reason why
        """
        # add new packet
        packet = self.packets.packet.add()
        # set blame resaon
        if reason in range(9): # Better to place evident reason states here
            packet.packet.message.blame.reason = reason
        # set blame acused
        packet.packet.message.blame.accused.key = accused
        # set phase (it is 'Blame' here, for real ;) )
        packet.packet.phase = message_factory.BLAME
        # we return nothing here. Message_factory is a state machine, We just update state


    def blame_insufficient_funds(self, offender):
        """
        offender is a veryfikation key! of player who have insufficient funds
        """
        self.general_blame(message_factory.INSUFFICIENTFUNDS, offender)

    def blame_equivocation_failure(self, accused):
        """
        accused - is verification key of player with hash mismathc
        """
        self.general_blame(message_factory.EQUIVOCATIONFAILURE, accused)

    def blame_missing_output(self, accused):
        """
        accused - is verification key of player who haven't find his address
        """
        self.general_blame(message_factory.MISSINGOUTPUT, accused)

    def blame_invalid_signature(self, accused):
        """
        accused - is verification key of player whos signature have failed
        """
        self.general_blame(message_factory.INVALIDSIGNATURE, accused)

    def blame_wrong_transaction_signature(self, accused):
        """
        accused - is verification key of player with wrong signature
        """
        self.general_blame(message_factory.INVALIDSIGNATURE, accused)

    def add_encryption_key(self, ek, change):
        """
        Adds encryption keys at the Announcement stage
        ek - is serialized encryption key
        """
        packet = self.packets.packet.add()
        packet.packet.message.key.key = ek
        if change : packet.packet.message.address.address = change

    def get_new_addresses(self):
        return [packet.packet.message.str for packet in self.packets.packet]

    def get_hashes(self):
        return {str(packet.packet.from_key.key) : packet.packet.message.hash.hash.encode('utf-8')  for packet in  self.packets.packet}

    def add_str(self, string):
        packet = self.packets.packet.add()
        packet.packet.message.str = string

    def add_hash(self, hash_value):
        packet = self.packets.packet.add()
        packet.packet.message.hash.hash = hash_value

    def add_signature(self, signature):
        packet = self.packets.packet.add()
        packet.packet.message.signature.signature = signature

    def shuffle_packets(self):
        packs = [p for p in self.packets.packet]
        shuffle(packs)
        self.clear_packets()
        for i in range(0,len(packs)):
            self.packets.packet.add()
            self.packets.packet[-1].CopyFrom(packs[i])

    def encryption_keys_count(self):
        return len([1 for packet in self.packets.packet if len(packet.packet.message.key.key) != 0])

    def get_session(self):
        return self.packets.packet[-1].packet.session

    def get_number(self):
        return self.packets.packet[-1].packet.number

    def get_encryption_key(self):
        return self.packets.packet[-1].packet.message.key.key

    def get_address(self):
        return self.packets.packet[-1].packet.message.address.address

    def get_from_key(self):
        return self.packets.packet[-1].packet.from_key.key

    def get_to_key(self):
        return self.packets.packet[-1].packet.to_key.key

    def get_phase(self):
        return self.packets.packet[-1].packet.phase

    def get_hash(self):
        return self.packets.packet[-1].packet.message.hash.hash

    def get_str(self):
        return self.packets.packet[-1].packet.message.str

    def get_signature(self):
        return self.packets.packet[-1].packet.message.signature.signature

    def get_signatures_and_packets(self):
        return [ [packet.signature.signature, packet.packet.SerializeToString(), packet.packet.from_key.key] for packet in self.packets.packet]

    def get_players(self):
        return {packet.packet.number : str(packet.packet.from_key.key) for packet in self.packets.packet}

    def get_blame(self):
        return [packet.packet.message for packet in self.packets.packet]

    def clear_packets(self):
        self.__init__()
